import json
import ast
import logging
import math
from datetime import date
from datetime import datetime as date_time, timedelta
from psycopg2 import IntegrityError
from Crypto.Cipher import DES3
import base64
from collections import OrderedDict
import requests

from odoo import http, fields, _
from odoo.exceptions import UserError, ValidationError, AccessDenied, AccessError
from odoo.addons.restful.common import (
    extract_arguments,
    invalid_response,
    valid_response,
    default,
)
from odoo.addons.website_form.controllers.main import WebsiteForm
from odoo.addons.tm_base_gateway.common import (
    suds_to_json,
)

from odoo.http import request
from odoo.addons.smartpay_api.controllers.main import APIController as SmartAPIController
from odoo.addons.smartpay_api_extend.tools.validate_machine import validate_machine
from odoo.addons.smartpay_multi_devices.tools.validate_token import validate_token

_REQUEST_TYPES_IDS = ['general_inquiry', 'recharge_wallet', 'service_bill_inquiry', 'pay_service_bill', 'pay_invoice',
                      'wallet_invitation']
SECRET_KEY = base64.b64decode('MfG6sLDTQIaS8QgOnkBS2THxurCw00CG')
UNPAD = lambda s: s[0:-s[-1]]

REQUEST_FIELDS = {
    'billingAcct': 'request_billing_acct',
    'extraBillingAcctKeys': 'request_extra_billing_acct_keys',
    'customProperties': 'request_custom_properties',
    'inquiryTransactionId': 'request_inquiry_transaction_id',
    'machine_serial': 'request_machine_serial',
}

STATIC_VALUES_PROVIDER = {
    "khales": {
        'currency_id': '818',
        'pmtMethod': 'ACTDEB',
        'pmtType': 'BNKPTN',
    },
    "fawry": {
        'currency_id': 'EGP',
        'pmtMethod': 'CASH',
        'pmtType': 'BNKPTN',
        'notifyMobile': '',
    },
}

_logger = logging.getLogger(__name__)


def get_record(model_name, record_id, request):
    """Get record for a given model.
    @type: model_name: char
    @param model_name: Name of a model.

    @type: record_id: char
    @param record_id: record_id(maybe name of record) to search.
    @type: request: Request object
    @param request: Object from request

    @retype: smartpay_operations.request object
    """
    if not all([model_name, record_id, request]):
        return None
    model_record = request.env['ir.model'].sudo().search([('model', '=', model_name)])
    if not model_record:
        _logger.info("Model '%s' not found", model_name)
        return None
    return request.env[model_name].sudo().search(
        [('name', '=', record_id)], limit=1)


def parse_request_data_to_fields(request_data, request):
    """Parse request data to fields on object smartpay_operations_request.

    @param request: Object from request.
    @param request_data: Request data from API.

    @rtype: dict
    """
    request_fields = {}
    new_request_data = {k: request_data.get(k) for k in REQUEST_FIELDS.keys() if request_data.get(k)}
    for request_data_field in new_request_data.keys():
        if request_data_field == 'inquiryTransactionId' and \
                isinstance(new_request_data[request_data_field], str):
            model_name = 'smartpay_operations.request'
            record = get_record(model_name,
                                new_request_data.get(request_data_field),
                                request)
            if record:
                request_fields[REQUEST_FIELDS[request_data_field]] = record.id
        else:
            request_fields[REQUEST_FIELDS[request_data_field]] = new_request_data.get(request_data_field)
    return request_fields


def get_static_values(value_name, provider):
    """Returns the static values for the given provider.
    @param value_name: Name of the value.
    @param provider: Name of the provider.

    @rtype: str
    @return : Static value for the given value name of the related provider.
    """
    value = None
    try:
        value = STATIC_VALUES_PROVIDER.get(provider).get(value_name, '')
    except Exception as es:
        _logger.info("Error on read static values %s on provider %s" %
                     (value_name, provider))
        _logger.error('Error is %s' % str(es))
    return value


class InheritRequestApiTemp(SmartAPIController.RequestApiTemp):

    @validate_token
    @validate_machine
    @http.route('/api/create_machine_request', type="http", auth="none", methods=["POST"], csrf=False)
    def create_machine_request(self, **request_data):
        """Override this method to change call decorated method."""
        _logger.info("@@@@@@@@@@@@@@@@@@@ Calling Machine Request API")
        machine_serial = request.httprequest.headers.get("machine_serial")
        request_data['machine_serial'] = request.httprequest.headers.get("machine_serial")

        if not request_data.get('request_type') or request_data.get('request_type') not in _REQUEST_TYPES_IDS:
            return invalid_response("request_type", _("request type invalid"), 400)

        if request_data.get('request_type') == 'recharge_wallet':
            if not request_data.get('trans_number'):
                return invalid_response("receipt_number_not_found", _("missing deposit receipt number in request data"),
                                        400)
            if not request_data.get('trans_date'):
                return invalid_response("date_not_found", _("missing deposit date in request data"), 400)
            if not request_data.get('trans_amount'):
                return invalid_response("amount_not_found", _("missing deposit amount in request data"), 400)
            if not any(hasattr(field_value, 'filename') for field_name, field_value in request_data.items()):
                return invalid_response("receipt_not_found", _("missing deposit receipt attachment in request data"),
                                        400)

            open_request = request.env["smartpay_operations.request"].sudo().search(
                [('request_type', '=', 'recharge_wallet'), ("partner_id", "=", request.env.user.partner_id.id),
                 ("stage_id", "=", 1)], order="id DESC", limit=1)
            if open_request:
                open_request_in_minute = open_request.filtered(
                    lambda r: r.create_date >= date_time.now() - timedelta(minutes=1))
                if open_request_in_minute:
                    return invalid_response("request_already_exist",
                                            _("You have a wallet recharge request in progress with REQ Number (%s)")
                                            % (open_request_in_minute.name), 400)
                else:
                    open_request.update({'stage_id': 3})

            request_data['product_id'] = request.env["product.product"].sudo().search(
                [('name', '=', 'Wallet Recharge')]).id

        if not request_data.get('product_id') and request_data.get('request_type') not in (
                'general_inquiry', 'pay_invoice', 'wallet_invitation'):
            return invalid_response("service_not_found", _("missing service in request data"), 400)
        elif request_data.get('request_type') not in ('general_inquiry', 'pay_invoice', 'wallet_invitation'):
            service = request.env["product.product"].sudo().search(
                [("id", "=", request_data.get('product_id')), ("type", "=", "service")],
                order="id DESC", limit=1)
            if not service:
                return invalid_response("service", _("service invalid"), 400)

        if request_data.get('request_type') == 'wallet_invitation':
            if not request_data.get('mobile_number'):
                return invalid_response("mobile_number_not_found",
                                        _("missing mobile number for invited user in request data"), 400)

            open_request = request.env["smartpay_operations.request"].sudo().search(
                [('request_type', '=', 'wallet_invitation'), ('mobile_number', '=', request_data.get('mobile_number')),
                 ('partner_id', '=', request.env.user.partner_id.id), ("stage_id", "=", 1)], order="id DESC", limit=1)
            if open_request:
                return invalid_response("request_already_exist",
                                        _("You have a wallet invitation request in progress for mobile number (%s) with REQ Number (%s)") % (
                                            request_data.get('mobile_number'), open_request.name), 400)

            done_request = request.env["smartpay_operations.request"].sudo().search(
                [('request_type', '=', 'wallet_invitation'),
                 ('mobile_number', '=', request_data.get('mobile_number')), ("stage_id", "=", 5)],
                order="id DESC", limit=1)
            if done_request:
                return invalid_response("request_already_exist",
                                        _("The mobile number (%s) already has a wallet") % (
                                            request_data.get('mobile_number')), 400)

        if request_data.get('request_type') == 'pay_invoice':
            if not request_data.get('trans_amount'):
                return invalid_response("amount_not_found", _("missing invoice amount in request data"), 400)

        if request_data.get('request_type') == 'service_bill_inquiry' or request_data.get(
                'request_type') == 'pay_service_bill':
            # Tamayoz TODO: how to check billingAcct when provider in ('fawry', 'khales')
            # if not request_data.get('billingAcct'):
            # return invalid_response("billingAcct_not_found", _("missing billing account in request data"), 400)

            provider_provider = request_data.get('provider')
            if request_data.get('request_type') == 'pay_service_bill':
                # if provider_provider == 'fawry' or provider_provider == 'khales':
                # if not request_data.get('currency_id'):
                #     return invalid_response("curCode_not_found",
                #                             _("missing bill currency code in request data"), 400)
                # if not request_data.get('pmtMethod'):
                #     return invalid_response("pmtMethod_not_found",
                #                             _("missing payment method in request data"), 400)
                # Get static values
                pmtType = request_data.get('pmtType')
                if provider_provider == 'khales':
                    pmtType = get_static_values('pmtType', 'khales')
                elif provider_provider == 'fawry':
                    pmtType = get_static_values('pmtType', 'fawry')

                if provider_provider == 'khales':
                    # if not request_data.get('pmtType'):
                    #     return invalid_response("pmtType_not_found", _("missing payment type in request data"), 400)
                    '''
                    if not request_data.get('billerId'):
                        return invalid_response("billerId_not_found", _("missing biller id in request data"), 400)
                    '''
                    if not request_data.get('ePayBillRecID'):
                        return invalid_response("ePayBillRecID_not_found",
                                                _("missing ePay Bill Rec ID in request data"), 400)
                    # if not request_data.get('pmtId'):
                    # return invalid_response("pmtId_not_found", _("missing payment id in request data"), 400)
                    if not request_data.get('feesAmt'):
                        return invalid_response("feesAmt_not_found", _("missing fees amount in request data"), 400)
                    # if not request_data.get('pmtRefInfo'):
                    # return invalid_response("pmtRefInfo_not_found", _("missing payment Ref Info in request data"), 400)
                    payAmtTemp = float(request_data.get('trans_amount'))
                    payAmts = request_data.get('payAmts')
                    if payAmts:
                        payAmts = ast.literal_eval(payAmts)
                        for payAmt in payAmts:
                            payAmtTemp -= float(payAmt.get('AmtDue'))
                        if payAmtTemp != 0:
                            return invalid_response("payAmts_not_match",
                                                    _("The sum of payAmts must be equals trans_amount"), 400)
                    feesAmtTemp = request_data.get('feesAmt') or 0.00
                    feesAmts = request_data.get('feesAmts')
                    if feesAmts:
                        feesAmts = ast.literal_eval(feesAmts)
                        for feeAmt in feesAmts:
                            feesAmtTemp -= float(feeAmt.get('Amt'))
                        if feesAmtTemp != 0:
                            return invalid_response("feesAmts_not_match",
                                                    _("The sum of feesAmts must be equals feesAmt"), 400)

                if ((provider_provider == 'fawry' and pmtType == "POST")
                    or provider_provider == 'khales') \
                        and not request_data.get('billRefNumber'):
                    return invalid_response("billRefNumber_not_found",
                                            _("missing bill reference number in request data"), 400)

                # Provider is mandatory because the service fee is different per provider.
                # So the user must send provider that own the bill inquiry request for prevent pay bill
                # with total amount different of total amount in bill inquiry
                if provider_provider:
                    provider = request.env['payment.acquirer'].sudo().search([("provider", "=", provider_provider)])
                    # if provider: # Tamayoz Note: Comment this condition for solving service_providerinfo assign before initilizing
                    service_providerinfo = request.env['product.supplierinfo'].sudo().search([
                        ('product_tmpl_id', '=', service.product_tmpl_id.id),
                        ('name', '=', provider.related_partner.id)
                    ])
                    if not service_providerinfo:
                        return invalid_response(
                            "Incompatible_provider_service", _("%s is not a provider for (%s) service") % (
                                provider_provider, service.name or '-'), 400)
                    elif provider_provider in ('fawry', 'masary'):
                        inquiryTransactionId = request_data.get('inquiryTransactionId')
                        if (json.loads(service_providerinfo.biller_info, strict=False).get('inquiry_required')
                                # Tamayoz TODO: Rename inquiry_required in standard API
                                # or json.loads(service_providerinfo.biller_info, strict=False).get('SupportPmtReverse')
                        ) \
                                and not inquiryTransactionId:
                            return invalid_response("inquiryTransactionId_not_found",
                                                    _("missing inquiry transaction id in request data"), 400)
                else:
                    return invalid_response("provider_not_found",
                                            _("missing provider in request data"), 400)

                trans_amount = float(request_data.get('trans_amount'))
                if not trans_amount:
                    return invalid_response("amount_not_found",
                                            _("missing bill amount in request data"), 400)
                else:
                    # Calculate Fees
                    provider_fees_calculated_amount = 0.0
                    provider_fees_actual_amount = 0.0
                    merchant_cashback_amount = 0.0
                    customer_cashback_amount = 0.0
                    extra_fees_amount = 0.0
                    commissions = request.env['product.supplierinfo.commission'].sudo().search_read(
                        domain=[('vendor', '=', service_providerinfo.name.id),
                                ('vendor_product_code', '=', service_providerinfo.product_code)],
                        fields=['Amount_Range_From', 'Amount_Range_To',
                                'Extra_Fee_Amt', 'Extra_Fee_Prc',
                                'Mer_Fee_Amt', 'Mer_Fee_Prc', 'Mer_Fee_Prc_MinAmt', 'Mer_Fee_Prc_MaxAmt',
                                'Mer_Comm_Full_Fix_Amt', 'Cust_Comm_Full_Fix_Amt',
                                'Bill_Merchant_Comm_Prc', 'Bill_Customer_Comm_Prc']
                    )
                    for commission in commissions:
                        if commission['Amount_Range_From'] <= trans_amount \
                                and commission['Amount_Range_To'] >= trans_amount:
                            if commission['Mer_Comm_Full_Fix_Amt'] > 0:
                                merchant_cashback_amount = commission['Mer_Comm_Full_Fix_Amt']
                                customer_cashback_amount = commission['Cust_Comm_Full_Fix_Amt']
                            elif commission['Bill_Merchant_Comm_Prc'] > 0:
                                merchant_cashback_amount = trans_amount * commission[
                                    'Bill_Merchant_Comm_Prc'] / 100
                                customer_cashback_amount = trans_amount * commission[
                                    'Bill_Customer_Comm_Prc'] / 100
                            if commission['Extra_Fee_Amt'] > 0:
                                extra_fees_amount = commission['Extra_Fee_Amt']
                            elif commission['Extra_Fee_Prc'] > 0:
                                extra_fees_amount = trans_amount * commission['Extra_Fee_Prc'] / 100
                            if commission['Mer_Fee_Amt'] > 0:
                                provider_fees_calculated_amount = commission['Mer_Fee_Amt']
                            elif commission['Mer_Fee_Prc'] > 0:
                                # Fees amount = FA + [Percentage * Payment Amount]
                                # Fees amount ====================> provider_fees_calculated_amount
                                # FA =============================> provider_fees_calculated_amount
                                # [Percentage * Payment Amount] ==> provider_fees_prc_calculated_amount
                                provider_fees_prc_calculated_amount = trans_amount * commission[
                                    'Mer_Fee_Prc'] / 100
                                if provider_fees_prc_calculated_amount < commission['Mer_Fee_Prc_MinAmt']:
                                    provider_fees_prc_calculated_amount = commission['Mer_Fee_Prc_MinAmt']
                                elif provider_fees_prc_calculated_amount > commission['Mer_Fee_Prc_MaxAmt'] \
                                        and commission['Mer_Fee_Prc_MaxAmt'] > 0:
                                    provider_fees_prc_calculated_amount = commission['Mer_Fee_Prc_MaxAmt']
                                provider_fees_calculated_amount += provider_fees_prc_calculated_amount
                            elif provider_provider == 'khales':
                                provider_fees_calculated_amount = float(request_data.get('feesAmt'))
                            break
                    calculated_payment_amount = trans_amount + provider_fees_calculated_amount + extra_fees_amount
                    machine_wallet_reservation_id = False
                    unlink_wallet_reservation = False
                    if not json.loads(service_providerinfo.biller_info, strict=False).get(
                            'CorrBillTypeCode') or json.loads(service_providerinfo.biller_info, strict=False).get(
                        'Type') == 'CASHININT':
                        if service.has_sale_limit:
                            limit_fees_amounts = {}
                            for sale_limit_id in service.sale_limit_ids:
                                limit_type = sale_limit_id.limit_type
                                limit_amount = sale_limit_id.limit_amount
                                partner_sale_limit_id = request.env['res.partner.product.sale.limit'].sudo().search(
                                    [('partner_id', '=', request.env.user.partner_id.id),
                                     ('product_tmpl_id', '=', service.product_tmpl_id.id),
                                     ('limit_type', '=', limit_type)], limit=1)
                                if partner_sale_limit_id:
                                    limit_amount = partner_sale_limit_id.limit_amount
                                timetuple = date_time.now().timetuple()
                                sale_limit_domain = [('partner_id', '=', request.env.user.partner_id.id),
                                                     ('product_id', '=', service.id),
                                                     ('limit_type', '=', limit_type),
                                                     ('year', '=', timetuple.tm_year)]
                                if limit_type == 'daily':
                                    sale_limit_domain += [('day', '=', timetuple.tm_yday)]
                                elif limit_type == 'weekly':
                                    sale_limit_domain += [('week', '=', date_time.now().isocalendar()[1])]
                                elif limit_type == 'monthly':
                                    sale_limit_domain += [('month', '=', timetuple.tm_mon)]
                                sale_limit = request.env['res.partner.sale.limit'].sudo().search(sale_limit_domain,
                                                                                                 order="id DESC",
                                                                                                 limit=1)
                                calculated_sold_amount = calculated_payment_amount
                                if sale_limit:
                                    calculated_sold_amount += sale_limit.sold_amount
                                if limit_amount < calculated_sold_amount:
                                    over_limit_fees_ids = []
                                    if partner_sale_limit_id:
                                        if partner_sale_limit_id.over_limit_fees_policy == 'product_over_limit_fees' and partner_sale_limit_id.product_over_limit_fees_ids:
                                            over_limit_fees_ids = partner_sale_limit_id.product_over_limit_fees_ids
                                            limit_amount = \
                                                over_limit_fees_ids.sorted(lambda l: l.sale_amount_to, reverse=True)[
                                                    0].sale_amount_to + partner_sale_limit_id.limit_amount
                                        if partner_sale_limit_id.over_limit_fees_policy == 'custom_over_limit_fees' and partner_sale_limit_id.over_limit_fees_ids:
                                            over_limit_fees_ids = partner_sale_limit_id.over_limit_fees_ids
                                            limit_amount = \
                                                over_limit_fees_ids.sorted(lambda l: l.sale_amount_to, reverse=True)[
                                                    0].sale_amount_to + partner_sale_limit_id.limit_amount
                                    else:
                                        if sale_limit_id.has_over_limit_fees and sale_limit_id.over_limit_fees_ids:
                                            over_limit_fees_ids = sale_limit_id.over_limit_fees_ids
                                            limit_amount = \
                                                over_limit_fees_ids.sorted(lambda l: l.sale_amount_to, reverse=True)[
                                                    0].sale_amount_to + sale_limit_id.limit_amount

                                    if limit_amount < calculated_sold_amount:
                                        return invalid_response("%s_limit_exceeded" % limit_type,
                                                                _("%s limit exceeded for service (%s)") % (
                                                                    limit_type, service.name), 400)

                                    limit_fees_amount = 0
                                    for over_limit_fees_id in over_limit_fees_ids:
                                        if over_limit_fees_id['sale_amount_from'] <= trans_amount and \
                                                over_limit_fees_id['sale_amount_to'] >= trans_amount:
                                            if over_limit_fees_id['fees_amount'] > 0:
                                                limit_fees_amount = over_limit_fees_id['fees_amount']
                                            elif over_limit_fees_id['fees_amount_percentage'] > 0:
                                                limit_fees_amount = trans_amount * over_limit_fees_id[
                                                    'fees_amount_percentage'] / 100
                                            break
                                    if limit_fees_amount > 0:
                                        limit_fees_amounts.update({limit_type: limit_fees_amount})
                                        calculated_payment_amount += limit_fees_amount

                        if request_data.get("wallet_id"):
                            partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(
                                wallet_id=request_data.get("wallet_id"),
                                service=service,
                                trans_amount=calculated_payment_amount)
                        else:
                            partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(service=service,
                                                                                                   trans_amount=calculated_payment_amount)
                        if not partner_wallet_id:
                            return invalid_response("wallet_not_found",
                                                    _("No Matched Wallet found for partner [%s] %s") % (
                                                        request.env.user.partner_id.ref,
                                                        request.env.user.partner_id.name), 400)
                        # Check Wallet Transaction limits
                        if partner_wallet_id.type.has_trans_limit:
                            wallet_limit_fees_amounts = {}
                            for trans_limit_id in partner_wallet_id.type.trans_limit_ids:
                                wallet_limit_type = trans_limit_id.limit_type
                                wallet_limit_amount = trans_limit_id.limit_amount
                                wallet_trans_limit_id = request.env['wallet.wallet.type.trans.limit'].sudo().search(
                                    [('wallet_id', '=', partner_wallet_id.id),
                                     # ('wallet_type_id', '=', partner_wallet_id.type.id),
                                     ('limit_type', '=', wallet_limit_type)], limit=1)
                                if wallet_trans_limit_id:
                                    wallet_limit_amount = wallet_trans_limit_id.limit_amount
                                timetuple = date_time.now().timetuple()
                                trans_limit_domain = [('wallet_id', '=', partner_wallet_id.id),
                                                      # ('wallet_type_id', '=', partner_wallet_id.type.id),
                                                      ('limit_type', '=', wallet_limit_type),
                                                      ('year', '=', timetuple.tm_year)]
                                if wallet_limit_type == 'daily':
                                    trans_limit_domain += [('day', '=', timetuple.tm_yday)]
                                elif wallet_limit_type == 'weekly':
                                    trans_limit_domain += [('week', '=', date_time.now().isocalendar()[1])]
                                elif wallet_limit_type == 'monthly':
                                    trans_limit_domain += [('month', '=', timetuple.tm_mon)]
                                trans_limit = request.env['wallet.trans.limit'].sudo().search(trans_limit_domain,
                                                                                              order="id DESC", limit=1)
                                calculated_trans_amount = calculated_payment_amount
                                if trans_limit:
                                    calculated_trans_amount += trans_limit.trans_amount
                                if wallet_limit_amount < calculated_trans_amount:
                                    wallet_over_limit_fees_ids = []
                                    if wallet_trans_limit_id:
                                        if wallet_trans_limit_id.over_limit_fees_policy == 'wallet_type_over_limit_fees' and wallet_trans_limit_id.wallet_type_over_limit_fees_ids:
                                            wallet_over_limit_fees_ids = wallet_trans_limit_id.wallet_type_over_limit_fees_ids
                                            wallet_limit_amount = \
                                                wallet_over_limit_fees_ids.sorted(lambda l: l.trans_amount_to,
                                                                                  reverse=True)[
                                                    0].trans_amount_to + wallet_trans_limit_id.limit_amount
                                        if wallet_trans_limit_id.over_limit_fees_policy == 'custom_over_limit_fees' and wallet_trans_limit_id.over_limit_fees_ids:
                                            wallet_over_limit_fees_ids = wallet_trans_limit_id.over_limit_fees_ids
                                            wallet_limit_amount = \
                                                wallet_over_limit_fees_ids.sorted(lambda l: l.trans_amount_to,
                                                                                  reverse=True)[
                                                    0].trans_amount_to + wallet_trans_limit_id.limit_amount
                                    else:
                                        if trans_limit_id.has_over_limit_fees and trans_limit_id.over_limit_fees_ids:
                                            wallet_over_limit_fees_ids = trans_limit_id.over_limit_fees_ids
                                            wallet_limit_amount = \
                                                wallet_over_limit_fees_ids.sorted(lambda l: l.trans_amount_to,
                                                                                  reverse=True)[
                                                    0].trans_amount_to + trans_limit_id.limit_amount

                                    if wallet_limit_amount < calculated_trans_amount:
                                        return invalid_response("%s_limit_exceeded" % wallet_limit_type,
                                                                _("%s limit exceeded for wallet type (%s)") % (
                                                                    wallet_limit_type, partner_wallet_id.type.name),
                                                                400)

                                    wallet_limit_fees_amount = 0
                                    for wallet_over_limit_fees_id in wallet_over_limit_fees_ids:
                                        if wallet_over_limit_fees_id['trans_amount_from'] <= trans_amount and \
                                                wallet_over_limit_fees_id['trans_amount_to'] >= trans_amount:
                                            if wallet_over_limit_fees_id['fees_amount'] > 0:
                                                wallet_limit_fees_amount = wallet_over_limit_fees_id['fees_amount']
                                            elif wallet_over_limit_fees_id['fees_amount_percentage'] > 0:
                                                wallet_limit_fees_amount = trans_amount * wallet_over_limit_fees_id[
                                                    'fees_amount_percentage'] / 100
                                            break
                                    if wallet_limit_fees_amount > 0:
                                        wallet_limit_fees_amounts.update({wallet_limit_type: wallet_limit_fees_amount})
                                        calculated_payment_amount += wallet_limit_fees_amount

                        unlink_wallet_reservation = False
                        machine_wallet_reservation_id, machine_wallet_balance, machine_wallet_available_amount = \
                            partner_wallet_id.update_wallet_reserved_balance(
                                _('Pay Service Bill for %s service') % (service.name), calculated_payment_amount,
                                request.env.user.company_id.currency_id, 'request'
                            )
                        # # machine_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                        # machine_wallet_available_amount = partner_wallet_id.available_amount if partner_wallet_id else 0
                        # if machine_wallet_available_amount < calculated_payment_amount:
                        if not machine_wallet_reservation_id:
                            return invalid_response("machine_balance_not_enough",
                                                    _("Machine Wallet Available Balance (%s) less than the payment amount (%s)") % (
                                                        machine_wallet_available_amount, calculated_payment_amount),
                                                    400)

        request_data['partner_id'] = request.env.user.partner_id.id
        model_name = 'smartpay_operations.request'
        model_record = request.env['ir.model'].sudo().search([('model', '=', model_name)])

        try:
            data = WebsiteForm().extract_data(model_record, request_data)
        # If we encounter an issue while extracting data
        except ValidationError as e:
            # I couldn't find a cleaner way to pass data to an exception
            return invalid_response("Error", _("Could not submit you request.") + " ==> " + str(e), 500)

        try:
            id_record = WebsiteForm().insert_record(request, model_record, data['record'], data['custom'],
                                                    data.get('meta'))
            if id_record:
                WebsiteForm().insert_attachment(model_record, id_record, data['attachments'])
                request.env.cr.commit()
                machine_request = model_record.env[model_name].sudo().browse(id_record)
                try:
                    _logger.info("Parse data to request")
                    _logger.info("Request Data {}".format(request_data))
                    request_fields = parse_request_data_to_fields(request_data, request)
                    _logger.info('Request Fields {}'.format(request_fields))
                    if request_fields and machine_request:
                        machine_request.write(request_fields)
                    request.env.cr.commit()
                except Exception as e:
                    _logger.info("Error on parse request data to request")
                    _logger.error(e)
            else:
                return invalid_response("Error", _("Could not submit you request."), 500)

        # Some fields have additional SQL constraints that we can't check generically
        # Ex: crm.lead.probability which is a float between 0 and 1
        # TODO: How to get the name of the erroneous field ?
        except IntegrityError as e:
            return invalid_response("Error", _("Could not submit you request.") + " ==> " + str(e), 500)

        if request_data.get('request_type') == 'recharge_wallet':
            return valid_response({"message": _("Recharge your wallet request was submit successfully."),
                                   "request_number": machine_request.name
                                   })
        elif request_data.get('request_type') == 'wallet_invitation':
            return valid_response(
                {"message": _("Wallet inivitation request for mobile number (%s) was submit successfully.") % (
                    request_data.get('mobile_number')),
                 "request_number": machine_request.name
                 })
        elif request_data.get('request_type') == 'service_bill_inquiry':
            lang = request_data.get('lang')
            billingAcct = request_data.get('billingAcct')
            extraBillingAcctKeys = request_data.get('extraBillingAcctKeys')
            if extraBillingAcctKeys:
                extraBillingAcctKeys = ast.literal_eval(extraBillingAcctKeys)
            customProperties = request_data.get('customProperties')
            if customProperties:
                customProperties = ast.literal_eval(customProperties)

            provider_response = {}
            error = {}
            for provider_info in service.seller_ids:
                provider = request.env['payment.acquirer'].sudo().search(
                    [("related_partner", "=", provider_info.name.id)])
                if provider:
                    if provider.server_state == 'offline':
                        error.update({provider.provider + "_response": {'error_message': _("Service Not Available")}})
                        break
                    trans_amount = 0.0
                    provider_channel = False
                    machine_channels = request.env['payment.acquirer.channel'].sudo().search(
                        [("acquirer_id", "=", provider.id),
                         ("type", "in", ("machine", "internet"))], limit=1)
                    if machine_channels:
                        provider_channel = machine_channels[0]
                    if provider.provider == "fawry":
                        provider_response = provider.get_fawry_bill_details(lang, provider_info.product_code,
                                                                            billingAcct, extraBillingAcctKeys,
                                                                            provider_channel, customProperties,
                                                                            machine_request.name)
                        if provider_response.get('Success'):
                            billRecType = provider_response.get('Success')
                            provider_response_json = suds_to_json(billRecType)
                            for BillSummAmt in billRecType['BillInfo']['BillSummAmt']:
                                if BillSummAmt['BillSummAmtCode'] == 'TotalAmtDue':
                                    trans_amount += float(BillSummAmt['CurAmt']['Amt'])
                                    break
                    elif provider.provider == "khales":
                        provider_response = {}
                        biller_info_json_dict = json.loads(
                            provider_info.with_context(lang=request.env.user.lang).biller_info, strict=False)
                        # Handel billingAcct format if exist
                        if biller_info_json_dict.get('BillTypeAcctFormat') and biller_info_json_dict.get(
                                'BillTypeAcctFormatSpliter'):
                            formatedBillingAcct = []
                            keysToBeRemoved = []
                            for format in biller_info_json_dict.get('BillTypeAcctFormat').split(
                                    biller_info_json_dict.get('BillTypeAcctFormatSpliter')):
                                if format == 'billingAcct':
                                    formatedBillingAcct.append(billingAcct)
                                else:
                                    is_extra_key = False
                                    for extraBillingAcctKey in extraBillingAcctKeys:
                                        if extraBillingAcctKey.get("Key") == format:
                                            formatedBillingAcct.append(extraBillingAcctKey.get("Value"))
                                            keysToBeRemoved.append(extraBillingAcctKey)
                                            is_extra_key = True
                                            break
                                    if not is_extra_key:
                                        formatedBillingAcct.append(format)
                            extraBillingAcctKeys = [x for x in extraBillingAcctKeys if x not in keysToBeRemoved]
                            billingAcct = biller_info_json_dict.get('BillTypeAcctFormatSpliter').join(
                                formatedBillingAcct)

                        '''
                        machine_serial = None
                        if len(request.env.user.machine_serial) > 16:  # Ingenico POS
                            machine_serial = request.env.user.machine_serial
                            machine_serial = machine_serial[len(machine_serial) - 16:len(machine_serial)]
                        '''
                        # machine_serial = request.env.user.machine_serial
                        if machine_serial and len(machine_serial) > 16:
                            machine_serial = machine_serial[len(machine_serial) - 16:len(machine_serial)]
                        bill_response = provider.get_khales_bill_details(lang, machine_serial or machine_request.name,
                                                                         provider_info.product_code,
                                                                         biller_info_json_dict.get('Code'),
                                                                         billingAcct, extraBillingAcctKeys,
                                                                         provider_channel, machine_request.name)
                        if bill_response.get('Success'):
                            billRecType = bill_response.get('Success')
                            payAmts = billRecType['BillInfo']['CurAmt']
                            if payAmts and isinstance(payAmts, OrderedDict):
                                payAmts = [payAmts]
                                billRecType['BillInfo']['CurAmt'] = payAmts
                            success_response = {"bill_response": suds_to_json(billRecType)}
                            # for payAmt in payAmts:
                            # trans_amount += float(payAmt.get("AmtDue"))
                            trans_amount += float(payAmts[0].get("AmtDue"))
                            if biller_info_json_dict.get('PmtType') == 'POST':
                                ePayBillRecID = billRecType['EPayBillRecID']
                                fees_response = provider.get_khales_fees(lang, machine_serial or machine_request.name,
                                                                         ePayBillRecID, payAmts[0], provider_channel,
                                                                         machine_request.name)
                                provider_fees_calculated_amount = 0.0
                                if fees_response.get('Success'):
                                    feeInqRsType = fees_response.get('Success')
                                    provider_fees_calculated_amount = float(feeInqRsType['FeesAmt']['Amt'])
                                    # success_response.update({"fees_response": suds_to_json(feeInqRsType)})
                                else:
                                    feeInqRsType = {"EPayBillRecID": ePayBillRecID,
                                                    "FeesAmt": {"Amt": "0.0", "CurCode": "818"}}

                                if provider_fees_calculated_amount == 0:
                                    service_providerinfo = request.env['product.supplierinfo'].sudo().search([
                                        ('product_tmpl_id', '=', service.product_tmpl_id.id),
                                        ('name', '=', provider.related_partner.id)
                                    ])
                                    commissions = request.env[
                                        'product.supplierinfo.commission'].sudo().search_read(
                                        domain=[('vendor', '=', service_providerinfo.name.id),
                                                (
                                                    'vendor_product_code', '=', service_providerinfo.product_code)],
                                        fields=['Amount_Range_From', 'Amount_Range_To',
                                                'Extra_Fee_Amt', 'Extra_Fee_Prc',
                                                'Mer_Fee_Amt', 'Mer_Fee_Prc', 'Mer_Fee_Prc_MinAmt',
                                                'Mer_Fee_Prc_MaxAmt']
                                    )
                                    for commission in commissions:
                                        if commission['Amount_Range_From'] <= trans_amount \
                                                and commission['Amount_Range_To'] >= trans_amount:
                                            if commission['Extra_Fee_Amt'] > 0:
                                                extra_fees_amount = commission['Extra_Fee_Amt']
                                            elif commission['Extra_Fee_Prc'] > 0:
                                                extra_fees_amount = trans_amount * commission[
                                                    'Extra_Fee_Prc'] / 100
                                            if commission['Mer_Fee_Amt'] > 0:
                                                provider_fees_calculated_amount = commission['Mer_Fee_Amt']
                                            elif commission['Mer_Fee_Prc'] > 0:
                                                # Fees amount = FA + [Percentage * Payment Amount]
                                                # Fees amount ====================> provider_fees_calculated_amount
                                                # FA =============================> provider_fees_calculated_amount
                                                # [Percentage * Payment Amount] ==> provider_fees_prc_calculated_amount
                                                provider_fees_prc_calculated_amount = trans_amount * commission[
                                                    'Mer_Fee_Prc'] / 100
                                                if provider_fees_prc_calculated_amount < commission[
                                                    'Mer_Fee_Prc_MinAmt']:
                                                    provider_fees_prc_calculated_amount = commission[
                                                        'Mer_Fee_Prc_MinAmt']
                                                elif provider_fees_prc_calculated_amount > commission[
                                                    'Mer_Fee_Prc_MaxAmt'] \
                                                        and commission['Mer_Fee_Prc_MaxAmt'] > 0:
                                                    provider_fees_prc_calculated_amount = commission[
                                                        'Mer_Fee_Prc_MaxAmt']
                                                provider_fees_calculated_amount += provider_fees_prc_calculated_amount
                                            break
                                    feeInqRsType['FeesAmt']['Amt'] = "%s" % (
                                            (math.floor(provider_fees_calculated_amount * 100)) / 100.0)

                                success_response.update({"fees_response": suds_to_json(feeInqRsType)})
                            provider_response = {'Success': success_response}

                            provider_response_json = provider_response.get('Success')
                        else:
                            provider_response = bill_response
                    elif provider.provider == "masary":
                        provider_response = provider.get_masary_bill_details(lang, int(provider_info.product_code),
                                                                             extraBillingAcctKeys, provider_channel,
                                                                             machine_request.name)
                        if provider_response.get('Success'):
                            billData = provider_response.get('Success')
                            provider_response_json = billData
                            if billData.get('amount'):
                                trans_amount += float(billData.get('amount'))
                            # elif billData.get('min_amount'):
                            # trans_amount += float(billData.get('min_amount'))
                    elif provider.provider == "momken":
                        provider_response = provider.get_momken_bill_details(lang, int(provider_info.product_code),
                                                                             extraBillingAcctKeys, provider_channel,
                                                                             machine_request.name)
                        if provider_response.get('Success'):
                            billData = provider_response.get('Success')
                            provider_response_json = billData
                            if billData.get('amount'):
                                trans_amount += float(billData.get('amount'))

                    if provider_response.get('Success'):
                        commissions = request.env['product.supplierinfo.commission'].sudo().search_read(
                            domain=[('vendor', '=', provider_info.name.id),
                                    ('vendor_product_code', '=', provider_info.product_code)],
                            fields=['Amount_Range_From', 'Amount_Range_To', 'Extra_Fee_Amt', 'Extra_Fee_Prc']
                        )
                        extra_fees_amount = 0.0
                        for commission in commissions:
                            if commission['Amount_Range_From'] <= trans_amount \
                                    and commission['Amount_Range_To'] >= trans_amount:
                                if commission['Extra_Fee_Amt'] > 0:
                                    extra_fees_amount = commission['Extra_Fee_Amt']
                                elif commission['Extra_Fee_Prc'] > 0:
                                    extra_fees_amount = trans_amount * commission['Extra_Fee_Prc'] / 100
                                break
                        machine_request.update(
                            {"provider_id": provider.id, "provider_response": provider_response_json,
                             "trans_amount": trans_amount, "extra_fees_amount": extra_fees_amount,
                             "extra_fees": commissions, "stage_id": 5})
                        request.env.cr.commit()
                        return valid_response(
                            {"message": _("Service Bill Inquiry request was submit successfully."),
                             "request_number": machine_request.name,
                             "provider": provider.provider,
                             "provider_response": provider_response_json,
                             "extra_fees_amount": extra_fees_amount,
                             # "extra_fees": commissions
                             })
                    else:
                        error.update({provider.provider + "_response": provider_response or ''})
                else:
                    error.update({provider_info.name.name + "_response": _("%s is not a provider for (%s) service") % (
                        provider_info.name.name, service.name)})

            machine_request.update({
                "provider_response": error or _("(%s) service has not any provider.") % (service.name),
                "stage_id": 5
            })
            request.env.cr.commit()
            error_key = "user_error"
            error_msg = _("(%s) service has not any provider.") % (service.name)
            if provider:
                if error.get(provider.provider + "_response").get("error_message"):
                    error_msg = error.get(provider.provider + "_response").get("error_message")
                elif error.get(provider.provider + "_response").get("error_message_to_be_translated"):
                    error_msg = error.get(provider.provider + "_response").get("error_message_to_be_translated")
                    error_key = "Error"
            elif error.get(provider_info.name.name + "_response"):
                error_msg = error.get(provider_info.name.name + "_response")
            return invalid_response(error_key, error_msg, 400)

        elif request_data.get('request_type') == 'pay_service_bill':
            provider_provider = request_data.get('provider')
            if machine_wallet_reservation_id:
                machine_wallet_reservation_id.update({'request_id': machine_request.id})
                request.env.cr.commit()
            lang = request_data.get('lang')
            billingAcct = request_data.get('billingAcct')

            extraBillingAcctKeys = request_data.get('extraBillingAcctKeys')
            if extraBillingAcctKeys:
                extraBillingAcctKeys = ast.literal_eval(extraBillingAcctKeys)

            notifyMobile = request_data.get('notifyMobile')
            # Get static values
            if provider_provider == 'fawry':
                notifyMobile = get_static_values('notifyMobile', 'fawry')

            billRefNumber = request_data.get('billRefNumber')
            billerId = request_data.get('billerId')
            # Get static values
            pmtType = request_data.get('pmtType')
            if provider_provider == 'khales':
                pmtType = get_static_values('pmtType', 'khales')
            elif provider_provider == 'fawry':
                pmtType = get_static_values('pmtType', 'fawry')

            trans_amount = request_data.get('trans_amount')
            # Get static values based on the provider
            curCode = request_data.get('currency_id')
            pmtMethod = request_data.get('pmtMethod')
            if provider_provider == 'khales':
                curCode = get_static_values('currency_id', 'khales')
                pmtMethod = get_static_values('pmtMethod', 'khales')
            elif provider_provider == 'fawry':
                curCode = get_static_values('currency_id', 'fawry')
                pmtMethod = get_static_values('pmtMethod', 'fawry')

            payAmts = request_data.get('payAmts')
            if payAmts:
                payAmts = ast.literal_eval(payAmts)
            else:
                payAmts = [{'Sequence': '1', 'AmtDue': trans_amount, 'CurCode': curCode}]

            ePayBillRecID = request_data.get('ePayBillRecID')
            pmtId = request_data.get('pmtId') or machine_request.name
            feesAmt = request_data.get('feesAmt') or 0.00
            feesAmts = request_data.get('feesAmts')
            if feesAmts:
                feesAmts = ast.literal_eval(feesAmts)
            else:
                feesAmts = [{'Amt': feesAmt, 'CurCode': curCode}]
            pmtRefInfo = request_data.get('pmtRefInfo')

            providers_info = []
            '''
            provider_provider = request_data.get('provider')
            if provider_provider:
                provider = request.env['payment.acquirer'].sudo().search([("provider", "=", provider_provider)])
                if provider:
                    service_providerinfo = request.env['product.supplierinfo'].sudo().search([
                        ('product_tmpl_id', '=', service.product_tmpl_id.id),
                        ('name', '=', provider.related_partner.id)
                    ])
                    if service_providerinfo:
                        providers_info.append(service_providerinfo)
            if not provider_provider or len(providers_info) == 0:
                providers_info = service.seller_ids
            '''
            providers_info.append(service_providerinfo)

            provider_response = {}
            provider_response_json = {}
            '''
            provider_fees_calculated_amount = 0.0
            provider_fees_actual_amount = 0.0
            merchant_cashback_amount = 0.0
            customer_cashback_amount = 0.0
            extra_fees_amount = 0.0
            '''
            error = {}
            for provider_info in providers_info:
                biller_info_json_dict = json.loads(provider_info.with_context(lang=request.env.user.lang).biller_info,
                                                   strict=False)
                '''
                # Get Extra Fees
                commissions = request.env['product.supplierinfo.commission'].sudo().search_read(
                    domain=[('vendor', '=', provider_info.name.id),
                            ('vendor_product_code', '=', provider_info.product_code)],
                    fields=['Amount_Range_From', 'Amount_Range_To',
                            'Extra_Fee_Amt', 'Extra_Fee_Prc',
                            'Mer_Fee_Amt', 'Mer_Fee_Prc', 'Mer_Fee_Prc_MinAmt', 'Mer_Fee_Prc_MaxAmt',
                            'Mer_Comm_Full_Fix_Amt', 'Cust_Comm_Full_Fix_Amt',
                            'Bill_Merchant_Comm_Prc', 'Bill_Customer_Comm_Prc']
                )
                for commission in commissions:
                    if commission['Amount_Range_From'] <= machine_request.trans_amount \
                            and commission['Amount_Range_To'] >= machine_request.trans_amount:
                        if commission['Mer_Comm_Full_Fix_Amt'] > 0:
                            merchant_cashback_amount = commission['Mer_Comm_Full_Fix_Amt']
                            customer_cashback_amount = commission['Cust_Comm_Full_Fix_Amt']
                        elif commission['Bill_Merchant_Comm_Prc'] > 0:
                            merchant_cashback_amount = machine_request.trans_amount * commission[
                                'Bill_Merchant_Comm_Prc'] / 100
                            customer_cashback_amount = machine_request.trans_amount * commission[
                                'Bill_Customer_Comm_Prc'] / 100
                        if commission['Extra_Fee_Amt'] > 0:
                            extra_fees_amount = commission['Extra_Fee_Amt']
                        elif commission['Extra_Fee_Prc'] > 0:
                            extra_fees_amount = machine_request.trans_amount * commission['Extra_Fee_Prc'] / 100
                        if commission['Mer_Fee_Amt'] > 0:
                            provider_fees_calculated_amount = commission['Mer_Fee_Amt']
                        elif commission['Mer_Fee_Prc'] > 0:
                            # Fees amount = FA + [Percentage * Payment Amount]
                            # Fees amount ====================> provider_fees_calculated_amount
                            # FA =============================> provider_fees_calculated_amount
                            # [Percentage * Payment Amount] ==> provider_fees_prc_calculated_amount
                            provider_fees_prc_calculated_amount = machine_request.trans_amount * commission['Mer_Fee_Prc'] / 100
                            if provider_fees_prc_calculated_amount < commission['Mer_Fee_Prc_MinAmt']:
                                provider_fees_prc_calculated_amount = commission['Mer_Fee_Prc_MinAmt']
                            elif provider_fees_prc_calculated_amount > commission['Mer_Fee_Prc_MaxAmt'] \
                                    and commission['Mer_Fee_Prc_MaxAmt'] > 0:
                                provider_fees_prc_calculated_amount = commission['Mer_Fee_Prc_MaxAmt']
                            provider_fees_calculated_amount += provider_fees_prc_calculated_amount
                        elif provider_provider == 'khales':
                            provider_fees_calculated_amount = float(request_data.get('feesAmt'))
                        break
                calculated_payment_amount = machine_request.trans_amount + provider_fees_calculated_amount + extra_fees_amount
                if request_data.get("wallet_id"):
                    partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(wallet_id=request_data.get("wallet_id"),
                                                                                           service=service,
                                                                                           trans_amount=calculated_payment_amount)
                else:
                    partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(service=service,
                                                                                           trans_amount=calculated_payment_amount)
                unlink_wallet_reservation = False
                machine_wallet_reservation_id, machine_wallet_balance, machine_wallet_available_amount = partner_wallet_id.update_wallet_reserved_balance(
                        _('Pay Service Bill for %s service') % (service.name), calculated_payment_amount,
                        request.env.user.company_id.currency_id, 'request'
                    )
                # # machine_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                # machine_wallet_available_amount = partner_wallet_id.available_amount if partner_wallet_id else 0
                # if machine_wallet_available_amount < calculated_payment_amount 
                if not machine_wallet_reservation_id
                    and (not json.loads(service_providerinfo.biller_info, strict=False).get('CorrBillTypeCode') or json.loads(service_providerinfo.biller_info, strict=False).get('Type') == 'CASHININT'):
                    error.update({"machine_balance_not_enough":
                                            _("Machine Wallet Available Balance (%s) less than the payment amount (%s)") % (machine_wallet_available_amount,
                                                                                                                  calculated_payment_amount)})
                '''

                machine_request.update({'provider_fees_calculated_amount': provider_fees_calculated_amount})
                request.env.cr.commit()
                provider = request.env['payment.acquirer'].sudo().search(
                    [("related_partner", "=", provider_info.name.id)])
                if provider:
                    try:
                        if provider.server_state == 'offline':
                            error.update(
                                {provider.provider + "_response": {'error_message': _("Service Not Available")}})
                            break
                        provider_channel = False
                        machine_channels = request.env['payment.acquirer.channel'].sudo().search(
                            [("acquirer_id", "=", provider.id),
                             ("type", "in", ("machine", "internet"))], limit=1)
                        if machine_channels:
                            provider_channel = machine_channels[0]
                        if provider.provider == "fawry":
                            # Tamayoz TODO: Provider Server Timeout Handling
                            machine_request.update(
                                {'action_status': 'in_progress'})  # ==> current 'payment_status': is 'new'
                            request.env.cr.commit()
                            provider_response = provider.pay_fawry_bill(lang, provider_info.product_code,
                                                                        billingAcct, extraBillingAcctKeys,
                                                                        trans_amount, curCode, pmtMethod,
                                                                        notifyMobile, billRefNumber,
                                                                        billerId, pmtType, provider_channel,
                                                                        inquiryTransactionId, machine_request.name,
                                                                        biller_info_json_dict.get('SupportPmtReverse'),
                                                                        biller_info_json_dict.get('AllowRetry'))
                            if provider_response.get('Success'):
                                if provider_response.get('Success').get('timeout'):
                                    machine_request.update(
                                        {'payment_status': 'timeout'})  # ==> current 'action_status': is 'in_progress'
                                    if biller_info_json_dict.get('PmtType') == 'VOCH':
                                        provider_response = {"error_code": "0", "error_message": None,
                                                             "error_message_to_be_translated": "FW Server timeout:\n", }
                                        if biller_info_json_dict.get('SupportPmtReverse'):
                                            provider_response.update({"TO_CANCEL": "VOCH"})
                                        else:
                                            provider_response.update({"TO_REVIEW": "VOCH"})
                                else:
                                    machine_request.update(
                                        {'action_status': 'completed'})  # ==> current 'payment_status': is 'new'
                                request.env.cr.commit()
                                if not provider_response.get('error_code'):
                                    provider_response_json = suds_to_json(
                                        provider_response.get('Success')['pmtInfoValType']).replace('REQUEST_NUMBER',
                                                                                                    machine_request.name)
                                    msgRqHdr_response_json = suds_to_json(
                                        provider_response.get('Success')['msgRqHdrType'])
                                    # Get customProperties
                                    msgRqHdr_response_json_dict = json.loads(msgRqHdr_response_json, strict=False)
                                    customProperties = msgRqHdr_response_json_dict.get('CustomProperties')
                                    cardMetadata = ''
                                    if customProperties:
                                        # Get CardMetadata
                                        for customProperty in customProperties['CustomProperty']:
                                            if customProperty['Key'] == 'CardMetadata':
                                                cardMetadata = customProperty['Value']
                                                break
                                    # Get Provider Fees
                                    provider_response_json_dict = json.loads(provider_response_json, strict=False)
                                    # provider_response_json_dict['PmtInfo']['CurAmt']['Amt'] == machine_request.trans_amount
                                    provider_fees_actual_amount = provider_response_json_dict['PmtInfo']['FeesAmt'][
                                                                      'Amt'] or float(feesAmt)
                                    machine_request.update({'provider_fees_amount': provider_fees_actual_amount})
                                    request.env.cr.commit()
                                    # Get Provider Payment Trans ID
                                    for payment in provider_response_json_dict['PmtTransId']:
                                        if payment['PmtIdType'] == 'FCRN':
                                            provider_payment_trans_id = payment['PmtId']
                                            break
                        elif provider.provider == "khales":
                            if not billerId:
                                billerId = biller_info_json_dict.get('Code')
                            # Handel billingAcct format if exist
                            if biller_info_json_dict.get('BillTypeAcctFormat') and biller_info_json_dict.get(
                                    'BillTypeAcctFormatSpliter'):
                                formatedBillingAcct = []
                                keysToBeRemoved = []
                                for format in biller_info_json_dict.get('BillTypeAcctFormat').split(
                                        biller_info_json_dict.get('BillTypeAcctFormatSpliter')):
                                    if format == 'billingAcct':
                                        formatedBillingAcct.append(billingAcct)
                                    else:
                                        is_extra_key = False
                                        for extraBillingAcctKey in extraBillingAcctKeys:
                                            if extraBillingAcctKey.get("Key") == format:
                                                formatedBillingAcct.append(extraBillingAcctKey.get("Value"))
                                                keysToBeRemoved.append(extraBillingAcctKey)
                                                is_extra_key = True
                                                break
                                        if not is_extra_key:
                                            formatedBillingAcct.append(format)
                                extraBillingAcctKeys = [x for x in extraBillingAcctKeys if x not in keysToBeRemoved]
                                billingAcct = biller_info_json_dict.get('BillTypeAcctFormatSpliter').join(
                                    formatedBillingAcct)
                            # Tamayoz TODO: Provider Server Timeout Handling
                            # Tamayoz TODO: Remove the next temporary line
                            pmtMethod = "CARD"  # TEMP CODE
                            machine_request.update(
                                {'action_status': 'in_progress'})  # ==> current 'payment_status': is 'new'
                            request.env.cr.commit()
                            '''
                            machine_serial = None
                            if len(request.env.user.machine_serial) > 16:  # Ingenico POS
                                machine_serial = request.env.user.machine_serial
                                machine_serial = machine_serial[len(machine_serial) - 16:len(machine_serial)]
                            '''
                            # machine_serial = request.env.user.machine_serial
                            if machine_serial and len(machine_serial) > 16:
                                machine_serial = machine_serial[len(machine_serial) - 16:len(machine_serial)]
                            provider_response = provider. \
                                with_context(current_partner=request.env.user.partner_id). \
                                pay_khales_bill(lang, machine_serial or machine_request.name,
                                                billingAcct, extraBillingAcctKeys, billerId,
                                                ePayBillRecID,
                                                payAmts, pmtId, pmtType, feesAmts,
                                                billRefNumber, pmtMethod, pmtRefInfo,
                                                provider_channel, machine_request.name,
                                                biller_info_json_dict.get('SupportPmtReverse'),
                                                biller_info_json_dict.get('AllowRetry'))
                            if provider_response.get('Success'):
                                if provider_response.get('Success').get('timeout'):
                                    machine_request.update(
                                        {'payment_status': 'timeout'})  # ==> current 'action_status': is 'in_progress'
                                    if biller_info_json_dict.get('PmtType') == 'VOCH':
                                        provider_response = {"error_code": "0", "error_message": None,
                                                             "error_message_to_be_translated": "KH Server timeout:\n", }
                                        if biller_info_json_dict.get('SupportPmtReverse'):
                                            provider_response.update({"TO_CANCEL": "VOCH"})
                                        else:
                                            provider_response.update({"TO_REVIEW": "VOCH"})
                                else:
                                    machine_request.update(
                                        {'action_status': 'completed'})  # ==> current 'payment_status': is 'new'
                                request.env.cr.commit()
                                if not provider_response.get('error_code'):
                                    provider_response_json = suds_to_json(provider_response.get('Success'))
                                    # Add required parameters for cancel payment scenario
                                    # parsing JSON string:
                                    provider_response_json_dict = json.loads(provider_response_json)
                                    pmtId = provider_response_json_dict['PmtRecAdviceStatus']['PmtTransId']['PmtId']
                                    # appending the data
                                    provider_response_json_dict.update(
                                        {'billingAcct': billingAcct, 'billRefNumber': billRefNumber,
                                         'billerId': billerId, 'pmtType': pmtType, 'trans_amount': trans_amount,
                                         'curCode': curCode, 'pmtMethod': pmtMethod, 'ePayBillRecID': ePayBillRecID,
                                         'pmtId': pmtId, 'feesAmt': feesAmt, 'pmtRefInfo': pmtRefInfo})
                                    if payAmts:
                                        provider_response_json_dict.update({'payAmts': payAmts})
                                    if feesAmts:
                                        provider_response_json_dict.update({'feesAmts': feesAmts})
                                    # the result is a JSON string:
                                    provider_response_json = json.dumps(provider_response_json_dict)
                                    # Provider Fees
                                    provider_fees_actual_amount = float(feesAmt)
                                    machine_request.update({'provider_fees_amount': provider_fees_actual_amount})
                                    request.env.cr.commit()
                                    # Provider Payment Trans ID
                                    provider_payment_trans_id = pmtId
                        elif provider.provider == "masary":
                            machine_request.update(
                                {'action_status': 'in_progress'})  # ==> current 'payment_status': is 'new'
                            request.env.cr.commit()
                            provider_response = provider.pay_masary_bill(lang, int(provider_info.product_code),
                                                                         float(trans_amount), float(feesAmt),
                                                                         inquiryTransactionId, 1,  # quantity
                                                                         extraBillingAcctKeys, provider_channel,
                                                                         machine_request.name)
                            if provider_response.get('Success'):
                                if provider_response.get('Success').get('timeout'):
                                    machine_request.update(
                                        {'payment_status': 'timeout'})  # ==> current 'action_status': is 'in_progress'
                                    if biller_info_json_dict.get('PmtType') == 'VOCH':
                                        provider_response = {"error_code": "0", "error_message": None,
                                                             "error_message_to_be_translated": "KH Server timeout:\n", }
                                        if biller_info_json_dict.get('SupportPmtReverse'):
                                            provider_response.update({"TO_CANCEL": "VOCH"})
                                        else:
                                            provider_response.update({"TO_REVIEW": "VOCH"})
                                else:
                                    machine_request.update(
                                        {'action_status': 'completed'})  # ==> current 'payment_status': is 'new'
                                request.env.cr.commit()
                                if not provider_response.get('error_code'):
                                    provider_response_json = provider_response.get('Success')
                                    # Get Provider Fees
                                    # provider_response_json_dict = json.loads(provider_response_json, strict=False)
                                    provider_response_json_dict = provider_response_json
                                    transactionId = provider_response_json_dict['transaction_id']
                                    # provider_fees_actual_amount = provider_response_json_dict['details_list']['???']
                                    provider_fees_actual_amount = float(feesAmt)
                                    machine_request.update({'provider_fees_amount': provider_fees_actual_amount})
                                    request.env.cr.commit()
                                    # Provider Payment Trans ID
                                    provider_payment_trans_id = transactionId
                        if provider_response.get('Success'):
                            try:
                                machine_wallet_create = False
                                # provider_invoice_id = False
                                # refund = False
                                # customer_invoice_id = False
                                # credit_note = False
                                machine_request_response = {"request_number": machine_request.name,
                                                            "request_datetime": machine_request.create_date + timedelta(
                                                                hours=2),
                                                            "provider": provider.provider,
                                                            "provider_response": provider_response_json
                                                            }

                                if provider.provider == "fawry":
                                    if cardMetadata:
                                        machine_request_response.update({"cardMetadata": cardMetadata})

                                provider_actual_amount = machine_request.trans_amount + provider_fees_actual_amount
                                customer_actual_amount = provider_actual_amount + extra_fees_amount
                                if not biller_info_json_dict.get('CorrBillTypeCode') or biller_info_json_dict.get(
                                        'Type') == 'CASHININT':
                                    # Deduct Transaction Amount from Machine Wallet Balance
                                    '''
                                    wallet_transaction_sudo = request.env['website.wallet.transaction'].sudo()
                                    label = _('Pay Service Bill for %s service') % (service.name)
                                    if request_data.get("wallet_id"):
                                        partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(wallet_id=request_data.get("wallet_id"),
                                                                                                               service=service,
                                                                                                               trans_amount=customer_actual_amount)
                                    else:
                                        partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(service=service,
                                                                                                               trans_amount=customer_actual_amount)
                                    partner_id_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                                    machine_wallet_create = wallet_transaction_sudo.create(
                                        {'wallet_type': 'debit', 'partner_id': request.env.user.partner_id.id,
                                         'request_id': machine_request.id,
                                         'reference': 'request',
                                         'label': label,
                                         'amount': customer_actual_amount, 'currency_id': machine_request.currency_id.id,
                                         'wallet_balance_before': partner_id_wallet_balance,
                                         'wallet_balance_after': partner_id_wallet_balance - customer_actual_amount,
                                         'status': 'done'})
                                    request.env.cr.commit()

                                    request.env.user.partner_id.update(
                                        {'wallet_balance': partner_id_wallet_balance - customer_actual_amount})
                                    request.env.cr.commit()
                                    '''
                                    machine_wallet_create, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                                        'debit', request.env.user.partner_id, 'request',
                                        _('Pay Service Bill for %s service') % (service.name),
                                        customer_actual_amount, machine_request.currency_id, machine_request,
                                        'smartpay_operations.wallet_pay_service_bill_notify_mode', 'wallet_pay_service',
                                        _('<p>%s %s successfully deducted from your wallet.</p>') % (
                                            customer_actual_amount, _(machine_request.currency_id.name))
                                    )

                                    if provider_response.get('Success').get('timeout'):
                                        if not biller_info_json_dict.get('Timeout') and not biller_info_json_dict.get(
                                                'SupportPmtReverse'):
                                            machine_request.update({'payment_status': 'in_queue'})
                                        elif biller_info_json_dict.get('Timeout') == 'PENDING':
                                            machine_request.update({'payment_status': 'pending'})
                                        elif biller_info_json_dict.get('SupportPmtReverse'):
                                            # if biller_info_json_dict.get('PmtType') == 'VOCH':
                                            # machine_request.update({'payment_status': 'to_cancel'})
                                            # else:
                                            if biller_info_json_dict.get('PmtType') != 'VOCH':
                                                machine_request.update({'payment_status': 'to_refund'})
                                        # else:
                                        # machine_request.update({'payment_status': 'done'}) # Tamayoz: No need to handel "else" case
                                        machine_request.update({'action_status': 'new'})
                                    elif provider_response.get('Success').get('pending'):
                                        machine_request.update({'payment_status': 'pending', 'action_status': 'new'})
                                    else:
                                        machine_request.update({'payment_status': 'done',
                                                                'action_status': 'completed'})  # ==> current 'action_status': is 'completed'
                                    request.env.cr.commit()

                                    # Log Sold Limit
                                    if service.has_sale_limit:
                                        for sale_limit_id in service.sale_limit_ids:
                                            limit_type = sale_limit_id.limit_type
                                            timetuple = date_time.now().timetuple()
                                            sale_limit_domain = [
                                                ('partner_id', '=', request.env.user.partner_id.id),
                                                ('product_id', '=', service.id),
                                                ('limit_type', '=', limit_type),
                                                ('year', '=', timetuple.tm_year)]
                                            if limit_type == 'daily':
                                                sale_limit_domain += [('day', '=', timetuple.tm_yday)]
                                            elif limit_type == 'weekly':
                                                sale_limit_domain += [('week', '=', date_time.now().isocalendar()[1])]
                                            elif limit_type == 'monthly':
                                                sale_limit_domain += [('month', '=', timetuple.tm_mon)]
                                            sale_limit = request.env['res.partner.sale.limit'].sudo().search(
                                                sale_limit_domain,
                                                order="id DESC", limit=1)
                                            if sale_limit:
                                                sale_limit.update({
                                                    'sold_amount': sale_limit.sold_amount + customer_actual_amount})  # calculated_payment_amount
                                            else:
                                                sale_limit_values = {
                                                    'partner_id': request.env.user.partner_id.id,
                                                    'product_id': service.id,
                                                    'limit_type': limit_type,
                                                    'year': timetuple.tm_year,
                                                    'sold_amount': customer_actual_amount
                                                }
                                                if limit_type == 'daily':
                                                    sale_limit_values.update({'day': timetuple.tm_yday})
                                                elif limit_type == 'weekly':
                                                    sale_limit_values.update({'week': date_time.now().isocalendar()[1]})
                                                elif limit_type == 'monthly':
                                                    sale_limit_values.update({'month': timetuple.tm_mon})
                                                sale_limit = request.env['res.partner.sale.limit'].sudo().create(
                                                    sale_limit_values)

                                            # Log Sold Over Limit Fees
                                            if limit_fees_amounts.get(limit_type):
                                                wallet_transaction_id, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                                                    'debit', request.env.user.partner_id, 'request',
                                                    _('%s over limit fees for %s service') % (limit_type, service.name),
                                                    limit_fees_amounts.get(limit_type), machine_request.currency_id,
                                                    machine_request,
                                                    'smartpay_operations.wallet_pay_service_bill_notify_mode',
                                                    'wallet_pay_service',
                                                    _('<p>%s %s successfully deducted from your wallet.</p>') % (
                                                        limit_fees_amounts.get(limit_type),
                                                        _(machine_request.currency_id.name))
                                                )
                                                sale_limit_fees = request.env[
                                                    'res.partner.sale.limit.fees'].sudo().create(
                                                    {'user_request_id': machine_request.id,
                                                     'limit_type': limit_type,
                                                     'fees_amount': limit_fees_amounts.get(limit_type),
                                                     'wallet_transaction_id': wallet_transaction_id.id})
                                    # Log Wallet Transaction Limit
                                    if partner_wallet_id.type.has_trans_limit:
                                        for trans_limit_id in partner_wallet_id.type.trans_limit_ids:
                                            wallet_limit_type = trans_limit_id.limit_type
                                            timetuple = date_time.now().timetuple()
                                            trans_limit_domain = [
                                                ('wallet_id', '=', partner_wallet_id.id),
                                                # ('wallet_type_id', '=', partner_wallet_id.type.id),
                                                ('limit_type', '=', wallet_limit_type),
                                                ('year', '=', timetuple.tm_year)]
                                            if wallet_limit_type == 'daily':
                                                trans_limit_domain += [('day', '=', timetuple.tm_yday)]
                                            elif wallet_limit_type == 'weekly':
                                                trans_limit_domain += [('week', '=', date_time.now().isocalendar()[1])]
                                            elif wallet_limit_type == 'monthly':
                                                trans_limit_domain += [('month', '=', timetuple.tm_mon)]
                                            trans_limit = request.env['wallet.trans.limit'].sudo().search(
                                                trans_limit_domain, order="id DESC", limit=1)
                                            if trans_limit:
                                                trans_limit.update({
                                                    'trans_amount': trans_limit.trans_amount + customer_actual_amount})  # calculated_payment_amount
                                            else:
                                                trans_limit_values = {
                                                    'wallet_id': partner_wallet_id.id,
                                                    # 'wallet_type_id': partner_wallet_id.type.id,
                                                    'limit_type': wallet_limit_type,
                                                    'year': timetuple.tm_year,
                                                    'trans_amount': customer_actual_amount
                                                }
                                                if wallet_limit_type == 'daily':
                                                    trans_limit_values.update({'day': timetuple.tm_yday})
                                                elif wallet_limit_type == 'weekly':
                                                    trans_limit_values.update(
                                                        {'week': date_time.now().isocalendar()[1]})
                                                elif wallet_limit_type == 'monthly':
                                                    trans_limit_values.update({'month': timetuple.tm_mon})
                                                trans_limit = request.env['wallet.trans.limit'].sudo().create(
                                                    trans_limit_values)

                                            # Log Transaction Over Limit Fees
                                            if wallet_limit_fees_amounts.get(wallet_limit_type):
                                                wallet_transaction_id, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                                                    'debit', request.env.user.partner_id, 'request',
                                                    _('%s over limit fees for %s wallet type') % (
                                                        wallet_limit_type, partner_wallet_id.type.name),
                                                    wallet_limit_fees_amounts.get(wallet_limit_type),
                                                    machine_request.currency_id, machine_request,
                                                    'smartpay_operations.wallet_pay_service_bill_notify_mode',
                                                    'wallet_pay_service',
                                                    _('<p>%s %s successfully deducted from your wallet.</p>') % (
                                                        wallet_limit_fees_amounts.get(wallet_limit_type),
                                                        _(machine_request.currency_id.name))
                                                )
                                                trans_limit_fees = request.env['wallet.trans.limit.fees'].sudo().create(
                                                    {'user_request_id': machine_request.id,
                                                     'limit_type': wallet_limit_type,
                                                     'fees_amount': wallet_limit_fees_amounts.get(wallet_limit_type),
                                                     'wallet_transaction_id': wallet_transaction_id.id})

                                    machine_wallet_reservation_id.sudo().unlink()
                                    request.env.cr.commit()
                                    unlink_wallet_reservation = True

                                    '''
                                    # Notify customer
                                    irc_param = request.env['ir.config_parameter'].sudo()
                                    wallet_pay_service_bill_notify_mode = irc_param.get_param("smartpay_operations.wallet_pay_service_bill_notify_mode")
                                    if wallet_pay_service_bill_notify_mode == 'inbox':
                                        request.env['mail.thread'].sudo().message_notify(
                                            subject=label,
                                            body=_('<p>%s %s successfully deducted from your wallet.</p>') % (
                                                customer_actual_amount, _(machine_request.currency_id.name)),
                                            partner_ids=[(4, request.env.user.partner_id.id)],
                                        )
                                    elif wallet_pay_service_bill_notify_mode == 'email':
                                        machine_wallet_create.wallet_transaction_email_send()
                                    elif wallet_pay_service_bill_notify_mode == 'sms' and request.env.user.partner_id.mobile:
                                        machine_wallet_create.sms_send_wallet_transaction(wallet_pay_service_bill_notify_mode,
                                                                                          'wallet_pay_service',
                                                                                          request.env.user.partner_id.mobile,
                                                                                          request.env.user.name, label,
                                                                                          '%s %s' % (customer_actual_amount,
                                                                                                     _(machine_request.currency_id.name)),
                                                                                          request.env.user.partner_id.country_id.phone_code or '2')
                                    '''

                                    payment_info = {"service": service.with_context(lang=request.env.user.lang).name,
                                                    "provider": provider.provider,
                                                    "request_number": machine_request.name,
                                                    "request_datetime": machine_request.create_date + timedelta(
                                                        hours=2),
                                                    "label": biller_info_json_dict.get("BillTypeAcctLabel"),
                                                    "billing_acct": billingAcct,
                                                    "ref_number": provider_payment_trans_id,
                                                    "amount": trans_amount,
                                                    "fees": (provider_fees_actual_amount + extra_fees_amount),
                                                    "total": customer_actual_amount}

                                machine_request.update(
                                    {'extra_fees_amount': extra_fees_amount,
                                     'wallet_transaction_id': machine_wallet_create and machine_wallet_create.id or False,
                                     'trans_date': date.today(),
                                     'provider_id': provider.id,
                                     'provider_response': provider_response_json, "stage_id": 5})
                                if biller_info_json_dict.get('CorrBillTypeCode'):
                                    machine_request.update(
                                        {'description': _(
                                            'Initiation Service Payment request (%s) was submit successfully @ %s') % (
                                                            machine_request.name,
                                                            str(date_time.now() + timedelta(hours=2)))
                                         })
                                request.env.cr.commit()
                                machine_request_response.update({'extra_fees_amount': extra_fees_amount})

                                # VouchPIN Decryption if exist
                                if provider_response_json_dict.get('VouchInfo'):
                                    decrypted_bytes = bytes(provider_response_json_dict['VouchInfo']['VouchPIN'],
                                                            encoding='utf-8')
                                    # text = base64.decodestring(decrypted_bytes) #
                                    text = base64.b64decode(decrypted_bytes)  #
                                    cipher = DES3.new(SECRET_KEY, DES3.MODE_ECB)
                                    VouchPIN = cipher.decrypt(text)
                                    VouchPIN = UNPAD(VouchPIN)
                                    VouchPIN = VouchPIN.decode('utf-8')  # unpad and decode bytes to str
                                    machine_request_response.update({'vouch_pin': VouchPIN})
                                    if not biller_info_json_dict.get('CorrBillTypeCode'):
                                        payment_info.update({"vouch_pin": VouchPIN,
                                                             "vouch_sn": provider_response_json_dict['VouchInfo'][
                                                                 'VouchSN']})
                                        if provider_response_json_dict['VouchInfo'].get('VouchDesc'):
                                            payment_info.update(
                                                {"vouch_desc": provider_response_json_dict['VouchInfo']['VouchDesc']})

                                # ExtraBillInfo
                                # ePayBillRecID : RBINQRQ-220627-619014259490-GT-99959 (Khales)
                                # billRefNumber : 6bb67311-dde8-47f8-b8f3-3cf8fe5a4be6 (Fawry)
                                if (provider.provider == 'fawry' and billRefNumber) or (
                                        provider.provider == 'khales' and ePayBillRecID):
                                    inquiryTransactionId = request_data.get('inquiryTransactionId')
                                    if inquiryTransactionId:
                                        inquiry_request = request.env["smartpay_operations.request"].sudo().search(
                                            [('name', '=', inquiryTransactionId)], limit=1)
                                    else:
                                        inquiry_request = request.env["smartpay_operations.request"].sudo().search(
                                            [('request_type', '=', 'service_bill_inquiry'),
                                             ('partner_id', '=', request.env.user.partner_id.id),
                                             ('product_id', '=', service.id),
                                             ('create_date', '<=', date_time.now()),
                                             ('create_date', '>=', date_time.now() - timedelta(minutes=15)),
                                             ('provider_response', 'ilike',
                                              '"BillRefNumber": "%s"' % (billRefNumber) if provider.provider == "fawry"
                                              else '"EPayBillRecID": "%s"' % (ePayBillRecID)
                                              # provider.provider == "khales"
                                              )], limit=1)

                                    if inquiry_request:
                                        inquiry_request_provider_response = inquiry_request.provider_response.replace(
                                            "'bill_response'", '"bill_response"').replace("'fees_response'",
                                                                                          '"fees_response"').replace(
                                            "'", "")
                                        inquiry_request_provider_response_json_dict = json.loads(
                                            inquiry_request_provider_response)

                                        # Fawry
                                        if inquiry_request_provider_response_json_dict.get('BillInfo') and \
                                                inquiry_request_provider_response_json_dict.get('BillInfo').get(
                                                    'ExtraBillInfo'):
                                            payment_info.update({"extra_bill_info":
                                                                     inquiry_request_provider_response_json_dict[
                                                                         'BillInfo']['ExtraBillInfo']})

                                        # Khales
                                        if inquiry_request_provider_response_json_dict.get('bill_response') and \
                                                inquiry_request_provider_response_json_dict.get('bill_response').get(
                                                    'Msg'):
                                            for msg in inquiry_request_provider_response_json_dict.get(
                                                    'bill_response').get('Msg'):
                                                if msg.get('LanguagePref') == 'ar-eg':  # en-gb
                                                    payment_info.update({"extra_bill_info": msg.get('Text')})
                                                    break

                                if not biller_info_json_dict.get('CorrBillTypeCode') or biller_info_json_dict.get(
                                        'Type') == 'CASHININT':
                                    # Wallet Transaction Info with payment info
                                    machine_wallet_create.update({"wallet_transaction_info": json.dumps(
                                        {"payment_info": payment_info}, default=default)})
                                    request.env.cr.commit()

                                '''
                                # Create Vendor (Provider) Invoices
                                provider_invoice_ids = ()
                                # 1- Create Vendor bill
                                provider_journal_id = request.env['account.journal'].sudo().search([('type', '=', 'purchase'),
                                                                                          ('company_id', '=', request.env.user.company_id.id)], limit=1)
                                name = provider.provider + ': [' + provider_info.product_code + '] ' + provider_info.product_name
                                provider_invoice_vals = machine_request.with_context(name=name,
                                                                                     provider_payment_trans_id=provider_payment_trans_id,
                                                                                     journal_id=provider_journal_id.id,
                                                                                     invoice_date=date.today(),
                                                                                     invoice_type='in_invoice',
                                                                                     partner_id=provider_info.name.id)._prepare_invoice()
                                provider_invoice_id = request.env['account.invoice'].sudo().create(provider_invoice_vals)
                                invoice_line = provider_invoice_id._prepare_invoice_line_from_request(request=machine_request,
                                                                                                      name=name,
                                                                                                      qty=1,
                                                                                                      price_unit=provider_actual_amount)
                                new_line = request.env['account.invoice.line'].sudo().new(invoice_line)
                                new_line._set_additional_fields(provider_invoice_id)
                                provider_invoice_id.invoice_line_ids += new_line
                                provider_invoice_id.action_invoice_open()
                                provider_invoice_ids += (tuple(provider_invoice_id.ids),)
                                provider_invoice_id.pay_and_reconcile(request.env['account.journal'].sudo().search(
                                    [('type', '=', 'cash'),
                                     ('company_id', '=', request.env.user.company_id.id),
                                     ('provider_id', '=', provider.id)], limit=1),
                                    provider_actual_amount)
                                request.env.cr.commit()
                                # 2- Create Vendor Refund with commision amount
                                if merchant_cashback_amount > 0:
                                    refund = request.env['account.invoice.refund'].with_context(
                                        active_ids=provider_invoice_id.ids).sudo().create({
                                        'filter_refund': 'refund',
                                        'description': name,
                                        'date': provider_invoice_id.date_invoice,
                                    })
                                    result = refund.invoice_refund()
                                    refund_id = result.get('domain')[1][2]
                                    refund = request.env['account.invoice'].sudo().browse(refund_id)
                                    refund.update({'reference': provider_payment_trans_id, 'request_id': machine_request.id})
                                    refund_line = refund.invoice_line_ids[0]
                                    refund_line.update({'price_unit': merchant_cashback_amount, 'request_id': machine_request.id})
                                    refund.refresh()
                                    refund.action_invoice_open()
                                    provider_invoice_ids += (tuple(refund.ids),)
                                machine_request.update({'provider_invoice_ids': provider_invoice_ids})
                                request.env.cr.commit()

                                # Create Customer Invoices
                                customer_invoice_ids = ()
                                # 1- Create Customer Invoice
                                customer_journal_id = request.env['account.journal'].sudo().search([('type', '=', 'sale'),
                                                                                          ('company_id', '=', request.env.user.company_id.id)], limit=1)
                                customer_invoice_vals = machine_request.with_context(name=provider_payment_trans_id,
                                                                                     journal_id=customer_journal_id.id,
                                                                                     invoice_date=date.today(),
                                                                                     invoice_type='out_invoice',
                                                                                     partner_id=request.env.user.partner_id.id)._prepare_invoice()
                                customer_invoice_id = request.env['account.invoice'].sudo().create(customer_invoice_vals)
                                machine_request.invoice_line_create(invoice_id=customer_invoice_id.id, name=name,
                                                                    qty=1, price_unit=customer_actual_amount)
                                customer_invoice_id.action_invoice_open()
                                customer_invoice_ids += (tuple(customer_invoice_id.ids),)
                                # Auto Reconcile customer invoice with prepaid wallet recharge payments and previous cashback credit note
                                domain = [('account_id', '=', customer_invoice_id.account_id.id),
                                          ('partner_id', '=',
                                           customer_invoice_id.env['res.partner']._find_accounting_partner(customer_invoice_id.partner_id).id),
                                          ('reconciled', '=', False),
                                          '|',
                                          '&', ('amount_residual_currency', '!=', 0.0), ('currency_id', '!=', None),
                                          '&', ('amount_residual_currency', '=', 0.0), '&', ('currency_id', '=', None),
                                          ('amount_residual', '!=', 0.0)]
                                domain.extend([('credit', '>', 0), ('debit', '=', 0)])
                                lines = customer_invoice_id.env['account.move.line'].sudo().search(domain)
                                for line in lines:
                                    # get the outstanding residual value in invoice currency
                                    if line.currency_id and line.currency_id == customer_invoice_id.currency_id:
                                        amount_residual_currency = abs(line.amount_residual_currency)
                                    else:
                                        currency = line.company_id.currency_id
                                        amount_residual_currency = currency._convert(abs(line.amount_residual),
                                                                                     customer_invoice_id.currency_id,
                                                                                     customer_invoice_id.company_id,
                                                                                     line.date or fields.Date.today())
                                    if float_is_zero(amount_residual_currency, precision_rounding=customer_invoice_id.currency_id.rounding):
                                        continue

                                    customer_invoice_id.assign_outstanding_credit(line.id)
                                    if customer_invoice_id.state == 'paid':
                                        break
                                request.env.cr.commit()

                                # 2- Create Customer Credit Note with commission amount for only customers have commission
                                if request.env.user.commission and customer_cashback_amount > 0:
                                    credit_note = request.env['account.invoice.refund'].with_context(
                                        active_ids=customer_invoice_id.ids).sudo().create({
                                        'filter_refund': 'refund',
                                        'description': provider_payment_trans_id,
                                        'date': customer_invoice_id.date_invoice,
                                    })
                                    result = credit_note.invoice_refund()
                                    credit_note_id = result.get('domain')[1][2]
                                    credit_note = request.env['account.invoice'].sudo().browse(credit_note_id)
                                    credit_note.update({'request_id': machine_request.id})
                                    credit_note_line = credit_note.invoice_line_ids[0]
                                    credit_note_line.update({'price_unit': customer_cashback_amount, 'request_id': machine_request.id})
                                    credit_note.refresh()
                                    """  Don't validate the customer credit note until the vendor refund reconciliation
                                    After vendor refund reconciliation, validate the customer credit note with
                                    the net amount of vendor refund sent in provider cashback statement then
                                    increase the customer wallet with the same net amount. """
                                    # credit_note.action_invoice_open()
                                    customer_invoice_ids += (tuple(credit_note.ids),)
                                machine_request.update({'customer_invoice_ids': customer_invoice_ids})
                                request.env.cr.commit()
                                '''
                                if provider.provider == "khales":
                                    # Add required parameters for cancel payment scenario
                                    machine_request_response.update(
                                        {'billingAcct': billingAcct, 'billRefNumber': billRefNumber,
                                         'billerId': billerId, 'pmtType': pmtType, 'trans_amount': trans_amount,
                                         'curCode': curCode, 'pmtMethod': pmtMethod, 'ePayBillRecID': ePayBillRecID,
                                         'pmtId': pmtId, 'feesAmt': feesAmt, 'pmtRefInfo': pmtRefInfo})
                                    if payAmts:
                                        machine_request_response.update({'payAmts': payAmts})
                                    if feesAmts:
                                        machine_request_response.update({'feesAmts': feesAmts})
                                if not biller_info_json_dict.get('CorrBillTypeCode') or biller_info_json_dict.get(
                                        'Type') == 'CASHININT':
                                    machine_request_response.update({"message": _(
                                        "Pay Service Bill request was submit successfully with amount %s %s. Your Machine Wallet Balance is %s %s")
                                                                                % (customer_actual_amount,
                                                                                   machine_request.currency_id.name,
                                                                                   wallet_balance_after,
                                                                                   machine_request.currency_id.name)})
                                else:
                                    machine_request_response.update({"message": _(
                                        "Pay Service Bill Initiation request was submit successfully with amount %s %s.")
                                                                                % (customer_actual_amount,
                                                                                   machine_request.currency_id.name)})

                                # Cancel
                                # request_number = {"request_number": machine_request.name}
                                # self.cancel_request(**request_number)

                                if not unlink_wallet_reservation and machine_wallet_reservation_id:
                                    machine_wallet_reservation_id.sudo().unlink()
                                    request.env.cr.commit()
                                    unlink_wallet_reservation = True
                                return valid_response(machine_request_response)
                            except Exception as e:
                                try:
                                    _logger.error("%s", e, exc_info=True)
                                    machine_request_update = {'extra_fees_amount': extra_fees_amount,
                                                              'trans_date': date.today(),
                                                              'provider_id': provider.id,
                                                              'provider_response': provider_response_json,
                                                              "stage_id": 5,
                                                              'description': _(
                                                                  "After the Pay Service Request submit successfuly with provider, Error is occur:") + " ==> " + str(
                                                                  e)}
                                    if machine_wallet_create:
                                        machine_request_update.update(
                                            {'wallet_transaction_id': machine_wallet_create.id})
                                    '''
                                    provider_invoice_ids = ()
                                    if provider_invoice_id or refund:
                                        if provider_invoice_id:
                                            provider_invoice_ids += (tuple(provider_invoice_id.ids),)
                                        if refund:
                                            provider_invoice_ids += (tuple(refund.ids),)
                                        machine_request_update.update({'provider_invoice_ids': provider_invoice_ids})
                                    customer_invoice_ids = ()
                                    if customer_invoice_id or credit_note:
                                        if customer_invoice_id:
                                            customer_invoice_ids += (tuple(customer_invoice_id.ids),)
                                        if credit_note:
                                            customer_invoice_ids += (tuple(credit_note.ids),)
                                        machine_request_update.update({'customer_invoice_ids': customer_invoice_ids})
                                    '''
                                    machine_request.update(machine_request_update)
                                    request.env.cr.commit()
                                except Exception as e1:
                                    _logger.error("%s", e1, exc_info=True)
                                    if machine_request and not machine_request.description:
                                        machine_request.update({'description': _(
                                            "After the Pay Service Request submit successfuly with provider, Error is occur:") + " ==> " + str(
                                            e)})
                                        request.env.cr.commit()

                                if not unlink_wallet_reservation and machine_wallet_reservation_id:
                                    machine_wallet_reservation_id.sudo().unlink()
                                    request.env.cr.commit()
                                    unlink_wallet_reservation = True
                                return invalid_response(machine_request_response,
                                                        _("After the Pay Service Request submit successfuly with provider, Error is occur:") + " ==> " + str(
                                                            e),
                                                        500)
                        else:
                            machine_request.update({'payment_status': 'canceled' if provider_response.get(
                                'CANCEL_SUCCESS') else ('to_cancel' if provider_response.get('TO_CANCEL') else (
                                'to_review' if provider_response.get('TO_REVIEW') else 'failure')),
                                                    'action_status': 'new' if provider_response.get(
                                                        'TO_CANCEL') or provider_response.get(
                                                        'TO_REVIEW') else 'completed'})  # ==> current 'action_status': is 'completed'
                            request.env.cr.commit()
                            error.update({provider.provider + "_response": provider_response or ''})
                    except Exception as e2:
                        _logger.error("%s", e2, exc_info=True)
                        # _logger.error(traceback.format_exc())
                        if machine_request and not machine_request.description:
                            machine_request.update({'description': _("Error is occur:") + " ==> " + str(e2)})
                            request.env.cr.commit()
                        if not unlink_wallet_reservation and machine_wallet_reservation_id:
                            machine_wallet_reservation_id.sudo().unlink()
                            request.env.cr.commit()
                            unlink_wallet_reservation = True
                        return invalid_response("Error", _("Error is occur:") + " ==> " + str(e2), 500)
                else:
                    error.update({provider_info.name.name + "_response": _("%s is not a provider for (%s) service") % (
                        provider_info.name.name, service.name)})

            machine_request.update({
                'provider_response': error or _('(%s) service has not any provider.') % (service.name),
                'stage_id': 5
            })
            request.env.cr.commit()
            error_key = "user_error"
            error_msg = _("(%s) service has not any provider.") % (service.name)
            if provider:
                if error.get(provider.provider + "_response").get("error_message"):
                    error_msg = error.get(provider.provider + "_response").get("error_message")
                elif error.get(provider.provider + "_response").get("error_message_to_be_translated"):
                    error_msg = error.get(provider.provider + "_response").get("error_message_to_be_translated")
                    error_key = "Error"
            elif error.get(provider_info.name.name + "_response"):
                error_msg = error.get(provider_info.name.name + "_response")
            if not unlink_wallet_reservation and machine_wallet_reservation_id:
                machine_wallet_reservation_id.sudo().unlink()
                request.env.cr.commit()
                unlink_wallet_reservation = True
            return invalid_response(error_key, error_msg, 400)

        elif request_data.get('request_type') == 'pay_invoice':
            return valid_response({"message": _("Pay invoice request was submit successfully."),
                                   "request_number": machine_request.name
                                   })
        else:
            return valid_response({"message": _("Your request was submit successfully."),
                                   "request_number": machine_request.name
                                   })

    @validate_token
    @validate_machine
    @http.route('/api/recharge_mobile_wallet', type="http", auth="none", methods=["POST"], csrf=False)
    def recharge_mobile_wallet(self, **request_data):
        """Override this method to change call decorated method."""
        _logger.info("@@@@@@@@@@@@@@@@@@@ Calling Recharge Mobile Wallet Request API")
        machine_serial = request.httprequest.headers.get("machine_serial")
        if not request_data.get('request_number'):
            if request_data.get('transfer_to') and request_data.get('trans_amount'):
                # current_user = request.env.user
                # current_user_access_token = request.httprequest.headers.get("access_token")
                # current_user_machine_serial = request.httprequest.headers.get("machine_serial")
                # Create Recharge Mobile Wallet Request
                transfer_to_user = request.env['res.users'].sudo().search(['|',
                                                                           ('login', '=',
                                                                            request_data.get('transfer_to')),
                                                                           ('ref', '=',
                                                                            request_data.get('transfer_to'))], limit=1)

                transfer_to_user = transfer_to_user and transfer_to_user[0]
                if not transfer_to_user:
                    return invalid_response("request_code_invalid", _("invalid transfer user in request data"), 400)

                _token = request.env["api.access_token"]
                access_token = (
                    _token
                    .sudo()
                    .search([
                        ("user_id", "=", transfer_to_user.id)
                    ], order="id DESC", limit=1)
                )
                if access_token:
                    access_token = access_token[0]
                    if access_token.has_expired():
                        # return invalid_response("token_expired", _("transfer to user token expired"), 400)
                        access_token.update({'expires': date_time.now() + timedelta(minutes=15)})
                        request.env.cr.commit()
                    token = access_token.token
                else:
                    # return invalid_response("account_deactivate", _("transfer to user account is deactivated"), 400)
                    token = access_token.find_one_or_generate_token(generate=True)
                    request.env.cr.commit()

                base_url = request.env['ir.config_parameter'].sudo().get_param('smartpay.base.url',
                                                                               default='web.base.url')
                headers = {
                    'content-type': 'application/x-www-form-urlencoded',
                    'charset': 'utf-8',
                    'access_token': token
                }
                data = {
                    'request_type': 'recharge_wallet',
                    'trans_amount': request_data.get('trans_amount')
                }

                res = requests.post('{}/api/create_mobile_request'.format(base_url), headers=headers, data=data)
                content = json.loads(res.content.decode('utf-8'))
                # res = self.create_mobile_request(**data)
                _logger.info("@@@@@@@@@@@@@@@@@@@ Recharge Mobile Wallet Response: " + str(content))
                if content.get('data'):
                    request_number = content.get('data').get(
                        'request_number')  # json.loads(res.response[0].decode('utf-8')).get('request_number')
                    if not request_number:
                        return invalid_response("recharge_request_not created",
                                                _("wallet recharge request not cteated"), 400)
                    request_data.update({'request_number': request_number})
                    request.env.cr.commit()
                else:
                    return invalid_response('Error: %s' % content.get('response'), _(content.get('message')), 400)
                '''
                request.httprequest.headers = {
                    'content-type': 'application/x-www-form-urlencoded',
                    'charset': 'utf-8',
                    'access_token': current_user_access_token,
                    'access_token': current_user_machine_serial
                }
                request.session.uid = current_user.id
                request.uid = current_user.id
                '''
            else:
                return invalid_response("request_code_missing", _("missing request number in request data"), 400)
        user_request = request.env['smartpay_operations.request'].sudo().search(
            [('name', '=', request_data.get('request_number')), ('request_type', '=', "recharge_wallet")], limit=1)
        if user_request:
            if user_request.stage_id.id != 1:
                return invalid_response("request_not_found",
                                        _("REQ Number (%s) invalid!") % (request_data.get('request_number')), 400)
            if request_data.get("wallet_id"):
                partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(
                    wallet_id=request_data.get("wallet_id"),
                    # service=user_request.product_id,
                    trans_amount=user_request.trans_amount,
                    allow_transfer_to=True)
            else:
                partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(
                    # service=user_request.product_id,
                    trans_amount=user_request.trans_amount,
                    allow_transfer_to=True)
            if not partner_wallet_id:
                return invalid_response("wallet_not_found",
                                        _("No Matched Wallet found for partner [%s] %s") % (
                                            request.env.user.partner_id.ref,
                                            request.env.user.partner_id.name), 400)
            # Check minimum and maximum transfer amount
            min_transfer_amount = partner_wallet_id.type.min_transfer_amount
            max_transfer_amount = partner_wallet_id.type.max_transfer_amount
            if min_transfer_amount and user_request.trans_amount < min_transfer_amount:
                return invalid_response("min_transfer_amount_exceeded",
                                        _("Minimum transfer amount (%s) exceeded!") % min_transfer_amount, 400)
            if max_transfer_amount and user_request.trans_amount > max_transfer_amount:
                return invalid_response("max_transfer_amount_exceeded",
                                        _("Maximum transfer amount (%s) exceeded!") % max_transfer_amount, 400)
            if partner_wallet_id.type.allowed_transfer_ids:
                allowed_type_ids = partner_wallet_id.type.allowed_transfer_ids.mapped('wallet_type_dest_id')
                if all(wallet.type.id not in allowed_type_ids.ids for wallet in user_request.partner_id.wallet_ids):
                    return invalid_response("machine_allowed_transfer_not_matched",
                                            _("Machine Wallet does not allowed for transfer to Customer Wallet Types"),
                                            400)
            unlink_wallet_reservation = False
            machine_wallet_reservation_id, machine_wallet_balance, machine_wallet_available_amount = \
                partner_wallet_id.update_wallet_reserved_balance(
                    _('Transfer wallet balance to %s') % (user_request.partner_id.name), user_request.trans_amount,
                    user_request.currency_id, 'request', user_request
                )
            # # machine_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
            # machine_wallet_available_amount = partner_wallet_id.available_amount if partner_wallet_id else 0
            # if machine_wallet_available_amount < user_request.trans_amount:
            if not machine_wallet_reservation_id:
                user_request.update({'stage_id': 3})
                return invalid_response("machine_balance_not_enough",
                                        _("Machine Wallet Available Balance less than the request amount"), 400)

            # Transfer Balance from Machine Wallet to Mobile Wallet
            '''
            wallet_transaction_sudo = request.env['website.wallet.transaction'].sudo()
            label = _('Transfer wallet balance from %s') % (request.env.user.partner_id.name)
            partner_wallet_id = user_request.partner_id.get_transaction_wallet()
            partner_id_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
            mobile_wallet_create = wallet_transaction_sudo.create(
                {'wallet_type': 'credit', 'partner_id': user_request.partner_id.id, 'request_id': user_request.id,
                 'reference': 'request', 'label': label,
                 'amount': user_request.trans_amount, 'currency_id': user_request.currency_id.id,
                 'wallet_balance_before': partner_id_wallet_balance,
                 'wallet_balance_after': partner_id_wallet_balance + user_request.trans_amount,
                 'status': 'done'})
            request.env.cr.commit()

            user_request.partner_id.update(
                {'wallet_balance': partner_id_wallet_balance
                + user_request.trans_amount})
            request.env.cr.commit()

            # Notify Mobile User
            irc_param = request.env['ir.config_parameter'].sudo()
            wallet_transfer_balance_notify_mode = irc_param.get_param("smartpay_operations.wallet_transfer_balance_notify_mode")
            if wallet_transfer_balance_notify_mode == 'inbox':
                request.env['mail.thread'].sudo().message_notify(
                    subject=label,
                    body=_('<p>%s %s successfully added to your wallet.</p>') % (
                        user_request.trans_amount, _(user_request.currency_id.name)),
                    partner_ids=[(4, user_request.partner_id.id)],
                )
            elif wallet_transfer_balance_notify_mode == 'email':
                mobile_wallet_create.wallet_transaction_email_send()
            elif wallet_transfer_balance_notify_mode == 'sms' and user_request.partner_id.mobile:
                mobile_wallet_create.sms_send_wallet_transaction(wallet_transfer_balance_notify_mode,
                                                                 'wallet_transfer_balance',
                                                                 user_request.partner_id.mobile,
                                                                 user_request.partner_id.name, label,
                                                                 '%s %s' % (user_request.trans_amount,
                                                                            _(user_request.currency_id.name)),
                                                                 user_request.partner_id.country_id.phone_code or '2')
            '''
            machine_customer_receivable_account = request.env.user.partner_id.property_account_receivable_id
            user_wallet_id = None
            if request_data.get("wallet_dest_id"):
                user_wallet_id = request.env['website.wallet'].sudo().search(
                    [('id', '=', request_data.get("wallet_dest_id")), ('active', '=', True),
                     ('partner_id', '=', user_request.partner_id.id)], limit=1)
            if partner_wallet_id.type.allowed_transfer_ids:
                allowed_type_ids = partner_wallet_id.type.allowed_transfer_ids.mapped('wallet_type_dest_id')
                mobile_wallet_id = user_wallet_id.filtered(
                    lambda w: w.type.id in allowed_type_ids.ids) if user_wallet_id else \
                    user_request.partner_id.wallet_ids.filtered(lambda w: w.type.id in allowed_type_ids.ids)[0]
            else:
                mobile_wallet_id = user_wallet_id or user_request.partner_id.get_transaction_wallet()
            if not mobile_wallet_id:
                machine_wallet_reservation_id.sudo().unlink()
                request.env.cr.commit()
                return invalid_response("wallet_not_found",
                                        _("No Matched Wallet found for partner [%s] %s") % (
                                            user_request.partner_id.ref,
                                            user_request.partner_id.name), 400)
            mobile_wallet_create, wallet_balance_after = mobile_wallet_id.create_wallet_transaction(
                'credit', user_request.partner_id, 'request',
                _('Transfer wallet balance from %s') % (request.env.user.partner_id.name),
                user_request.trans_amount, user_request.currency_id, user_request,
                'smartpay_operations.wallet_transfer_balance_notify_mode', 'wallet_transfer_balance',
                _('<p>%s %s successfully added to your wallet.</p>') % (
                    user_request.trans_amount, _(user_request.currency_id.name)),
                machine_customer_receivable_account, 'Transfer Wallet Balance', request.env.user.partner_id
            )
            # Check Customer Wallet Balance Maximum Balance
            if not mobile_wallet_create:
                # user_request.sudo().write({'stage_id': 5})
                machine_wallet_reservation_id.sudo().unlink()
                request.env.cr.commit()
                return invalid_response("wallet_max_balance_exceeded",
                                        _("Wallet [%s] maximum balance exceeded!") % partner_wallet_id.name, 400)

            '''
            label = _('Transfer wallet balance to %s') % (user_request.partner_id.name)
            if request_data.get("wallet_id"):
                partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(wallet_id=request_data.get("wallet_id"),
                                                                                       # service=user_request.product_id,
                                                                                       trans_amount=user_request.trans_amount)
            else:
                partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(# service=user_request.product_id,
                                                                                       trans_amount=user_request.trans_amount)
            partner_id_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
            machine_wallet_create = wallet_transaction_sudo.create(
                {'wallet_type': 'debit', 'partner_id': request.env.user.partner_id.id, 'request_id': user_request.id,
                 'reference': 'request', 'label': label,
                 'amount': user_request.trans_amount, 'currency_id': user_request.currency_id.id,
                 'wallet_balance_before': partner_id_wallet_balance,
                 'wallet_balance_after': partner_id_wallet_balance - user_request.trans_amount,
                 'status': 'done'})
            request.env.cr.commit()

            request.env.user.partner_id.update(
                {'wallet_balance': partner_id_wallet_balance 
                - user_request.trans_amount})
            request.env.cr.commit()
            user_request.sudo().write({'wallet_transaction_id': machine_wallet_create.id, 'stage_id': 5})
            request.env.cr.commit()

            # Notify customer
            if wallet_transfer_balance_notify_mode == 'inbox':
                request.env['mail.thread'].sudo().message_notify(
                    subject=label,
                    body=_('<p>%s %s successfully deducted from your wallet.</p>') % (
                        user_request.trans_amount, _(user_request.currency_id.name)),
                    partner_ids=[(4, request.env.user.partner_id.id)],
                )
            elif wallet_transfer_balance_notify_mode == 'email':
                machine_wallet_create.wallet_transaction_email_send()
            elif wallet_transfer_balance_notify_mode == 'sms' and request.env.user.partner_id.mobile:
                machine_wallet_create.sms_send_wallet_transaction(wallet_transfer_balance_notify_mode,
                                                                  'wallet_transfer_balance',
                                                                  request.env.user.partner_id.mobile,
                                                                  request.env.user.name, label,
                                                                  '%s %s' % (user_request.trans_amount,
                                                                             _(user_request.currency_id.name)),
                                                                  request.env.user.partner_id.country_id.phone_code or '2')
            '''
            machine_wallet_create, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                'debit', request.env.user.partner_id, 'request',
                _('Transfer wallet balance to %s') % (user_request.partner_id.name),
                user_request.trans_amount, user_request.currency_id, user_request,
                'smartpay_operations.wallet_transfer_balance_notify_mode', 'wallet_transfer_balance',
                _('<p>%s %s successfully deducted from your wallet.</p>') % (
                    user_request.trans_amount, _(user_request.currency_id.name))
            )
            user_request.sudo().write({'wallet_transaction_id': machine_wallet_create.id, 'stage_id': 5})
            machine_wallet_reservation_id.sudo().unlink()
            request.env.cr.commit()
            unlink_wallet_reservation = True

            '''
            # Create journal entry for transfer AR balance from machine customer to mobile user.
            machine_customer_receivable_account = request.env.user.partner_id.property_account_receivable_id
            mobile_user_receivable_account = user_request.partner_id.property_account_receivable_id
            account_move = request.env['account.move'].sudo().create({
                'journal_id': request.env['account.journal'].sudo().search([('type', '=', 'general')], limit=1).id,
            })
            request.env['account.move.line'].with_context(check_move_validity=False).sudo().create({
                'name': user_request.name + ': Transfer Wallet Balance',
                'move_id': account_move.id,
                'account_id': machine_customer_receivable_account.id,
                'partner_id': request.env.user.partner_id.id,
                'debit': user_request.trans_amount,
            })
            request.env['account.move.line'].with_context(check_move_validity=False).sudo().create({
                'name': user_request.name + ': Transfer Wallet Balance',
                'move_id': account_move.id,
                'account_id': mobile_user_receivable_account.id,
                'partner_id': user_request.partner_id.id,
                'credit': user_request.trans_amount,
            })
            account_move.post()
            '''

            return valid_response(_(
                "Wallet for User (%s) recharged successfully with amount %s %s. Your Machine Wallet Balance is %s %s") %
                                  (user_request.partner_id.name, user_request.trans_amount,
                                   user_request.currency_id.name,
                                   wallet_balance_after,
                                   user_request.currency_id.name))
        else:
            return invalid_response("request_not_found", _("REQ Number (%s) does not exist!") % (
                request_data.get('request_number')), 400)

    @validate_token
    @http.route('/api/get_service_fees', type="http", auth="none", methods=["POST"], csrf=False)
    def get_service_fees(self, **request_data):
        _logger.info("@@@@@@@@@@@@@@@@@@@ Calling Get Service Fees API")
        access_token = request.httprequest.headers.get("access_token")
        access_token_data = (
            request.env["api.access_token"]
            .sudo()
            .search([
                ('active', '=', True),
                ("token", "=", access_token),
                ("user_id.active", "=", True),
                # ('machine_serial', '=', machine_serial),
            ], order="id DESC", limit=1)
        )
        machine_serial = access_token_data.machine_serial

        if not request_data.get('product_id'):
            return invalid_response("service_not_found", _("missing service in request data"), 400)
        else:
            service = request.env["product.product"].sudo().search(
                [("id", "=", request_data.get('product_id')), ("type", "=", "service")],
                order="id DESC", limit=1)
            if not service:
                return invalid_response("service", _("service invalid"), 400)

        # Provider is mandatory because the service fee is different per provider.
        # So the user must send provider that own the bill inquiry request for prevent pay bill
        # with total amount different of total amount in bill inquiry
        provider_provider = request_data.get('provider')
        if provider_provider:
            provider = request.env['payment.acquirer'].sudo().search([("provider", "=", provider_provider)])
            # if provider: # Tamayoz Note: Comment this condition for solving service_providerinfo assign before initilizing
            if provider_provider == 'khales' and provider.server_state == 'offline':
                return invalid_response("service_fees_not_available",
                                        _("Service Fees Not Available"), 400)
            service_providerinfo = request.env['product.supplierinfo'].sudo().search([
                ('product_tmpl_id', '=', service.product_tmpl_id.id),
                ('name', '=', provider.related_partner.id)
            ])
            if not service_providerinfo:
                return invalid_response(
                    "Incompatible_provider_service", _("%s is not a provider for (%s) service") % (
                        provider_provider, service.name or '-'), 400)
        else:
            return invalid_response("provider_not_found",
                                    _("missing provider in request data"), 400)

        trans_amount = float(request_data.get('trans_amount'))
        if not trans_amount:
            return invalid_response("amount_not_found",
                                    _("missing bill amount in request data"), 400)
        else:
            # Calculate Fees
            provider_fees_calculated_amount = 0.0
            extra_fees_amount = 0.0
            if provider_provider == 'khales':
                if not request_data.get('ePayBillRecID'):
                    return invalid_response("ePayBillRecID_not_found",
                                            _("missing ePayBillRecID in request data"), 400)
                if not request_data.get('currency_id'):
                    return invalid_response("currency_not_found", _("missing currency in request data"), 400)

                provider_channel = False
                provider_channels = request.env['payment.acquirer.channel'].sudo().search(
                    [("acquirer_id", "=", provider.id)], limit=1)
                if provider_channels:
                    provider_channel = provider_channels[0]

                curCode = request_data.get('currency_id')
                payAmts = request_data.get('payAmts')
                if payAmts:
                    payAmts = ast.literal_eval(payAmts)
                    payAmtTemp = trans_amount
                    for payAmt in payAmts:
                        payAmtTemp -= float(payAmt.get('AmtDue'))
                    if payAmtTemp != 0:
                        return invalid_response("payAmts_not_match",
                                                _("The sum of payAmts must be equals trans_amount"), 400)
                else:
                    payAmts = [{'Sequence': '1', 'AmtDue': trans_amount, 'CurCode': curCode}]

                '''
                machine_serial = None
                if len(request.env.user.machine_serial) > 16:  # Ingenico POS
                    machine_serial = request.env.user.machine_serial
                    machine_serial = machine_serial[len(machine_serial) - 16:len(machine_serial)]
                '''
                # machine_serial = request.env.user.machine_serial
                if machine_serial and len(machine_serial) > 16:
                    machine_serial = machine_serial[len(machine_serial) - 16:len(machine_serial)]
                fees_response = provider.get_khales_fees('', machine_serial or '',
                                                         request_data.get('ePayBillRecID'), payAmts,
                                                         provider_channel)
                if fees_response.get('Success'):
                    feeInqRsType = fees_response.get('Success')
                    provider_fees_calculated_amount = float(feeInqRsType['FeesAmt']['Amt'])

            if provider_fees_calculated_amount == 0 or provider_provider == 'khales':
                calculate_provider_fees = True
                if provider_provider == 'khales' and provider_fees_calculated_amount != 0:
                    calculate_provider_fees = False
                commissions = request.env['product.supplierinfo.commission'].sudo().search_read(
                    domain=[('vendor', '=', service_providerinfo.name.id),
                            ('vendor_product_code', '=', service_providerinfo.product_code)],
                    fields=['Amount_Range_From', 'Amount_Range_To',
                            'Extra_Fee_Amt', 'Extra_Fee_Prc',
                            'Mer_Fee_Amt', 'Mer_Fee_Prc', 'Mer_Fee_Prc_MinAmt', 'Mer_Fee_Prc_MaxAmt']
                )
                for commission in commissions:
                    if commission['Amount_Range_From'] <= trans_amount \
                            and commission['Amount_Range_To'] >= trans_amount:
                        if commission['Extra_Fee_Amt'] > 0:
                            extra_fees_amount = commission['Extra_Fee_Amt']
                        elif commission['Extra_Fee_Prc'] > 0:
                            extra_fees_amount = trans_amount * commission['Extra_Fee_Prc'] / 100
                        if calculate_provider_fees:
                            if commission['Mer_Fee_Amt'] > 0:
                                provider_fees_calculated_amount = commission['Mer_Fee_Amt']
                            elif commission['Mer_Fee_Prc'] > 0:
                                # Fees amount = FA + [Percentage * Payment Amount]
                                # Fees amount ====================> provider_fees_calculated_amount
                                # FA =============================> provider_fees_calculated_amount
                                # [Percentage * Payment Amount] ==> provider_fees_prc_calculated_amount
                                provider_fees_prc_calculated_amount = trans_amount * commission[
                                    'Mer_Fee_Prc'] / 100
                                if provider_fees_prc_calculated_amount < commission['Mer_Fee_Prc_MinAmt']:
                                    provider_fees_prc_calculated_amount = commission['Mer_Fee_Prc_MinAmt']
                                elif provider_fees_prc_calculated_amount > commission['Mer_Fee_Prc_MaxAmt'] \
                                        and commission['Mer_Fee_Prc_MaxAmt'] > 0:
                                    provider_fees_prc_calculated_amount = commission['Mer_Fee_Prc_MaxAmt']
                                provider_fees_calculated_amount += provider_fees_prc_calculated_amount
                        break
                if calculate_provider_fees and provider_fees_calculated_amount != 0 and provider_provider == 'khales':
                    provider_fees_calculated_amount = ((math.floor(provider_fees_calculated_amount * 100)) / 100.0)

            calculated_payment_amount = trans_amount + provider_fees_calculated_amount + extra_fees_amount
            return valid_response(
                {"message": _("Get Service Fees request was submit successfully."),
                 "provider": provider.provider,
                 "provider_service_code": service_providerinfo.product_code,
                 "provider_service_name": service_providerinfo.product_name,
                 "trans_amount": trans_amount,
                 "provider_fees_amount": provider_fees_calculated_amount,
                 "extra_fees_amount": extra_fees_amount
                 })
