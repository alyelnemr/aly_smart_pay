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

_logger = logging.getLogger(__name__)


class RequestApiTempMachineSerial(SmartAPIController.RequestApiTemp):

    @validate_token
    @http.route('/api/create_mobile_request', type="http", auth="none", methods=["POST"], csrf=False)
    def create_mobile_request(self, **request_data):
        _logger.info("@@@@@@@@@@@@@@@@@@@ Calling Mobile Request API")
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
        if not request_data.get('request_type') or request_data.get('request_type') not in _REQUEST_TYPES_IDS:
            return invalid_response("request_type", _("request type invalid"), 400)

        if request_data.get('request_type') == 'recharge_wallet':
            if not request_data.get('trans_amount'):
                return invalid_response("amount_not_found", _("missing amount in request data"), 400)
            open_request = request.env["smartpay_operations.request"].sudo().search(
                [('request_type', '=', 'recharge_wallet'), ("partner_id", "=", request.env.user.partner_id.id),
                 ("stage_id", "=", 1)],
                order="id DESC", limit=1)
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
                'general_inquiry', 'wallet_invitation'):
            return invalid_response("service_not_found", _("missing service in request data"), 400)
        elif request_data.get('request_type') not in ('general_inquiry', 'wallet_invitation'):
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

        if request_data.get('request_type') == 'service_bill_inquiry' or request_data.get(
                'request_type') == 'pay_service_bill':
            if not request_data.get('billingAcct'):
                return invalid_response("billingAcct_not_found", _("missing billing account in request data"), 400)

            provider_provider = request_data.get('provider')
            if request_data.get('request_type') == 'pay_service_bill':
                if not request_data.get('currency_id'):
                    return invalid_response("curCode_not_found",
                                            _("missing bill currency code in request data"), 400)
                if not request_data.get('pmtMethod'):
                    return invalid_response("pmtMethod_not_found",
                                            _("missing payment method in request data"), 400)

                if provider_provider == 'khales':
                    if not request_data.get('pmtType'):
                        return invalid_response("pmtType_not_found", _("missing payment type in request data"), 400)
                    '''
                    if not request_data.get('billerId'):
                        return invalid_response("billerId_not_found", _("missing biller id in request data"), 400)
                    '''
                    if not request_data.get('ePayBillRecID'):
                        return invalid_response("ePayBillRecID_not_found",
                                                _("missing ePay Bill Rec ID in request data"), 400)
                    if not request_data.get('pmtId'):
                        return invalid_response("pmtId_not_found", _("missing payment id in request data"), 400)
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

                if ((provider_provider == 'fawry' and request_data.get(
                        'pmtType') == "POST") or provider_provider == 'khales') \
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
                                    if over_limit_fees_id['sale_amount_from'] <= trans_amount and over_limit_fees_id[
                                        'sale_amount_to'] >= trans_amount:
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
                                                                wallet_limit_type, partner_wallet_id.type.name), 400)

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
                    mobile_wallet_reservation_id, mobile_wallet_balance, mobile_wallet_available_amount = \
                        partner_wallet_id.update_wallet_reserved_balance(
                            _('Pay Service Bill for %s service') % (service.name), calculated_payment_amount,
                            request.env.user.company_id.currency_id, 'request'
                        )
                    # # mobile_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                    # mobile_wallet_available_amount = partner_wallet_id.available_amount if partner_wallet_id else 0
                    # if mobile_wallet_available_amount < calculated_payment_amount:
                    if not mobile_wallet_reservation_id:
                        return invalid_response("mobile_balance_not_enough",
                                                _("Mobile Wallet Available Balance (%s) less than the payment amount (%s)") % (
                                                    mobile_wallet_available_amount, calculated_payment_amount), 400)

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
                user_request = model_record.env[model_name].sudo().browse(id_record)
            else:
                return invalid_response("Error", _("Could not submit you request."), 500)

        # Some fields have additional SQL constraints that we can't check generically
        # Ex: crm.lead.probability which is a float between 0 and 1
        # TODO: How to get the name of the erroneous field ?
        except IntegrityError as e:
            return invalid_response("Error", _("Could not submit you request.") + " ==> " + str(e), 500)

        if request_data.get('request_type') == 'recharge_wallet':
            return valid_response({"message": _("Recharge your wallet request was submit successfully."),
                                   "request_number": user_request.name
                                   })
        elif request_data.get('request_type') == 'wallet_invitation':
            return valid_response(
                {"message": _("Wallet inivitation request for mobile number (%s) was submit successfully.") % (
                    request_data.get('mobile_number')),
                 "request_number": user_request.name
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
                                                                            user_request.name)
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
                        bill_response = provider.get_khales_bill_details(lang, machine_serial or user_request.name,
                                                                         provider_info.product_code,
                                                                         biller_info_json_dict.get('Code'),
                                                                         billingAcct, extraBillingAcctKeys,
                                                                         provider_channel, user_request.name)
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
                                fees_response = provider.get_khales_fees(lang, machine_serial or user_request.name,
                                                                         ePayBillRecID, payAmts[0], provider_channel,
                                                                         user_request.name)
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
                                                                             user_request.name)
                        if provider_response.get('Success'):
                            billData = provider_response.get('Success')
                            provider_response_json = billData
                            if billData.get('amount'):
                                trans_amount += float(billData.get('amount'))
                            # elif billData.get('min_amount'):
                            # trans_amount += float(billData.get('min_amount'))

                    if provider_response.get('Success'):
                        # if not provider_response_json:
                        # provider_response_json = suds_to_json(provider_response.get('Success'))
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
                        user_request.update(
                            {"provider_id": provider.id, "provider_response": provider_response_json,
                             "trans_amount": trans_amount, "extra_fees_amount": extra_fees_amount,
                             "extra_fees": commissions, "stage_id": 5})
                        request.env.cr.commit()
                        return valid_response(
                            {"message": _("Service Bill Inquiry request was submit successfully."),
                             "request_number": user_request.name,
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

            user_request.update({
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
            if mobile_wallet_reservation_id:
                mobile_wallet_reservation_id.update({'request_id': user_request.id})
                request.env.cr.commit()
            lang = request_data.get('lang')
            billingAcct = request_data.get('billingAcct')

            extraBillingAcctKeys = request_data.get('extraBillingAcctKeys')
            if extraBillingAcctKeys:
                extraBillingAcctKeys = ast.literal_eval(extraBillingAcctKeys)

            notifyMobile = request_data.get('notifyMobile')
            billRefNumber = request_data.get('billRefNumber')
            billerId = request_data.get('billerId')
            pmtType = request_data.get('pmtType')

            trans_amount = request_data.get('trans_amount')
            curCode = request_data.get('currency_id')
            payAmts = request_data.get('payAmts')
            if payAmts:
                payAmts = ast.literal_eval(payAmts)
            else:
                payAmts = [{'Sequence': '1', 'AmtDue': trans_amount, 'CurCode': curCode}]
            pmtMethod = request_data.get('pmtMethod')

            ePayBillRecID = request_data.get('ePayBillRecID')
            pmtId = request_data.get('pmtId') or user_request.name
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
                mobile_wallet_reservation_id, mobile_wallet_balance, mobile_wallet_available_amount = partner_wallet_id.update_wallet_reserved_balance(
                        _('Pay Service Bill for %s service') % (service.name), calculated_payment_amount,
                        request.env.user.company_id.currency_id, 'request'
                    )
                # # mobile_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                # mobile_wallet_available_amount = partner_wallet_id.available_amount if partner_wallet_id else 0
                # if mobile_wallet_available_amount < calculated_payment_amount:
                if not mobile_wallet_reservation_id:
                    error.update({"mobile_balance_not_enough":
                                            _("Mobile Wallet Available Balance (%s) less than the payment amount (%s)") % (mobile_wallet_available_amount,
                                                                                                                  calculated_payment_amount)})
                '''

                user_request.update({'provider_fees_calculated_amount': provider_fees_calculated_amount})
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
                             ("type", "in", ("mobile", "internet"))], limit=1)
                        if machine_channels:
                            provider_channel = machine_channels[0]
                        if provider.provider == "fawry":
                            # Tamayoz TODO: Provider Server Timeout Handling
                            user_request.update(
                                {'action_status': 'in_progress'})  # ==> current 'payment_status': is 'new'
                            request.env.cr.commit()
                            provider_response = provider.pay_fawry_bill(lang, provider_info.product_code,
                                                                        billingAcct, extraBillingAcctKeys,
                                                                        trans_amount, curCode, pmtMethod,
                                                                        notifyMobile, billRefNumber,
                                                                        billerId, pmtType, provider_channel,
                                                                        inquiryTransactionId, user_request.name,
                                                                        biller_info_json_dict.get('SupportPmtReverse'),
                                                                        biller_info_json_dict.get('AllowRetry'))
                            if provider_response.get('Success'):
                                if provider_response.get('Success').get('timeout'):
                                    user_request.update(
                                        {'payment_status': 'timeout'})  # ==> current 'action_status': is 'in_progress'
                                    if biller_info_json_dict.get('PmtType') == 'VOCH':
                                        provider_response = {"error_code": "0", "error_message": None,
                                                             "error_message_to_be_translated": "FW Server timeout:\n", }
                                        if biller_info_json_dict.get('SupportPmtReverse'):
                                            provider_response.update({"TO_CANCEL": "VOCH"})
                                        else:
                                            provider_response.update({"TO_REVIEW": "VOCH"})
                                else:
                                    user_request.update(
                                        {'action_status': 'completed'})  # ==> current 'payment_status': is 'new'
                                request.env.cr.commit()
                                if not provider_response.get('error_code'):
                                    provider_response_json = suds_to_json(
                                        provider_response.get('Success')['pmtInfoValType'])
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
                                    # provider_response_json_dict['PmtInfo']['CurAmt']['Amt'] == user_request.trans_amount
                                    provider_fees_actual_amount = provider_response_json_dict['PmtInfo']['FeesAmt'][
                                        'Amt']
                                    user_request.update({'provider_fees_amount': provider_fees_actual_amount})
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
                                extraBillingAcctKeys = [x for x in extraBillingAcctKeys if
                                                        x not in keysToBeRemoved]
                                billingAcct = biller_info_json_dict.get('BillTypeAcctFormatSpliter').join(
                                    formatedBillingAcct)
                            # Tamayoz TODO: Provider Server Timeout Handling
                            # Tamayoz TODO: Remove the next temporary line
                            pmtMethod = "CARD"  # TEMP CODE
                            user_request.update(
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
                            provider_response = provider.pay_khales_bill(lang, machine_serial or user_request.name,
                                                                         billingAcct, extraBillingAcctKeys, billerId,
                                                                         ePayBillRecID,
                                                                         payAmts, pmtId, pmtType, feesAmts,
                                                                         billRefNumber, pmtMethod, pmtRefInfo,
                                                                         provider_channel, user_request.name,
                                                                         biller_info_json_dict.get('SupportPmtReverse'),
                                                                         biller_info_json_dict.get('AllowRetry'))
                            if provider_response.get('Success'):
                                if provider_response.get('Success').get('timeout'):
                                    user_request.update(
                                        {'payment_status': 'timeout'})  # ==> current 'action_status': is 'in_progress'
                                    if biller_info_json_dict.get('PmtType') == 'VOCH':
                                        provider_response = {"error_code": "0", "error_message": None,
                                                             "error_message_to_be_translated": "KH Server timeout:\n", }
                                        if biller_info_json_dict.get('SupportPmtReverse'):
                                            provider_response.update({"TO_CANCEL": "VOCH"})
                                        else:
                                            provider_response.update({"TO_REVIEW": "VOCH"})
                                else:
                                    user_request.update(
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
                                    user_request.update({'provider_fees_amount': provider_fees_actual_amount})
                                    request.env.cr.commit()
                                    # Provider Payment Trans ID
                                    provider_payment_trans_id = pmtId
                        elif provider.provider == "masary":
                            user_request.update(
                                {'action_status': 'in_progress'})  # ==> current 'payment_status': is 'new'
                            request.env.cr.commit()
                            provider_response = provider.pay_masary_bill(lang, int(provider_info.product_code),
                                                                         float(trans_amount), float(feesAmt),
                                                                         inquiryTransactionId, 1,  # quantity
                                                                         extraBillingAcctKeys, provider_channel,
                                                                         user_request.name)
                            if provider_response.get('Success'):
                                if provider_response.get('Success').get('timeout'):
                                    user_request.update(
                                        {'payment_status': 'timeout'})  # ==> current 'action_status': is 'in_progress'
                                    if biller_info_json_dict.get('PmtType') == 'VOCH':
                                        provider_response = {"error_code": "0", "error_message": None,
                                                             "error_message_to_be_translated": "KH Server timeout:\n", }
                                        if biller_info_json_dict.get('SupportPmtReverse'):
                                            provider_response.update({"TO_CANCEL": "VOCH"})
                                        else:
                                            provider_response.update({"TO_REVIEW": "VOCH"})
                                else:
                                    user_request.update(
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
                                    user_request.update({'provider_fees_amount': provider_fees_actual_amount})
                                    request.env.cr.commit()
                                    # Provider Payment Trans ID
                                    provider_payment_trans_id = transactionId

                        if provider_response.get('Success'):
                            try:
                                mobile_wallet_create = False
                                # provider_invoice_id = False
                                # refund = False
                                # customer_invoice_id = False
                                # credit_note = False
                                user_request_response = {"request_number": user_request.name,
                                                         "request_datetime": user_request.create_date + timedelta(
                                                             hours=2),
                                                         "provider": provider.provider,
                                                         "provider_response": provider_response_json
                                                         }

                                if provider.provider == "fawry":
                                    if cardMetadata:
                                        user_request_response.update({"cardMetadata": cardMetadata})

                                provider_actual_amount = user_request.trans_amount + provider_fees_actual_amount
                                customer_actual_amount = provider_actual_amount + extra_fees_amount

                                if not biller_info_json_dict.get('CorrBillTypeCode') or biller_info_json_dict.get(
                                        'Type') == 'CASHININT':
                                    # Deduct Transaction Amount from Mobile Wallet Balance
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
                                    mobile_wallet_create = wallet_transaction_sudo.create(
                                        {'wallet_type': 'debit', 'partner_id': request.env.user.partner_id.id,
                                         'request_id': user_request.id,
                                         'reference': 'request',
                                         'label': label,
                                         'amount': customer_actual_amount, 'currency_id': user_request.currency_id.id,
                                         'wallet_balance_before': partner_id_wallet_balance,
                                         'wallet_balance_after': partner_id_wallet_balance - customer_actual_amount,
                                         'status': 'done'})
                                    request.env.cr.commit()

                                    request.env.user.partner_id.update(
                                        {'wallet_balance': partner_id_wallet_balance - customer_actual_amount})
                                    request.env.cr.commit()
                                    '''
                                    mobile_wallet_create, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                                        'debit', request.env.user.partner_id, 'request',
                                        _('Pay Service Bill for %s service') % (service.name),
                                        customer_actual_amount, user_request.currency_id, user_request,
                                        'smartpay_operations.wallet_pay_service_bill_notify_mode', 'wallet_pay_service',
                                        _('<p>%s %s successfully deducted from your wallet.</p>') % (
                                            customer_actual_amount, _(user_request.currency_id.name))
                                    )

                                    if provider_response.get('Success').get('timeout'):
                                        if not biller_info_json_dict.get('Timeout') and not biller_info_json_dict.get(
                                                'SupportPmtReverse'):
                                            user_request.update({'payment_status': 'in_queue'})
                                        elif biller_info_json_dict.get('Timeout') == 'PENDING':
                                            user_request.update({'payment_status': 'pending'})
                                        elif biller_info_json_dict.get('SupportPmtReverse'):
                                            # if biller_info_json_dict.get('PmtType') == 'VOCH':
                                            # user_request.update({'payment_status': 'to_cancel'})
                                            # else:
                                            if biller_info_json_dict.get('PmtType') != 'VOCH':
                                                user_request.update({'payment_status': 'to_refund'})
                                        # else:
                                        # user_request.update({'payment_status': 'done'}) # Tamayoz: No need to handel "else" case
                                        user_request.update({'action_status': 'new'})
                                    elif provider_response.get('Success').get('pending'):
                                        user_request.update({'payment_status': 'pending', 'action_status': 'new'})
                                    else:
                                        user_request.update({'payment_status': 'done',
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
                                                    sale_limit_values.update(
                                                        {'week': date_time.now().isocalendar()[1]})
                                                elif limit_type == 'monthly':
                                                    sale_limit_values.update({'month': timetuple.tm_mon})
                                                sale_limit = request.env['res.partner.sale.limit'].sudo().create(
                                                    sale_limit_values)

                                            # Log Sold Over Limit Fees
                                            if limit_fees_amounts.get(limit_type):
                                                wallet_transaction_id, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                                                    'debit', request.env.user.partner_id, 'request',
                                                    _('%s over limit fees for %s service') % (limit_type, service.name),
                                                    limit_fees_amounts.get(limit_type), user_request.currency_id,
                                                    user_request,
                                                    'smartpay_operations.wallet_pay_service_bill_notify_mode',
                                                    'wallet_pay_service',
                                                    _('<p>%s %s successfully deducted from your wallet.</p>') % (
                                                        limit_fees_amounts.get(limit_type),
                                                        _(user_request.currency_id.name))
                                                )
                                                sale_limit_fees = request.env[
                                                    'res.partner.sale.limit.fees'].sudo().create(
                                                    {'user_request_id': user_request.id,
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
                                                trans_limit_domain,
                                                order="id DESC", limit=1)
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
                                                    user_request.currency_id, user_request,
                                                    'smartpay_operations.wallet_pay_service_bill_notify_mode',
                                                    'wallet_pay_service',
                                                    _('<p>%s %s successfully deducted from your wallet.</p>') % (
                                                        wallet_limit_fees_amounts.get(wallet_limit_type),
                                                        _(user_request.currency_id.name))
                                                )
                                                trans_limit_fees = request.env['wallet.trans.limit.fees'].sudo().create(
                                                    {'user_request_id': user_request.id,
                                                     'limit_type': wallet_limit_type,
                                                     'fees_amount': wallet_limit_fees_amounts.get(wallet_limit_type),
                                                     'wallet_transaction_id': wallet_transaction_id.id})

                                    mobile_wallet_reservation_id.sudo().unlink()
                                    request.env.cr.commit()
                                    unlink_wallet_reservation = True

                                    '''
                                    # Notify user
                                    irc_param = request.env['ir.config_parameter'].sudo()
                                    wallet_pay_service_bill_notify_mode = irc_param.get_param("smartpay_operations.wallet_pay_service_bill_notify_mode")
                                    if wallet_pay_service_bill_notify_mode == 'inbox':
                                        request.env['mail.thread'].sudo().message_notify(
                                            subject=label,
                                            body=_('<p>%s %s successfully deducted from your wallet.</p>') % (
                                                customer_actual_amount, _(user_request.currency_id.name)),
                                            partner_ids=[(4, request.env.user.partner_id.id)],
                                        )
                                    elif wallet_pay_service_bill_notify_mode == 'email':
                                        mobile_wallet_create.wallet_transaction_email_send()
                                    elif wallet_pay_service_bill_notify_mode == 'sms' and request.env.user.partner_id.mobile:
                                        mobile_wallet_create.sms_send_wallet_transaction(wallet_pay_service_bill_notify_mode,
                                                                                         'wallet_pay_service',
                                                                                         request.env.user.partner_id.mobile,
                                                                                         request.env.user.name, label,
                                                                                         '%s %s' % (customer_actual_amount,
                                                                                                    _(user_request.currency_id.name)),
                                                                                         request.env.user.partner_id.country_id.phone_code or '2')
                                    '''

                                    payment_info = {"service": service.with_context(lang=request.env.user.lang).name,
                                                    "provider": provider.provider,
                                                    "request_number": user_request.name,
                                                    "request_datetime": user_request.create_date + timedelta(hours=2),
                                                    "label": biller_info_json_dict.get("BillTypeAcctLabel"),
                                                    "billing_acct": billingAcct,
                                                    "ref_number": provider_payment_trans_id,
                                                    "amount": trans_amount,
                                                    "fees": (provider_fees_actual_amount + extra_fees_amount),
                                                    "total": customer_actual_amount}

                                user_request.update(
                                    {'extra_fees_amount': extra_fees_amount,
                                     'wallet_transaction_id': mobile_wallet_create and mobile_wallet_create.id or False,
                                     'trans_date': date.today(),
                                     'provider_id': provider.id,
                                     'provider_response': provider_response_json, "stage_id": 5})
                                if biller_info_json_dict.get('CorrBillTypeCode'):
                                    user_request.update(
                                        {'description': _(
                                            'Initiation Service Payment request (%s) was submit successfully @ %s') % (
                                                            user_request.name,
                                                            str(date_time.now() + timedelta(hours=2)))
                                         })
                                request.env.cr.commit()
                                user_request_response.update({'extra_fees_amount': extra_fees_amount})

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
                                    user_request_response.update({'vouch_pin': VouchPIN})
                                    if not biller_info_json_dict.get('CorrBillTypeCode') or biller_info_json_dict.get(
                                            'Type') == 'CASHININT':
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
                                    mobile_wallet_create.update({"wallet_transaction_info": json.dumps(
                                        {"payment_info": payment_info}, default=default)})
                                    request.env.cr.commit()

                                '''
                                # Create Vendor (Provider) Invoices
                                provider_invoice_ids = ()
                                # 1- Create Vendor bill
                                provider_journal_id = request.env['account.journal'].sudo().search([('type', '=', 'purchase'),
                                                                                          ('company_id', '=', request.env.user.company_id.id)], limit=1)
                                name = provider.provider + ': [' + provider_info.product_code + '] ' + provider_info.product_name
                                provider_invoice_vals = user_request.with_context(name=name,
                                                                                  provider_payment_trans_id=provider_payment_trans_id,
                                                                                  journal_id=provider_journal_id.id,
                                                                                  invoice_date=date.today(),
                                                                                  invoice_type='in_invoice',
                                                                                  partner_id=provider_info.name.id)._prepare_invoice()
                                provider_invoice_id = request.env['account.invoice'].sudo().create(provider_invoice_vals)
                                invoice_line = provider_invoice_id._prepare_invoice_line_from_request(request=user_request,
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
                                    refund.update({'reference': provider_payment_trans_id, 'request_id': user_request.id})
                                    refund_line = refund.invoice_line_ids[0]
                                    refund_line.update({'price_unit': merchant_cashback_amount, 'request_id': user_request.id})
                                    refund.refresh()
                                    refund.action_invoice_open()
                                    provider_invoice_ids += (tuple(refund.ids),)
                                user_request.update({'provider_invoice_ids': provider_invoice_ids})
                                request.env.cr.commit()

                                # Create Customer Invoices
                                customer_invoice_ids = ()
                                # 1- Create Customer Invoice
                                customer_journal_id = request.env['account.journal'].sudo().search([('type', '=', 'sale'),
                                                                                          ('company_id', '=', request.env.user.company_id.id)], limit=1)
                                customer_invoice_vals = user_request.with_context(name=provider_payment_trans_id,
                                                                                  journal_id=customer_journal_id.id,
                                                                                  invoice_date=date.today(),
                                                                                  invoice_type='out_invoice',
                                                                                  partner_id=request.env.user.partner_id.id)._prepare_invoice()
                                customer_invoice_id = request.env['account.invoice'].sudo().create(customer_invoice_vals)
                                user_request.invoice_line_create(invoice_id=customer_invoice_id.id, name=name,
                                                                    qty=1, price_unit=customer_actual_amount)
                                customer_invoice_id.action_invoice_open()
                                customer_invoice_ids += (tuple(customer_invoice_id.ids),)
                                # Auto Reconcile customer invoice with prepaid wallet recharge payments and previous cashback credit note
                                domain = [('account_id', '=', customer_invoice_id.account_id.id),
                                          ('partner_id', '=',
                                           customer_invoice_id.env['res.partner']._find_accounting_partner(
                                               customer_invoice_id.partner_id).id),
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
                                    if float_is_zero(amount_residual_currency,
                                                     precision_rounding=customer_invoice_id.currency_id.rounding):
                                        continue

                                    customer_invoice_id.assign_outstanding_credit(line.id)
                                    if customer_invoice_id.state == 'paid':
                                        break
                                request.env.cr.commit()

                                # 2- Create Customer Credit Note with commision amount for only mobile users have commission
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
                                    credit_note.update({'request_id': user_request.id})
                                    credit_note_line = credit_note.invoice_line_ids[0]
                                    credit_note_line.update({'price_unit': customer_cashback_amount, 'request_id': user_request.id})
                                    credit_note.refresh()
                                    """  Don't validate the customer credit note until the vendor refund reconciliation
                                    After vendor refund reconciliation, validate the customer credit note with
                                    the net amount of vendor refund sent in provider cashback statement then
                                    increase the customer wallet with the same net amount. """
                                    # credit_note.action_invoice_open()
                                    customer_invoice_ids += (tuple(credit_note.ids),)
                                user_request.update({'customer_invoice_ids': customer_invoice_ids})
                                request.env.cr.commit()
                                '''

                                if provider.provider == "khales":
                                    # Add required parameters for cancel payment scenario
                                    user_request_response.update(
                                        {'billingAcct': billingAcct, 'billRefNumber': billRefNumber,
                                         'billerId': billerId, 'pmtType': pmtType, 'trans_amount': trans_amount,
                                         'curCode': curCode, 'pmtMethod': pmtMethod, 'ePayBillRecID': ePayBillRecID,
                                         'pmtId': pmtId, 'feesAmt': feesAmt, 'pmtRefInfo': pmtRefInfo})
                                    if payAmts:
                                        user_request_response.update({'payAmts': payAmts})
                                    if feesAmts:
                                        user_request_response.update({'feesAmts': feesAmts})
                                if not biller_info_json_dict.get('CorrBillTypeCode') or biller_info_json_dict.get(
                                        'Type') == 'CASHININT':
                                    user_request_response.update({"message": _(
                                        "Pay Service Bill request was submit successfully with amount %s %s. Your Machine Wallet Balance is %s %s")
                                                                             % (customer_actual_amount,
                                                                                user_request.currency_id.name,
                                                                                wallet_balance_after,
                                                                                user_request.currency_id.name)})
                                else:
                                    user_request_response.update({"message": _(
                                        "Pay Service Bill Initiation request was submit successfully with amount %s %s.")
                                                                             % (customer_actual_amount,
                                                                                user_request.currency_id.name)})
                                if not unlink_wallet_reservation and mobile_wallet_reservation_id:
                                    mobile_wallet_reservation_id.sudo().unlink()
                                    request.env.cr.commit()
                                    unlink_wallet_reservation = True
                                return valid_response(user_request_response)
                            except Exception as e:
                                try:
                                    _logger.error("%s", e, exc_info=True)
                                    user_request_update = {'extra_fees_amount': extra_fees_amount,
                                                           'trans_date': date.today(),
                                                           'provider_id': provider.id,
                                                           'provider_response': provider_response_json, "stage_id": 5,
                                                           'description': _(
                                                               "After the Pay Service Request submit successfuly with provider, Error is occur:") + " ==> " + str(
                                                               e)}
                                    if mobile_wallet_create:
                                        user_request_update.update({'wallet_transaction_id': mobile_wallet_create.id})
                                    '''
                                    provider_invoice_ids = ()
                                    if provider_invoice_id or refund:
                                        if provider_invoice_id:
                                            provider_invoice_ids += (tuple(provider_invoice_id.ids),)
                                        if refund:
                                            provider_invoice_ids += (tuple(refund.ids),)
                                        user_request_update.update({'provider_invoice_ids': provider_invoice_ids})
                                    customer_invoice_ids = ()
                                    if customer_invoice_id or credit_note:
                                        if customer_invoice_id:
                                            customer_invoice_ids += (tuple(customer_invoice_id.ids),)
                                        if credit_note:
                                            customer_invoice_ids += (tuple(credit_note.ids),)
                                        user_request_update.update({'customer_invoice_ids': customer_invoice_ids})
                                    '''
                                    user_request.update(user_request_update)
                                    request.env.cr.commit()
                                except Exception as e1:
                                    _logger.error("%s", e1, exc_info=True)
                                    if user_request and not user_request.description:
                                        user_request.update({'description': _(
                                            "After the Pay Service Request submit successfuly with provider, Error is occur:") + " ==> " + str(
                                            e)})
                                        request.env.cr.commit()

                                if not unlink_wallet_reservation and mobile_wallet_reservation_id:
                                    mobile_wallet_reservation_id.sudo().unlink()
                                    request.env.cr.commit()
                                    unlink_wallet_reservation = True
                                return invalid_response(user_request_response,
                                                        _("After the Pay Service Request submit successfuly with provider, Error is occur:") + " ==> " + str(
                                                            e),
                                                        500)
                        else:
                            user_request.update({'payment_status': 'canceled' if provider_response.get(
                                'CANCEL_SUCCESS') else ('to_cancel' if provider_response.get('TO_CANCEL') else (
                                'to_review' if provider_response.get('TO_REVIEW') else 'failure')),
                                                 'action_status': 'new' if provider_response.get(
                                                     'TO_CANCEL') or provider_response.get(
                                                     'TO_REVIEW') else 'completed'})  # ==> current 'action_status': is 'completed'
                            request.env.cr.commit()
                            error.update({provider.provider + "_response": provider_response or ''})
                    except Exception as e2:
                        _logger.error("%s", e2, exc_info=True)
                        if user_request and not user_request.description:
                            user_request.update({'description': _("Error is occur:") + " ==> " + str(e2)})
                            request.env.cr.commit()
                        if not unlink_wallet_reservation and mobile_wallet_reservation_id:
                            mobile_wallet_reservation_id.sudo().unlink()
                            request.env.cr.commit()
                            unlink_wallet_reservation = True
                        return invalid_response("Error", _("Error is occur:") + " ==> " + str(e2), 500)
                else:
                    error.update({provider_info.name.name + "_response": _("%s is not a provider for (%s) service") % (
                        provider_info.name.name, service.name)})

            user_request.update({
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
            if not unlink_wallet_reservation and mobile_wallet_reservation_id:
                mobile_wallet_reservation_id.sudo().unlink()
                request.env.cr.commit()
                unlink_wallet_reservation = True
            return invalid_response(error_key, error_msg, 400)
        else:
            return valid_response({"message": _("Your request was submit successfully."),
                                   "request_number": user_request.name
                                   })

    @validate_token
    @http.route('/api/cancel_request', type="http", auth="none", methods=["PUT"], csrf=False)
    def cancel_request(self, **request_data):
        _logger.info("@@@@@@@@@@@@@@@@@@@ Calling Cancel Mobile Request API")
        user_request = False
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
        request_number = request_data.get('request_number')
        if request_number:
            user_request = request.env['smartpay_operations.request'].sudo().search([('name', '=', request_number)],
                                                                                    limit=1)
        else:  # elif request_data.get('provider') == 'khales':
            # if not request_data.get('ePayBillRecID'):
            # return invalid_response("ePayBillRecID_request_number_not_found", _("missing Request Number or ePay Bill Rec ID in request data"), 400)
            user_request = request.env['smartpay_operations.request'].sudo().search(
                [('request_type', '=', 'pay_service_bill'),
                 ('create_date', '<=', date_time.now()),
                 ('create_date', '>=', date_time.now() - timedelta(hours=1)),
                 ('provider_response', 'like', request_data.get('ePayBillRecID') or request_data.get('billRefNumber'))],
                limit=1)
            # _logger.info("@@@@@@@@@@@@@@@@@@@ " + '"EPayBillRecID": "%s"' % (request_data.get('ePayBillRecID')))
        if user_request:
            request_number = user_request.name
            try:
                service = user_request.product_id
                provider = user_request.provider_id

                service_providerinfo = request.env['product.supplierinfo'].sudo().search([
                    ('product_tmpl_id', '=', service.product_tmpl_id.id),
                    ('name', '=', provider.related_partner.id)
                ])
                biller_info_json_dict = json.loads(
                    service_providerinfo.with_context(lang=request.env.user.lang).biller_info, strict=False)
                isAllowCancel = biller_info_json_dict.get('SupportPmtReverse', False)

                if user_request.request_type == 'pay_service_bill' and user_request.stage_id.id == 5 and isAllowCancel \
                        and (not user_request.description
                             or (
                                     'Cancel Service Payment request (%s) was submit successfully' % user_request.name not in user_request.description
                                     and 'Cancel Service Payment request (%s) In progress' % user_request.name not in user_request.description
                                     and 'Correlation Service Payment request (%s) was submit successfully' % user_request.name not in user_request.description
                                     and 'Correlation Service Payment request (%s) In progress' % user_request.name not in user_request.description
                             )):

                    user_request.update({
                        'description': _('Cancel Service Payment request (%s) In progress @ %s') % (
                            user_request.name, str(date_time.now() + timedelta(hours=2))),
                        'payment_status': 'canceled', 'action_status': 'new'
                    })
                    request.env.cr.commit()

                    isInternalCancel = biller_info_json_dict.get('IsInternalCancel', False)
                    lang = 'ar-eg'
                    partner = user_request.partner_id
                    # trans_date = user_request.trans_date
                    trans_amount = user_request.trans_amount
                    provider_fees_amount = user_request.provider_fees_amount
                    extra_fees_amount = user_request.extra_fees_amount
                    currency = user_request.currency_id

                    provider_pay_response = user_request.provider_response
                    provider_response_json = {}
                    provider_response_json['provider_pay_response'] = provider_pay_response
                    provider_pay_response_json = json.loads(provider_pay_response)
                    billingAcct = request_data.get('billingAcct') or provider_pay_response_json.get('billingAcct') \
                                  or provider_pay_response_json.get('PmtInfo').get('BillingAcct')

                    extraBillingAcctKeys = request_data.get('extraBillingAcctKeys')
                    if extraBillingAcctKeys:
                        extraBillingAcctKeys = ast.literal_eval(extraBillingAcctKeys)
                    else:
                        extraBillingAcctKeys = provider_pay_response_json.get('extraBillingAcctKeys') or \
                                               (provider_pay_response_json.get('PmtInfo').get(
                                                   'ExtraBillingAcctKeys').get(
                                                   'ExtraBillingAcctKey') if provider_pay_response_json.get(
                                                   'PmtInfo') and provider_pay_response_json.get('PmtInfo').get(
                                                   'ExtraBillingAcctKeys') else [])
                    notifyMobile = request_data.get('notifyMobile') or provider_pay_response_json.get(
                        'notifyMobile') or 'NCName'

                    billRefNumber = request_data.get('billRefNumber') or provider_pay_response_json.get('billRefNumber') \
                                    or provider_pay_response_json.get('PmtInfo').get('BillRefNumber')
                    billerId = request_data.get('billerId') or provider_pay_response_json.get('billerId')
                    pmtType = request_data.get('pmtType') or provider_pay_response_json.get('pmtType')
                    # trans_amount = request_data.get('trans_amount') or provider_pay_response_json.get('trans_amount')
                    curCode = request_data.get('currency_id') or provider_pay_response_json.get('curCode') \
                              or provider_pay_response_json.get('PmtInfo').get('CurAmt').get('CurCode')
                    payAmts = request_data.get('payAmts')
                    if payAmts:
                        payAmts = ast.literal_eval(payAmts)
                    else:
                        payAmts = [{'Sequence': '1', 'AmtDue': trans_amount, 'CurCode': curCode}]
                    pmtMethod = request_data.get('pmtMethod') or provider_pay_response_json.get('pmtMethod') \
                                or provider_pay_response_json.get('PmtInfo').get('PmtMethod')
                    ePayBillRecID = request_data.get('ePayBillRecID') or provider_pay_response_json.get('ePayBillRecID')
                    pmtId = request_data.get('pmtId') or provider_pay_response_json.get('pmtId')
                    feesAmt = request_data.get('feesAmt') or provider_pay_response_json.get('feesAmt')
                    feesAmts = request_data.get('feesAmts')
                    if feesAmts:
                        feesAmts = ast.literal_eval(feesAmts)
                    else:
                        feesAmts = [{'Amt': feesAmt, 'CurCode': curCode}]
                    pmtRefInfo = request_data.get('pmtRefInfo') or provider_pay_response_json.get('pmtRefInfo')
                    cancelReason = request_data.get('cancelReason') or '001'
                    inquiryTransactionId = request_data.get('inquiryTransactionId')

                    error = {}

                    provider_channel = False
                    machine_channels = request.env['payment.acquirer.channel'].sudo().search(
                        [("acquirer_id", "=", provider.id),
                         ("type", "in", ("machine", "internet"))], limit=1)
                    if machine_channels:
                        provider_channel = machine_channels[0]
                    provider_cancel_response = {}
                    if isInternalCancel:
                        provider_cancel_response["Success"] = _("Internal Cancel")
                    else:
                        if provider.provider == "khales":
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
                            provider_cancel_response = provider.cancel_khales_payment(lang,
                                                                                      machine_serial or request_number,
                                                                                      billingAcct, billerId,
                                                                                      ePayBillRecID,
                                                                                      payAmts, pmtId, pmtType, feesAmts,
                                                                                      billRefNumber, pmtMethod,
                                                                                      pmtRefInfo,
                                                                                      cancelReason, provider_channel,
                                                                                      request_number)
                        if provider.provider == "fawry":
                            provider_cancel_response = provider.reverse_fawry_bill(lang,
                                                                                   service_providerinfo.product_code,
                                                                                   billingAcct, extraBillingAcctKeys,
                                                                                   trans_amount, curCode, pmtMethod,
                                                                                   notifyMobile, billRefNumber,
                                                                                   billerId, pmtType or "POST",
                                                                                   provider_channel,
                                                                                   inquiryTransactionId,
                                                                                   request_number)
                    if provider_cancel_response.get('Success'):
                        try:
                            if isInternalCancel:
                                provider_response_json['provider_cancel_response'] = _("Internal Cancel")
                            else:
                                provider_cancel_response_json = suds_to_json(provider_cancel_response.get('Success'))
                                provider_response_json['provider_cancel_response'] = provider_cancel_response_json

                            provider_actual_amount = trans_amount + provider_fees_amount
                            customer_actual_amount = provider_actual_amount + extra_fees_amount

                            if not biller_info_json_dict.get('CorrBillTypeCode') or biller_info_json_dict.get(
                                    'Type') == 'CASHININT':
                                # Refund Payment Amount to Customer Wallet Balance
                                '''
                                wallet_transaction_sudo = request.env['website.wallet.transaction'].sudo()
                                label = _('Cancel Service Payment for %s service') % (service.name)
                                partner_wallet_id = user_request.wallet_transaction_id.wallet_id or partner.get_transaction_wallet(service=service)
                                partner_id_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                                customer_wallet_create = wallet_transaction_sudo.create({'wallet_type': 'credit', 'partner_id': partner.id,
                                                                                         'request_id': user_request.id, 'reference': 'request',
                                                                                         'label': label, 'amount': customer_actual_amount,
                                                                                         'currency_id': currency.id,
                                                                                         'wallet_balance_before': partner_id_wallet_balance,
                                                                                         'wallet_balance_after': partner_id_wallet_balance + customer_actual_amount,
                                                                                         'status': 'done'})
                                request.env.cr.commit()

                                partner.update({'wallet_balance': partner_id_wallet_balance 
                                + customer_actual_amount})
                                request.env.cr.commit()
                                '''
                                partner_wallet_id = user_request.wallet_transaction_id.wallet_id or partner.get_transaction_wallet(
                                    service=service)
                                if not partner_wallet_id:
                                    return invalid_response("wallet_not_found",
                                                            _("No Matched Wallet found for partner [%s] %s") % (
                                                                partner.ref,
                                                                partner.name), 400)
                                customer_wallet_create, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                                    'credit', partner, 'request',
                                    _('Cancel Service Payment for %s service') % (service.name),
                                    customer_actual_amount, currency, user_request,
                                    'smartpay_operations.wallet_canel_service_payment_notify_mode',
                                    'wallet_cancel_service_payment',
                                    _('<p>%s %s successfully Added to your wallet.</p>') % (
                                        customer_actual_amount, _(currency.name))
                                )

                                # Deduct Sold Limit
                                if service.has_sale_limit:
                                    for sale_limit_id in service.sale_limit_ids:
                                        limit_type = sale_limit_id.limit_type
                                        timetuple = date_time.now().timetuple()
                                        sale_limit_domain = [
                                            ('partner_id', '=', partner.id),
                                            ('product_id', '=', service.id),
                                            ('limit_type', '=', limit_type),
                                            ('year', '=', timetuple.tm_year)]
                                        if limit_type == 'daily':
                                            sale_limit_domain += [('day', '=', timetuple.tm_yday)]
                                        elif limit_type == 'weekly':
                                            sale_limit_domain += [
                                                ('week', '=', date_time.now().isocalendar()[1])]
                                        elif limit_type == 'monthly':
                                            sale_limit_domain += [('month', '=', timetuple.tm_mon)]
                                        sale_limit = request.env['res.partner.sale.limit'].sudo().search(
                                            sale_limit_domain,
                                            order="id DESC", limit=1)
                                        if sale_limit:
                                            sale_limit.update({
                                                'sold_amount': sale_limit.sold_amount - customer_actual_amount})  # calculated_payment_amount

                                        # Refund Sold Over Limit Fees
                                        sale_limit_fees = request.env['res.partner.sale.limit.fees'].sudo().search(
                                            [('user_request_id', '=', user_request.id),
                                             ('limit_type', '=', limit_type),
                                             ('refund_wallet_transaction_id', '=', False)], limit=1)
                                        if sale_limit_fees:
                                            wallet_transaction_id, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                                                'credit', partner, 'request',
                                                _('Refund %s over limit fees for %s service') % (
                                                    limit_type, service.name),
                                                sale_limit_fees.fees_amount, currency, user_request,
                                                'smartpay_operations.wallet_canel_service_payment_notify_mode',
                                                'wallet_cancel_service_payment',
                                                _('<p>%s %s successfully Added to your wallet.</p>') % (
                                                    sale_limit_fees.fees_amount, _(currency.name))
                                            )
                                            sale_limit_fees.update({'refund_amount': sale_limit_fees.fees_amount,
                                                                    'refund_wallet_transaction_id': wallet_transaction_id.id})

                                # Deduct Transaction Limit
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
                                                'trans_amount': trans_limit.trans_amount - customer_actual_amount})  # calculated_payment_amount

                                        # Refund Transaction Over Limit Fees
                                        trans_limit_fees = request.env['wallet.trans.limit.fees'].sudo().search(
                                            [('user_request_id', '=', user_request.id),
                                             ('limit_type', '=', wallet_limit_type),
                                             ('refund_wallet_transaction_id', '=', False)], limit=1)
                                        if trans_limit_fees:
                                            wallet_transaction_id, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                                                'credit', partner, 'request',
                                                _('Refund %s over limit fees for %s wallet type') % (
                                                    wallet_limit_type, partner_wallet_id.type.name),
                                                trans_limit_fees.fees_amount, currency, user_request,
                                                'smartpay_operations.wallet_canel_service_payment_notify_mode',
                                                'wallet_cancel_service_payment',
                                                _('<p>%s %s successfully Added to your wallet.</p>') % (
                                                    trans_limit_fees.fees_amount, _(currency.name))
                                            )
                                            trans_limit_fees.update({'refund_amount': trans_limit_fees.fees_amount,
                                                                     'refund_wallet_transaction_id': wallet_transaction_id.id})

                                '''
                                # Notify customer
                                irc_param = request.env['ir.config_parameter'].sudo()
                                wallet_canel_service_payment_notify_mode = irc_param.get_param("smartpay_operations.wallet_canel_service_payment_notify_mode")
                                if wallet_canel_service_payment_notify_mode == 'inbox':
                                    request.env['mail.thread'].sudo().message_notify(subject=label,
                                                                                  body=_('<p>%s %s successfully Added to your wallet.</p>') % (
                                                                                      customer_actual_amount, _(currency.name)),
                                                                                  partner_ids=[(4, partner.id)],
                                    )
                                elif wallet_canel_service_payment_notify_mode == 'email':
                                    customer_wallet_create.wallet_transaction_email_send()
                                elif wallet_canel_service_payment_notify_mode == 'sms' and partner.mobile:
                                    customer_wallet_create.sms_send_wallet_transaction(wallet_canel_service_payment_notify_mode, 'wallet_cancel_service_payment',
                                                                                       partner.mobile, partner.name, # request.env.user.name,
                                                                                       label, '%s %s' % (customer_actual_amount, _(currency.name)),
                                                                                       partner.country_id.phone_code or '2')
                                '''

                                # Refund provider bill for reconciliation purpose
                                # Cancel provider refund (cashback), customer invoice and customer credit note (cashback)
                                '''
                                refund = False
                                provider_invoice_ids = ()
                                for provider_invoice_id in user_request.provider_invoice_ids:
                                    provider_invoice_ids += (tuple(provider_invoice_id.ids),)
                                    # Refund Provider Bill
                                    if provider_invoice_id.type == 'in_invoice' and len(user_request.provider_invoice_ids) == 2:
                                        refund = request.env['account.invoice.refund'].with_context(
                                            active_ids=provider_invoice_id.ids).sudo().create({
                                            'filter_refund': 'refund',
                                            'description': provider_invoice_id.name,
                                            'date': provider_invoice_id.date_invoice,
                                        })
                                        result = refund.invoice_refund()
                                        refund_id = result.get('domain')[1][2]
                                        refund = request.env['account.invoice'].sudo().browse(refund_id)
                                        refund.update({'reference': pmtId, 'request_id': user_request.id})
                                        refund_line = refund.invoice_line_ids[0]
                                        refund_line.update({'request_id': user_request.id})
                                        refund.refresh()
                                        refund.action_invoice_open()
                                        refund.pay_and_reconcile(request.env['account.journal'].sudo().search(
                                            [('type', '=', 'cash'),
                                             ('company_id', '=', request.env.user.company_id.id),
                                             ('provider_id', '=', provider.id)], limit=1),
                                            provider_actual_amount)
                                        provider_invoice_ids += (tuple(refund.ids),)
                                    # Cancel provider refund (cashback)
                                    if provider_invoice_id.type == 'in_refund':
                                        if provider_invoice_id.state in ('in_payment', 'paid'):
                                            provider_invoice_id.action_invoice_re_open()
                                        provider_invoice_id.action_invoice_cancel()

                                user_request.update({'provider_invoice_ids': provider_invoice_ids})
                                request.env.cr.commit()

                                # customer_invoice_ids = ()
                                for customer_invoice_id in user_request.customer_invoice_ids:
                                    # customer_invoice_ids += (tuple(customer_invoice_id.ids),)
                                    # Cancel Customer Invoice and Customer Credit Note (cashback)
                                    if len(user_request.customer_invoice_ids) == 2:
                                        if customer_invoice_id.state in ('in_payment', 'paid'):
                                            customer_invoice_id.action_invoice_re_open()
                                        customer_invoice_id.action_invoice_cancel()

                                # user_request.update({'customer_invoice_ids': customer_invoice_ids})
                                # request.env.cr.commit()
                                '''

                                user_request.update({'wallet_transaction_id': customer_wallet_create.id})

                            user_request.update({
                                'provider_response': provider_response_json,  # "stage_id": 4
                                'description': _('Cancel Service Payment request (%s) was submit successfully @ %s') % (
                                    user_request.name, str(date_time.now() + timedelta(hours=2))),
                                'action_status': 'completed'
                            })
                            request.env.cr.commit()

                            return valid_response({"request_number": user_request.name, "provider": provider.provider,
                                                   "provider_response": provider_response_json,
                                                   "message":
                                                       _("Cancel Service Payment request (%s) was submit successfully. Your Machine Wallet Balance is %s %s")
                                                       % (user_request.name,
                                                          wallet_balance_after,
                                                          currency.name)
                                                   })
                        except Exception as e:
                            try:
                                _logger.error("%s", e, exc_info=True)
                                user_request_update = {'provider_response': provider_response_json,  # "stage_id": 4,
                                                       'description': _(
                                                           "After the Cancel Service Payment Request submit successfuly with provider, Error is occur:") + " ==> " + str(
                                                           e)}
                                if customer_wallet_create:
                                    user_request_update.update({'wallet_transaction_id': customer_wallet_create.id})
                                '''
                                provider_invoice_ids = ()
                                if provider_invoice_id or refund:
                                    if provider_invoice_id:
                                        provider_invoice_ids += (tuple(provider_invoice_id.ids),)
                                    if refund:
                                        provider_invoice_ids += (tuple(refund.ids),)
                                    user_request_update.update({'provider_invoice_ids': provider_invoice_ids})
                                '''
                                '''
                                customer_invoice_ids = ()
                                if customer_invoice_id or credit_note:
                                    if customer_invoice_id:
                                        customer_invoice_ids += (tuple(customer_invoice_id.ids),)
                                    if credit_note:
                                        customer_invoice_ids += (tuple(credit_note.ids),)
                                    user_request_update.update({'customer_invoice_ids': customer_invoice_ids})
                                '''
                                user_request.update(user_request_update)
                                request.env.cr.commit()
                            except Exception as e1:
                                _logger.error("%s", e1, exc_info=True)
                                if user_request and not user_request.description:
                                    user_request.update({'description': _(
                                        "After the Cancel Service Payment Request submit successfuly with provider, Error is occur:") + " ==> " + str(
                                        e)})
                                    request.env.cr.commit()

                            return invalid_response({"request_number": user_request.name, "provider": provider.provider,
                                                     "provider_response": provider_response_json,
                                                     "message":
                                                         _("Cancel Service Payment request (%s) was submit successfully. Your Machine Wallet Balance is %s %s")
                                                         % (user_request.name,
                                                            currency.name,
                                                            wallet_balance_after,
                                                            currency.name)
                                                     }, _(
                                "After the Cancel Service Payment Request submit successfuly with provider, Error is occur:") + " ==> " + str(
                                e), 500)
                    else:
                        provider_response_json["provider_cancel_response"] = provider_cancel_response
                        error.update({provider.provider + "_response": provider_response_json or ''})

                    user_request.update(
                        {'provider_response': json.dumps(error), 'description': json.dumps(error)})  # 'stage_id': 5
                    request.env.cr.commit()
                    return invalid_response("Error", error, 400)

                elif (
                        user_request.request_type == 'pay_service_bill' and user_request.stage_id.id == 5 and isAllowCancel
                        and (
                                'Cancel Service Payment request (%s) was submit successfully' % user_request.name in user_request.description
                                # or 'Cancel Service Payment request (%s) In progress' % user_request.name in user_request.description
                                # or 'Correlation Service Payment request (%s) was submit successfully' % user_request.name in user_request.description
                                # or 'Correlation Service Payment request (%s) In progress' % user_request.name in user_request.description
                        )) or user_request.sudo().write({'stage_id': 4}):
                    return valid_response(_("Cancel REQ Number (%s) successfully!") % (request_number))
            except Exception as ex:
                _logger.error("%s", ex, exc_info=True)
        else:
            return invalid_response("request_not_found", _("Request does not exist!"), 400)

        return invalid_response("request_not_canceled", _("Could not cancel REQ Number (%s)") % (request_number), 400)