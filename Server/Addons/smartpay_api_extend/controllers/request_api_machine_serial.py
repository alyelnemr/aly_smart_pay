import json
import ast
import logging
import math
from datetime import date, datetime as date_time, timedelta
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


class InheritRequestAPIMachineSerial(SmartAPIController.RequestApi):

    @validate_token
    @http.route('/api/cancelRequest', type="http", auth="none", methods=["PUT"], csrf=False)
    def cancelRequest(self, **request_data):
        _logger.info(">>>>>>>>>>>>>>>>>>>> Calling Cancel Mobile Request API")
        user_request = False
        request_number = request_data.get('request_number')
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
                                               provider_pay_response_json.get('PmtInfo').get(
                                                   'ExtraBillingAcctKeys').get('ExtraBillingAcctKey')
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

                                partner.update({'wallet_balance': partner_id_wallet_balance + customer_actual_amount})
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
                                            sale_limit_fees.update(
                                                {'refund_amount': sale_limit_fees.fees_amount,
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

    @validate_token
    @validate_machine
    @http.route('/api/rechargeMobileWallet', type="http", auth="none", methods=["POST"], csrf=False)
    def rechargeMobileWallet(self, **request_data):
        _logger.info(">>>>>>>>>>>>>>>>>>>> Calling Recharge Mobile Wallet Request API")
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
                    trans_amount=user_request.trans_amount)
            else:
                partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(
                    # service=user_request.product_id,
                    trans_amount=user_request.trans_amount)
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
                {'wallet_balance': partner_id_wallet_balance + user_request.trans_amount})
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
                                                                                       service=service,
                                                                                       trans_amount=customer_actual_amount)
            else:
                partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(service=service,
                                                                                       trans_amount=customer_actual_amount)
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
                {'wallet_balance': partner_id_wallet_balance - user_request.trans_amount})
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
                                   wallet_balance_after, user_request.currency_id.name))
        else:
            return invalid_response("request_not_found", _("REQ Number (%s) does not exist!") % (
                request_data.get('request_number')), 400)

    @validate_token
    @http.route('/api/getServiceFees', type="http", auth="none", methods=["POST"], csrf=False)
    def getServiceFees(self, **request_data):
        _logger.info(">>>>>>>>>>>>>>>>>>>> Calling Get Service Fees API")
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
