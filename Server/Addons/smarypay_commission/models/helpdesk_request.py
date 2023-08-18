# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

import json
from datetime import date, datetime, timedelta
import calendar
import logging
from odoo import api, fields, models, _

_logger = logging.getLogger(__name__)

class HelpdeskRequest(models.Model):
    _inherit = "smartpay_operations.request"

    commission_amount = fields.Float(string='Customer Commission Amount',
                                     # compute='_compute_commission',
                                     store=True, digits=(12, 2), default=0.0)
    commission_paid = fields.Boolean(string='Customer Commission Paid', default=False)

    '''
    @api.one
    @api.depends('trans_amount','stage_id')
    def _compute_commission(self):
        customer_cashback_amount = 0.0
        if self.request_type == 'pay_service_bill' and self.stage_id.id == self.env.ref('smartpay_operations.stage_done').id\
                and create_date > (datetime.now() - relativedelta(months=1))\
                and 'error_message' not in self.provider_response and 'provider_cancel_response' not in self.provider_response:
            # Set commision amount for only customers have commission
            customer_user = self.env['res.users'].sudo().search([('partner_id', '=', self.partner_id.id)], limit=1)[0]
            if customer_user.commission:
                provider_info = self.env['product.supplierinfo'].sudo().search([
                    ('product_tmpl_id', '=', self.product_id.product_tmpl_id.id),
                    ('name', '=', self.provider_id.related_partner.id)
                ])
                commissions = self.env['product.supplierinfo.commission'].sudo().search_read(
                    domain=[('vendor', '=', provider_info.name.id),
                            ('vendor_product_code', '=', provider_info.product_code)],
                    fields=['Amount_Range_From', 'Amount_Range_To',
                            'Mer_Comm_Full_Fix_Amt', 'Cust_Comm_Full_Fix_Amt',
                            'Bill_Merchant_Comm_Prc', 'Bill_Customer_Comm_Prc']
                )
                for commission in commissions:
                    if commission['Amount_Range_From'] <= self.trans_amount \
                            and commission['Amount_Range_To'] >= self.trans_amount:
                        if commission['Mer_Comm_Full_Fix_Amt'] > 0:
                            customer_cashback_amount = commission['Cust_Comm_Full_Fix_Amt']
                        elif commission['Bill_Merchant_Comm_Prc'] > 0:
                            customer_cashback_amount = self.trans_amount * commission[
                                'Bill_Customer_Comm_Prc'] / 100
                        break
        self.commission_amount = float(customer_cashback_amount)
    '''

    @api.multi
    def button_commission_paid(self):
        for request in self:
            if request.request_type == 'pay_service_bill' and request.stage_id.id == request.env.ref('smartpay_operations.stage_done').id \
                    and 'error_message' not in request.provider_response and 'provider_cancel_response' not in request.provider_response:
                customer_invoice_ids = request.customer_invoice_ids or request.aggregated_customer_invoice_ids
                request_customer_credit_notes = customer_invoice_ids.filtered(lambda x: x.type == 'out_refund')
                if len(request_customer_credit_notes) > 0 and request_customer_credit_notes[0].state not in ('draft', 'cancel'):
                    request.update({'commission_paid': True})

    @api.multi
    def button_compute_commission(self):
        for request in self:
            customer_cashback_amount = 0.0
            if request.request_type == 'pay_service_bill' and request.stage_id.id == request.env.ref('smartpay_operations.stage_done').id \
                    and 'error_message' not in request.provider_response and 'provider_cancel_response' not in request.provider_response:
                if request.commission_paid:
                    customer_cashback_amount = request.commission_amount
                else:
                    # Set commision amount for only customers have commission
                    customer_user = request.env['res.users'].sudo().search([('partner_id', '=', request.partner_id.id)], limit=1)
                    if customer_user.commission:
                        provider_info = request.env['product.supplierinfo'].sudo().search([
                            ('product_tmpl_id', '=', request.product_id.product_tmpl_id.id),
                            ('name', '=', request.provider_id.related_partner.id)
                        ])
                        commissions = request.env['product.supplierinfo.commission'].sudo().search_read(
                            domain=[('vendor', '=', provider_info.name.id),
                                    ('vendor_product_code', '=', provider_info.product_code)],
                            fields=['Amount_Range_From', 'Amount_Range_To',
                                    'Mer_Comm_Full_Fix_Amt', 'Cust_Comm_Full_Fix_Amt',
                                    'Bill_Merchant_Comm_Prc', 'Bill_Customer_Comm_Prc']
                        )
                        for commission in commissions:
                            if commission['Amount_Range_From'] <= request.trans_amount \
                                    and commission['Amount_Range_To'] >= request.trans_amount:
                                if commission['Mer_Comm_Full_Fix_Amt'] > 0:
                                    customer_cashback_amount = commission['Cust_Comm_Full_Fix_Amt']
                                elif commission['Bill_Merchant_Comm_Prc'] > 0:
                                    customer_cashback_amount = request.trans_amount * commission[
                                        'Bill_Customer_Comm_Prc'] / 100
                                break
            request.commission_amount = float(customer_cashback_amount)

    @api.multi
    def button_commission(self):
        previous_requests = []
        previous_partner_id = False
        previous_wallet_id = False
        previous_day = False
        cashback_amounts = {}

        wallet_transaction_sudo = self.env['website.wallet.transaction'].sudo()
        wallet_transaction_line_sudo = self.env['website.wallet.transaction.line'].sudo()
        # irc_param = self.env['ir.config_parameter'].sudo()
        # wallet_customer_cashback_notify_mode = irc_param.get_param("smartpay_operations.wallet_customer_cashback_notify_mode")

        for request in self.filtered(lambda x: x.commission_amount > 0 and not x.commission_paid).sorted(key=lambda r: (r.partner_id.id, r.create_date.date(), r.wallet_transaction_id.wallet_id.id, r.id)):
            if previous_partner_id != request.partner_id or previous_day != request.create_date.date() or previous_wallet_id != request.wallet_transaction_id.wallet_id:
                cashback_amount = cashback_amounts.get(previous_wallet_id.id if previous_wallet_id else -1) or 0.0
                if cashback_amount > 0:
                    partner_wallet_id = previous_wallet_id or previous_partner_id.get_transaction_wallet()
                    '''
                    customer_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                    customer_wallet_create.update({'amount': round(cashback_amount, 2),
                                                   'wallet_balance_before': customer_wallet_balance,
                                                   'wallet_balance_after': customer_wallet_balance + cashback_amount,
                                                   'status': 'done'})

                    previous_partner_id.update({'wallet_balance': customer_wallet_balance + cashback_amount})
                    '''
                    wallet_balance_before, wallet_balance_after, force_update = partner_wallet_id.update_wallet_balance('credit', cashback_amount)
                    customer_wallet_create.update({'wallet_id': partner_wallet_id.id,
                                                   'amount': round(cashback_amount, 2),
                                                   'wallet_balance_before': wallet_balance_before,
                                                   'wallet_balance_after': wallet_balance_after,
                                                   'status': 'done'})
                    for previous_request in previous_requests:
                        previous_request.update({'commission_paid': True})
                    # request.env.cr.commit()

                    '''
                    # # Notify Mobile User
                    # if wallet_customer_cashback_notify_mode == 'inbox':
                    #     request.env['mail.thread'].sudo().message_notify(subject=customer_wallet_create.label,
                    #                                                      body=_(
                    #                                                           '<p>%s %s successfully added to your wallet.</p>') % (
                    #                                                           cashback_amount, _(previous_request[0].currency_id.name)),
                    #                                                      partner_ids=[(4, previous_partner_id.id)],
                    #                                                      )
                    # elif wallet_customer_cashback_notify_mode == 'email':
                    #     customer_wallet_create.wallet_transaction_email_send()
                    # elif wallet_customer_cashback_notify_mode == 'sms' and previous_partner_id.mobile:
                    #     customer_wallet_create.sms_send_wallet_transaction(wallet_customer_cashback_notify_mode,
                    #                                                        'wallet_customer_cashback',
                    #                                                        previous_partner_id.mobile,
                    #                                                        previous_partner_id.name, customer_wallet_create.label,
                    #                                                        '%s %s' % (cashback_amount,
                    #                                                                   _(previous_request[0].currency_id.name)),
                    #                                                        previous_partner_id.country_id.phone_code or '2')
                    # Tamayoz TODO: Create Schedule Action for Notify Partner
                    partner_wallet_id.notify_customer_with_wallet_transaction(
                        'smartpay_operations.wallet_customer_cashback_notify_mode', customer_wallet_create.label,
                        _('<p>%s %s successfully added to your wallet.</p>') % (
                            cashback_amount, _(previous_request.currency_id.name)), 'wallet_customer_cashback', 
                            previous_partner_id, customer_wallet_create, cashback_amount, previous_request.currency_id)
                    '''

                    previous_requests = []

                previous_partner_id = request.partner_id
                previous_wallet_id = request.wallet_transaction_id.wallet_id
                previous_day = request.create_date.date()

                label = _('Customer Cashback for %s') % (request.create_date.date())
                cashback_amounts.update({previous_wallet_id.id: 0.0})
                customer_wallet_create = wallet_transaction_sudo.create({'wallet_type': 'credit',
                                                                         'partner_id': request.partner_id.id,
                                                                         'reference': 'cashback', 'label': label,
                                                                         'amount': 0.0,
                                                                         'currency_id': request.currency_id.id,
                                                                         'status': 'draft'})

            previous_requests.append(request)
            cashback_amount = float(cashback_amounts.get(previous_wallet_id.id) or 0.0) + float(request.commission_amount)
            cashback_amounts.update({previous_wallet_id.id: cashback_amount})

            label = _('Customer Cashback for %s service') % (request.product_id.name)
            customer_wallet_line_create = wallet_transaction_line_sudo.create(
                {'wallet_type': 'credit', 'partner_id': request.partner_id.id,
                 'request_id': request.id, 'reference': 'request', 'label': label,
                 'wallet_transaction_id': customer_wallet_create.id,
                 'amount': request.commission_amount, 'currency_id': request.currency_id.id, 'status': 'done'})
            # request.env.cr.commit()

        # Update last website.wallet.transaction
        cashback_amount = cashback_amounts.get(previous_wallet_id.id) or 0.0
        if cashback_amount > 0:
            partner_wallet_id = previous_wallet_id or previous_partner_id.get_transaction_wallet()
            '''
            customer_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
            customer_wallet_create.update({'amount': round(cashback_amount, 2),
                                           'wallet_balance_before': customer_wallet_balance,
                                           'wallet_balance_after': customer_wallet_balance + cashback_amount,
                                           'status': 'done'})

            previous_partner_id.update({'wallet_balance': customer_wallet_balance + cashback_amount})
            '''
            wallet_balance_before, wallet_balance_after, force_update = partner_wallet_id.update_wallet_balance('credit', cashback_amount)
            customer_wallet_create.update({'wallet_id': partner_wallet_id.id, 'amount': round(cashback_amount, 2),
                                           'wallet_balance_before': wallet_balance_before,
                                           'wallet_balance_after': wallet_balance_after,
                                           'status': 'done'})
            for previous_request in previous_requests:
                previous_request.update({'commission_paid': True})
            # request.env.cr.commit()

            '''
            # # Notify Mobile User
            # if wallet_customer_cashback_notify_mode == 'inbox':
            #     request.env['mail.thread'].sudo().message_notify(subject=customer_wallet_create.label,
            #                                                      body=_(
            #                                                          '<p>%s %s successfully added to your wallet.</p>') % (
            #                                                               cashback_amount,
            #                                                               _(previous_request.currency_id.name)),
            #                                                      partner_ids=[(4, previous_partner_id.id)],
            #                                                      )
            # elif wallet_customer_cashback_notify_mode == 'email':
            #     customer_wallet_create.wallet_transaction_email_send()
            # elif wallet_customer_cashback_notify_mode == 'sms' and previous_partner_id.mobile:
            #     customer_wallet_create.sms_send_wallet_transaction(wallet_customer_cashback_notify_mode,
            #                                                        'wallet_customer_cashback',
            #                                                        previous_partner_id.mobile,
            #                                                        previous_partner_id.name,
            #                                                        customer_wallet_create.label,
            #                                                        '%s %s' % (cashback_amount,
            #                                                                   _(previous_request.currency_id.name)),
            #                                                        previous_partner_id.country_id.phone_code or '2')
            # Tamayoz TODO: Create Schedule Action for Notify Partner
            partner_wallet_id.notify_customer_with_wallet_transaction(
                'smartpay_operations.wallet_customer_cashback_notify_mode', customer_wallet_create.label,
                _('<p>%s %s successfully added to your wallet.</p>') % (
                    cashback_amount, _(previous_request.currency_id.name)), 'wallet_customer_cashback',
                previous_partner_id, customer_wallet_create, cashback_amount, previous_request.currency_id)
            '''

    '''
    def auto_create_invoices_for_pay_request(self, date_from=None, date_to=None, raise_error=None):
        try:
            request_pool = self.env['smartpay_operations.request']
            # request_hours = int(self.env['ir.config_parameter'].sudo().get_param("smartpay_operations.request_hours"))

            domain = [('stage_id','=',self.env.ref('smartpay_operations.stage_done').id),
                      ('request_type', '=', 'pay_service_bill'),
                      ('provider_response', 'not ilike', 'error_message'),
                      ('provider_response', 'not ilike', 'provider_cancel_response'),
                      '|',
                      ('description', '=', False),
                      '&',
                      ('description', 'not ilike', 'Cancel Service Payment request'),
                      ('description', 'not ilike', 'Initiation Service Payment request'),
                      ## ('create_date','<=',str(datetime.now() - timedelta(hours=request_hours))),
                      # '|',
                      # ('customer_invoice_ids_count', '<', 2),
                      # ('provider_invoice_ids_count', '<', 2)
            ]
            if date_from:
                domain += [('create_date','>=','%s' % (date_from))]
            if date_to:
                domain += [('create_date', '<=','%s' % (date_to))]
            domain += ['|',
                      ('customer_invoice_ids_count', '=', 0),
                      ('provider_invoice_ids_count', '=', 0)]
            requests = request_pool.search(domain, order='id'
                                          )#.filtered(lambda x: len(x.customer_invoice_ids) < 2 or len(x.provider_invoice_ids) < 2)
            _logger.info("@@@@@@@@@@@@@@@@@@@ Start Create auto invoices for [%s] requests" % (len(requests)))
            for request in requests:
                _logger.info("@@@@@@@@@@@@@@@@@@@ Create auto invoices for request [%s]" % (request.name))

                provider_response = request.provider_response
                if "provider_correlation_response" in provider_response:
                    provider_response = json.dumps(
                        json.loads(provider_response.replace("\'{", "{").replace("}\'", "}").replace("\'", "\""))[
                            'provider_correlation_response'])
                provider_response_json = json.loads(provider_response)
                # Get Provider Payment Trans ID
                if request.provider_id.provider == "fawry":
                    for payment in provider_response_json['PmtTransId']:
                        if payment['PmtIdType'] == 'FCRN':
                            provider_payment_trans_id = payment['PmtId']
                            break
                if request.provider_id.provider == "khales":
                    provider_payment_trans_id = provider_response_json['PmtRecAdviceStatus']['PmtTransId']['PmtId']

                provider_actual_amount = request.trans_amount + request.provider_fees_amount
                customer_actual_amount = provider_actual_amount + request.extra_fees_amount

                merchant_cashback_amount = 0.0
                customer_cashback_amount = 0.0
                provider_info = request.env['product.supplierinfo'].sudo().search([
                    ('product_tmpl_id', '=', request.product_id.product_tmpl_id.id),
                    ('name', '=', request.provider_id.related_partner.id)
                ])
                commissions = request.env['product.supplierinfo.commission'].sudo().search_read(
                    domain=[('vendor', '=', provider_info.name.id),
                            ('vendor_product_code', '=', provider_info.product_code)],
                    fields=['Amount_Range_From', 'Amount_Range_To',
                            'Mer_Comm_Full_Fix_Amt', 'Cust_Comm_Full_Fix_Amt',
                            'Bill_Merchant_Comm_Prc', 'Bill_Customer_Comm_Prc']
                )
                for commission in commissions:
                    if commission['Amount_Range_From'] <= request.trans_amount \
                            and commission['Amount_Range_To'] >= request.trans_amount:
                        if commission['Mer_Comm_Full_Fix_Amt'] > 0:
                            merchant_cashback_amount = commission['Mer_Comm_Full_Fix_Amt']
                            customer_cashback_amount = commission['Cust_Comm_Full_Fix_Amt']
                        elif commission['Bill_Merchant_Comm_Prc'] > 0:
                            merchant_cashback_amount = request.trans_amount * commission[
                                'Bill_Merchant_Comm_Prc'] / 100
                            customer_cashback_amount = request.trans_amount * commission[
                                'Bill_Customer_Comm_Prc'] / 100
                        break

                name = request.provider_id.provider + ': [' + provider_info.product_code + '] ' + provider_info.product_name
                # Create Vendor (Provider) Invoices
                provider_invoice_ids = ()
                request_provider_bills = request.provider_invoice_ids.filtered(lambda x: x.type == 'in_invoice')
                if len(request_provider_bills) == 0:
                    # 1- Create Vendor bill
                    provider_journal_id = request.env['account.journal'].sudo().search([('type', '=', 'purchase'),
                                                                                        ('company_id', '=',
                                                                                         request.company_id.id)], limit=1)
                    provider_invoice_vals = request.with_context(name=name,
                                                                         provider_payment_trans_id=provider_payment_trans_id,
                                                                         journal_id=provider_journal_id.id,
                                                                         invoice_date= request.create_date.date(), #date.today(),
                                                                         invoice_type='in_invoice',
                                                                         partner_id=provider_info.name.id)._prepare_invoice()
                    provider_invoice_id = request.env['account.invoice'].sudo().create(provider_invoice_vals)
                    invoice_line = provider_invoice_id._prepare_invoice_line_from_request(request=request,
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
                         ('company_id', '=', request.company_id.id),
                         ('provider_id', '=', request.provider_id.id)], limit=1),
                        provider_actual_amount)
                    request.env.cr.commit()
                else:
                    provider_invoice_id = request_provider_bills[0]
                    provider_invoice_ids += (tuple(provider_invoice_id.ids),)

                request_provider_refunds = request.provider_invoice_ids.filtered(lambda x: x.type == 'in_refund')
                if len(request_provider_refunds) == 0:
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
                        refund.update({'reference': provider_payment_trans_id, 'request_id': request.id})
                        refund_line = refund.invoice_line_ids[0]
                        refund_line.update({'price_unit': merchant_cashback_amount, 'request_id': request.id})
                        refund.refresh()
                        refund.action_invoice_open()
                        provider_invoice_ids += (tuple(refund.ids),)
                        request.env.cr.commit()
                else:
                    refund = request_provider_refunds[0]
                    provider_invoice_ids += (tuple(refund.ids),)

                request.update({'provider_invoice_ids': provider_invoice_ids})
                request.env.cr.commit()

                # Create Customer Invoices
                customer_invoice_ids = ()
                request_customer_invoices = request.customer_invoice_ids.filtered(lambda x: x.type == 'out_invoice')
                if len(request_customer_invoices) == 0:
                    # 1- Create Customer Invoice
                    # Calculate Over limit fees
                    over_limit_fees_wallet_transaction_ids = self.env['website.wallet.transaction'].sudo().search(
                        [('reference', '=', 'request'),
                         ('status', '=', 'done'),
                         ('label', 'like', 'over limit fees for'),
                         # Tamayoz: TODO: depend on wallet transaction type instead of label
                         ('request_id', '=', request.id)])
                    over_limit_fees = 0
                    for over_limit_fees_wallet_transaction_id in over_limit_fees_wallet_transaction_ids:
                        over_limit_fees += float(over_limit_fees_wallet_transaction_id.amount)
                    over_limit_fees = round(over_limit_fees, 2)

                    customer_journal_id = request.env['account.journal'].sudo().search([('type', '=', 'sale'),
                                                                                        ('company_id', '=',
                                                                                         request.company_id.id)],
                                                                                       limit=1)
                    customer_invoice_vals = request.with_context(name=provider_payment_trans_id,
                                                                         journal_id=customer_journal_id.id,
                                                                         invoice_date=request.create_date.date(), #date.today(),
                                                                         invoice_type='out_invoice',
                                                                         partner_id=request.partner_id.id)._prepare_invoice()
                    customer_invoice_id = request.env['account.invoice'].sudo().create(customer_invoice_vals)
                    request.invoice_line_create(invoice_id=customer_invoice_id.id, name=name,
                                                        qty=1, price_unit=customer_actual_amount + over_limit_fees) # Tamayoz TODO: Create a new invoice line for over limit fees
                    customer_invoice_id.action_invoice_open()
                    customer_invoice_ids += (tuple(customer_invoice_id.ids),)
                    # Tamayoz TODO: Auto Reconcile customer invoice with prepaid wallet recharge payments and previous cashback credit note
                    """
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
                                                                         line.date or or request.create_date.date() or fields.Date.today())
                        if float_is_zero(amount_residual_currency,
                                         precision_rounding=customer_invoice_id.currency_id.rounding):
                            continue

                        customer_invoice_id.assign_outstanding_credit(line.id)
                        if customer_invoice_id.state == 'paid':
                            break
                    """
                    request.env.cr.commit()
                else:
                    customer_invoice_id = request_customer_invoices[0]
                    customer_invoice_ids += (tuple(customer_invoice_id.ids),)

                request_customer_credit_notes = request.customer_invoice_ids.filtered(lambda x: x.type == 'out_refund')
                if len(request_customer_credit_notes) == 0:
                    # 2- Create Customer Credit Note with commision amount for only customers have commission
                    customer_user = request.env['res.users'].sudo().search([('partner_id', '=', request.partner_id.id)], limit=1)
                    if customer_user and customer_user.commission and customer_cashback_amount > 0:
                        credit_note = request.env['account.invoice.refund'].with_context(
                            active_ids=customer_invoice_id.ids).sudo().create({
                            'filter_refund': 'refund',
                            'description': provider_payment_trans_id,
                            'date': customer_invoice_id.date_invoice,
                        })
                        result = credit_note.invoice_refund()
                        credit_note_id = result.get('domain')[1][2]
                        credit_note = request.env['account.invoice'].sudo().browse(credit_note_id)
                        credit_note.update({'request_id': request.id})
                        credit_note_line = credit_note.invoice_line_ids[0]
                        credit_note_line.update({'price_unit': customer_cashback_amount, 'request_id': request.id})
                        credit_note.refresh()
                        """  Tamayoz: Override auto_create_invoices_for_pay_request in smartpay_operations add-on and validate the customer credit note 
                        without waiting the vendor refund reconciliation.. """
                        credit_note.action_invoice_open()
                        customer_invoice_ids += (tuple(credit_note.ids),)
                        request.env.cr.commit()
                else:
                    credit_note = request_customer_credit_notes[0]
                    customer_invoice_ids += (tuple(credit_note.ids),)

                request.update({'customer_invoice_ids': customer_invoice_ids})
                request.env.cr.commit()
        except Exception as e:
            _logger.error("%s", e)
            if raise_error:
                raise e
            return "internal error"
    '''

    def _auto_create_invoices_for_pay_request(self, date_from=None, date_to=None, raise_error=None):
        try:
            request_pool = self.env['smartpay_operations.request']
            # request_hours = int(self.env['ir.config_parameter'].sudo().get_param("smartpay_operations.request_hours"))

            domain = [('stage_id','=',self.env.ref('smartpay_operations.stage_done').id),
                      ('request_type', '=', 'pay_service_bill'),
                      ('provider_response', 'not ilike', 'error_message'),
                      ('provider_response', 'not ilike', 'provider_cancel_response'),
                      '|',
                      ('description', '=', False),
                      '&',
                      ('description', 'not ilike', 'Cancel Service Payment request'),
                      ('description', 'not ilike', 'Initiation Service Payment request'),
                      ## ('create_date','<=',str(datetime.now() - timedelta(hours=request_hours))),
                      # '|',
                      # ('customer_invoice_ids_count', '<', 2),
                      # ('provider_invoice_ids_count', '<', 2)
            ]
            if date_from:
                domain += [('create_date','>=','%s' % (date_from))]
            if date_to:
                domain += [('create_date', '<=','%s' % (date_to))]
            domain += ['|',
                      ('customer_invoice_ids_count', '=', 0),
                      ('provider_invoice_ids_count', '=', 0)]
            requests = request_pool.search(domain, order='id'
                                          )#.filtered(lambda x: len(x.customer_invoice_ids) < 2 or len(x.provider_invoice_ids) < 2)

            # Prepare the required objects before requests loop for enhancement
            provider_infos = self.env['product.supplierinfo'].sudo().search([])
            provider_commissions = self.env['product.supplierinfo.commission'].sudo().search([])
            provider_journal_ids = self.env['account.journal'].sudo().search([('type', '=', 'purchase')])
            provider_wallets = self.env['account.journal'].sudo().search([('type', '=', 'cash'),
                                                                          ('provider_id', '!=', False)])
            customer_journal_ids = self.env['account.journal'].sudo().search([('type', '=', 'sale')])
            customer_users = self.env['res.users'].sudo().search([])
            over_limit_fees_wallet_transaction_ids = self.env['website.wallet.transaction'].sudo().search(
                [('reference', '=', 'request'),
                 ('status', '=', 'done'),
                 ('label', 'like', 'over limit fees for') # Tamayoz: TODO: depend on wallet transaction type instead of label
                ]
            )

            _logger.info("################### Start Create auto invoices for [%s] requests" % (len(requests)))
            for request in requests:
                _logger.info("################### Create auto invoices for request [%s]" % (request.name))

                _logger.info(">>>>>>>>>>>>>>>>>>> Start Preparing provider_response_json")
                provider_response = request.provider_response
                if "provider_correlation_response" in provider_response:
                    provider_response = json.dumps(
                        json.loads(provider_response.replace("\'{", "{").replace("}\'", "}").replace("\'", "\""))[
                            'provider_correlation_response'])
                provider_response_json = json.loads(provider_response)
                _logger.info(">>>>>>>>>>>>>>>>>>> Start Getting Provider Payment Trans ID")
                # Get Provider Payment Trans ID
                if request.provider_id.provider == "fawry":
                    for payment in provider_response_json['PmtTransId']:
                        if payment['PmtIdType'] == 'FCRN':
                            provider_payment_trans_id = payment['PmtId']
                            break
                if request.provider_id.provider == "khales":
                    provider_payment_trans_id = provider_response_json['PmtRecAdviceStatus']['PmtTransId']['PmtId']

                provider_actual_amount = request.trans_amount + request.provider_fees_amount
                customer_actual_amount = provider_actual_amount + request.extra_fees_amount

                merchant_cashback_amount = 0.0
                customer_cashback_amount = 0.0
                """
                provider_info = request.env['product.supplierinfo'].sudo().search([
                    ('product_tmpl_id', '=', request.product_id.product_tmpl_id.id),
                    ('name', '=', request.provider_id.related_partner.id)
                ])
                """
                _logger.info(">>>>>>>>>>>>>>>>>>> Start Getting provider_info (%s) " % len(provider_infos))
                provider_info = provider_infos.filtered(lambda pi: pi.product_tmpl_id.id ==
                                                                   request.product_id.product_tmpl_id.id and
                                                                   pi.name.id == request.provider_id.related_partner.id)
                _logger.info(">>>>>>>>>>>>>>>>>>> End Getting provider_info %s" % provider_info)

                """
                commissions = request.env['product.supplierinfo.commission'].sudo().search_read(
                    domain=[('vendor', '=', provider_info.name.id),
                            ('vendor_product_code', '=', provider_info.product_code)],
                    fields=['Amount_Range_From', 'Amount_Range_To',
                            'Mer_Comm_Full_Fix_Amt', 'Cust_Comm_Full_Fix_Amt',
                            'Bill_Merchant_Comm_Prc', 'Bill_Customer_Comm_Prc']
                )
                """
                _logger.info(">>>>>>>>>>>>>>>>>>> Start Getting commissions")
                commissions = provider_commissions.filtered(lambda com: com.vendor.id == provider_info.name.id and
                                                                        com.vendor_product_code == provider_info.product_code)
                _logger.info(">>>>>>>>>>>>>>>>>>> Start commissions loop")
                for commission in commissions:
                    if commission['Amount_Range_From'] <= request.trans_amount \
                            and commission['Amount_Range_To'] >= request.trans_amount:
                        if commission['Mer_Comm_Full_Fix_Amt'] > 0:
                            merchant_cashback_amount = commission['Mer_Comm_Full_Fix_Amt']
                            customer_cashback_amount = commission['Cust_Comm_Full_Fix_Amt']
                        elif commission['Bill_Merchant_Comm_Prc'] > 0:
                            merchant_cashback_amount = request.trans_amount * commission[
                                'Bill_Merchant_Comm_Prc'] / 100
                            customer_cashback_amount = request.trans_amount * commission[
                                'Bill_Customer_Comm_Prc'] / 100
                        break
                _logger.info(">>>>>>>>>>>>>>>>>>> End commissions loop")

                name =  '%s: [%s] %s' % (request.provider_id.provider, provider_info.product_code, provider_info.product_name) # request.provider_id.provider + ': [' + provider_info.product_code + '] ' + provider_info.product_name
                # Create Vendor (Provider) Invoices
                provider_invoice_ids = ()
                request_provider_bills = request.provider_invoice_ids.filtered(lambda x: x.type == 'in_invoice')
                if len(request_provider_bills) == 0:
                    # 1- Create Vendor bill
                    _logger.info(">>>>>>>>>>>>>>>>>>> Start Creating Vendor bill")
                    """
                    provider_journal_id = request.env['account.journal'].sudo().search([('type', '=', 'purchase'),
                                                                                        ('company_id', '=',
                                                                                         request.company_id.id)], limit=1)
                    """
                    provider_journal_id = provider_journal_ids.filtered(lambda journal: journal.company_id.id == request.company_id.id)[0]
                    provider_invoice_vals = request.with_context(name=name,
                                                                         provider_payment_trans_id=provider_payment_trans_id,
                                                                         journal_id=provider_journal_id.id,
                                                                         invoice_date=request.create_date.date(), #date.today(),
                                                                         invoice_type='in_invoice',
                                                                         partner_id=provider_info.name.id)._prepare_invoice()
                    provider_invoice_id = request.env['account.invoice'].sudo().create(provider_invoice_vals)
                    invoice_line = provider_invoice_id._prepare_invoice_line_from_request(request=request,
                                                                                          name=name,
                                                                                          qty=1,
                                                                                          price_unit=provider_actual_amount)
                    new_line = request.env['account.invoice.line'].sudo().new(invoice_line)
                    new_line._set_additional_fields(provider_invoice_id)
                    provider_invoice_id.invoice_line_ids += new_line
                    provider_invoice_id.action_invoice_open()
                    provider_invoice_ids += (tuple(provider_invoice_id.ids),)
                    provider_invoice_id.pay_and_reconcile(
                        provider_wallets.filtered(lambda wallet: wallet.company_id.id == request.company_id.id and
                                                   wallet.provider_id.id == request.provider_id.id)[0],
                        provider_actual_amount)
                    request.env.cr.commit()
                else:
                    provider_invoice_id = request_provider_bills[0]
                    provider_invoice_ids += (tuple(provider_invoice_id.ids),)

                request_provider_refunds = request.provider_invoice_ids.filtered(lambda x: x.type == 'in_refund')
                if len(request_provider_refunds) == 0:
                    # 2- Create Vendor Refund with commission amount
                    _logger.info(">>>>>>>>>>>>>>>>>>> Start Creating Vendor Refund with commission amount")
                    if merchant_cashback_amount > 0:
                        refund = request.env['account.invoice.refund'].with_context(
                            active_ids=provider_invoice_id.ids).sudo().create({
                            'filter_refund': 'refund',
                            'description': name,
                            'date': request.create_date.date(), #provider_invoice_id.date_invoice,
                        })
                        result = refund.invoice_refund()
                        refund_id = result.get('domain')[1][2]
                        refund = request.env['account.invoice'].sudo().browse(refund_id)
                        refund.update({'reference': provider_payment_trans_id, 'request_id': request.id})
                        refund_line = refund.invoice_line_ids[0]
                        refund_line.update({'price_unit': merchant_cashback_amount, 'request_id': request.id})
                        refund.refresh()
                        refund.action_invoice_open()
                        provider_invoice_ids += (tuple(refund.ids),)
                        request.env.cr.commit()
                else:
                    refund = request_provider_refunds[0]
                    provider_invoice_ids += (tuple(refund.ids),)

                request.update({'provider_invoice_ids': provider_invoice_ids})
                request.env.cr.commit()

                # Create Customer Invoices
                customer_invoice_ids = ()
                request_customer_invoices = request.customer_invoice_ids.filtered(lambda x: x.type == 'out_invoice')
                if len(request_customer_invoices) == 0:
                    # 1- Create Customer Invoice
                    _logger.info(">>>>>>>>>>>>>>>>>>> Start Creating Customer Invoice")
                    # Calculate Over limit fees
                    """
                    over_limit_fees_wallet_transaction_ids = self.env['website.wallet.transaction'].sudo().search([('reference', '=', 'request'),
                                                                                                                   ('status', '=', 'done'),
                                                                                                                   ('label', 'like', 'over limit fees for'), # Tamayoz: TODO: depend on wallet transaction type instead of label
                                                                                                                   ('request_id', '=', request.id)])
                    """
                    request_over_limit_fees_wallet_transaction_ids = over_limit_fees_wallet_transaction_ids.filtered(
                        lambda trans: trans.request_id.id == request.id)
                    over_limit_fees = 0
                    for request_over_limit_fees_wallet_transaction_id in request_over_limit_fees_wallet_transaction_ids:
                        over_limit_fees += float(request_over_limit_fees_wallet_transaction_id.amount)
                    over_limit_fees = round(over_limit_fees, 2)

                    """
                    customer_journal_id = request.env['account.journal'].sudo().search([('type', '=', 'sale'),
                                                                                        ('company_id', '=',
                                                                                         request.company_id.id)],
                                                                                       limit=1)
                    """
                    customer_journal_id = customer_journal_ids.filtered(lambda journal: journal.company_id.id == request.company_id.id)[0]

                    customer_invoice_vals = request.with_context(name=provider_payment_trans_id,
                                                                         journal_id=customer_journal_id.id,
                                                                         invoice_date=request.create_date.date(), #date.today(),
                                                                         invoice_type='out_invoice',
                                                                         partner_id=request.partner_id.id)._prepare_invoice()
                    customer_invoice_id = request.env['account.invoice'].sudo().create(customer_invoice_vals)
                    request.invoice_line_create(invoice_id=customer_invoice_id.id, name=name,
                                                        qty=1, price_unit=customer_actual_amount + over_limit_fees) # Tamayoz TODO: Create a new invoice line for over limit fees
                    customer_invoice_id.action_invoice_open()
                    customer_invoice_ids += (tuple(customer_invoice_id.ids),)
                    # Tamayoz TODO: Auto Reconcile customer invoice with prepaid wallet recharge payments and previous cashback credit note
                    """
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
                                                                         line.date or request.create_date.date() or fields.Date.today())
                        if float_is_zero(amount_residual_currency,
                                         precision_rounding=customer_invoice_id.currency_id.rounding):
                            continue

                        customer_invoice_id.assign_outstanding_credit(line.id)
                        if customer_invoice_id.state == 'paid':
                            break
                    """
                    request.env.cr.commit()
                else:
                    customer_invoice_id = request_customer_invoices[0]
                    customer_invoice_ids += (tuple(customer_invoice_id.ids),)

                request_customer_credit_notes = request.customer_invoice_ids.filtered(lambda x: x.type == 'out_refund')
                if len(request_customer_credit_notes) == 0:
                    # 2- Create Customer Credit Note with commision amount for only customers have commission
                    _logger.info(">>>>>>>>>>>>>>>>>>> Start Creating Customer Credit Note with commision amount for only customers have commission")
                    """
                    customer_user = request.env['res.users'].sudo().search([('partner_id', '=', request.partner_id.id)], limit=1)
                    """
                    customer_user = customer_users.filtered(lambda user: user.partner_id.id == request.partner_id.id)
                    if customer_user and customer_user.commission and customer_cashback_amount > 0:
                        credit_note = request.env['account.invoice.refund'].with_context(
                            active_ids=customer_invoice_id.ids).sudo().create({
                            'filter_refund': 'refund',
                            'description': provider_payment_trans_id,
                            'date': request.create_date.date(), #customer_invoice_id.date_invoice,
                        })
                        result = credit_note.invoice_refund()
                        credit_note_id = result.get('domain')[1][2]
                        credit_note = request.env['account.invoice'].sudo().browse(credit_note_id)
                        credit_note.update({'request_id': request.id})
                        credit_note_line = credit_note.invoice_line_ids[0]
                        credit_note_line.update({'price_unit': customer_cashback_amount, 'request_id': request.id})
                        credit_note.refresh()
                        """  Tamayoz: Override auto_create_invoices_for_pay_request in smartpay_operations add-on and validate the customer credit note 
                        without waiting the vendor refund reconciliation.. """
                        credit_note.action_invoice_open()
                        customer_invoice_ids += (tuple(credit_note.ids),)
                        request.env.cr.commit()
                else:
                    credit_note = request_customer_credit_notes[0]
                    customer_invoice_ids += (tuple(credit_note.ids),)

                request.update({'customer_invoice_ids': customer_invoice_ids})
                request.env.cr.commit()
        except Exception as e:
            _logger.error("%s", e)
            if raise_error:
                raise e
            return "internal error"

    '''
    def auto_create_invoices_for_pay_request(self, date_from=None, date_to=None):
        return "internal error"
    '''

    def _auto_create_aggregated_invoices_for_pay_request(self, year, month, day=None, raise_error=None):
        try:
            request_pool = self.env['smartpay_operations.request']
            # request_hours = int(self.env['ir.config_parameter'].sudo().get_param("smartpay_operations.request_hours"))

            invoice_date = start_date = datetime(year=year, month=month, day=day if day else 1).date()
            start_date = datetime(year=year, month=month, day=day if day else 1) - timedelta(hours=2)
            end_date = datetime(year=year, month=month, day=day if day else calendar.monthrange(year, month)[1]) + timedelta(hours=21, minutes=59, seconds=59)

            domain = [('stage_id','=',self.env.ref('smartpay_operations.stage_done').id),
                      ('request_type', '=', 'pay_service_bill'),
                      ('provider_response', 'not ilike', 'error_message'),
                      ('provider_response', 'not ilike', 'provider_cancel_response'),
                      '|',
                      ('description', '=', False),
                      '&',
                      ('description', 'not ilike', 'Cancel Service Payment request'),
                      ('description', 'not ilike', 'Initiation Service Payment request'), # After the Pay Service Request submit successfuly with provider, Error is occur: ==>
                      ## ('create_date','<=',str(datetime.now() - timedelta(hours=request_hours))),
                      # '|',
                      # ('aggregated_customer_invoice_ids_count', '<', 2),
                      # ('aggregated_provider_invoice_ids_count', '<', 2)
            ]
            domain += [('create_date', '>=', str(start_date))] # '%s-%s-%s' % (year, '0%s' %month if month <= 10 else month, ('0%s' %day if day <= 10 else day) if day else '01')
            domain += [('create_date', '<=', str(end_date))] # '%s-%s-%s' % (year, '0%s' %month if month <= 10 else month, ('0%s' %day if day <= 10 else day) if day else calendar.monthrange(year, month)[1])
            domain += [
                # '|',
                ('aggregated_customer_invoice_ids_count', '=', 0),
                ('aggregated_provider_invoice_ids_count', '=', 0),
                ('customer_invoice_ids_count', '=', 0),
                ('provider_invoice_ids_count', '=', 0)
            ]
            requests = request_pool.search(domain, order='id'
                                          )#.filtered(lambda x: len(x.aggregated_customer_invoice_ids) < 2 or len(x.aggregated_provider_invoice_ids) < 2)

            # Prepare the required objects before requests loop for enhancement
            companies = self.env['res.company'].sudo().search([])
            providers = self.env['payment.acquirer'].sudo().search([("id", "in", requests.mapped('provider_id').ids)])
            provider_infos = self.env['product.supplierinfo'].sudo().search([])
            provider_commissions = self.env['product.supplierinfo.commission'].sudo().search([])
            provider_journal_ids = self.env['account.journal'].sudo().search([('type', '=', 'purchase')])
            provider_wallets = self.env['account.journal'].sudo().search([('type', '=', 'cash'),
                                                                          ('provider_id', '!=', False)])
            customer_journal_ids = self.env['account.journal'].sudo().search([('type', '=', 'sale')])
            # customers = self.env['res.partner'].sudo().search([("id", "in", requests.mapped('pertner_id').ids)])
            customer_users = self.env['res.users'].sudo().search([])
            over_limit_fees_wallet_transaction_ids = self.env['website.wallet.transaction'].sudo().search(
                [('reference', '=', 'request'),
                 ('status', '=', 'done'),
                 ('label', 'like', 'over limit fees for') # Tamayoz: TODO: depend on wallet transaction type instead of label
                ]
            )

            _logger.info("################### Start Create auto aggregated invoice for [%s] providers from (%s) to (%s)" % (len(providers), start_date, end_date))
            ## _logger.info("################### Start Create auto aggregated invoices for [%s] customers from (%s) to (%s)" % (len(customers), start_date, end_date))
            _logger.info("################### Start Create auto aggregated invoices for [%s] requests from (%s) to (%s)" % (len(requests), start_date, end_date))
            for company in companies.filtered(lambda c: c.id == 1):
                provider_journal_id = provider_journal_ids.filtered(lambda journal: journal.company_id.id == company.id)[0]
                customer_journal_id = customer_journal_ids.filtered(lambda journal: journal.company_id.id == company.id)[0]
                for provider in providers:
                    provider_requests = requests.filtered(lambda r: r.provider_id.id == provider.id and
                                                          r.company_id.id == company.id)

                    # _logger.info("################### Create auto aggregated invoice for provider [%s]" % (provider.name))
                    # Create Vendor (Provider) Invoices
                    provider_invoice_ids = ()
                    # 1- Create Vendor bill
                    # _logger.info(">>>>>>>>>>>>>>>>>>> Start Creating Vendor bill")
                    provider_invoice_vals = provider_requests._prepare_aggregated_invoice(name='%s: %s Bill for Services' % (provider.name, 'Daily' if day else 'Monthly'),
                                                                              origin=','.join(provider_requests.mapped('name')), # [:2000]
                                                                              journal_id=provider_journal_id.id,
                                                                              currency_id=company.currency_id.id,
                                                                              company_id=company.id,
                                                                              invoice_date=invoice_date, # datetime.strptime('%s-%s-%s' % (year, '0%s' % month if month <= 10 else month, ('0%s' %day if day <= 10 else day) if day else calendar.monthrange(year, month)[1]), '%Y-%m-%d').date(),
                                                                              invoice_type='in_invoice',
                                                                              partner_id=provider.related_partner.id)
                    provider_invoice_id = self.env['account.invoice'].sudo().create(provider_invoice_vals)

                    # 2- Create Vendor Refund with commission amount
                    # _logger.info(">>>>>>>>>>>>>>>>>>> Start Creating Vendor Refund with commission amount")
                    provider_refund_vals = provider_requests._prepare_aggregated_invoice(name='%s: %s Cashback for Services' % (provider.name, 'Daily' if day else 'Monthly'),
                                                                                      origin=provider_invoice_id.number,
                                                                                      journal_id=provider_journal_id.id,
                                                                                      currency_id=company.currency_id.id,
                                                                                      company_id=company.id,
                                                                                      invoice_date=invoice_date, # datetime.strptime('%s-%s-%s' % (year, '0%s' % month if month <= 10 else month, ('0%s' % day if day <= 10 else day) if day else calendar.monthrange(year, month)[1]), '%Y-%m-%d').date(),
                                                                                      invoice_type='in_refund',
                                                                                      partner_id=provider.related_partner.id)
                    refund = self.env['account.invoice'].sudo().create(provider_refund_vals)

                    # _logger.info(">>>>>>>>>>>>>>>>>>> Preparing data for provider [%s]" % (provider.name))
                    provider_payment_trans_ids = []
                    provider_payment_trans_ids_per_customer = {}
                    total_provider_actual_amount = 0.0
                    # merchant_cashback_amount = 0.0
                    # merchant_cashback_amount_per_request = {}
                    # customer_actual_amount_per_request = {}
                    # customer_actual_amount_per_provider = {}
                    # customer_cashback_amounts_per_request = {}

                    previous_partner_id = False
                    customer_invoice_id = False
                    credit_note = False
                    customer_user = False
                    provider_requests = provider_requests.sorted(lambda r: (r.partner_id.id, r.create_date))
                    for request in provider_requests:
                        provider_response = request.provider_response
                        if "provider_correlation_response" in provider_response:
                            provider_response = json.dumps(
                                json.loads(
                                    provider_response.replace("\'{", "{").replace("}\'", "}").replace("\'", "\""))[
                                    'provider_correlation_response'])
                        provider_response_json = json.loads(provider_response)
                        # Get Provider Payment Trans ID
                        if provider.provider == "fawry":
                            for payment in provider_response_json['PmtTransId']:
                                if payment['PmtIdType'] == 'FCRN':
                                    provider_payment_trans_ids.append(payment['PmtId'])
                                    customer_provider_payment_trans_ids = provider_payment_trans_ids_per_customer.get(request.partner_id.id)
                                    provider_payment_trans_ids_per_customer.update({
                                        request.partner_id.id: customer_provider_payment_trans_ids.append(
                                            payment['PmtId']
                                        ) if customer_provider_payment_trans_ids else [payment['PmtId']]
                                    })
                                    break
                        if provider.provider == "khales":
                            provider_payment_trans_ids.append(provider_response_json['PmtRecAdviceStatus']['PmtTransId']['PmtId'])
                            customer_provider_payment_trans_ids = provider_payment_trans_ids_per_customer.get(request.partner_id.id)
                            provider_payment_trans_ids_per_customer.update({
                                request.partner_id.id: customer_provider_payment_trans_ids.append(
                                    provider_response_json['PmtRecAdviceStatus']['PmtTransId']['PmtId']
                                ) if customer_provider_payment_trans_ids else
                                [provider_response_json['PmtRecAdviceStatus']['PmtTransId']['PmtId']]
                            })

                        provider_actual_amount = request.trans_amount + request.provider_fees_amount
                        total_provider_actual_amount += provider_actual_amount

                        customer_actual_amount = provider_actual_amount + request.extra_fees_amount
                        '''
                        customer_actual_amounts = customer_actual_amount_per_providerCashback.get(request.partner_id.id)
                        customer_actual_amount_per_provider.update({
                            request.partner_id.id: customer_actual_amounts + customer_actual_amount
                            if customer_actual_amounts else customer_actual_amount
                        })
                        '''
                        # customer_actual_amount_per_request.update({request.id: customer_actual_amount})

                        provider_info = provider_infos.filtered(lambda pi: pi.product_tmpl_id.id ==
                                                                           request.product_id.product_tmpl_id.id and
                                                                           pi.name.id == provider.related_partner.id)
                        commissions = provider_commissions.filtered(lambda com: com.vendor.id == provider_info.name.id and
                                                                                com.vendor_product_code == provider_info.product_code)
                        for commission in commissions:
                            if commission['Amount_Range_From'] <= request.trans_amount \
                                    and commission['Amount_Range_To'] >= request.trans_amount:
                                if commission['Mer_Comm_Full_Fix_Amt'] > 0:
                                    merchant_cashback_amount = commission['Mer_Comm_Full_Fix_Amt']
                                    # merchant_cashback_amount_per_request.update({request.id: merchant_cashback_amount})
                                    customer_cashback_amount = commission['Cust_Comm_Full_Fix_Amt']
                                    # customer_cashback_amounts_per_request.update({request.id: customer_cashback_amount})
                                elif commission['Bill_Merchant_Comm_Prc'] > 0:
                                    merchant_cashback_amount = request.trans_amount * commission[
                                        'Bill_Merchant_Comm_Prc'] / 100
                                    # merchant_cashback_amount_per_request.update({request.id: merchant_cashback_amount})
                                    customer_cashback_amount = request.trans_amount * commission[
                                        'Bill_Customer_Comm_Prc'] / 100
                                    # customer_cashback_amounts_per_request.update({request.id: customer_cashback_amount})
                                break

                        # _logger.info(">>>>>>>>>>>>>>>>>>> Create Vendor bill line for request (%s)" % request.name)
                        '''
                        invoice_line = provider_invoice_id._prepare_invoice_line_from_request(request=request,
                                                                                              name='[%s] %s' % (provider_info.product_code, provider_info.product_name),
                                                                                              qty=1,
                                                                                              price_unit=provider_actual_amount)
                        new_line = request.env['account.invoice.line'].sudo().new(invoice_line)
                        new_line._set_additional_fields(provider_invoice_id)
                        provider_invoice_id.invoice_line_ids += new_line
                        '''
                        request.invoice_line_create(invoice_id=provider_invoice_id.id,
                                                    name='[%s] %s' % (provider_info.product_code, provider_info.product_name),
                                                    qty=1,
                                                    price_unit=provider_actual_amount)

                        # _logger.info(">>>>>>>>>>>>>>>>>>> Create Vendor Refund line for request (%s)" % request.name)
                        '''
                        refund_line = refund._prepare_invoice_line_from_request(request=request,
                                                                                name='[%s] %s' % (provider_info.product_code, provider_info.product_name),
                                                                                qty=1,
                                                                                price_unit=merchant_cashback_amount)
                        new_line = request.env['account.invoice.line'].sudo().new(refund_line)
                        new_line._set_additional_fields(refund)
                        refund.invoice_line_ids += new_line
                        '''
                        request.invoice_line_create(invoice_id=refund.id,
                                                    name='[%s] %s' % (
                                                    provider_info.product_code, provider_info.product_name),
                                                    qty=1,
                                                    price_unit=merchant_cashback_amount)

                        if previous_partner_id != request.partner_id:
                            if customer_invoice_id and customer_invoice_id.state == 'draft' and customer_invoice_id.invoice_line_ids:
                                # _logger.info(">>>>>>>>>>>>>>>>>>> Validate aggregated invoice for customer [%s] with provider [%s] services" % (customer_invoice_id.partner_id.name, provider.name))
                                customer_invoice_id.update({'name': '%s: %s' % (customer_invoice_id.name , ','.join(provider_payment_trans_ids_per_customer.get(customer_invoice_id.partner_id.id)) if provider_payment_trans_ids_per_customer.get(customer_invoice_id.partner_id.id) else ''), # [:2000]
                                                            'customer_request_ids': customer_requests.ids})
                                customer_invoice_id.action_invoice_open()
                                customer_invoice_ids += (tuple(customer_invoice_id.ids),)
                                # Tamayoz TODO: Auto Reconcile customer invoice with prepaid wallet recharge payments and previous cashback credit note
                                '''
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
                                                                                     line.date or request.create_date.date() or fields.Date.today())
                                    if float_is_zero(amount_residual_currency,
                                                     precision_rounding=customer_invoice_id.currency_id.rounding):
                                        continue

                                    customer_invoice_id.assign_outstanding_credit(line.id)
                                    if customer_invoice_id.state == 'paid':
                                        break
                                '''
                                # self.env.cr.commit()

                                # 2- Create Customer Credit Note with commision amount for only customers have commission
                                '''
                                # _logger.info(">>>>>>>>>>>>>>>>>>> Start Creating Customer Credit Note with commision amount for only customers have commission")
                                customer_user = customer_users.filtered(lambda user: user.partner_id.id == customer_invoice_id.partner_id.id)
                                if customer_user and customer_user.commission: #  and customer_cashback_amount > 0
                                    credit_note = self.env['account.invoice.refund'].with_context(
                                        active_ids=customer_invoice_id.ids).sudo().create({
                                        'filter_refund': 'refund',
                                        'description': ','.join(provider_payment_trans_ids_per_customer.get(customer_invoice_id.partner_id.id)) if provider_payment_trans_ids_per_customer.get(customer_invoice_id.partner_id.id) else '', # [:2000]
                                        'date': customer_invoice_id.date_invoice,
                                    })
                                    result = credit_note.invoice_refund()
                                    credit_note_id = result.get('domain')[1][2]
                                    credit_note = self.env['account.invoice'].sudo().browse(credit_note_id)
                                    # credit_note.update({'request_id': request.id})
                                    # credit_note_line = credit_note.invoice_line_ids[0]
                                    # credit_note_line.update({'price_unit': customer_cashback_amount, 'request_id': request.id})
                                    for credit_note_line in credit_note.invoice_line_ids:
                                        credit_note_line.update({'price_unit': customer_cashback_amounts_per_request.get(
                                            credit_note_line.request_id.id) or 0.0})
                                    credit_note.refresh()
                                    """  Tamayoz: Override auto_create_invoices_for_pay_request in smartpay_operations add-on and validate the customer credit note 
                                    without waiting the vendor refund reconciliation.. """
                                    credit_note.action_invoice_open()
                                    customer_invoice_ids += (tuple(credit_note.ids),)
                                    # self.env.cr.commit()
                                '''

                                # customer_user = customer_users.filtered(lambda user: user.partner_id.id == customer_invoice_id.partner_id.id)
                                if credit_note and credit_note.state == 'draft' and credit_note.invoice_line_ids: # and customer_user and customer_user.commission:  # and customer_cashback_amount > 0
                                    # _logger.info(">>>>>>>>>>>>>>>>>>> Validate aggregated credit note for customer [%s] with provider [%s] services" % (credit_note.partner_id.name, provider.name))
                                    credit_note.update({'name': '%s: %s' % (credit_note.name, ','.join(provider_payment_trans_ids_per_customer.get(credit_note.partner_id.id)) if provider_payment_trans_ids_per_customer.get(credit_note.partner_id.id) else ''), # [:2000]
                                                        'customer_request_ids': customer_requests.ids})
                                    credit_note.action_invoice_open()
                                    customer_invoice_ids += (tuple(credit_note.ids),)
                                # elif not credit_note.invoice_line_ids:
                                    # credit_note.unlink()

                                # customer_requests = provider_requests.filtered(lambda r: r.partner_id.id == customer_invoice_id.partner_id.id)
                                customer_requests.update({'aggregated_customer_invoice_ids': customer_invoice_ids})
                                # self.env.cr.commit()

                            # _logger.info("################### Create auto aggregated invoice for customer [%s] with provider [%s] services" % (request.partner_id.name, provider.name))
                            # name = '%s: %s Invoice for Services' % (provider.name, 'Daily' if day else 'Monthly')
                            # Create Customer Invoices
                            customer_invoice_ids = ()
                            # 1- Create Customer Invoice
                            # _logger.info(">>>>>>>>>>>>>>>>>>> Start Creating Customer Invoice")
                            # Calculate Over limit fees
                            request_over_limit_fees_wallet_transaction_ids = over_limit_fees_wallet_transaction_ids.filtered(
                                lambda trans: trans.request_id.id == request.id)
                            over_limit_fees = 0
                            for request_over_limit_fees_wallet_transaction_id in request_over_limit_fees_wallet_transaction_ids:
                                over_limit_fees += float(request_over_limit_fees_wallet_transaction_id.amount)
                            over_limit_fees = round(over_limit_fees, 2)

                            customer_requests = provider_requests.filtered(lambda r: r.partner_id.id == request.partner_id.id)
                            customer_invoice_vals = provider_requests._prepare_aggregated_invoice(
                                name='%s Invoice for %s Services' % ('Daily' if day else 'Monthly', provider.name), # provider_payment_trans_id
                                origin=','.join(customer_requests.mapped('name')), # [:2000]
                                journal_id=customer_journal_id.id,
                                currency_id=company.currency_id.id,
                                company_id=company.id,
                                invoice_date=invoice_date, # datetime.strptime('%s-%s-%s' % (year, '0%s' % month if month <= 10 else month, ('0%s' %day if day <= 10 else day) if day else calendar.monthrange(year, month)[1]), '%Y-%m-%d').date(),
                                invoice_type='out_invoice',
                                partner_id=request.partner_id.id)
                            customer_invoice_id = request.env['account.invoice'].sudo().create(customer_invoice_vals)

                            # _logger.info(">>>>>>>>>>>>>>>>>>> Create Customer Invoice line for request (%s)" % request.name)
                            request.invoice_line_create(invoice_id=customer_invoice_id.id,
                                                        name='[%s] %s' % (provider_info.product_code, provider_info.product_name),
                                                        qty=1,
                                                        price_unit=customer_actual_amount + over_limit_fees)  # Tamayoz TODO: Create a new invoice line for over limit fees

                            # 2- Create Customer Credit Note with commision amount for only customers have commission
                            # _logger.info(">>>>>>>>>>>>>>>>>>> Start Creating Customer Credit Note with commision amount for only customers have commission")
                            customer_user = customer_users.filtered(lambda user: user.partner_id.id == customer_invoice_id.partner_id.id)
                            if customer_user and customer_user.commission:  # and customer_cashback_amount > 0
                                customer_credit_note_vals = provider_requests._prepare_aggregated_invoice(
                                    name='%s Cashback for %s Services' % ('Daily' if day else 'Monthly', provider.name),  # provider_payment_trans_id
                                    origin=customer_invoice_id.number,
                                    journal_id=customer_journal_id.id,
                                    currency_id=company.currency_id.id,
                                    company_id=company.id,
                                    invoice_date=invoice_date, # datetime.strptime('%s-%s-%s' % (year, '0%s' % month if month <= 10 else month, ('0%s' % day if day <= 10 else day) if day else calendar.monthrange(year, month)[1]), '%Y-%m-%d').date(),
                                    invoice_type='out_refund',
                                    partner_id=request.partner_id.id)
                                credit_note = request.env['account.invoice'].sudo().create(customer_credit_note_vals)

                                if customer_cashback_amount > 0:
                                    # _logger.info(">>>>>>>>>>>>>>>>>>> Create Customer Credit Note line for request (%s)" % request.name)
                                    request.invoice_line_create(invoice_id=credit_note.id,
                                                                name='[%s] %s' % (provider_info.product_code, provider_info.product_name),
                                                                qty=1,
                                                                price_unit=customer_cashback_amount)
                        else:
                            if customer_invoice_id and customer_invoice_id.state == 'draft':
                                # _logger.info(">>>>>>>>>>>>>>>>>>> Create Customer Invoice line for request (%s)" % request.name)
                                request.invoice_line_create(invoice_id=customer_invoice_id.id,
                                                            name='[%s] %s' % (provider_info.product_code, provider_info.product_name),
                                                            qty=1,
                                                            price_unit=customer_actual_amount + over_limit_fees)  # Tamayoz TODO: Create a new invoice line for over limit fees

                            if credit_note and credit_note.state == 'draft' and customer_user and customer_user.commission and customer_cashback_amount > 0:
                                # _logger.info(">>>>>>>>>>>>>>>>>>> Create Customer Credit Note line for request (%s)" % request.name)
                                request.invoice_line_create(invoice_id=credit_note.id,
                                                            name='[%s] %s' % (provider_info.product_code, provider_info.product_name),
                                                            qty=1,
                                                            price_unit=customer_cashback_amount)

                        previous_partner_id = request.partner_id

                   # Validate invoice and credit note for last provider request
                    if customer_invoice_id and customer_invoice_id.state == 'draft' and customer_invoice_id.invoice_line_ids:
                        # _logger.info(">>>>>>>>>>>>>>>>>>> Validate aggregated invoice for customer [%s] with provider [%s] services" % (customer_invoice_id.partner_id.name, provider.name))
                        customer_invoice_id.update({'name': '%s: %s' % (customer_invoice_id.name, ','.join(
                            provider_payment_trans_ids_per_customer.get(
                                customer_invoice_id.partner_id.id)) if provider_payment_trans_ids_per_customer.get(
                            customer_invoice_id.partner_id.id) else ''),  # [:2000]
                                                    'customer_request_ids': customer_requests.ids})
                        customer_invoice_id.action_invoice_open()
                        customer_invoice_ids += (tuple(customer_invoice_id.ids),)
                        # Tamayoz TODO: Auto Reconcile customer invoice with prepaid wallet recharge payments and previous cashback credit note
                        '''
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
                                                                             line.date or request.create_date.date() or fields.Date.today())
                            if float_is_zero(amount_residual_currency,
                                             precision_rounding=customer_invoice_id.currency_id.rounding):
                                continue

                            customer_invoice_id.assign_outstanding_credit(line.id)
                            if customer_invoice_id.state == 'paid':
                                break
                        '''
                        # self.env.cr.commit()

                        # customer_user = customer_users.filtered(lambda user: user.partner_id.id == customer_invoice_id.partner_id.id)
                        if credit_note and credit_note.state == 'draft' and credit_note.invoice_line_ids: # and customer_user and customer_user.commission:  # and customer_cashback_amount > 0
                            # _logger.info(">>>>>>>>>>>>>>>>>>> Validate aggregated credit note for customer [%s] with provider [%s] services" % (credit_note.partner_id.name, provider.name))
                            credit_note.update({'name': '%s: %s' % (credit_note.name, ','.join(
                                provider_payment_trans_ids_per_customer.get(
                                    credit_note.partner_id.id)) if provider_payment_trans_ids_per_customer.get(
                                credit_note.partner_id.id) else ''),  # [:2000]
                                                'customer_request_ids': customer_requests.ids})
                            credit_note.action_invoice_open()
                            customer_invoice_ids += (tuple(credit_note.ids),)
                        # elif not credit_note.invoice_line_ids:
                            # credit_note.unlink()

                        # customer_requests = provider_requests.filtered(lambda r: r.partner_id.id == customer_invoice_id.partner_id.id)
                        customer_requests.update({'aggregated_customer_invoice_ids': customer_invoice_ids})
                        # self.env.cr.commit()

                    # _logger.info(">>>>>>>>>>>>>>>>>>> Validate aggregated vendor bill for provider [%s] services" % (provider.name))
                    provider_invoice_id.action_invoice_open()
                    provider_invoice_id.update({'reference': ','.join(provider_payment_trans_ids), # Tamayoz TODO: [:2000] FIXME: index row size 3424 exceeds maximum 2712 for index "account_move_line_partner_id_ref_idx"
                                                'provider_request_ids': provider_requests.ids})
                    provider_invoice_ids += (tuple(provider_invoice_id.ids),)
                    '''
                    provider_invoice_id.pay_and_reconcile(
                        provider_wallets.filtered(lambda wallet: wallet.company_id.id == company.id and
                                                   wallet.provider_id.id == provider.id)[0], total_provider_actual_amount
                    )
                    '''
                    # self.env.cr.commit()

                    # 2- Create Vendor Refund with commission amount
                    '''
                    # _logger.info(">>>>>>>>>>>>>>>>>>> Start Creating Vendor Refund with commission amount")
                    refund = self.env['account.invoice.refund'].with_context(
                        active_ids=provider_invoice_id.ids).sudo().create({
                        'filter_refund': 'refund',
                        'description': '%s: %s Cashback for Services' % (provider.name, 'Daily' if day else 'Monthly'),
                        'date': provider_invoice_id.date_invoice,
                    })
                    result = refund.invoice_refund()
                    refund_id = result.get('domain')[1][2]
                    refund = self.env['account.invoice'].sudo().browse(refund_id)
                    refund.update({'reference': ','.join(provider_payment_trans_ids), # [:2000]
                                   # 'request_id': request.id
                                   })
                    # refund_line = refund.invoice_line_ids[0]
                    # refund_line.update({'price_unit': merchant_cashback_amount, 'request_id': request.id})
                    for refund_line in refund.invoice_line_ids:
                        refund_line.update({'price_unit': merchant_cashback_amount_per_request.get(refund_line.request_id.id) or 0.0})
                    refund.refresh()
                    refund.action_invoice_open()
                    provider_invoice_ids += (tuple(refund.ids),)
                    # self.env.cr.commit()
                    '''
                    # _logger.info(">>>>>>>>>>>>>>>>>>> Validate aggregated vendor refund for provider [%s] services" % (provider.name))
                    refund.action_invoice_open()
                    refund.update({'reference': ','.join(provider_payment_trans_ids), # Tamayoz TODO: [:2000] FIXME: index row size 3424 exceeds maximum 2712 for index "account_move_line_partner_id_ref_idx"
                                   'provider_request_ids': provider_requests.ids})
                    provider_invoice_ids += (tuple(refund.ids),)
                    # self.env.cr.commit()

                    provider_requests.update({'aggregated_provider_invoice_ids': provider_invoice_ids})
                    # self.env.cr.commit()
            _logger.info("################### Start Create auto aggregated invoices for [%s] requests from (%s) to (%s)" % (len(requests), start_date, end_date))
            ## _logger.info("################### Start Create auto aggregated invoices for [%s] customers from (%s) to (%s)" % (len(customers), start_date, end_date))
            _logger.info("################### Start Create auto aggregated invoice for [%s] providers from (%s) to (%s)" % (len(providers), start_date, end_date))
        except Exception as e:
            _logger.error("%s", e)
            if raise_error:
                raise e
            return "internal error"

    # @api.multi
    def _prepare_aggregated_invoice(self, name, origin, journal_id, currency_id, company_id,
                                 invoice_date, invoice_type, partner_id, provider_payment_trans_id=None):
        """
        Prepare the dict of values to create the new invoice for a helpdesk requests. This method may be
        overridden to implement custom invoice generation (making sure to call super() to establish
        a clean extension chain).
        """
        vinvoice = self.env['account.invoice'].new({'partner_id': partner_id, 'type': invoice_type})
        # Get partner extra fields
        vinvoice._onchange_partner_id()
        invoice_vals = vinvoice._convert_to_write(vinvoice._cache)
        invoice_vals.update({
            'name': name,
            'origin': origin,
            'journal_id': journal_id,
            'currency_id': currency_id,
            'company_id': company_id,
            # 'user_id': user_id,
            'date_invoice': invoice_date,
            # 'comment': description,
            # 'request_id': request.id,
        })
        if invoice_type in ('in_invoice', 'in_refund') and provider_payment_trans_id:
            invoice_vals.update({'reference': provider_payment_trans_id})
        return invoice_vals