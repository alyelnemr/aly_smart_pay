# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

from odoo import api, fields, models, _


class AccountInvoice(models.Model):
    _inherit = 'account.invoice'

    def _prepare_payment_vals(self, pay_journal, pay_amount=None, date=None, writeoff_acc=None, communication=None):
        payment_vals = super(AccountInvoice, self)._prepare_payment_vals(pay_journal, pay_amount=pay_amount, date=date,
                                                                         writeoff_acc=writeoff_acc, communication=communication)
        if self.type in ('in_invoice', 'in_refund') and self.request_id:
            invoice_line = self.invoice_line_ids[0]
            payment_vals.update({'communication': '%s (%s)' % (payment_vals.get('communication'), invoice_line.name)})
        return payment_vals

    @api.multi
    def action_invoice_paid(self):
        """ When a provider cashback refund is reconciled by importing a provider cashback statement.
        customer cashback credit note must be validated then increase customer wallet balance
        with the net amount in provider cashback statement. """
        res = super(AccountInvoice, self).action_invoice_paid()
        if self.type == 'in_refund' and self.request_id:
            # Validate a Drafted Customer Cashback Credit Note if exists with the net amount of provider payment
            customer_credit_notes = self.env['account.invoice'].search([('type', '=', 'out_refund'),
                                                                        ('name', '=', self.reference), # Provider Payment ID
                                                                        ('request_id', '=', self.request_id.id),
                                                                        ('state', '=', 'draft')])
            if len(customer_credit_notes) == 1:
                customer_credit_note = customer_credit_notes[0]
                validate_credit_note = True
                vendor_refund_payments_amount = 0
                for payment_move_line in self.payment_move_line_ids:
                    payment = payment_move_line.payment_id
                    company_currency = payment.journal_id.company_id.currency_id or self.env.user.company_id.currency_id
                    journal_currency = payment.journal_id.currency_id or company_currency
                    payment_currency = payment.currency_id or company_currency
                    if payment_currency == journal_currency:
                        vendor_refund_payments_amount += payment.amount
                    else:
                        # Tamayoz TODO: Check if manual_currency_exchange_rate module is installed
                        # Note : this makes self.date the value date, which IRL probably is the date of the reception by the bank
                        vendor_refund_payments_amount += payment_currency._convert(payment.amount, journal_currency,
                                                            self.journal_id.company_id,
                                                            self.date or fields.Date.today())
                vendor_refund_difference = (self.amount_total_signed * -1) - vendor_refund_payments_amount
                customer_credit_note_line = customer_credit_note.invoice_line_ids[0]
                customer_credit_note_amount = customer_credit_note_line.price_unit
                if vendor_refund_difference > 0: # and (customer_credit_note.amount_total_signed * -1) > vendor_refund_payments_amount:
                    customer_credit_note_amount -= vendor_refund_difference
                    if customer_credit_note_amount < 0:
                        customer_credit_note_amount = 0
                    customer_credit_note_line.update({'price_unit': customer_credit_note_amount})
                    customer_credit_note.refresh()
                    if customer_credit_note_amount == 0:
                        customer_credit_note.action_invoice_cancel()
                        validate_credit_note = False
                if validate_credit_note:
                    customer_credit_note.action_invoice_open()

                label = _('Customer Cashback for %s service') % (self.request_id.product_id.name)
                '''
                # Increase the customer wallet balance with the net amount of provider payment
                wallet_transaction_sudo = self.env['website.wallet.transaction'].sudo()
                customer_wallet_balance = customer_credit_note.partner_id.wallet_balance
                customer_wallet_create = wallet_transaction_sudo.create(
                    {'wallet_type': 'credit', 'partner_id': customer_credit_note.partner_id.id, 'request_id': self.request_id.id,
                     'reference': 'request', 'label': label,
                     'amount': customer_credit_note_amount, 'currency_id': self.currency_id.id, 
                     'wallet_balance_before': customer_wallet_balance,
                     'wallet_balance_after': customer_wallet_balance + customer_credit_note_amount,
                     'status': 'done'})
                self.env.cr.commit()

                customer_credit_note.partner_id.update({'wallet_balance': customer_credit_note.partner_id.wallet_balance + customer_credit_note_amount})
                self.env.cr.commit()

                # Notify Mobile User
                irc_param = self.env['ir.config_parameter'].sudo()
                wallet_customer_cashback_notify_mode = irc_param.get_param("smartpay_operations.wallet_customer_cashback_notify_mode")
                if wallet_customer_cashback_notify_mode == 'inbox':
                    self.env['mail.thread'].sudo().message_notify(subject=label,
                                                                  body=_('<p>%s %s successfully added to your wallet.</p>') % (
                                                                      customer_credit_note_amount, _(customer_credit_note.currency_id.name)),
                                                                  partner_ids=[(4, customer_credit_note.partner_id.id)],
                                                                )
                elif wallet_customer_cashback_notify_mode == 'email':
                    customer_wallet_create.wallet_transaction_email_send()
                elif wallet_customer_cashback_notify_mode == 'sms' and customer_credit_note.partner_id.mobile:
                    customer_wallet_create.sms_send_wallet_transaction(wallet_customer_cashback_notify_mode,
                                                                      'wallet_customer_cashback',
                                                                      customer_credit_note.partner_id.mobile,
                                                                      customer_credit_note.partner_id.name, label,
                                                                      '%s %s' % (customer_credit_note_amount,
                                                                                 _(customer_credit_note.currency_id.name)),
                                                                      customer_credit_note.partner_id.country_id.phone_code or '2')
                '''
                wallet_transaction_line_sudo = self.env['website.wallet.transaction.line'].sudo()
                customer_wallet_create = wallet_transaction_line_sudo.create(
                    {'wallet_type': 'credit', 'partner_id': customer_credit_note.partner_id.id,
                     'request_id': self.request_id.id, 'reference': 'request', 'label': label,
                     'statement_line_id': self.payment_move_line_ids[0].statement_line_id.id,
                     'statement_id': self.payment_move_line_ids[0].statement_id.id,
                     'amount': customer_credit_note_amount, 'currency_id': self.currency_id.id, 'status': 'done'})
                self.env.cr.commit()
        return res

    @api.multi
    def action_invoice_re_open(self):
        res = super(AccountInvoice, self).action_invoice_re_open()
        if self.type == 'in_refund' and self.request_id:
            # Cancel a Validated Customer Cashback Credit Note if exists then set to draft
            customer_credit_notes = self.env['account.invoice'].search([('type', '=', 'out_refund'),
                                                                        ('name', '=', self.reference), # Provider Payment ID
                                                                        ('request_id', '=', self.request_id.id),
                                                                        ('state', 'in', ('open','in_payment','paid'))])
            if len(customer_credit_notes) == 1:
                customer_credit_note = customer_credit_notes[0]
                if customer_credit_note.state in ('in_payment', 'paid'):
                    customer_credit_note.action_invoice_re_open()
                customer_credit_note.action_invoice_cancel()
                customer_credit_note.action_invoice_draft()

                label = _('Reverse Customer Cashback for %s service') % (self.request_id.product_id.name)
                '''
                # Deduct from the customer wallet balance the total amount of customer credit note (Reverse Cashback transaction)
                wallet_transaction_sudo = self.env['website.wallet.transaction'].sudo()
                customer_wallet_balance = customer_credit_note.partner_id.wallet_balance
                customer_wallet_create = wallet_transaction_sudo.create(
                    {'wallet_type': 'debit', 'partner_id': customer_credit_note.partner_id.id, 'request_id': self.request_id.id,
                     'reference': 'request', 'label': label,
                     'amount': (customer_credit_note.amount_total_signed * -1), 'currency_id': self.currency_id.id, 
                     'wallet_balance_before': customer_wallet_balance,
                     'wallet_balance_after': customer_wallet_balance - (customer_credit_note.amount_total_signed * -1),
                     'status': 'done'})
                self.env.cr.commit()

                customer_credit_note.partner_id.update({'wallet_balance': customer_credit_note.partner_id.wallet_balance - (customer_credit_note.amount_total_signed * -1)})
                self.env.cr.commit()

                # Notify Mobile User
                irc_param = self.env['ir.config_parameter'].sudo()
                wallet_customer_cashback_notify_mode = irc_param.get_param(
                    "smartpay_operations.wallet_customer_cashback_notify_mode")
                if wallet_customer_cashback_notify_mode == 'inbox':
                    self.env['mail.thread'].sudo().message_notify(subject=label,
                                                                  body=_('<p>%s %s successfully deducted from your wallet.</p>') % (
                                                                      (customer_credit_note.amount_total_signed * -1),
                                                                      _(customer_credit_note.currency_id.name)),
                                                                  partner_ids=[(4, customer_credit_note.partner_id.id)],
                                                                  )
                elif wallet_customer_cashback_notify_mode == 'email':
                    customer_wallet_create.wallet_transaction_email_send()
                elif wallet_customer_cashback_notify_mode == 'sms' and customer_credit_note.partner_id.mobile:
                    customer_wallet_create.sms_send_wallet_transaction(wallet_customer_cashback_notify_mode,
                                                                       'wallet_customer_cashback',
                                                                       customer_credit_note.partner_id.mobile,
                                                                       customer_credit_note.partner_id.name, label,
                                                                       '%s %s' % ((customer_credit_note.amount_total_signed * -1),
                                                                                  _(customer_credit_note.currency_id.name)),
                                                                       customer_credit_note.partner_id.country_id.phone_code or '2')
                '''
                wallet_transaction_line_sudo = self.env['website.wallet.transaction.line'].sudo()
                customer_wallet_previous_credit = wallet_transaction_line_sudo.search([('wallet_type', '=', 'credit'),
                                                                                       ('partner_id', '=', customer_credit_note.partner_id.id),
                                                                                       ('request_id', '=', self.request_id.id),
                                                                                       ('reference', '=', 'request'),
                                                                                       ('status', '=', 'done')], limit=1)
                customer_wallet_create = wallet_transaction_line_sudo.create(
                    {'wallet_type': 'debit', 'partner_id': customer_credit_note.partner_id.id,
                     'request_id': self.request_id.id, 'reference': 'request', 'label': label,
                     # Tamayoz: SET statement_id and statement_line_id from last credit website.wallet.transaction.line for the same request
                     'statement_line_id': customer_wallet_previous_credit.statement_line_id.id,
                     'statement_id': customer_wallet_previous_credit.statement_id.id,
                     'amount': (customer_credit_note.amount_total_signed * -1), 'currency_id': self.currency_id.id,
                     'status': 'done'})
                self.env.cr.commit()
        return res