# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

from odoo import api, fields, models, _


class AccountBankStatement(models.Model):
    _inherit = 'account.bank.statement'

    @api.multi
    def button_confirm_bank(self):
        """ When a bank statement used for provider wallet reconciliation is validated.
            Create an aggregated cashback wallet transaction per customer then increase customer wallet balance
            with the sum of amount in cashback wallet transaction lines. """
        res = super(AccountBankStatement, self).button_confirm_bank()
        for statement in self:
            if statement.journal_type == 'cash' and statement.journal_id.provider_id:
                statement.ensure_one()
                sql_distinct_partner_id = """
                            SELECT
                                distinct(wwtl.partner_id)
                            FROM
                                website_wallet_transaction_line wwtl
                            WHERE
                                wwtl.statement_id = %s and wwtl.wallet_transaction_id is null
                        """
                statement.env.cr.execute(sql_distinct_partner_id, (statement.id,))
                rows = statement.env.cr.fetchall()
                partner_ids = statement.env['res.partner'].sudo().search([('id', 'in', list(set([row[0] for row in rows])))])

                wallet_transaction_sudo = statement.env['website.wallet.transaction'].sudo()
                wallet_transaction_line_sudo = statement.env['website.wallet.transaction.line'].sudo()
                for partner_id in partner_ids:
                    wallet_type = 'credit'
                    label = _('Customer Cashback for [%s] statement') % (statement.name)
                    cashback_amount = 0.00
                    customer_wallet_create = wallet_transaction_sudo.create(
                        {'wallet_type': wallet_type, 'partner_id': partner_id.id,
                         'statement_id': statement.id, 'reference': 'cashback', 'label': label,
                         'amount': cashback_amount, 'currency_id': statement.journal_id.currency_id.id,
                         'status': 'draft'})

                    wallet_transaction_line_ids = wallet_transaction_line_sudo.search([('partner_id','=',partner_id.id),
                                                                                       ('statement_id','=',statement.id),
                                                                                       ('wallet_transaction_id','=',False)])
                    for wallet_transaction_line_id in wallet_transaction_line_ids:
                        wallet_transaction_line_id.update({'wallet_transaction_id': customer_wallet_create.id})

                        if wallet_transaction_line_id.wallet_type == 'credit':
                            cashback_amount += float(wallet_transaction_line_id.amount) # Tamayoz TODO: Temp code for type custing until convert its type and amount field type in website.wallet.transaction to float
                        elif wallet_transaction_line_id.wallet_type == 'debit':
                            cashback_amount -= float(wallet_transaction_line_id.amount) # Tamayoz TODO: Temp code for type custing until convert its type and amount field type in website.wallet.transaction to float

                    cashback_amount = round(cashback_amount, 2)
                    if cashback_amount < 0:
                        wallet_type = 'debit'
                        label = _('Reverse Customer Cashback for [%s] statement') % (statement.name)
                        customer_wallet_create.update({'wallet_type': wallet_type, 'label': label})

                    customer_wallet_balance = partner_id.wallet_balance
                    customer_wallet_create.update({'amount': cashback_amount if wallet_type == 'credit' else cashback_amount * -1,
                                                   'wallet_balance_before': customer_wallet_balance,
                                                   'wallet_balance_after': customer_wallet_balance + cashback_amount, # Whether cashback_amount positive or negative
                                                   'status': 'done'})

                    # Increase or Decrease the customer wallet balance with the net amount of provider payment
                    partner_id.update({'wallet_balance': partner_id.wallet_balance + cashback_amount}) # Whether cashback_amount positive or negative
                    statement.env.cr.commit()

                    if cashback_amount != 0:
                        # Notify Mobile User
                        irc_param = statement.env['ir.config_parameter'].sudo()
                        wallet_customer_cashback_notify_mode = irc_param.get_param("smartpay_operations.wallet_customer_cashback_notify_mode")
                        if wallet_customer_cashback_notify_mode == 'inbox':
                            statement.env['mail.thread'].sudo().message_notify(subject=label,
                                                                          body=_('<p>%s %s %s.</p>') % (
                                                                              cashback_amount if wallet_type == 'credit' else cashback_amount * -1,
                                                                              _(statement.journal_id.currency_id.name),
                                                                              'successfully added to your wallet' if wallet_type == 'credit'
                                                                              else 'successfully deducted from your wallet'
                                                                          ),
                                                                          partner_ids=[
                                                                              (4, partner_id.id)],
                                                                          )
                        elif wallet_customer_cashback_notify_mode == 'email':
                            customer_wallet_create.wallet_transaction_email_send()
                        elif wallet_customer_cashback_notify_mode == 'sms' and partner_id.mobile:
                            customer_wallet_create.sms_send_wallet_transaction(wallet_customer_cashback_notify_mode,
                                                                               'wallet_customer_cashback',
                                                                               partner_id.mobile,
                                                                               partner_id.name, label,
                                                                               '%s %s' % (cashback_amount if wallet_type == 'credit' else cashback_amount * -1,
                                                                                          _(statement.journal_id.currency_id.name)),
                                                                               partner_id.country_id.phone_code or '2')