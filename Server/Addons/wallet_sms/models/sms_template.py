# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

from odoo import models, fields, api, _

class SmsTemplate(models.Model):
    _inherit = 'sms.template'

    condition = fields.Selection(selection_add=[('wallet_recharge', 'Wallet Recharge'),
                                                ('wallet_bouns', 'Wallet Bonus'),
                                                ('wallet_pay_service', 'Wallet Pay Service Bill'),
                                                ('wallet_cancel_service_payment', 'Wallet Cancel Service Payment'),
                                                ('wallet_correlation_service_payment', 'Wallet Correlation Service Payment'),
                                                ('wallet_pay_invoice', 'Wallet Pay Invoice'),
                                                ('wallet_transfer_balance', 'Wallet Transfer Balance'),
                                                ('wallet_customer_cashback', 'Wallet Customer Cashback')
                                                ])

    @api.depends('condition')
    def onchange_condition(self):
        super(SmsTemplate, self).onchange_condition()
        if self.condition:
            if self.condition in ('wallet_recharge','wallet_bouns','wallet_pay_service','wallet_cancel_service_payment',
                                  'wallet_correlation_service_payment', 'wallet_pay_invoice','wallet_transfer_balance',
                                  'wallet_customer_cashback'):
                model_id = self.env['ir.model'].search(
                    [('model', '=', 'website.wallet.transaction')])
                self.model_id = model_id.id if model_id else False
