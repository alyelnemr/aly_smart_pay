# -*- coding: utf-8 -*-
from odoo import fields, models, api

class SmartpayOperationsSettings(models.TransientModel):
    _inherit = 'res.config.settings'
    # _name = 'smartpay.operations.settings'
    
    request_hours = fields.Integer(string='Hours to expire request',
                                              config_parameter='smartpay_operations.request_hours', default=24)

    inviter_bonus = fields.Float(string='Bonus Amount for Inviter',
                                    config_parameter='smartpay_operations.inviter_bonus',
                                    default=0.0)

    inviter_bonus_currency_id = fields.Many2one('res.currency',
                                                config_parameter='smartpay_operations.inviter_bonus_currency_id',
                                                default=lambda self: self.env.user.company_id.currency_id)

    invited_user_bonus = fields.Float(string='Bonus Amount for Invited User',
                                         config_parameter='smartpay_operations.invited_user_bonus',
                                         default=0.0)

    invited_user_bonus_currency_id = fields.Many2one('res.currency',
                                                     config_parameter='smartpay_operations.invited_user_bonus_currency_id',
                                                     default=lambda self: self.env.user.company_id.currency_id)

    bounce_expense_account_id = fields.Many2one('account.account',
                                                 'Bounce Expense Account',
                                                 domain="[('internal_type', '=', 'expense')]",
                                                 default=lambda self: self.env.ref('account.data_account_type_expenses'),
                                                 config_parameter='smartpay_operations.bounce_expense_account_id',
                                                 help='Bounce Expense Account used for invitation bouns')

    wallet_recharge_notify_mode = fields.Selection([('inbox', 'Odoo'),
                                                    ('email', 'Email')],
                                                   string='Wallet Recharge Notification Mode',
                                                   config_parameter='smartpay_operations.wallet_recharge_notify_mode')

    wallet_bouns_notify_mode = fields.Selection([('inbox', 'Odoo'),
                                                 ('email', 'Email')],
                                                string='Wallet Bonus Notification Mode',
                                                config_parameter='smartpay_operations.wallet_bouns_notify_mode')

    wallet_pay_service_bill_notify_mode = fields.Selection([('inbox', 'Odoo'),
                                                            ('email', 'Email')],
                                                           string='Wallet Pay Service Bill Notification Mode',
                                                           config_parameter='smartpay_operations.wallet_pay_service_bill_notify_mode')

    wallet_cancel_service_bill_notify_mode = fields.Selection([('inbox', 'Odoo'),
                                                               ('email', 'Email')],
                                                              string='Wallet Cancel Service Bill Notification Mode',
                                                              config_parameter='smartpay_operations.wallet_cancel_service_bill_notify_mode')

    wallet_correlation_service_bill_notify_mode = fields.Selection([('inbox', 'Odoo'),
                                                                    ('email', 'Email')],
                                                                    string='Wallet Correlation Service Bill Notification Mode',
                                                                    config_parameter='smartpay_operations.wallet_correlation_service_bill_notify_mode')

    wallet_pay_invoice_notify_mode = fields.Selection([('inbox', 'Odoo'),
                                                       ('email', 'Email')],
                                                      string='Wallet Pay Invoice Notification Mode',
                                                      config_parameter='smartpay_operations.wallet_pay_invoice_notify_mode')

    wallet_transfer_balance_notify_mode = fields.Selection([('inbox', 'Odoo'),
                                                            ('email', 'Email')],
                                                           string='Wallet Transfer Balance Notification Mode',
                                                           config_parameter='smartpay_operations.wallet_transfer_balance_notify_mode')

    wallet_customer_cashback_notify_mode = fields.Selection([('inbox', 'Odoo'),
                                                            ('email', 'Email')],
                                                           string='Wallet Customer Cashback Notification Mode',
                                                           config_parameter='smartpay_operations.wallet_customer_cashback_notify_mode')

    '''
    @api.multi
    def set_values(self):
        super(SmartpayOperationsSettings, self).set_values()
        IrDefault = self.env['ir.default'].sudo()
        IrDefault.set('smartpay.operations.settings', 'request_hours', self.request_hours)
        IrDefault.set('smartpay.operations.settings', 'inviter_bonus', self.inviter_bonus)
        IrDefault.set('smartpay.operations.settings', 'inviter_bonus_currency_id', self.inviter_bonus_currency_id)
        IrDefault.set('smartpay.operations.settings', 'invited_user_bonus', self.invited_user_bonus)
        IrDefault.set('smartpay.operations.settings', 'invited_user_bonus_currency_id', self.invited_user_bonus_currency_id)
        IrDefault.set('smartpay.operations.settings', 'bounce_expense_account_id', self.bounce_expense_account_id)
        IrDefault.set('smartpay.operations.settings', 'wallet_recharge_notify_mode', self.wallet_recharge_notify_mode)
        IrDefault.set('smartpay.operations.settings', 'wallet_bouns_notify_mode', self.wallet_bouns_notify_mode)
        IrDefault.set('smartpay.operations.settings', 'wallet_pay_service_bill_notify_mode',
                      self.wallet_pay_service_bill_notify_mode)
        IrDefault.set('smartpay.operations.settings', 'wallet_cancel_service_bill_notify_mode',
                      self.wallet_cancel_service_bill_notify_mode)
        IrDefault.set('smartpay.operations.settings', 'wallet_correlation_service_bill_notify_mode',
                      self.wallet_correlation_service_bill_notify_mode)
        IrDefault.set('smartpay.operations.settings', 'wallet_pay_invoice_notify_mode',
                      self.wallet_pay_invoice_notify_mode)
        IrDefault.set('smartpay.operations.settings', 'wallet_transfer_balance_notify_mode',
                      self.wallet_transfer_balance_notify_mode)
        IrDefault.set('smartpay.operations.settings', 'wallet_customer_cashback_notify_mode',
                      self.wallet_customer_cashback_notify_mode)
        return True

    @api.multi
    def get_values(self):
        res = super(SmartpayOperationsSettings, self).get_values()
        IrDefault = self.env['ir.default'].sudo()
        res.update({
            'request_hours': IrDefault.get('smartpay.operations.settings', 'request_hours', self.request_hours),
            'inviter_bonus': IrDefault.get('smartpay.operations.settings', 'inviter_bonus', self.inviter_bonus),
            'inviter_bonus_currency_id': IrDefault.get('smartpay.operations.settings', 'inviter_bonus_currency_id',
                                                         self.inviter_bonus_currency_id),
            'invited_user_bonus': IrDefault.get('smartpay.operations.settings', 'invited_user_bonus',
                                                         self.invited_user_bonus),
            'invited_user_bonus_currency_id': IrDefault.get('smartpay.operations.settings', 'invited_user_bonus_currency_id',
                                                         self.invited_user_bonus_currency_id),
            'bounce_expense_account_id': IrDefault.get('smartpay.operations.settings', 'bounce_expense_account_id',
                                                         self.bounce_expense_account_id),
            'wallet_recharge_notify_mode': IrDefault.get('smartpay.operations.settings', 'wallet_recharge_notify_mode',
                                                         self.wallet_recharge_notify_mode),
            'wallet_bouns_notify_mode': IrDefault.get('smartpay.operations.settings', 'wallet_bouns_notify_mode',
                                                      self.wallet_bouns_notify_mode),
            'wallet_pay_service_bill_notify_mode': IrDefault.get('smartpay.operations.settings', 'wallet_pay_service_bill_notify_mode',
                                                                 self.wallet_pay_service_bill_notify_mode),
            'wallet_cancel_service_bill_notify_mode': IrDefault.get('smartpay.operations.settings', 'wallet_cancel_service_bill_notify_mode',
                                                                 self.wallet_cancel_service_bill_notify_mode),
            'wallet_correlation_service_bill_notify_mode': IrDefault.get('smartpay.operations.settings', 'wallet_correlation_service_bill_notify_mode',
                                                                 self.wallet_correlation_service_bill_notify_mode),
            'wallet_pay_invoice_notify_mode': IrDefault.get('smartpay.operations.settings', 'wallet_pay_invoice_notify_mode',
                                                            self.wallet_pay_invoice_notify_mode),
            'wallet_transfer_balance_notify_mode': IrDefault.get('smartpay.operations.settings', 'wallet_transfer_balance_notify_mode',
                                                                 self.wallet_transfer_balance_notify_mode),
            'wallet_customer_cashback_notify_mode': IrDefault.get('smartpay.operations.settings', 'wallet_customer_cashback_notify_mode',
                                                                  self.wallet_customer_cashback_notify_mode),
        })
        return res
    '''