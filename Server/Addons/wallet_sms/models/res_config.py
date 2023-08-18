# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

from odoo import api, fields, models, _

class SmartpayOperationsSettings(models.TransientModel):
    # _inherit = 'smartpay.operations.settings'
    _inherit = 'res.config.settings'

    wallet_recharge_notify_mode = fields.Selection(selection_add=[('sms', 'SMS')])
    wallet_bouns_notify_mode = fields.Selection(selection_add=[('sms', 'SMS')])
    wallet_pay_service_bill_notify_mode = fields.Selection(selection_add=[('sms', 'SMS')])
    wallet_cancel_service_bill_notify_mode = fields.Selection(selection_add=[('sms', 'SMS')])
    wallet_correlation_service_bill_notify_mode = fields.Selection(selection_add=[('sms', 'SMS')])
    wallet_pay_invoice_notify_mode = fields.Selection(selection_add=[('sms', 'SMS')])
    wallet_transfer_balance_notify_mode = fields.Selection(selection_add=[('sms', 'SMS')])
    wallet_customer_cashback_notify_mode = fields.Selection(selection_add=[('sms', 'SMS')])

    '''
    @api.multi
    def set_values(self):
        super(SmartpayOperationsSettings, self).set_values()
        IrDefault = self.env['ir.default'].sudo()
        IrDefault.set('smartpay.operations.settings','wallet_recharge_notify_mode', self.wallet_recharge_notify_mode)
        IrDefault.set('smartpay.operations.settings', 'wallet_bouns_notify_mode', self.wallet_bouns_notify_mode)
        IrDefault.set('smartpay.operations.settings', 'wallet_pay_service_bill_notify_mode', self.wallet_pay_service_bill_notify_mode)
        IrDefault.set('smartpay.operations.settings', 'wallet_cancel_service_bill_notify_mode', self.wallet_cancel_service_bill_notify_mode)
        IrDefault.set('smartpay.operations.settings', 'wallet_correlation_service_bill_notify_mode', self.wallet_correlation_service_bill_notify_mode)
        IrDefault.set('smartpay.operations.settings', 'wallet_pay_invoice_notify_mode', self.wallet_pay_invoice_notify_mode)
        IrDefault.set('smartpay.operations.settings', 'wallet_transfer_balance_notify_mode', self.wallet_transfer_balance_notify_mode)
        IrDefault.set('smartpay.operations.settings', 'wallet_customer_cashback_notify_mode', self.wallet_customer_cashback_notify_mode)
        return True

    @api.multi
    def get_values(self):
        res = super(SmartpayOperationsSettings, self).get_values()
        IrDefault = self.env['ir.default'].sudo()
        res.update({
            'wallet_recharge_notify_mode':IrDefault.get('smartpay.operations.settings', 'wallet_recharge_notify_mode',
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
