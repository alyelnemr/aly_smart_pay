from odoo import fields, models


class InheritSmartPayOperationsRequest(models.Model):
    _inherit = 'smartpay_operations.request'

    request_billing_acct = fields.Char(string="Billing Account")
    request_extra_billing_acct_keys = fields.Text(string='Extra Billing AcctKeys')
    request_custom_properties = fields.Text(string='Extra Custom Properties')
    request_bill_ref_number = fields.Char(string="Billing Ref Number")
    request_currency_id = fields.Many2one('res.currency', string="Currency")
    request_pm_method = fields.Char(string="Payment Method")
    request_provider = fields.Char(string="Provider")
    request_pmt_type = fields.Char(string="Payment Type")
    request_fees_amt = fields.Float(string="Fees Amount")
    request_all_fees_amt = fields.Text(string="Fees Amount")
    request_notify_mobile = fields.Char(string="Notify Mobile")
    request_inquiry_transaction_id = fields.Many2one('smartpay_operations.request',
                                                     string="Inquire Record")
    request_machine_serial = fields.Char(string="Machine Serial")
