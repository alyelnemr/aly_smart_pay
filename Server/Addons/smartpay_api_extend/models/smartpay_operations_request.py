from odoo import fields, models


class InheritSmartPayOperationsRequest(models.Model):
    _inherit = 'smartpay_operations.request'

    request_billing_acct = fields.Char(string="Billing Account")
    request_extra_billing_acct_keys = fields.Text(string='Extra Billing AcctKeys')
    request_custom_properties = fields.Text(string='Extra Custom Properties')
    request_inquiry_transaction_id = fields.Many2one('smartpay_operations.request',
                                                     string="Inquire Record")
    request_machine_serial = fields.Char(string="Machine Serial")
