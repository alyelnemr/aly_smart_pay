from odoo import fields, models, _


class InheritSmartPayOperationsRequest(models.Model):
    _inherit = 'smartpay_operations.request'

    request_billing_acct = fields.Char(string="Billing Account")
    request_extra_billing_acct_keys = fields.Text(string='Extra Billing AcctKeys')
    request_custom_properties = fields.Text(string='Extra Custom Properties')
    request_inquiry_transaction_id = fields.Many2one('smartpay_operations.request',
                                                     string="Inquire Record")
    request_machine_serial = fields.Char(string="Machine Serial")

    def action_open_inquiry_transaction(self):
        self.ensure_one()
        if not self.request_inquiry_transaction_id:
            return
        context = dict(self.env.context or {})
        return {
            'name': _('Inquiry Transaction'),
            'type': 'ir.actions.act_window',
            'view_type': 'form',
            'view_mode': 'form',
            'res_model': 'smartpay_operations.request',
            'res_id': self.request_inquiry_transaction_id.id,
            'context': context,
        }

    def open_user_device(self):
        self.ensure_one()
        device = self.env['api.access_token'].search([('machine_serial', '=', self.request_machine_serial)], limit=1)
        if not device:
            return
        return {
            'name': _('User Device'),
            'type': 'ir.actions.act_window',
            'view_type': 'form',
            'view_mode': 'form',
            'res_model': 'api.access_token',
            'res_id': device.id,
        }