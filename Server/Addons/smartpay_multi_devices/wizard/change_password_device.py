import logging

from odoo import api, fields, models, _
from odoo.exceptions import UserError

_logger = logging.getLogger(__name__)


class ChangePasswordWizard(models.TransientModel):
    """ A wizard to change devices' passwords. """
    _name = "change.password.wizard.device"
    _description = "Change Password Wizard"

    def _default_device_ids(self):
        device_ids = self._context.get('active_model') == 'api.access_token' \
                     and self._context.get('active_ids') or []
        devices = [
            (0, 0, {
                'device_id': device.id,
                'user_id': device.user_id.id,
                'user_login': device.user_id.login,
            })
            for device in self.env['api.access_token'].browse(device_ids).
            filtered(lambda d: d.active)
        ]
        return devices

    @api.multi
    def change_password_button_devices(self):
        self.ensure_one()
        self.device_ids.change_password_button_device()
        if self.env.user in self.mapped('device_ids.user_id'):
            return {'type': 'ir.actions.client', 'tag': 'reload'}
        return {'type': 'ir.actions.act_window_close'}

    device_ids = fields.One2many('change.password.device', 'wizard_id',
                                 string='Devices', default=_default_device_ids)


class ChangePasswordDevice(models.TransientModel):
    """ A model to configure devices in the change password wizard.. """
    _name = 'change.password.device'
    _description = "Change Password's Device Wizard"

    wizard_id = fields.Many2one('change.password.wizard.device', string='Wizard',
                                required=True, ondelete='cascade')
    device_id = fields.Many2one('api.access_token', string='Device',
                                required=True, ondelete='cascade', readonly=True)
    user_id = fields.Many2one('res.users', string='User',
                              required=True, ondelete='cascade', readonly=True)
    user_login = fields.Char(string='User Login', readonly=True)
    new_password = fields.Char(string='Password')

    @api.multi
    def change_password_button_device(self):
        for line in self:
            if not line.new_password:
                raise UserError(_("Before clicking on 'Change Password',"
                                  " you have to write a new password."))
            line.device_id.write({'password': line.new_password})
            line.device_id.write({'temp_password_date': fields.Datetime.now()})
        # don't keep temporary passwords in the database longer than necessary
        self.write({'new_password': False})
