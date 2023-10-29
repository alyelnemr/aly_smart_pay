import logging
from odoo.addons.base_smartpay_otp.tools.generate_random import generate_secrets_code
from odoo import fields, models, api, _

_logger = logging.getLogger(__name__)


class DeviceGenerateTempPasswordWizard(models.TransientModel):
    """ A wizard to generate temporary devices' passwords. """
    _name = "device.generate.password.wizard"
    _description = "Device Generate Password Wizard"

    def _default_device_ids(self):
        device_ids = self._context.get('active_model') == 'api.access_token' and \
                     self._context.get('active_ids') or []
        temp_password_length = int(self.env['ir.config_parameter'].sudo().
                                   get_param('base_smartpay_otp.temp_password_length')) or 4
        # _logger.info('Generate temp password length {}'.format(temp_password_length))

        devices = [
            (0, 0, {
                'device_id': device.id,
                'device_login': device.user_name,
                'new_passwd': generate_secrets_code(length=temp_password_length).lower(),
            })
            for device in self.env['api.access_token'].browse(device_ids).
            filtered(lambda u: u.otp_active)
        ]
        for tup in devices:
            if isinstance(tup[2], dict):
                device_id = self.env['api.access_token'].browse(tup[2].get('device_id'))
                device_id.write({'password': tup[2].get('new_passwd')})
                device_id.write({'temp_password_date': fields.Datetime.now()})
                device_id.device_reset_otp_auth()
        return devices

    device_ids = fields.One2many('generate.temp.password.device', 'wizard_id',
                                 string='Devices', default=_default_device_ids)


class GeneratePasswordUser(models.TransientModel):
    """ A model to configure device in the generated temporary password wizard. """
    _name = 'generate.temp.password.device'
    _description = 'Device, Generate Password Wizard'

    wizard_id = fields.Many2one('device.generate.password.wizard', string='Wizard',
                                required=True, ondelete='cascade')
    device_id = fields.Many2one('api.access_token', string='User', required=True,
                                ondelete='cascade')
    device_login = fields.Char(string='Device Login', readonly=True)
    new_passwd = fields.Char(string='Temp Password', readonly=True)
