import logging
from odoo.addons.smartpay_otp.tools.generate_random import generate_secrets_code
from odoo import fields, models, api, _

_logger = logging.getLogger(__name__)


class GenerateTempPasswordWizard(models.TransientModel):
    """ A wizard to generate temporary users' passwords. """
    _name = "generate.password.wizard"
    _description = "Generate Password Wizard"

    def _default_user_ids(self):
        user_ids = self._context.get('active_model') == 'res.users' and self._context.get('active_ids') or []
        temp_password_length = int(self.env['ir.config_parameter'].sudo(). \
                                   get_param('smartpay_otp.temp_password_length')) or 4
        _logger.info('Generate temp password length {}'.format(temp_password_length))

        users = [
            (0, 0, {
                'user_id': user.id,
                'user_login': user.login,
                'new_passwd': generate_secrets_code(length=temp_password_length).lower(),
            })
            for user in self.env['res.users'].browse(user_ids)
        ]
        for tup in users:
            if isinstance(tup[2], dict):
                user_id = self.env['res.users'].browse(tup[2].get('user_id'))
                user_id.write({'password': tup[2].get('new_passwd')})
                user_id.write({'temp_password_date': fields.Datetime.now()})
        return users

    user_ids = fields.One2many('generate.temp.password.user', 'wizard_id', string='Users', default=_default_user_ids)


class GeneratePasswordUser(models.TransientModel):
    """ A model to configure users in the generated temporary password wizard. """
    _name = 'generate.temp.password.user'
    _description = 'User, Generate Password Wizard'

    wizard_id = fields.Many2one('generate.password.wizard', string='Wizard', required=True, ondelete='cascade')
    user_id = fields.Many2one('res.users', string='User', required=True, ondelete='cascade')
    user_login = fields.Char(string='User Login', readonly=True)
    new_passwd = fields.Char(string='Temp Password', readonly=True)
