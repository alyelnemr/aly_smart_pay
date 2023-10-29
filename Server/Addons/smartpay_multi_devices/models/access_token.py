import re
import datetime
import logging
import passlib.context
from datetime import datetime, timedelta

from odoo import api, fields, models, _
from odoo.exceptions import UserError, AccessError, AccessDenied, ValidationError
from odoo.tools import DEFAULT_SERVER_DATETIME_FORMAT
from odoo.addons.restful.models.access_token import expires_in, nonce
from odoo.addons.base_smartpay_otp.tools.generate_random import generate_secrets_code
from odoo.addons.base_smartpay_otp.tools.date_utils import get_timedelta, \
    convert_datetime_client_tz, convert_date_client_tz

_logger = logging.getLogger(__name__)

DEFAULT_CRYPT_CONTEXT = passlib.context.CryptContext(
    # Kdf which can be verified by the context. The default encryption kdf is
    # the first of the list
    ['pbkdf2_sha512', 'plaintext'],
    # Deprecated algorithms are still verified as usual, but ``needs_update``
    # will indicate that the stored hash should be replaced by a more recent
    # algorithm. Passlib 1.6 supports an `auto` value which deprecates any
    # algorithm but the default, but Ubuntu LTS only provides 1.5 so far.
    deprecated=['plaintext'],
)


class OtherAccountSameLogin(models.Model):
    _inherit = "api.access_token"
    _description = "Other account under same login"

    # Basic Fields
    token = fields.Char("Access Token", required=False, copy=False, readonly=True)
    expires = fields.Datetime(help="Time for token expiration", required=False,
                              copy=False, readonly=True)
    user_id = fields.Many2one(ondelete="cascade", readonly=True, copy=False)
    company_id = fields.Many2one(related="user_id.company_id",
                                 readonly=True, required=True, store=True,
                                 copy=False)
    image = fields.Binary(related="user_id.image", attachment=True, readonly=True,
                          copy=False)
    user_name = fields.Char(related="user_id.login", string="UserName",
                            required=True, readonly=True, store=True, copy=False)
    password = fields.Char("Password", invisible=True, copy=False, store=True,
                           compute='_compute_password', inverse='_set_password',
                           help="Keep empty if you don't want the user to be able to connect on the system.")
    active = fields.Boolean(default=True)
    machine_serial = fields.Char(string="Machine Serial", required=False,
                                 help='Machine Serial for user', copy=False)

    allowed_product_tag_ids = fields.Many2many('product.tags', string='Allowed Services Tags')
    commission = fields.Boolean(string="Commission", copy=False, default=False)

    device_status = fields.Selection([
        ('confirmed', 'Confirmed'),
        ('reset_password', 'ResetPassword'),
        ('expired', 'Expired'),
        ('unconfirmed', 'Unconfirmed'),
    ], string='Device Status', help='Device authentication status')

    # OTP Fields
    otp_status = fields.Selection([
        ('new', 'New'),
        ('progress', 'IN progress(Generated Code)'),
        ('pre_verify', 'Waiting Pre-Verify (Sending OTP)'),
        ('waiting_confirm', 'Waiting Confirm (Verify OTP)'),
        ('confirmed', 'Successful set new password'),
    ], default='new', string='OTP Status')
    otp_active = fields.Boolean(string="OTP Enable", default=False,
                                help="Enable OR Disable OTP")

    # generate code (valid-code) fields
    generate_code = fields.Char('Generate Code', readonly=True)
    generate_code_time = fields.Datetime('Generate Code Time', readonly=True)
    number_of_generate_code = fields.Integer('Number of Generated Code', default=0,
                                             readonly=True)
    # otp code fields
    otp_code = fields.Char('OTP Code', readonly=True)
    otp_time = fields.Datetime('OTP Time', readonly=True)
    number_of_generate_otp_code = fields.Integer('Number of Generated OTP Code',
                                                 readonly=True, default=0)
    # secrete code fields
    secrete_code = fields.Char('Secrete Code', readonly=True)
    secrete_code_time = fields.Datetime('Secrete Code Time', readonly=True)

    # temp password fields
    temp_password_date = fields.Datetime(string='Temp-Password Date')

    # Unique machine serial with user, every user have unique machine serial.
    # _sql_constraints = [
    #     ('unique_machine_serial_user', 'unique(machine_serial, user_id)', 'Machine serial must be unique!'),
    # ]

    # Unique machine serial on all devices
    _sql_constraints = [
        ('machine_serial_unique', 'unique(machine_serial)', 'Machine serial must be unique!'),
    ]

    # Internal Methods
    def init(self):
        cr = self.env.cr
        # allow setting plaintext passwords via SQL and have them
        # automatically encrypted at startup: look for passwords which don't
        # match the "extended" MCF and pass those through passlib.
        # Alternative: iterate on *all* passwords and use CryptContext.identify
        cr.execute("""
        SELECT id, password FROM api_access_token
        WHERE password IS NOT NULL
          AND password !~ '^\$[^$]+\$[^$]+\$.'
        """)
        if self.env.cr.rowcount:
            Devices = self.sudo()
            for device_id, pw in cr.fetchall():
                Devices.browse(device_id).password = pw

    def _set_password(self):
        ctx = self._crypt_context()
        for device in self:
            device._set_encrypted_password(device.id, ctx.encrypt(device.password))

    def _set_encrypted_password(self, device_id, pw):
        assert self._crypt_context().identify(pw) != 'plaintext'

        self.env.cr.execute(
            'UPDATE api_access_token SET password=%s WHERE id=%s',
            (pw, device_id)
        )
        self.invalidate_cache(['password'], [device_id])

    def _crypt_context(self):
        """ Passlib CryptContext instance used to encrypt and verify
        passwords.
        """
        return DEFAULT_CRYPT_CONTEXT

    def _check_credentials_device(self, password):
        """ Validates the current device's password.
        @param password: The password to validate
        """
        assert password
        self.env.cr.execute(
            "SELECT COALESCE(password, '') FROM api_access_token WHERE id=%s",
            [self.id]
        )
        [hashed] = self.env.cr.fetchone()
        valid, replacement = self._crypt_context() \
            .verify_and_update(password, hashed)
        if replacement is not None:
            self._set_encrypted_password(self.id, replacement)
        if not valid:
            raise AccessDenied()

    def _compute_password(self):
        for device in self:
            device.password = ''

    # Sometime sql constrains not working so use @api.constrains
    @api.constrains('machine_serial', 'user_name')
    def _check_duplicate_machine_serial(self):
        for device in self:
            exists_devices = self.search([
                ('id', '!=', device.id),
                ('machine_serial', '=', device.machine_serial),
                ('machine_serial', '!=', False),
            ])
            if exists_devices:
                raise ValidationError(_(f'This {device.machine_serial} already exists.'))

    # ----------------------------------------------------------
    #  Verify OTP Operation Logic
    # ----------------------------------------------------------
    def device_verify_temp_password(self):
        """Verify that the temp password not expired.
        @return: True means the temp password is expired
        """
        self.ensure_one()
        _logger.info('Checking temp password expired')
        temp_password_expired_duration = int(self.env['ir.config_parameter'].sudo()
                                             .get_param('base_smartpay_otp.temp_password_duration'))
        temp_password_period = self.env['ir.config_parameter'].sudo(). \
            get_param('base_smartpay_otp.temp_password_period')
        # _logger.info('Temp password expired duration {}, period {}'.format(temp_password_expired_duration,
        #                                                                    temp_password_period))
        temp_password_date_tz = convert_datetime_client_tz(self, self.temp_password_date)
        datetime_now_tz = convert_datetime_client_tz(self, datetime.now())
        temp_password_date_after_period = temp_password_date_tz + self._get_relativedelta(
            temp_password_expired_duration,
            temp_password_period, 2)
        # _logger.info('Temp password after add period {}'.format(temp_password_date_after_period))
        if self.temp_password_date and temp_password_date_after_period < datetime_now_tz:
            return True
        return False

    def device_verify_valid_code(self, valid_code):
        """Verify that valid code (generated code) is valid and not expired.
        @return: True means the valid code is valid and not expired
        """
        self.ensure_one()
        if not self.generate_code_time:
            return False
        is_valid_code_expired = False
        generated_code_expired_duration = int(
            self.env['ir.config_parameter'].sudo().
            get_param('base_smartpay_otp.generated_code_expired_duration'))
        generated_code_period = self.env['ir.config_parameter'].sudo(). \
            get_param('base_smartpay_otp.generated_code_period')
        _logger.info('Generate code duration {}, period {} '.
                     format(generated_code_expired_duration, generated_code_period))
        generated_code_datetime_tz = convert_datetime_client_tz(self, self.generate_code_time)
        datetime_now_tz = convert_datetime_client_tz(self, datetime.now())
        generated_code_datetime_after_period = \
            generated_code_datetime_tz + \
            self._get_relativedelta(generated_code_expired_duration,
                                    generated_code_period, 30)
        # _logger.info('Generated code date tz {}'.format(generated_code_datetime_after_period))
        if self.generate_code_time and generated_code_datetime_after_period < datetime_now_tz:
            is_valid_code_expired = True
        if self.generate_code == valid_code and not is_valid_code_expired:
            return True
        return False

    def device_valid_code_max_generated(self):
        """Verify that the number of calls valid code is not more than limit.
        @return: True means the number of calls valid code is more than limit
        """
        self.ensure_one()
        _logger.info('Checking if the number of calls valid code generated is not more than limit')
        generated_code_max_number = int(self.env['ir.config_parameter'].sudo().
                                        get_param('base_smartpay_otp.generated_code_max_number'))
        # _logger.info('Generate code max number {}'.format(generated_code_max_number))
        if generated_code_max_number and \
                self.number_of_generate_code >= generated_code_max_number:
            return True
        return False

    def device_verify_otp(self, otp_code):
        """Verify that otp code is valid and not expired
        @return: True means the otp code is valid and not expired
        """
        self.ensure_one()
        if not self.otp_time:
            return False
        otp_expired_duration = int(self.env['ir.config_parameter'].sudo().
                                   get_param('base_smartpay_otp.otp_expired_duration'))
        otp_period = self.env['ir.config_parameter'].sudo(). \
            get_param('base_smartpay_otp.otp_period')
        _logger.info('OTP code duration {}, period {} '.
                     format(otp_expired_duration, otp_period))
        otp_datetime_tz = convert_datetime_client_tz(self, self.otp_time)
        datetime_now_tz = convert_datetime_client_tz(self, datetime.now())
        otp_datetime_after_period = otp_datetime_tz + self._get_relativedelta(otp_expired_duration, otp_period, 2)
        # _logger.info('OTP datetime after period {}'.format(otp_datetime_after_period))
        is_otp_code_expired = False
        if self.otp_time and otp_datetime_after_period < datetime_now_tz:
            is_otp_code_expired = True
        if self.otp_code == otp_code and not is_otp_code_expired:
            return True
        return False

    def device_otp_max_generated(self):
        """Verify that the number of generations otp code is not more than limit.
        @return: True means the number of generations otp code is more than limit
        """
        self.ensure_one()
        _logger.info('Checking if the number of calls otp code generated is not more than limit')
        otp_max_number = int(self.env['ir.config_parameter'].sudo().
                             get_param('base_smartpay_otp.otp_max_number'))
        # _logger.info('OTP code max number {}'.format(otp_max_number))
        if otp_max_number and self.number_of_generate_otp_code >= otp_max_number:
            return True
        return False

    def device_verify_secrete_code(self, secrete_code):
        """Verify that secrete code is valid and not expired
        @return: True means the secret code is valid and not expired
        """
        self.ensure_one()
        if not self.secrete_code_time:
            return False
        is_secrete_code_expired = False
        secret_code_duration = int(self.env['ir.config_parameter'].sudo().
                                   get_param('base_smartpay_otp.secret_code_duration'))
        secret_code_period = self.env['ir.config_parameter'].sudo(). \
            get_param('base_smartpay_otp.secret_code_period')
        _logger.info('Secrete code duration {}, period {} '.
                     format(secret_code_duration, secret_code_period))
        secret_code_datetime_tz = convert_datetime_client_tz(self, self.secrete_code_time)
        datetime_now_tz = convert_datetime_client_tz(self, datetime.now())
        secrete_code_datetime_after_period = secret_code_datetime_tz + \
                                             self._get_relativedelta(secret_code_duration,
                                                                     secret_code_period, 5)
        # _logger.info('Secrete datetime after period {}'.format(secrete_code_datetime_after_period))
        if self.secrete_code_time and secrete_code_datetime_after_period < datetime_now_tz:
            is_secrete_code_expired = True
        if self.secrete_code == secrete_code and not is_secrete_code_expired:
            return True
        return False

    # ----------------------------------------------------------
    #  Generate OTP Operation Logic
    # ----------------------------------------------------------

    def device_generate_valid_code(self, choices):
        """Generate valid code for user"""
        self.ensure_one()
        _logger.info('Generate reset code')
        date_now = datetime.now()
        time_now = date_now.time().hour + date_now.minute / 60
        choices += f'{time_now:.0f}'
        generate_code_length = int(self.env['ir.config_parameter'].sudo().
                                   get_param('base_smartpay_otp.generated_code_length')) or 32
        # _logger.info('Generate code length {}'.format(generate_code_length))
        self.generate_code = generate_secrets_code(length=generate_code_length, choices=choices,
                                                   generate_type='valid_code')
        self.generate_code_time = date_now
        self.write({'otp_status': 'progress'})
        self.number_of_generate_code += 1
        # Delete the last value of otp data and secrete code data
        self.reset_otp_data()
        self.reset_secret_code_data()
        return self.generate_code

    def device_generate_secrete_code(self):
        """Generate secrete code for user"""
        self.ensure_one()
        _logger.info('Generate secrete code for user')
        secret_code_added = self.env['ir.config_parameter'].sudo(). \
                                get_param('base_smartpay_otp.secret_code_added') or ''
        # _logger.info('secret_code_added {}'.format(secret_code_added))
        choices = self.generate_code + self.otp_code + secret_code_added
        secret_code_length = int(self.env['ir.config_parameter'].sudo().
                                 get_param('base_smartpay_otp.secret_code_length')) or 16
        # _logger.info('secret code length {}'.format(secret_code_length))
        self.write({
            'secrete_code': generate_secrets_code(length=secret_code_length, choices=choices,
                                                  generate_type='secrete_code'),
            'secrete_code_time': datetime.now(),
            'otp_status': 'waiting_confirm',
            'device_status': 'unconfirmed',
        })
        return self.secrete_code

    def device_send_otp(self):
        """Send OTP code to user"""
        self.ensure_one()
        _logger.info('Generate and send OTP code to user')
        date_now = datetime.now()
        self.write({
            'otp_code': self._generate_otp(),
            'otp_time': date_now,
            'number_of_generate_otp_code': self.number_of_generate_otp_code + 1,
        })
        otp_method = self.env['ir.config_parameter'].sudo(). \
            get_param('base_smartpay_otp.otp_method')
        # _logger.info('otp_method {}'.format(otp_method))
        if otp_method == 'sms':
            self._send_otp_sms()
        elif otp_method == 'email':
            self._send_otp_email()
        self.write({'otp_status': 'pre_verify'})
        # Delete the last data of secret_code
        self.reset_secret_code_data()
        return True

    def _generate_otp(self):
        """Generate OTP Code"""
        _logger.info('Generate OTP Code')
        otp_length = int(self.env['ir.config_parameter'].sudo().
                         get_param('base_smartpay_otp.otp_length')) or 4
        # _logger.info('otp code length {}'.format(otp_length))
        return generate_secrets_code(length=otp_length, generate_type='otp_code')

    def _send_otp_sms(self):
        """Send OTP To User via SMS"""
        self.ensure_one()
        _logger.info('Send OTP via SMS')
        return True

    def _send_otp_email(self):
        """Send OTP To User via Email"""
        self.ensure_one()
        _logger.info('Send OTP via email')
        return True

    def otp_set_new_password(self, new_password):
        """Set new password for user on otp authentication"""
        _logger.info('Checking new password')
        checked = self._check_otp_new_password(new_password)
        if checked:
            self.write({
                'password': new_password,
                'otp_status': 'confirmed',
                'device_status': 'confirmed'
            })
            # rest all otp info
            self.write({'otp_active': False, 'temp_password_date': False})
            return True
        return False

    def _check_otp_new_password(self, pw):
        """Checking new password based on otp authentication requirements
        @return True means the new password is matched authentication requirements.
        """
        new_password_length = int(self.env['ir.config_parameter'].sudo().
                                  get_param('base_smartpay_otp.new_password_length')) or 4
        new_password_length_to = new_password_length + 2
        match_string = '^[0-9]{%d,%d}$' % (new_password_length, new_password_length_to)
        if re.match(match_string, pw):
            return True
        return False

    # ------------------------------
    # Other business methods
    # ------------------------------

    @api.multi
    def device_reset_otp_auth(self):
        """Reset All Data of OTP Authentication"""
        self.reset_valid_code_data()
        self.reset_otp_data()
        self.reset_secret_code_data()
        self.reset_otp_status()
        self.change_device_status(state='reset_password')

    @api.multi
    def change_device_status(self, state=''):
        """Change user status to new state"""
        assert state
        for device in self:
            device.write({'device_status': state})

    @api.multi
    def reset_otp_status(self):
        """Reset otp status to new"""
        for device in self:
            device.write({'otp_status': 'new'})

    @api.multi
    def reset_valid_code_data(self):
        """Reset All Data of valid code (generated code)"""
        for device in self:
            device.write({
                'generate_code': '',
                'generate_code_time': False,
                'number_of_generate_code': 0,
            })

    @api.multi
    def reset_otp_data(self):
        """Reset All Data of otp"""
        for device in self:
            device.write({
                'otp_code': '',
                'otp_time': False,
                'number_of_generate_otp_code': 0,
            })

    @api.multi
    def reset_secret_code_data(self):
        """Reset All Data of secret code"""
        for device in self:
            device.write({
                'secrete_code': '',
                'secrete_code_time': False,
            })

    def is_otp_active(self):
        """Check if otp is enabled"""
        self.ensure_one()
        if self.device_status in ['reset_password', 'unconfirmed'] and self.otp_active:
            return True
        return False

    def find_one_or_generate_token(self, generate=False):
        """Adding a new method to work with new requirements.
           the token is a device related to the user,
           so generate the new token without creating another.

        @retype: str | None
        @return token: The token generated
        """
        self.ensure_one()
        if not (self.user_id and self.machine_serial):
            return None
        if generate is True:
            _logger.info("Create new token")
            self.token, self.expires = self._generate_token(generate=True)
            return self.token
        if not (self.token and self.expires):
           # _logger.info("Token not found")
           # _logger.info("Generate new token")
            self.token, self.expires = self._generate_token(generate=True)
            return self.token
        if self.has_expired():
           # _logger.info("Token expired")
           # _logger.info("Generate new token")
            self.token, self.expires = self._generate_token(generate=True)
            return self.token
        return self.token

    @api.multi
    def clear_token(self):
        for device in self:
            device._clear_token()

    def _clear_token(self):
        self.ensure_one()
        self.write({
            'token': '',
            'expires': False,
        })

    ###########
    # ORM Overrides methods
    ###########

    @api.model
    def _generate_token(self, generate=True):
        """Generate a default token for the new login of the user
        @param generate: Whether to sure generate a token process or not

        @return: The generated token and expiration time
        @rtype: tuple[str, datetime.datetime]
        """

        token, expires_time = '', False
        if not generate:
            return token, expires_time
        if generate:
            _logger.info("Generate new token")
            expires = datetime.now() + timedelta(
                seconds=int(self.env['ir.config_parameter'].sudo().get_param(expires_in))
            )
            expires_time = expires.strftime(DEFAULT_SERVER_DATETIME_FORMAT)
            token = nonce()

        return token, expires_time

    @api.model
    def default_get(self, fields):
        res = super(OtherAccountSameLogin, self).default_get(fields)
        user_id = self.env.context.get("default_user_id") or \
                  self.env.context.get("login_related_user") \
                  or self.env.user.id \
                  or self._uid or \
                  self.env.context.get('uid')
        if not res.get('user_id') and user_id:
            _logger.info('Get user from current user {}'.format(res.get('user_id')))
            res['user_id'] = user_id
        if res['user_id']:
            user = self.env['res.users'].sudo().browse(res['user_id'])
            if not res.get('user_name'):
                res['user_name'] = user.login
            if not res.get('company_id') and user.company_id:
                res['company_id'] = user.company_id.id
            if not res.get('image') and user.image:
                res['image'] = user.image
        # if not res.get('token') or not res.get('expires'):
        #     res['token'], res['expires'] = self._generate_token(generate=True)
        return res

    @api.multi
    def name_get(self):
        result = []
        for device in self:
            name = f'{device.user_name} - {device.machine_serial or "None Serial"}'
            result.append((device.id, name))
        return result

    @api.multi
    def write(self, vals):
        if "otp_active" in vals:
            for device in self:
                device.reset_valid_code_data()
                device.reset_otp_data()
                device.reset_secret_code_data()
                device.reset_otp_status()
                if vals.get("otp_active") is True and device.device_status == 'confirmed':
                    device.write({'temp_password_date': fields.Datetime.now()})
                    device.write({'device_status': 'reset_password'})
        if "active" in vals and vals.get("active"):
            for device in self:
                if device.user_id.active is False:
                    raise UserError(_('Can not unarchive this device,'
                                      f' Because it linked to the archive user called '
                                      f'{device.user_id.name}'))
        res = super(OtherAccountSameLogin, self).write(vals)
        return res

    # ------------------------------
    #  Helper Functions
    # ----------------------------------------------------------
    @staticmethod
    def _get_relativedelta(duration, period, default_value):
        """Get relativedelta object for the given duration on the period unit.

        @param duration: duration time as integer value.
        @param period: period time as string, can be year, quarter, month, week, day or hour.
        @param default_value: if not duration and period return default duration as the day.
        """
        if duration and period:
            return get_timedelta(duration, period)
        return get_timedelta(default_value, 'day')
