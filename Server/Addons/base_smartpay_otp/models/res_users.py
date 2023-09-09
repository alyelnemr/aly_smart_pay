import logging
import re
from dateutil.relativedelta import relativedelta
from datetime import datetime

from odoo import fields, models, api
from odoo.addons.base_smartpay_otp.tools.generate_random import generate_secrets_code
from odoo.addons.base_smartpay_otp.tools.date_utils import get_timedelta, \
    convert_datetime_client_tz, convert_date_client_tz

_logger = logging.getLogger(__name__)


class ResUsers(models.Model):
    _name = 'res.users'
    _inherit = 'res.users'

    otp_status = fields.Selection([
        ('new', 'New'),
        ('progress', 'IN progress(Generated Code)'),
        ('pre_verify', 'Waiting Pre-Verify (Sending OTP)'),
        ('waiting_confirm', 'Waiting Confirm (Verify OTP)'),
        ('confirmed', 'Successful set new password'),
    ], default='new', string='OTP Status')
    otp_active = fields.Boolean(string="OTP Enable", default=False,
                                help="Enable OR Disable OTP")
    user_status = fields.Selection([
        ('confirmed', 'Confirmed'),
        ('reset_password', 'ResetPassword'),
        ('expired', 'Expired'),
        ('unconfirmed', 'Unconfirmed'),
    ], string='User Status', help='User authentication status')

    # reset code (valid-code) fields
    reset_code = fields.Char('Reset Password Code', readonly=True)
    reset_code_time = fields.Datetime('Reset Code Time', readonly=True)
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

    # ----------------------------------------------------------
    #  Verify OTP Operation Logic
    # ----------------------------------------------------------
    def user_verify_temp_password(self):
        """Verify that the temp password not expired."""
        self.ensure_one()
        _logger.info('Checking temp password expired')
        temp_password_expired_duration = int(self.env['ir.config_parameter'].sudo()
                                             .get_param('base_smartpay_otp.temp_password_duration'))
        temp_password_period = self.env['ir.config_parameter'].sudo(). \
            get_param('base_smartpay_otp.temp_password_period')
        _logger.info('Temp password expired duration {}, period {}'.format(temp_password_expired_duration,
                                                                           temp_password_period))
        temp_password_date_tz = convert_datetime_client_tz(self, self.temp_password_date)
        datetime_now_tz = convert_datetime_client_tz(self, datetime.now())
        temp_password_date_after_period = temp_password_date_tz + self._get_relativedelta(
            temp_password_expired_duration,
            temp_password_period, 2)
        _logger.info('Temp password after add period {}'.format(temp_password_date_after_period))
        if self.temp_password_date and temp_password_date_after_period < datetime_now_tz:
            return True
        return False

    def user_verify_valid_code(self, valid_code):
        """Verify that valid code (generated code) is valid and not expired."""
        self.ensure_one()
        if not self.reset_code_time:
            return False
        is_valid_code_expired = False
        generated_code_expired_duration = int(self.env['ir.config_parameter'].sudo().
                                              get_param('base_smartpay_otp.generated_code_expired_duration'))
        generated_code_period = self.env['ir.config_parameter'].sudo(). \
            get_param('base_smartpay_otp.generated_code_period')
        _logger.info('Generate code duration {}, period {} '.
                     format(generated_code_expired_duration, generated_code_period))
        generated_code_datetime_tz = convert_datetime_client_tz(self, self.reset_code_time)
        datetime_now_tz = convert_datetime_client_tz(self, datetime.now())
        generated_code_datetime_after_period = generated_code_datetime_tz + \
                                               self._get_relativedelta(generated_code_expired_duration,
                                                                       generated_code_period, 30)
        _logger.info('Generated code date tz {}'.format(generated_code_datetime_after_period))
        if self.reset_code_time and generated_code_datetime_after_period < datetime_now_tz:
            is_valid_code_expired = True
        if self.reset_code == valid_code and not is_valid_code_expired:
            return True
        return False

    def verify_valid_code_max_generated(self):
        """Verify that the number of calls valid code generated is not more than limit."""
        self.ensure_one()
        _logger.info('Checking if the number of calls valid code generated is not more than limit')
        generated_code_max_number = int(self.env['ir.config_parameter'].sudo().
                                        get_param('base_smartpay_otp.generated_code_max_number'))
        _logger.info('Generate code max number {}'.format(generated_code_max_number))
        if self.number_of_generate_code >= generated_code_max_number:
            return True
        return False

    def user_verify_otp(self, otp_code):
        """Verify that otp code is valid and not expired"""
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
        _logger.info('OTP datetime after period {}'.format(otp_datetime_after_period))
        is_otp_code_expired = False
        if self.otp_time and otp_datetime_after_period < datetime_now_tz:
            is_otp_code_expired = True
        if self.otp_code == otp_code and not is_otp_code_expired:
            return True
        return False

    def verify_otp_max_generated(self):
        """Verify that the number of calls otp code generated is not more than limit."""
        self.ensure_one()
        _logger.info('Checking if the number of calls otp code generated is not more than limit')
        otp_max_number = int(self.env['ir.config_parameter'].sudo().
                             get_param('base_smartpay_otp.otp_max_number'))
        _logger.info('OTP code max number {}'.format(otp_max_number))
        if self.number_of_generate_otp_code >= otp_max_number:
            return True
        return False

    def user_verify_secrete_code(self, secrete_code):
        """Verify that secrete code is valid and not expired"""
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
        _logger.info('Secrete datetime after period {}'.format(secrete_code_datetime_after_period))
        if self.secrete_code_time and secrete_code_datetime_after_period < datetime_now_tz:
            is_secrete_code_expired = True
        if self.secrete_code == secrete_code and not is_secrete_code_expired:
            return True
        return False

    def user_verify_machine_serial(self, machine_serial):
        """Verify that machine_serial is same machine_serial on current user."""
        self.ensure_one()
        if self.machine_serial == machine_serial:
            return True
        return False

    # ----------------------------------------------------------
    #  Generate OTP Operation Logic
    # ----------------------------------------------------------

    def generate_valid_code(self, choices):
        """Generate valid code for user"""
        self.ensure_one()
        _logger.info('Generate reset code')
        date_now = datetime.now()
        time_now = date_now.time().hour + date_now.minute / 60
        choices += f'{time_now:.0f}'
        generate_code_length = int(self.env['ir.config_parameter'].sudo(). \
                                   get_param('base_smartpay_otp.generated_code_length')) or 32
        _logger.info('Generate code length {}'.format(generate_code_length))
        self.reset_code = generate_secrets_code(length=generate_code_length, choices=choices,
                                                generate_type='valid_code')
        self.reset_code_time = date_now
        self.write({'otp_status': 'progress'})
        self.number_of_generate_code += 1
        # Delete the last value of otp data and secrete code data
        self.reset_otp_data()
        self.reset_secret_code_data()
        return self.reset_code

    def generate_secrete_code(self):
        """Generate secrete code for user"""
        self.ensure_one()
        _logger.info('Generate secrete code for user')
        secret_code_added = self.env['ir.config_parameter'].sudo(). \
                                get_param('base_smartpay_otp.secret_code_added') or ''
        _logger.info('secret_code_added {}'.format(secret_code_added))
        choices = self.reset_code + self.otp_code + secret_code_added
        secret_code_length = int(self.env['ir.config_parameter'].sudo(). \
                                 get_param('base_smartpay_otp.secret_code_length')) or 16
        _logger.info('secret code length {}'.format(secret_code_length))
        self.secrete_code = generate_secrets_code(length=secret_code_length, choices=choices,
                                                  generate_type='secrete_code')
        self.secrete_code_time = datetime.now()
        self.otp_status = 'waiting_confirm'
        return self.secrete_code

    def send_otp(self):
        """Send OTP code to user"""
        self.ensure_one()
        _logger.info('Generate and send OTP code to user')
        date_now = datetime.now()
        self.otp_code = self._generate_otp()
        self.otp_time = date_now
        self.number_of_generate_otp_code += 1
        otp_method = self.env['ir.config_parameter'].sudo(). \
            get_param('base_smartpay_otp.otp_method')
        _logger.info('otp_method {}'.format(otp_method))
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
        _logger.info('otp code length {}'.format(otp_length))
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
            self.write({'password': new_password})
            self.write({'otp_status': 'confirmed'})
            self.write({'user_status': 'confirmed'})
            # rest all otp info
            self.reset_valid_code_data()
            self.reset_otp_data()
            self.reset_secret_code_data()
            self.reset_otp_status()
            return True
        return False

    def _check_otp_new_password(self, pw):
        """Checking new password based on otp authentication requirements"""
        new_password_length = int(self.env['ir.config_parameter'].sudo().
                                  get_param('base_smartpay_otp.new_password_length')) or 4
        new_password_length_to = new_password_length + 2
        match_string = '^[0-9]{%d,%d}$' % (new_password_length, new_password_length_to)
        if re.match(match_string, pw):
            return True
        return False

    def set_machine_serial(self, machine_serial):
        """Set machine serial"""
        assert machine_serial not in [None, False, ''], "Must be entered machine_serial."
        self.ensure_one()
        self.write({'machine_serial': machine_serial})

    # ------------------------------
    # Other business methods
    # ------------------------------
    @api.multi
    def otp_toggle(self):
        """Toggle otp authentication"""
        for user in self:
            user.otp_active = not user.otp_active

    @api.multi
    def user_reset_otp_auth(self):
        """Reset All Data of OTP Authentication"""
        self.reset_valid_code_data()
        self.reset_otp_data()
        self.reset_secret_code_data()
        self.reset_otp_status()
        self.change_user_status(state='reset_password')

    @api.multi
    def change_user_status(self, state=''):
        """Change user status to new state"""
        assert state
        self.write({'user_status': state})

    @api.multi
    def reset_otp_status(self):
        """Reset otp status to new"""
        self.write({'otp_status': 'new'})

    @api.multi
    def reset_valid_code_data(self):
        """Reset All Data of valid code (generated code)"""
        self.write({
            'reset_code': '',
            'reset_code_time': False,
            'number_of_generate_code': 0,
        })

    @api.multi
    def reset_otp_data(self):
        """Reset All Data of otp"""
        self.write({
            'otp_code': '',
            'otp_time': False,
            'number_of_generate_otp_code': 0,
        })

    @api.multi
    def reset_secret_code_data(self):
        """Reset All Data of secret code"""
        self.write({
            'secrete_code': '',
            'secrete_code_time': False,
        })

    def is_otp_active(self):
        """Check if otp is enabled"""
        self.ensure_one()
        if self.user_status == 'reset_password' and self.otp_active:
            return True
        return False

    # CURD methods
    @api.multi
    def write(self, vals):
        res = super().write(vals)
        for user in self:
            if "otp_active" in vals:
                user.reset_valid_code_data()
                user.reset_otp_data()
                user.reset_secret_code_data()
                user.reset_otp_status()

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
