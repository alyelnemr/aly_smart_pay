from odoo import fields, models

SELECTION_PERIOD = [
    ('day', 'Days'),
    ('hour', 'Hours'),
    ('minute', 'Minutes')
]


class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    # temp password info
    temp_password_length = fields.Integer(default=4, help='Temp-Password Length',
                                          config_parameter='smartpay_otp.temp_password_length')
    temp_password_duration = fields.Integer(help='Temp-Password Expired', default=2,
                                            config_parameter='smartpay_otp.temp_password_duration')
    temp_password_period = fields.Selection(SELECTION_PERIOD,
                                            help="Temp-Password Expired Period", default='day',
                                            config_parameter='smartpay_otp.temp_password_period')
    # generated code info
    generated_code_length = fields.Integer(help='Generated Code Length', default=32,
                                           config_parameter='smartpay_otp.generated_code_length')
    generated_code_expired_duration = fields.Integer(help='Generated Code Expired Duration', default=30,
                                                     config_parameter='smartpay_otp.generated_code_expired_duration')
    generated_code_max_number = fields.Integer(help='Max Number Generated Code', default=10,
                                               config_parameter='smartpay_otp.generated_code_max_number')
    generated_code_period = fields.Selection(SELECTION_PERIOD,
                                             help="Generate Code Period", default='minute',
                                             config_parameter='smartpay_otp.generated_code_period')
    # otp info
    otp_length = fields.Integer(help='OTP Length', default=4,
                                config_parameter='smartpay_otp.otp_length')
    otp_expired_duration = fields.Integer(help='OTP Expired Duration', default=2,
                                          config_parameter='smartpay_otp.otp_expired_duration')
    otp_max_number = fields.Integer(help='OTP Max Number Generated', default=4,
                                    config_parameter='smartpay_otp.otp_max_number')
    otp_method = fields.Selection([
        ('sms', 'Sms'),
        ('email', 'Email'),
    ], help='OTP Method', default='sms',
        config_parameter='smartpay_otp.otp_method')
    otp_period = fields.Selection(SELECTION_PERIOD,
                                  help="OTP Period", default='minute',
                                  config_parameter='smartpay_otp.otp_period')
    # secret code info
    secret_code_length = fields.Integer(help='Secrete Code Length', default=16,
                                        config_parameter='smartpay_otp.secret_code_length')

    secret_code_duration = fields.Integer(help='Secrete Code Expired Duration', default=5,
                                          config_parameter='smartpay_otp.secret_code_duration')
    secret_code_added = fields.Char(help='Secrete Code Added',
                                    config_parameter='smartpay_otp.secret_code_added')
    secret_code_period = fields.Selection(SELECTION_PERIOD,
                                          help="Secrete Code Period", default='minute',
                                          config_parameter='smartpay_otp.secret_code_period')
    # new password info
    new_password_length = fields.Integer(help='New-Password Length', default=4,
                                         config_parameter='smartpay_otp.new_password_length')
    new_password_expired_duration = fields.Integer(help='New-Password Time Expired Duration', default=365,
                                                   config_parameter='smartpay_otp.new_password_expired_duration')
    new_password_period = fields.Selection(SELECTION_PERIOD,
                                           help="New-Password Duration Period", default='day',
                                           config_parameter='smartpay_otp.new_password_period')
