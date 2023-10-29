import json
import logging
import functools

from odoo.http import request

from odoo.addons.restful.common import invalid_response

_logger = logging.getLogger(__name__)


def check_device_otp_enable(func):
    """Check otp enable on user"""

    @functools.wraps(func)
    def inner(*args, **kwargs):
        """Fetch login and machine_serial to authorized device linked with active users
           and check otp enable on device"""
        # _logger.info('Checking otp enable on device')
        try:
            params_names = ['machine_serial', 'login']
            params = {key: kwargs.get(key) for key in params_names if kwargs.get(key)}
            username = params.get("login")
            machine_serial = params.get("machine_serial")
            _credentials_includes_in_url = all([username, machine_serial])
            if not _credentials_includes_in_url:
                # The request post body is empty the credentials maybe passed via the headers
                # through kwargs.
                headers = request.httprequest.headers
                machine_serial = headers.get('machine_serial')
                username = headers.get('login')
                _credentials_includes_in_headers = all([username, machine_serial])
                if not _credentials_includes_in_headers:
                    # Empty 'db' or 'username' or 'password:
                    # _logger.info('Missing credentials (login, machine_serial)')
                    return invalid_response(
                        "missing error", "Missing login or machine_serial is not passed to api ", 403,
                    )
        except Exception as e:
            error = "There is error on fetch credentials on check otp on device level {}".format(e)
            typ = "internal_error"
            _logger.error(error)
            return invalid_response(typ, error, 500)
        # fetch user from database
        device = request.env['api.access_token'].sudo().search([
            ('user_name', '=', username),
            ('otp_active', '=', True),
            ('machine_serial', '=', machine_serial),
        ])
        if device:
            # _logger.info('OTP is enabled')
            return func(*args, **kwargs)
        else:
            # _logger.info('OTP is not enabled on account with machine serial {}'.format(machine_serial))
            return invalid_response("Access denied", "OTP is not enabled for this account", 451)

    return inner
