import json
import logging
import functools

from odoo.http import request

from odoo.addons.restful.common import invalid_response

_logger = logging.getLogger(__name__)


def check_otp_enable(func):
    """Check otp enable on user"""

    @functools.wraps(func)
    def inner(*args, **kwargs):
        """Fetch login to authorized user and check otp enable"""
        _logger.info('Checking otp enable')
        username = ''
        _credentials_includes_in_body = None
        try:
            if request.httprequest.data:
                body_data = json.loads(request.httprequest.data.decode('utf-8'))
                params = {key: body_data.get(key) for key in body_data if body_data.get(key)}
                username = params.get("login")
                _credentials_includes_in_body = all([username])
            if not _credentials_includes_in_body:
                # The request post body is empty the credentials maybe passed via the headers
                # through kwargs.
                username = kwargs.get("login")
                _credentials_includes_in_headers = all([username])
                if not _credentials_includes_in_headers:
                    # Empty 'db' or 'username' or 'password:
                    _logger.info('Missing credentials (login)')
                    return invalid_response(
                        "missing error", "Missing Login(username) is not passed to api ", 403,
                    )
        except Exception as e:
            error = "There is error on fetch credentials {}".format(e)
            typ = "internal_error"
            _logger.error(error)
            return invalid_response(typ, error, 500)
        # fetch user from database
        user = request.env['res.users'].sudo().search([('login', '=', username),
                                                       ('otp_active', '=', True)])
        if user:
            _logger.info('OTP is enabled')
            return func(*args, **kwargs)
        else:
            _logger.info('OTP is not enabled')
            return invalid_response("Access denied", "OTP is not enabled for this user", 451)

    return inner
