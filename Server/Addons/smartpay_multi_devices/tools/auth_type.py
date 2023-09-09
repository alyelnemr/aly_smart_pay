import logging
import functools

from odoo.http import request

from odoo.addons.restful.common import invalid_response

_logger = logging.getLogger(__name__)


def check_auth_type(func):
    """Check auth type before calling api."""

    @functools.wraps(func)
    def inner(*args, **kwargs):
        """."""
        try:
            params_names = ['machine_serial', 'authType']
            params = {key: kwargs.get(key) for key in params_names if kwargs.get(key)}
            if not (params.get('authType') == 'device' and params.get('machine_serial')):
                # The request url parameters is empty the credentials maybe passed via the headers.
                headers = request.httprequest.headers
                machine_serial = headers.get('machine_serial')
                auth_type = headers.get('authType')
                if not (auth_type and machine_serial):
                    return invalid_response(
                        "Access Denied", "Must be send machine_serial and authType must be device "
                                         "to authenticate on device", 401,
                    )
        except Exception as e:
            error = "There is error on auth type decorator {}".format(e)
            typ = "internal_error"
            _logger.error(error)
            return invalid_response(typ, error, 500)
        return func(*args, **kwargs)

    return inner
