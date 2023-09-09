import json
import logging
import functools

from odoo.http import request
from odoo.exceptions import AccessDenied, AccessError

from odoo.addons.restful.common import invalid_response

_logger = logging.getLogger(__name__)


def auth_api(func):
    """Check user credentials before calling api"""

    @functools.wraps(func)
    def inner(*args, **kwargs):
        """."""
        _credentials_includes_in_body = None
        try:
            # if request.httprequest.data:
            #     body_data = json.loads(request.httprequest.data.decode('utf-8'))
            headers = request.httprequest.headers
            params = {key: headers.get(key) for key in headers if headers.get(key)}
            db, username, password = (
                params.get("db"),
                params.get("login"),
                params.get("password"),
            )
            _credentials_includes_in_headers = all([db, username, password])
            if not _credentials_includes_in_headers:
                # The request post body is empty the credentials maybe passed via the body
                # through kwargs.
                db = kwargs.get("db")
                username = kwargs.get("login")
                password = kwargs.get("password")
                _credentials_includes_in_body = all([db, username, password])
                if not _credentials_includes_in_body:
                    # Empty 'db' or 'username' or 'password:
                    return invalid_response(
                        "missing error", "either of the following are missing [db, username,password]", 403,
                    )
        except Exception as e:
            error = "There is error on fetch credentials {}".format(e)
            typ = "internal_error"
            _logger.error(error)
            return invalid_response(typ, error, 500)
        # Login in odoo database:
        try:
            request.session.authenticate(db, username, password)
        except AccessError as aee:
            return invalid_response("Access error", "Error: %s" % aee.name)
        except AccessDenied as ade:
            return invalid_response("Access denied", "Login, password or db invalid")
        except Exception as e:
            # Invalid database:
            info = "The database name is not valid {}".format((e))
            error = "invalid_database"
            _logger.error(info)
            return invalid_response("wrong database name", error, 403)
        uid = request.session.uid
        # odoo login failed:
        if not uid:
            info = "authentication failed"
            error = "authentication failed"
            _logger.error(info)
            return invalid_response(401, error, info)
        kwargs['db'] = db
        kwargs['username'] = username
        kwargs['password'] = password
        return func(*args, **kwargs)

    return inner
