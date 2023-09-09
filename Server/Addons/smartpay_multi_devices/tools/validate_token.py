import functools
import logging

from odoo.addons.restful.common import invalid_response

from odoo.addons.restful.controllers import main

from odoo.http import request

_logger = logging.getLogger(__name__)


def validate_token(func):
    """."""

    @functools.wraps(func)
    def wrap(self, *args, **kwargs):
        """Override the function to regenerate the access token on a device."""
        _logger.info("In Extend validate token")
        access_token = request.httprequest.headers.get("access_token")
        # machine_serial = request.httprequest.headers.get("machine_serial")
        if not access_token:
            return invalid_response(
                "access_token_not_found",
                "missing access token in request header", 401
            )
        access_token_data = (
            request.env["api.access_token"]
            .sudo()
            .search([
                ('active', '=', True),
                ("token", "=", access_token),
                ("user_id.active", "=", True),
                # ('machine_serial', '=', machine_serial),
            ], order="id DESC", limit=1)
        )

        if not access_token_data or access_token_data.has_expired():
            return invalid_response(
                "access_token", "This token seems to have an expired or invalid access token", 401
            )
        # if (
        #         access_token_data.find_one_or_create_token(
        #             user_id=access_token_data.user_id.id
        #         )
        #         != access_token
        # ):
        #     return invalid_response(
        #         "access_token", "token seems to have expired or invalid", 401
        #     )

        request.session.uid = access_token_data.user_id.id
        request.uid = access_token_data.user_id.id
        return func(self, *args, **kwargs)

    return wrap


main.validate_token = validate_token
