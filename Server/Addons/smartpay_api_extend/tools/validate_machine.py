import functools
import logging

from odoo import http, fields, _
from odoo.addons.restful.common import invalid_response


from odoo.http import request
from odoo.addons.smartpay_api.controllers import main

_logger = logging.getLogger(__name__)


def validate_machine(func):
    """."""

    @functools.wraps(func)
    def wrap(self, *args, **kwargs):
        """ Update to new business logic,
            every user has a device with a machine serial and access token
        """
        _logger.info('In extend validate machine serial')
        access_token = request.httprequest.headers.get("access_token")
        machine_serial = request.httprequest.headers.get("machine_serial")
        if not machine_serial:
            return invalid_response(
                "machine_serial_not_found", _("missing machine serial in request header"), 400
            )

        device_data = (
            request.env["api.access_token"]
            .sudo()
            .search([
                ('active', '=', True),
                ("token", "=", access_token),
                ("user_id.active", "=", True),
                ('machine_serial', '=', machine_serial)
            ], order="id DESC", limit=1)
        )

        if not device_data:
            return invalid_response(
                "machine_serial", _("machine serial invalid"), 400
            )

        user_id = device_data.user_id.id

        request.session.uid = user_id
        request.uid = user_id
        return func(self, *args, **kwargs)

    return wrap


main.validate_machine = validate_machine
