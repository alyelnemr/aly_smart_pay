import string
import random
import json
import logging
import werkzeug
from odoo import http, fields, _
from odoo.addons.restful.common import (
    extract_arguments,
    invalid_response,
    valid_response,
    default,
)

from odoo.http import request

from odoo.addons.smartpay_api.controllers.main import APIController as SmartAPIController
from odoo.addons.smartpay_api_extend.tools.validate_machine import validate_machine
from odoo.addons.smartpay_multi_devices.tools.validate_token import validate_token

_logger = logging.getLogger(__name__)


class AccessTokenAPI(SmartAPIController.AccessToken):

    @validate_token
    @validate_machine
    @http.route("/api/auth/refresh_machine_token", methods=["PUT"], type="http", auth="none", csrf=False)
    def refresh_machine_token(self, **post):
        """Override this method to authenticate on device level."""
        _token = request.env["api.access_token"].sudo()
        access_token = request.httprequest.headers.get("access_token")
        machine_serial = request.httprequest.headers.get("machine_serial")
        device = _token.search([("token", "=", access_token), ('machine_serial', '=', machine_serial)])
        user_id = device.user_id.id
        if not device:
            info = _("No access token was provided in request!")
            error = "no_access_token"
            _logger.error(info)
            return invalid_response(400, error, info)

        # Generate new token
        token = device.find_one_or_generate_token(generate=True)
        # Successful response:
        return werkzeug.wrappers.Response(
            status=200,
            content_type="application/json; charset=utf-8",
            headers=[("Cache-Control", "no-store"), ("Pragma", "no-cache")],
            response=json.dumps(
                {
                    "uid": user_id,
                    "user_context": request.session.get_context() if user_id else {},
                    "company_id": request.env.user.company_id.id if user_id else None,
                    "access_token": token,
                    "expires_in": self._expires_in,
                }
            ),
        )

    @validate_token
    @http.route("/api/auth/refresh_token", methods=["PUT"], type="http", auth="none", csrf=False)
    def refresh_token(self, **post):
        """."""
        _token = request.env["api.access_token"].sudo()
        access_token = request.httprequest.headers.get("access_token")
        device = _token.search([("token", "=", access_token)])
        user_id = device.user_id.id
        if not device:
            info = _("No access token was provided in request!")
            error = "no_access_token"
            _logger.error(info)
            return invalid_response(400, error, info)

        # Generate new token
        token = device.find_one_or_generate_token(generate=True)
        # Successful response:
        return werkzeug.wrappers.Response(
            status=200,
            content_type="application/json; charset=utf-8",
            headers=[("Cache-Control", "no-store"), ("Pragma", "no-cache")],
            response=json.dumps(
                {
                    "uid": user_id,
                    "user_context": request.session.get_context() if user_id else {},
                    "company_id": request.env.user.company_id.id if user_id else None,
                    "access_token": token,
                    "expires_in": self._expires_in,
                }
            ),
        )
