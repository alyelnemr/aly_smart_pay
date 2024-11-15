# Part of odoo. See LICENSE file for full copyright and licensing details.
import logging
import json
import werkzeug.wrappers
from odoo import http, _
from odoo.http import request
from odoo.tools import config
from odoo.addons.restful.common import invalid_response, valid_response

_logger = logging.getLogger(__name__)

expires_in = 'restful.access_token_expires_in'


class AccessToken(http.Controller):
    """."""

    def __init__(self):

        self._token = request.env['api.access_token']
        self._expires_in = request.env['ir.config_parameter'].sudo().get_param(expires_in) # request.env.ref(expires_in).sudo().value

    @http.route('/api/auth/token', methods=['GET'], type='http', auth='none', csrf=False)
    def token(self, **post):
        """The token URL to be used for getting the access_token:

        Args:
            **post must contain login and password.
        Returns:

            returns https response code 404 if failed error message in the body in json format
            and status code 202 if successful with the access_token.
        Example:
           import requests

           headers = {'content-type': 'text/plain', 'charset':'utf-8'}

           data = {
               'login': 'admin',
               'password': 'admin',
               'db': 'galago.ng'
            }
           base_url = 'http://odoo.ng'
           eq = requests.post(
               '{}/api/auth/token'.format(base_url), data=data, headers=headers)
           content = json.loads(req.content.decode('utf-8'))
           headers.update(access-token=content.get('access_token'))
        """
        _token = request.env['api.access_token']
        params = ['db', 'login', 'password']
        params = {key: post.get(key) for key in params if post.get(key)}
        db, username, password, machine_serial = params.get(
            'db'), post.get('login'), post.get('password'), post.get('machine_serial')
        _credentials_includes_in_body = all([db, username, password])
        if not _credentials_includes_in_body:
            # The request post body is empty the credetials maybe passed via the headers.
            headers = request.httprequest.headers
            db = headers.get('db')
            db_name = config['db_name']
            username = headers.get('login')
            password = headers.get('password')
            machine_serial = headers.get('machine_serial')
            _credentials_includes_in_headers = all([db, username, password])
            if not _credentials_includes_in_headers:
                # Empty 'db' or 'username' or 'password:
                return invalid_response('missing error', 'either of the following are missing [db, username,password]', 403)
        # Login in odoo database:
        try:
            request.session.authenticate(db_name, username, password)
        except Exception as e:
            # Invalid database:
            info = "The database name is not valid {}".format(e)
            error = 'invalid_database'
            _logger.error(info)
            return invalid_response('wrong database name', error, info)

        uid = request.session.uid
        # odoo login failed:
        if not uid:
            info = "authentication failed"
            error = 'authentication failed'
            _logger.error(info)
            return invalid_response(info, error, 401)

        # Validate Machine Serial if exist
        user_data = request.env['res.users'].sudo().search([('id', '=', uid)], order='id DESC', limit=1)
        if user_data.machine_serial and user_data.machine_serial != machine_serial:
            return invalid_response('machine_serial', _('machine serial invalid'), 400)
        # Delete existing token
        access_token = request.env["api.access_token"].sudo().search([("user_id", "=", uid)], order="id DESC", limit=1)
        if access_token:
            access_token.unlink()
        # Generate tokens
        access_token = _token.find_one_or_create_token(
            user_id=uid, create=True)
        # Successful response:
        return werkzeug.wrappers.Response(
            status=200,
            content_type='application/json; charset=utf-8',
            headers=[('Cache-Control', 'no-store'),
                     ('Pragma', 'no-cache')],
            response=json.dumps({
                'uid': uid,
                'user_context': request.session.get_context() if uid else {},
                'company_id': request.env.user.company_id.id if uid else None,
                'access_token': access_token,
                'expires_in': self._expires_in,
                'transfer_to_salesperson': request.env.user.transfer_to_salesperson,
            }),
        )

    @http.route('/api/auth/token', methods=['DELETE'], type='http', auth='none', csrf=False)
    def delete(self, **post):
        """."""
        _token = request.env['api.access_token']
        access_token = request.httprequest.headers.get('access_token')
        access_token = _token.search([('token', '=', access_token)])
        if not access_token:
            info = "No access token was provided in request!"
            error = 'no_access_token'
            _logger.error(info)
            return invalid_response(info, error, 400)
        for token in access_token:
            token.unlink()
        # Successful response:
        return valid_response(
            {"desc": 'token successfully deleted', "delete": True}, 200
        )
