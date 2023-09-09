import json
import logging
import werkzeug.wrappers
from odoo import http, _
from odoo.http import request
from odoo.addons.restful.controllers.token import AccessToken
from odoo.addons.base_smartpay_otp.tools.auth import auth_api
from odoo.addons.base_smartpay_otp.tools.otp_enable import check_otp_enable
from odoo.addons.restful.common import invalid_response, valid_response

_logger = logging.getLogger(__name__)


class OtpLogin(AccessToken):

    @staticmethod
    def start_otp(user, password, username):
        """Start otp authentication process

        @param user: The current user of request
        @param password: The password of the user
        @param username: The username of the user
        """
        # check max number of generated code
        _logger.info('Checking if max number of generated code exceeds limit')
        if user.verify_valid_code_max_generated():
            _logger.info('Not allowed, You exceed the number of generated valid code')
            return invalid_response(
                "Access Denied", "Not allowed, You exceed the number of generated valid code", 423,
            )

        # check temp password expiration
        _logger.info('Checking temp is not expired')
        if user.user_verify_temp_password():
            _logger.info('Access Denied temp-password is expired')
            return invalid_response(
                "Access Denied", "Temp-password is expired", 403,
            )

        try:
            choices = password + username
            generated_code = user.generate_valid_code(choices)
            return werkzeug.wrappers.Response(
                status=200,
                content_type="application/json; charset=utf-8",
                headers=[("Cache-Control", "no-store"), ("Pragma", "no-cache")],
                response=json.dumps(
                    {
                        "code": generated_code,
                        "ChallengeName": "ResetPassword",
                        "userStatus": user.otp_status
                    }
                ),
            )
        except Exception as ee:
            _logger.info('Error on otp login on generate code {}'.format(ee))
            return invalid_response(
                "Error on opt login", ee, 500,
            )

    def generate_token(self, user, machine_serial):
        """Complete a process of generating a new token"""
        _token = request.env['api.access_token']
        # Validate Machine Serial if exist
        # user_data = request.env['res.users'].sudo().search([('id', '=', uid)], order='id DESC', limit=1)
        if user.machine_serial and user.machine_serial != machine_serial:
            return invalid_response('machine_serial', _('machine serial invalid'), 400)
        # Delete existing token
        access_token = request.env["api.access_token"].sudo().search([("user_id", "=", user.id)], order="id DESC",
                                                                     limit=1)
        if access_token:
            access_token.unlink()
        # Generate tokens
        access_token = _token.find_one_or_create_token(
            user_id=user.id, create=True)
        # Successful response:
        return werkzeug.wrappers.Response(
            status=200,
            content_type='application/json; charset=utf-8',
            headers=[('Cache-Control', 'no-store'),
                     ('Pragma', 'no-cache')],
            response=json.dumps({
                'uid': user.id,
                'user_context': request.session.get_context() if user else {},
                'company_id': request.env.user.company_id.id if user else None,
                'access_token': access_token,
                'expires_in': self._expires_in,
            }),
        )

    @http.route('/api/auth/token', methods=['GET'], type='http', auth='none', csrf=False)
    def token(self, **post):
        """
        Override this method to provide otp authentication
         if otp options are active for current user
        The token URL to be used for getting the access_token:

        Args:
            **post must contain login, password and db, optional machine_serial.
        Returns:
            returns https status code
             1- 400 if either of the following are missing [db, username, password] or
                machine_serial not equal same machine_serial of user.
             2- 401 if authentication error occurs when passed invalid username or password or db.
             3- 403 if temp-password is expired.
             4- 423 if the number of generated code exceeds ten times or failed authentication.
             5- 202 if successful with the access_token or
                successful with the generated code and ChallengeName.
             6- 500 if error on generated valid code or error on authenticating.

        Example:
           import requests

           Headers = {'content-type': 'text/plain', 'charset':'utf-8'}

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
        params = ['db', 'login', 'password']
        params = {key: post.get(key) for key in params if post.get(key)}
        db, username, password, machine_serial = params.get(
            'db'), post.get('login'), post.get('password'), post.get('machine_serial')
        _credentials_includes_in_body = all([db, username, password])
        if not _credentials_includes_in_body:
            # The request post body is empty the credetials maybe passed via the headers.
            headers = request.httprequest.headers
            db = headers.get('db')
            username = headers.get('login')
            password = headers.get('password')
            machine_serial = headers.get('machine_serial')
            _credentials_includes_in_headers = all([db, username, password])
            if not _credentials_includes_in_headers:
                # Empty 'db' or 'username' or 'password:
                return invalid_response('missing credentaional',
                                        'either of the following are missing [db, username,password]',
                                        400)
        # Login in odoo database:
        try:
            request.session.authenticate(db, username, password)
        except Exception as e:
            # Invalid database:
            info = "The database name is not valid or username and password is not correct {}" \
                .format(e)
            error = 'authentication failed'
            _logger.error(info)
            return invalid_response(info, error, 401)

        uid = request.session.uid
        # odoo login failed:
        if not uid:
            info = "authentication failed"
            error = 'authentication failed'
            _logger.error(info)
            return invalid_response(info, error, 401)

        # check if user active otp option
        user = request.env['res.users'].sudo().search([('id', '=', uid)], order='id DESC', limit=1)
        if user and user.is_otp_active():
            return self.start_otp(user, password, username)
        else:
            # generate a new token
            return self.generate_token(user, machine_serial)


class OTPController(http.Controller):

    @http.route("/api/otp/send", methods=["GET"], type="http", auth="none", csrf=False)
    @check_otp_enable
    def send_otp(self, **post):
        """The send otp api is the second steps on otp process
            to be used for send otp code to user:
        Args:
            **post or request body must contain login and validCode.
        Returns:
            returns https response code
             1- 401 if send invalid login, user is unauthorized.
             2- 402 if send invalid validCode, user is unauthorized.
             3- 403 if missing credentials validCode or login.
             4- 423 if generate otp code more than max allowed number.
             5- 451 if otp is not enabled.
             6- 500 if error on generate and send otp or error on authenticate.
             7- 202 if successful with send otp.
        """
        _logger.info('Calling send otp')
        # check credentials on headers
        valid_code, username = (
            post.get("validCode"),
            post.get("login"),
        )
        _credentials_includes_in_body = all([valid_code, username])
        if not _credentials_includes_in_body:
            # if no credentials on headers check on headers
            headers = request.httprequest.headers
            # if request.httprequest.data:
            #     body_data = json.loads(request.httprequest.data.decode('utf-8'))
            valid_code = headers.get('validCode', '')
            username = headers.get('login', '')
            _credentials_includes_in_headers = all([valid_code, username])
            if not _credentials_includes_in_headers:
                _logger.info('Either of the following are missing [validCode {}, login {}]' \
                             .format(valid_code, username))
                return invalid_response(
                    "missing error", "either of the following are missing [validCode, login]", 403,
                )

        _logger.info('Checking login is authorized')
        user = self._authenticate_user(username)
        if not user:
            _logger.info('Access denied login is invalid, unauthorized user' \
                         .format(username))
            return invalid_response("Access denied", "Unauthorized user, Login is invalid", 401)

        # check the number of generated otp code
        _logger.info('Checking number of generated otp')
        if user.verify_otp_max_generated():
            _logger.info('Not allowed, You exceed the number of generated otp code')
            return invalid_response(
                "Access Denied", "Not allowed, You exceed the number of generated otp code", 423,
            )

        # check temp password expiration
        _logger.info('Checking temp password is not expired')
        if user.user_verify_temp_password():
            _logger.info('Access Denied temp-password is expired')
            return invalid_response(
                "Access Denied", "Temp-password is expired", 401,
            )

        _logger.info('Checking valid code is authorized and not expired')
        if user.user_verify_valid_code(valid_code):
            try:
                user.send_otp()
                _logger.info('Successful generated and send otp')
                return werkzeug.wrappers.Response(
                    status=200,
                    content_type="application/json; charset=utf-8",
                    headers=[("Cache-Control", "no-store"), ("Pragma", "no-cache")],
                    response=json.dumps(
                        {
                            "ChallengeName": "Successful send OTP",
                            "otpStatus": user.otp_status
                        }
                    ),
                )
            except Exception as ee:
                _logger.info('Error on generate and send otp {}'.format(ee))
                return invalid_response(
                    "Error on send otp", ee, 500,
                )
        _logger.info('Access Denied, ValidCode is unauthorized, user {}, validCode {}'
                     .format(user.name, valid_code))
        return invalid_response(
            "Access Denied", "ValidCode is unauthorized", 402,
        )

    @http.route("/api/otp/verify", methods=["GET"], type="http", auth="none", csrf=False)
    @check_otp_enable
    def verify_otp(self, **post):
        """The verify otp api is the third steps on otp process
            to be used for verify otp and generate secrete code:
        Args:
            **post must contain db, login, password, validCode and otp.
        Returns:
            returns https response code
             1- 401 if send invalid login, user is unauthorized.
             2- 402 if send invalid validCode, user is unauthorized.
             3- 402 if send invalid otp, user is unauthorized.
             4- 403 if missing credentials validCode or login or otp.
             5- 451 if otp is not enabled.
             5- 500 if error on generates secrete code or error on authentication.
             6- 202 if successful with get secrete code.
        """
        # check credentials on headers
        _logger.info('Calling verify otp')
        _logger.info('Checking valid code , login and otp')
        valid_code, username, otp = (
            post.get("validCode"),
            post.get("login"),
            post.get("otp"),
        )
        _credentials_includes_in_body = all([valid_code, username, otp])
        # check credentials on headers
        if not _credentials_includes_in_body:
            headers = request.httprequest.headers
            # if request.httprequest.data:
            #     body_data = json.loads(request.httprequest.data.decode('utf-8'))
            valid_code = headers.get('validCode', '')
            username = headers.get('login', '')
            otp = headers.get('otp', '')
            _credentials_includes_in_headers = all([valid_code, username, otp])
            if not _credentials_includes_in_headers:
                _logger.info('Either of the following are missing [validCode {}, login {}, otp {}]' \
                             .format(valid_code, username, otp))
                return invalid_response(
                    "missing error", "either of the following are missing [validCode, login, otp]", 403,
                )

        _logger.info('Checking login is authorized')
        user = self._authenticate_user(username)
        if not user:
            _logger.info('Access denied login is invalid, unauthorized user' \
                         .format(username))
            return invalid_response("Access denied", "Unauthorized user, Login is invalid", 401)

        _logger.info('Checking temp password is not expired')
        # check temp password expiration
        if user.user_verify_temp_password():
            _logger.info('Access Denied temp-password is expired')
            return invalid_response(
                "Access Denied", "Temp-password is expired", 401,
            )

        _logger.info('Checking valid_code is authorized and not expired')
        if not user.user_verify_valid_code(valid_code):
            _logger.info('Access Denied, ValidCode is unauthorized, user {}, validCode {}'
                         .format(user.name, valid_code))
            return invalid_response(
                "Access Denied", "User is unauthorized, validCode is invalid", 402,
            )

        _logger.info('Checking otp is authorized and not expired')
        if not user.user_verify_otp(otp):
            _logger.info('Access Denied, OTP is unauthorized, user {}, otp {}'
                         .format(user.name, otp))
            return invalid_response(
                "Access Denied", "User is unauthorized, otp is invalid", 402,
            )
        try:
            secrete_code = user.generate_secrete_code()
            _logger.info('Successful generated secrete code')
            return werkzeug.wrappers.Response(
                status=200,
                content_type="application/json; charset=utf-8",
                headers=[("Cache-Control", "no-store"), ("Pragma", "no-cache")],
                response=json.dumps(
                    {
                        "ChallengeName": "Successful generate secrete code",
                        "secreteCode": secrete_code,
                        "otpStatus": user.otp_status
                    }
                ),
            )
        except Exception as ee:
            _logger.info('Error on generate secrete code {}'.format(ee))
            return invalid_response(
                "Error on send otp", ee, 500,
            )

    @http.route("/api/otp/resetpassword", methods=["GET"], type="http", auth="none", csrf=False)
    @check_otp_enable
    def resetpassword_otp(self, **post):
        """The resetpassword api is the last steps on otp process
            to be used for set new password and return access token:
        Args:
            **post or request body must contain login, validCode, secreteCode, newPassword and machine_serial.
        Returns:
            returns https response code
             1- 401 if send invalid login, user is unauthorized.
             2- 402 if send invalid validCode, user is unauthorized.
             3- 402 if send invalid secreteCode, user is unauthorized.
             3- 402 if send invalid machine_serial, user is unauthorized.
             4- 403 if missing credentials validCode or login or secreteCode or newPassword.
             5- 406 if send invalid newPassword.
             6- 451 if otp is not enabled.
             7- 500 if error on set new password, generate a new token and error on authentication.
             8- 202 if successful with new token.
        """
        # check credentials on headers
        _logger.info('Calling resetpassword otp')
        _logger.info('Checking validCode , login, secreteCode and newPassword')
        valid_code, username, secrete_code, new_password, machine_serial = (
            post.get("validCode"),
            post.get("login"),
            post.get("secreteCode"),
            post.get("newPassword"),
            post.get("machine_serial"),
        )
        _credentials_includes_in_body = all([valid_code, username, secrete_code, new_password, machine_serial])
        # check credentials on headers
        if not _credentials_includes_in_body:
            headers = request.httprequest.headers

            # if request.httprequest.data:
            #     body_data = json.loads(request.httprequest.data.decode('utf-8'))
            valid_code = headers.get('validCode', '')
            username = headers.get('login', '')
            secrete_code = headers.get('secreteCode', '')
            new_password = headers.get('newPassword', '')
            machine_serial = headers.get('machine_serial', '')
            _credentials_includes_in_headers = all([valid_code, username, secrete_code, new_password, machine_serial])
            if not _credentials_includes_in_headers:
                _logger.info('Either of the following are missing [validCode {}, login {},'
                             'secrete_code {}, new_password {} ]' \
                             .format(valid_code, username, secrete_code, new_password))
                return invalid_response(
                    "missing error",
                    "Either of the following are missing [validCode, login, secrete_code,new_password]", 403,
                )

        _logger.info('Checking login is authorized')
        user = self._authenticate_user(username)
        if not user:
            _logger.info('Access denied login is invalid, unauthorized user'
                         .format(username))
            return invalid_response("Access denied", "Unauthorized user, Login is invalid", 401)

        _logger.info('Checking temp password is not expired')
        # check temp password expiration
        if user.user_verify_temp_password():
            _logger.info('Access Denied temp-password is expired')
            return invalid_response(
                "Access Denied", "Temp-password is expired", 401,
            )

        _logger.info('Checking valid_code is authorized and not expired')
        if not user.user_verify_valid_code(valid_code):
            _logger.info('Access Denied, ValidCode is unauthorized, user {}, validCode {}'
                         .format(user.name, valid_code))
            return invalid_response(
                "Access Denied", "User is unauthorized, validCode is invalid", 402,
            )

        _logger.info('Checking secrete_code is authorized and not expired')
        if not user.user_verify_secrete_code(secrete_code):
            _logger.info('Access Denied, secreteCode is unauthorized, user {}, secrete_code {}'
                         .format(user.name, secrete_code))
            return invalid_response(
                "Access Denied", "User is unauthorized, secreteCode is invalid", 402,
            )
        # check if user has machine_serial check if invalid else enter new machine_serial
        _logger.info('Checking machine_serial is valid')
        _logger.info('Verify machine serial {}'.format(machine_serial))
        if not user.machine_serial:
            _logger.info('Set new machine_serial')
            user.set_machine_serial(machine_serial)
        elif not user.user_verify_machine_serial(machine_serial):
            _logger.info('Machine serial is not valid')
            return invalid_response(
                "Access Denied", "User is unauthorized, machine_serial is invalid", 402,
            )

        try:
            _logger.info('Set new password')
            if not user.otp_set_new_password(new_password):
                return invalid_response(
                    "Invalid newPassword", "Invalid newPassword, newPassword must be 4 to 6 digit ", 406,
                )

            _logger.info('Create a new access token')
            token = request.env["api.access_token"]
            uid = user.id
            access_token = token.find_one_or_create_token(user_id=uid, create=True)
            _logger.info('Successful generated token')
            return werkzeug.wrappers.Response(
                status=200,
                content_type="application/json; charset=utf-8",
                headers=[("Cache-Control", "no-store"), ("Pragma", "no-cache")],
                response=json.dumps(
                    {
                        "ChallengeName": "Successful generate access token",
                        "accessToken": access_token
                    }
                ),
            )
        except Exception as ee:
            _logger.info('Error on set new password, generate token {}'.format(ee))
            return invalid_response(
                "Error set new password, generate token", ee, 500,
            )

    @staticmethod
    def _authenticate_user(login):
        _logger.info('authenticate user using login')
        user = request.env['res.users'].sudo()
        user_id = user.search(user._get_login_domain(login), order=user._get_login_order(), limit=1)
        return user_id
