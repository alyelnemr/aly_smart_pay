import json
import logging
import werkzeug.wrappers
from odoo import http
from odoo.http import request

from odoo.addons.smartpay_otp.tools.auth import auth_api
from odoo.addons.smartpay_otp.tools.otp_enable import check_otp_enable
from odoo.addons.restful.common import invalid_response, valid_response

_logger = logging.getLogger(__name__)


class OTPController(http.Controller):

    @http.route("/api/otp/login", methods=["GET"], type="http", auth="none", csrf=False)
    @check_otp_enable
    @auth_api
    def otp_login(self, **post):
        """The otp login is the first steps on otp process
            to be used for getting generated code:
        Args:
            **post must contain db, login and password.
        Returns:
            returns https response code
             1- 401 if temp-password is expired or failed authentication.
             2- 403 if number of generated code exceeds ten times or failed authentication.
             3- 423 if the number of generated valid code exceeds the allowed limit.
             4- 451 if otp is not enabled.
             5- 500 if error on generated valid code or error on authenticate.
             6- 202 if successful with the generated code and ChallengeName.
        """
        _logger.info('Call OTP Login')
        password = post.get('password')
        username = post.get('username')
        user = request.env.user

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
                "Access Denied", "Temp-password is expired", 401,
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
        _credentials_includes_in_header = all([valid_code, username])
        if not _credentials_includes_in_header:
            # if no credentials on headers check body
            if request.httprequest.data:
                body_data = json.loads(request.httprequest.data.decode('utf-8'))
                valid_code = body_data.get('validCode') if body_data.get('validCode') else ''
                username = body_data.get('login') if body_data.get('login') else ''
                _credentials_includes_in_body = all([valid_code, username])
                if not _credentials_includes_in_body:
                    _logger.info('Either of the following are missing [validCode {}, login {}]' \
                                 .format(valid_code, username))
                    return invalid_response(
                        "missing error", "either of the following are missing [validCode, login]", 403,
                    )
            else:
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

        # check number of generated otp code
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
             5- 500 if error on generate secrete code or error on authentication.
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
        _credentials_includes_in_header = all([valid_code, username, otp])
        # check credentials on body
        if not _credentials_includes_in_header:
            if request.httprequest.data:
                body_data = json.loads(request.httprequest.data.decode('utf-8'))
                valid_code = body_data.get('validCode') if body_data.get('validCode') else ''
                username = body_data.get('login') if body_data.get('login') else ''
                otp = body_data.get('otp') if body_data.get('otp') else ''
                _credentials_includes_in_body = all([valid_code, username, otp])
                if not _credentials_includes_in_body:
                    _logger.info('Either of the following are missing [validCode {}, login {}, otp {}]' \
                                 .format(valid_code, username, otp))
                    return invalid_response(
                        "missing error", "either of the following are missing [validCode, login, otp]", 403,
                    )
            else:
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
            **post or request body must contain login, validCode, secreteCode and newPassword.
        Returns:
            returns https response code
             1- 401 if send invalid login, user is unauthorized.
             2- 402 if send invalid validCode, user is unauthorized.
             3- 402 if send invalid secreteCode, user is unauthorized.
             4- 403 if missing credentials validCode or login or secreteCode or newPassword.
             5- 406 if send invalid newPassword.
             6- 451 if otp is not enabled.
             7- 500 if error on set new password, generate a new token and error on authentication.
             8- 202 if successful with new token.
        """
        # check credentials on headers
        _logger.info('Calling resetpassword otp')
        _logger.info('Checking validCode , login, secreteCode and newPassword')
        valid_code, username, secrete_code, new_password = (
            post.get("validCode"),
            post.get("login"),
            post.get("secreteCode"),
            post.get("newPassword"),
        )
        _credentials_includes_in_header = all([valid_code, username, secrete_code, new_password])
        # check credentials on body
        if not _credentials_includes_in_header:
            if request.httprequest.data:
                body_data = json.loads(request.httprequest.data.decode('utf-8'))
                valid_code = body_data.get('validCode') if body_data.get('validCode') else ''
                username = body_data.get('login') if body_data.get('login') else ''
                secrete_code = body_data.get('secreteCode') if body_data.get('secreteCode') else ''
                new_password = body_data.get('newPassword') if body_data.get('newPassword') else ''
                _credentials_includes_in_body = all([valid_code, username, secrete_code, new_password])
                if not _credentials_includes_in_body:
                    _logger.info('Either of the following are missing [validCode {}, login {},'
                                 'secrete_code {}, new_password {} ]' \
                                 .format(valid_code, username, secrete_code, new_password))
                    return invalid_response(
                        "missing error",
                        "Either of the following are missing [validCode, login, secrete_code,new_password]", 403,
                    )
            else:
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
