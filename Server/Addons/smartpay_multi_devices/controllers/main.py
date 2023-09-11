import json
import logging
import werkzeug.wrappers
from odoo import http, _
from odoo.http import request
from odoo.tools import date_utils
from odoo.addons.restful.controllers.main import _routes, APIController
from odoo.addons.base_smartpay_otp.tools.date_utils import convert_datetime_client_tz, \
    convert_date_client_tz
from odoo.addons.restful.common import (
    extract_arguments,
    invalid_response,
    valid_response,
)
from odoo.addons.smartpay_multi_devices.tools.check_otp import check_device_otp_enable
from odoo.addons.smartpay_multi_devices.tools.validate_token import validate_token
from odoo.addons.base_smartpay_otp.controllers.otp import OtpLogin, OTPController

_logger = logging.getLogger(__name__)

expires_in = 'restful.access_token_expires_in'


class InheritAPIController(APIController):
    @validate_token
    @http.route(_routes, type="http", auth="none", methods=["GET"], csrf=False)
    def get(self, model=None, id=None, **payload):
        _logger.info("On Extend Get request ")
        ioc_name = model
        model = request.env[self._model].sudo().search([("model", "=", model)], limit=1)
        if model:
            domain, fields, offset, limit, order = extract_arguments(payload)
            data = (
                request.env[model.model]
                .sudo()
                .search_read(
                    domain=domain,
                    fields=fields,
                    offset=offset,
                    limit=limit,
                    order=order,
                )
            )
            if id:
                domain = [("id", "=", int(id))]
                data = (
                    request.env[model.model]
                    .sudo()
                    .search_read(
                        domain=domain,
                        fields=fields,
                        offset=offset,
                        limit=limit,
                        order=order,
                    )
                )
            if data:
                return valid_response(data)
            else:
                return valid_response(data)
        return invalid_response(
            "invalid object model",
            "The model %s is not available in the registry." % ioc_name,
        )


APIController.get = InheritAPIController.get


class DeviceOtpLogin(OtpLogin):

    @staticmethod
    def _get_expires_in():
        """Get expires period in for the token
        """
        return request.env['ir.config_parameter'].sudo().get_param(
            expires_in)  # request.env.ref(expires_in).sudo().value

    @staticmethod
    def start_otp_device(device, password, username):
        """Start an otp authentication process

        @param device: The current device linked to the user of request
        @param password: The password of the device
        @param username: The username of the device
        """
        # check the max number of generated code
        _logger.info('Checking if max number of generated code exceeds limit')
        if device.device_valid_code_max_generated():
            _logger.info('Not allowed, You exceed the number of generated valid code')
            return invalid_response(
                "Access Denied", "Not allowed, You exceed the number of generated valid code", 423,
            )

        # check temp password expiration
        _logger.info('Checking temp is not expired')
        if device.device_verify_temp_password():
            _logger.info('Access Denied temp-password is expired')
            return invalid_response(
                "Access Denied", "Temp-password is expired", 403,
            )

        try:
            choices = password + username
            generated_code = device.device_generate_valid_code(choices)
            return werkzeug.wrappers.Response(
                status=200,
                content_type="application/json; charset=utf-8",
                headers=[("Cache-Control", "no-store"), ("Pragma", "no-cache")],
                response=json.dumps(
                    {
                        "code": generated_code,
                        "ChallengeName": "ResetPassword",
                        "userStatus": device.otp_status
                    }
                ),
            )
        except Exception as ee:
            ee = str(ee)
            _logger.info('Error on otp login on generate code {}'.format(ee))
            return invalid_response(
                "Error on opt login", ee, 500,
            )

    def generate_token_device(self, device):
        """Complete the process of generating a new token
        @param device: The current device linked to the user of request
        """
        # Delete existing token not delete device.
        if device:
            device.clear_token()
        access_token = device.find_one_or_generate_token(generate=True)
        # Successful response:
        return werkzeug.wrappers.Response(
            status=200,
            content_type='application/json; charset=utf-8',
            headers=[('Cache-Control', 'no-store'),
                     ('Pragma', 'no-cache')],
            response=json.dumps({
                'uid': device.user_id.id,
                'user_context': request.session.get_context() if device else {},
                'company_id': request.env.user.company_id.id if device else None,
                'access_token': access_token,
                'expires_in': self._get_expires_in(),
                'transfer_to_salesperson': request.env.user.transfer_to_salesperson,
            }, default=date_utils.json_default),
        )

    @http.route('/api/auth/token', methods=['GET'], type='http', auth='none', csrf=False)
    def token(self, **post):
        """
        Override this method to provide otp authentication on the device level.
         If otp options are active for the device related to the current user
         default authType=device if you want to authenticate on the device
        The token URL to be used for getting the access_token:

        Args:
            **post must contain login, password, db and machine_serial.
        Returns:
            returns https status code
             1- 400 if either of the following is missing [db, username, password].
             2- 401 if authentication error occurs when passed invalid username or password or db or machine serial.
             3- 403 if temp-password is expired.
             4- 423 if the number of generated code exceeds ten times or failed authentication.
             5- 202 if successful with the access_token or
                successful with the generated code and ChallengeName.
             6- 500 if error on generated valid code or error on authenticating.

        Example:
           import requests
           headers = {'content-type': 'text/plain', 'charset':'utf-8'}
           params = {
               'login': 'admin',
               'password': 'admin',
               'db': 'galago.ng',
               'machine_serial': 'MMMMMMWWWW444',
            }
           base_url = 'http://odoo.ng'
           eq = requests.post(
               '{}/api/auth/token'.format(base_url), params=params, headers=headers)
           content = json.loads(req.content.decode('utf-8'))
           headers.update(access-token=content.get('access_token'))
        """
        params = ['db', 'login', 'password', 'machine_serial']
        params = {key: post.get(key) for key in params if post.get(key)}
        db, username, password, machine_serial = params.get('db'), \
            post.get('login'), post.get('password'), \
            post.get('machine_serial')
        _credentials_includes_in_url = all([db, username, password, machine_serial])
        # default auth_type is device
        auth_type = 'device'
        if not _credentials_includes_in_url:
            # The request url parameters is empty the credentials maybe passed via the headers.
            headers = request.httprequest.headers
            db = headers.get('db')
            username = headers.get('login')
            password = headers.get('password')
            machine_serial = headers.get('machine_serial')
            _credentials_includes_in_headers = all([db, username, password, machine_serial])
            if not _credentials_includes_in_headers:
                # Empty 'db' or 'username' or 'password:
                return invalid_response('missing credentials',
                                        'either of the following are missing [db, username,password, machine_serial]',
                                        400)
        # Login in odoo database:
        try:
            _logger.info('Calling Auth Token %s, %s, %s, %s', db, username, password, machine_serial)

            request.context = dict(request.context, auth_type=auth_type,
                                   machine_serial=machine_serial)
            request.session.authenticate(db, username, password)
        except Exception as e:
            # Invalid database:
            info = "The database name is not valid or username and password is not correct or " \
                   " authentication failed  {}" \
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
        # check device is linked to current user
        user = request.env['res.users'].sudo().search([('id', '=', uid)], order='id DESC',
                                                      limit=1)

        device = user.get_linked_device(machine_serial)

        if not (user and device):
            info = "authentication failed"
            error = 'authentication failed failed on device {}'.format(machine_serial)
            _logger.info('error {}'.format(error))
            return invalid_response(info, error, 403)
        if device and device.is_otp_active():
            return self.start_otp_device(device, password, username)
        elif device.device_status == 'confirmed':
            # generate a new token
            return self.generate_token_device(device)
        else:
            info = "authentication failed"
            error = 'authentication failed not allowed to generate token'
            _logger.error(info)
            return invalid_response(info, error, 401)


class DeviceOtpControllers(OTPController):

    @staticmethod
    def _authenticate_device(username, machine_serial):
        """Authenticate a device with the username and machine serial
        @param username: the username of device to authenticate.
        @param machine_serial: The machine serial of device to authenticate.

        @rtype: Api.access_token object
        @return: instance of api.access_token
        """
        user = request.env['res.users'].sudo().search([('login', '=', username)],
                                                      order='id DESC', limit=1)
        return user.get_linked_device(machine_serial)

    @http.route("/api/otp/send", methods=["GET"], type="http", auth="none", csrf=False)
    @check_device_otp_enable
    def send_otp(self, **post):
        """
        Override this method to provide send otp on the device level.
         If otp options are active for the device related to the active user
         default authType=device if you want to send otp on the device level.

        The send otp api is the second step in an otp process
            to be used for send otp code to user:
        Args:
            **post or request body must contain login, machine_serial and validCode.
        Returns:
            returns https response code
             1- 401 if send invalid login, a device is unauthorized.
             2- 402 if send invalid validCode, device is unauthorized.
             3- 403 if missing credentials validCode or login.
             4- 423 if generate otp code more than max allowed number.
             5- 451 if otp is not enabled.
             6- 500 if error generates and sends otp or error on authenticate.
             7- 202 if successful with send otp.
        """
        # check credentials on url
        valid_code, username, machine_serial = (
            post.get("validCode"),
            post.get("login"),
            post.get("machine_serial")
        )
        _logger.info('Calling send otp on device level')
        _credentials_includes_in_url = all([valid_code, username, machine_serial])
        if not _credentials_includes_in_url:
            # check credentials on headers
            headers = request.httprequest.headers
            valid_code = headers.get('validCode') if headers.get('validCode') else ''
            username = headers.get('login') if headers.get('login') else ''
            machine_serial = headers.get('machine_serial') if headers.get('machine_serial') else ''
            _credentials_includes_in_headers = all([valid_code, username, machine_serial])
            if not _credentials_includes_in_headers:
                _logger.info('Either of the following are missing'
                             ' [validCode {}, login {}]'
                             .format(valid_code, username, machine_serial))
                return invalid_response(
                    "missing error",
                    "either of the following are missing [validCode, login, machine_serial]",
                    403,
                )

        _logger.info('Checking login is authorized')
        device = self._authenticate_device(username, machine_serial)
        if not device:
            _logger.info('Access denied login is invalid, unauthorized device' \
                         .format(username))
            return invalid_response("Access denied", "Unauthorized device, Login is invalid", 401)

        # check number of generated otp code
        _logger.info('Checking number of generated otp')
        if device.device_otp_max_generated():
            _logger.info('Not allowed, You exceed the number of generated otp code')
            return invalid_response(
                "Access Denied", "Not allowed, You exceed the number of generated otp code", 423,
            )

        # check temp password expiration
        _logger.info('Checking temp password is not expired')
        if device.device_verify_temp_password():
            _logger.info('Access Denied temp-password is expired')
            return invalid_response(
                "Access Denied", "Temp-password is expired", 401,
            )

        _logger.info('Checking valid code is authorized and not expired')
        if device.device_verify_valid_code(valid_code):
            try:
                device.device_send_otp()
                _logger.info('Successful generated and send otp')
                return werkzeug.wrappers.Response(
                    status=200,
                    content_type="application/json; charset=utf-8",
                    headers=[("Cache-Control", "no-store"), ("Pragma", "no-cache")],
                    response=json.dumps(
                        {
                            "ChallengeName": "Successful send OTP",
                            "otpStatus": device.otp_status
                        }
                    ),
                )
            except Exception as ee:
                _logger.info('Error on generate and send otp {}'.format(ee))
                return invalid_response(
                    "Error on send otp", ee, 500,
                )
        _logger.info('Access Denied, ValidCode is unauthorized, machine serial {}, validCode {}'
                     .format(device.machine_serial, valid_code))
        return invalid_response(
            "Access Denied", "ValidCode is unauthorized", 402,
        )

    @http.route("/api/otp/verify", methods=["GET"], type="http", auth="none", csrf=False)
    @check_device_otp_enable
    def verify_otp(self, **post):
        """
        Override this method to provide verify otp on the device level.
         If otp options are active for the device related to the active user
         default authType=device and machine_serial if you want to verify otp on the device level.

        The verify otp api is the third step in an otp process
            to be used for verify otp and generate secrete code:
        Args:
            **post must contain login, validCode and otp.
        Returns:
            returns https response code
             1- 401 if send invalid login, a device is unauthorized.
             2- 402 if send invalid validCode, device is unauthorized.
             3- 402 if send invalid otp, device is unauthorized.
             4- 403 if missing credentials validCode or login or otp.
             5- 451 if otp is not enabled.
             5- 500 if error on generates secrete code or error on authentication.
             6- 202 if successful with get secrete code.
        """
        # check credentials on url
        valid_code, username, machine_serial, otp = (
            post.get("validCode"),
            post.get("login"),
            post.get("machine_serial"),
            post.get("otp"),
        )

        _logger.info('Calling verify otp on user device level')

        _credentials_includes_in_url = all([valid_code, username, otp, machine_serial])
        # check credentials on headers
        if not _credentials_includes_in_url:
            # check credentials on headers
            headers = request.httprequest.headers
            valid_code = headers.get('validCode') if headers.get('validCode') else ''
            username = headers.get('login') if headers.get('login') else ''
            machine_serial = headers.get('machine_serial') if headers.get('machine_serial') else ''
            otp = headers.get('otp') if headers.get('otp') else ''
            _credentials_includes_in_headers = all([valid_code, username, otp, machine_serial])
            if not _credentials_includes_in_headers:
                _logger.info('Either of the following are missing [validCode {}, login {}, otp {}]' \
                             .format(valid_code, username, otp))
                return invalid_response(
                    "missing error", "either of the following are missing [validCode, login, otp]", 403,
                )

        _logger.info('Checking login is authorized')
        device = self._authenticate_device(username, machine_serial)
        if not device:
            _logger.info('Access denied login is invalid, unauthorized device' \
                         .format(username))
            return invalid_response("Access denied", "Unauthorized device, Login is invalid", 401)

        _logger.info('Checking temp password is not expired')
        # check temp password expiration
        if device.device_verify_temp_password():
            _logger.info('Access Denied temp-password is expired')
            return invalid_response(
                "Access Denied", "Temp-password is expired", 401,
            )

        _logger.info('Checking valid_code is authorized and not expired')
        if not device.device_verify_valid_code(valid_code):
            _logger.info('Access Denied, ValidCode is unauthorized, '
                         'device with machine serial {}, validCode {}'
                         .format(device.machine_serial, valid_code))
            return invalid_response(
                "Access Denied", "User is unauthorized, validCode is invalid", 402,
            )

        _logger.info('Checking otp is authorized and not expired')
        if not device.device_verify_otp(otp):
            _logger.info('Access Denied, OTP is unauthorized, '
                         'device with machine_serial {}, otp {}'
                         .format(device.machine_serial, otp))
            return invalid_response(
                "Access Denied", "Device is unauthorized, otp is invalid", 402,
            )
        try:
            secrete_code = device.device_generate_secrete_code()
            _logger.info('Successful generated secrete code')
            return werkzeug.wrappers.Response(
                status=200,
                content_type="application/json; charset=utf-8",
                headers=[("Cache-Control", "no-store"), ("Pragma", "no-cache")],
                response=json.dumps(
                    {
                        "ChallengeName": "Successful generate secrete code",
                        "secreteCode": secrete_code,
                        "otpStatus": device.otp_status
                    }
                ),
            )
        except Exception as ee:
            _logger.info('Error on generate secrete code {}'.format(ee))
            return invalid_response(
                "Error on send otp", ee, 500,
            )

    @http.route("/api/otp/resetpassword", methods=["GET"], type="http", auth="none", csrf=False)
    @check_device_otp_enable
    def resetpassword_otp(self, **post):
        """
        Override this method to provide resetpassword on the device level.
         If otp options are active for the device related to the active user
         default authType=device and machine_serial if you want to resetpassword on the device level.

        The resetpassword api is the last steps on an otp process
            to be used for set new password and return access token:
        Args:
            **post or request body must contain login, validCode, secreteCode and newPassword.
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
        valid_code, username, secrete_code, new_password, machine_serial = (
            post.get("validCode"),
            post.get("login"),
            post.get("secreteCode"),
            post.get("newPassword"),
            post.get("machine_serial"),
        )

        _logger.info('Calling rest password on device level')
        _credentials_includes_in_url = all([valid_code, username, secrete_code, new_password, machine_serial])
        # check credentials on headers
        if not _credentials_includes_in_url:
            headers = request.httprequest.headers
            valid_code = headers.get('validCode') if headers.get('validCode') else ''
            username = headers.get('login') if headers.get('login') else ''
            secrete_code = headers.get('secreteCode') if headers.get('secreteCode') else ''
            new_password = headers.get('newPassword') if headers.get('newPassword') else ''
            machine_serial = headers.get('machine_serial') if headers.get('machine_serial') else ''
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
        device = self._authenticate_device(username, machine_serial)
        if not device:
            _logger.info('Access denied login is invalid, unauthorized device'
                         .format(username))
            return invalid_response("Access denied", "Unauthorized device, Login is invalid", 401)

        _logger.info('Checking temp password is not expired')
        # check temp password expiration
        if device.device_verify_temp_password():
            _logger.info('Access Denied temp-password is expired')
            return invalid_response(
                "Access Denied", "Temp-password is expired", 401,
            )

        _logger.info('Checking valid_code is authorized and not expired')
        if not device.device_verify_valid_code(valid_code):
            _logger.info('Access Denied, ValidCode is unauthorized,'
                         ' device with machine serial {}, validCode {}'
                         .format(machine_serial, valid_code))
            return invalid_response(
                "Access Denied", "User is unauthorized, validCode is invalid", 402,
            )

        _logger.info('Checking secrete_code is authorized and not expired')
        if not device.device_verify_secrete_code(secrete_code):
            _logger.info('Access Denied, secreteCode is unauthorized,'
                         ' device with machine serial {}, secrete_code {}'
                         .format(machine_serial, secrete_code))
            return invalid_response(
                "Access Denied", "User is unauthorized, secreteCode is invalid", 402,
            )

        try:
            _logger.info('Set new password')
            if not device.otp_set_new_password(new_password):
                return invalid_response(
                    "Invalid newPassword", "Invalid newPassword, newPassword must be 4 to 6 digit ", 406,
                )
            _logger.info('Create a new access token for device {}'.format(machine_serial))
            access_token = device.find_one_or_generate_token(generate=True)
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
