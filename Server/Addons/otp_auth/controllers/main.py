# -*- coding: utf-8 -*-
#################################################################################
#
#   Copyright (c) 2015-Present Webkul Software Pvt. Ltd. (<https://webkul.com/>)
#   See LICENSE file for full copyright and licensing details.
#   If not, see <https://store.webkul.com/license.html/>
#
#################################################################################

from odoo import http, _
from odoo.http import request
from odoo.addons.web.controllers.main import Home
from odoo import http
import pyotp
from logging import getLogger
_logger = getLogger(__name__)

class AuthSignupHome(Home):

    @http.route(['/generate/otp'], type='json', auth="public", methods=['POST'], website=True)
    def generate_otp(self, **kwargs):
        email = kwargs.get('email')
        if email:
            if int(kwargs.get('validUser',0))==0:
                message = self.checkExistingUser(**kwargs)
            else:
                message = [1, _("Thanks for the registration."), 0]
            if message[0] != 0:
                otpdata = self.getOTPData()
                otp = otpdata[0]
                otp_time = otpdata[1]
                self.sendOTP(otp, **kwargs)
                message = [1, _("OTP has been sent to given Email Address : {}".format(email)), otp_time]
        else:
            message = [0, _("Please enter an email address"), 0]
        return message

    def checkExistingUser(self, **kwargs):
        email = kwargs.get('email')
        user_obj = request.env["res.users"].sudo().search([("login", "=", email)])
        message = [1, _("Thanks for the registration."), 0]
        if user_obj:
            message = [0, _("Another user is already registered using this email address."), 0]
        return message

    def sendOTP(self, otp, **kwargs):
        user_name = kwargs.get('userName')
        email = kwargs.get('email')
        request.env['send.otp'].email_send_otp(email, user_name, otp)
        return True

    @http.route(['/verify/otp'], type='json', auth="public", methods=['POST'], website=True)
    def verify_otp(self, otp=False,email=False):
        if otp:
            totp = request.session.get('otpobj')
            if otp.isdigit():
                return True if int(totp)==int(otp) else False
            else:
                return False
        else:
            return False
    
    @http.route('/web/reset_password', type='http', auth='public', website=True, sitemap=False)
    def web_auth_reset_password(self, *args, **kw):
        request.session['radio-otp']=None
        return super(AuthSignupHome, self).web_auth_reset_password(*args, **kw)



    @http.route('/web/signup', type='http', auth='public', website=True, sitemap=False)
    def web_auth_signup(self, *args, **kw):
        if not kw.get('login'):
            return super(AuthSignupHome, self).web_auth_signup(*args, **kw)
        if kw.get('otp'):
            totp = int(request.session.get('otpobj'))
            if totp == int(kw.get('otp')):
                return super(AuthSignupHome, self).web_auth_signup(*args, **kw)
            else:
                qcontext = self.get_auth_signup_qcontext()
                response = request.render('auth_signup.signup', qcontext)
                response.headers['X-Frame-Options'] = 'DENY'
                return response
        else:
            return super(AuthSignupHome, self).web_auth_signup(*args, **kw)


    @http.route(['/send/otp'], type='json', auth="public", methods=['POST'], website=True)
    def send_otp(self, **kwargs):
        email = kwargs.get('email')
        if email:
            if request.env["res.users"].sudo().search([("login", "=", email)]):
                otpdata = kwargs.get('otpdata') if kwargs.get('otpdata') else self.getOTPData()
                otp = otpdata[0]
                otp_time = otpdata[1]
                request.env['send.otp'].email_send_otp(email, False, otp)
                message = {"email":{'status':1, 'message':_("OTP has been sent to given Email Address : {}.".format(email)), 'otp_time':otp_time, 'email':email}}
            else:
                message = {"email":{'status':0, 'message':_("Failed to send OTP !! Please ensure that you have given correct Email Address."), 'otp_time':0, 'email':email}}
        else:
            message = {"email":{'status':0, 'message':_("Failed to send OTP !! Please enter an email address."), 'otp_time':0, 'email':False}}
        return message

    def getOTPData(self):
        otp_time = request.env['ir.default'].sudo().get('website.otp.settings', 'otp_time_limit')
        otp_time = int(otp_time)
        if otp_time < 30:
            otp_time = 30
        #Extra Time added to process OTP
        main_otp_time = otp_time + 60
        totp = pyotp.TOTP(pyotp.random_base32(), interval=main_otp_time)
        # _logger.info('-------------------------------------------------{0}'.format(request.session['otploginobj'],request.session['otpobj']))
        otp = totp.now()
        request.session['otploginobj'] = otp
        request.session['otpobj'] = otp
        return [otp, otp_time]
