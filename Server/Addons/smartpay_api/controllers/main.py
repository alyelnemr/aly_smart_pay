# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

# import traceback
import functools
import json
import ast
import logging
import math
import string
import random
import werkzeug
import datetime
from datetime import date
from datetime import datetime as date_time, timedelta
from psycopg2 import IntegrityError
from Crypto.Cipher import DES3
import base64
from collections import OrderedDict
import requests

from odoo import http, fields, _
from odoo.tools import float_is_zero
from odoo.exceptions import UserError, ValidationError, AccessDenied, AccessError
from odoo.addons.auth_signup.models.res_users import SignupError
from odoo.addons.auth_signup.controllers.main import AuthSignupHome
from odoo.addons.restful.common import (
    extract_arguments,
    invalid_response,
    valid_response,
    default,
)
from odoo.addons.restful.controllers.main import (
    validate_token, APIController as restful_main
)
from odoo.addons.website_form.controllers.main import WebsiteForm
from odoo.addons.tm_base_gateway.common import (
    suds_to_json,
)
from odoo.addons.web.controllers.main import (
    ensure_db,
)

from odoo.http import request

_logger = logging.getLogger(__name__)

_REQUEST_TYPES_IDS = ['general_inquiry', 'recharge_wallet', 'service_bill_inquiry', 'pay_service_bill', 'pay_invoice', 'wallet_invitation']
SECRET_KEY = base64.b64decode('MfG6sLDTQIaS8QgOnkBS2THxurCw00CG')
UNPAD = lambda s: s[0:-s[-1]]

def validate_machine(func):
    """."""

    @functools.wraps(func)
    def wrap(self, *args, **kwargs):
        """."""
        access_token = request.httprequest.headers.get("access_token")
        machine_serial = request.httprequest.headers.get("machine_serial")
        if not machine_serial:
            return invalid_response(
                "machine_serial_not_found", _("missing machine serial in request header"), 400
            )

        access_token_data = (
            request.env["api.access_token"]
                .sudo()
                .search([("token", "=", access_token)], order="id DESC", limit=1)
        )
        user_id = access_token_data.user_id.id

        machine_serial_data = (
            request.env["res.users"]
            .sudo()
            .search([("machine_serial", "=", machine_serial), ("id", "=", user_id)], order="id DESC", limit=1)
        )
        if not machine_serial_data:
            return invalid_response(
                "machine_serial", _("machine serial invalid"), 400
            )

        request.session.uid = user_id
        request.uid = user_id
        return func(self, *args, **kwargs)

    return wrap


class APIController(http.Controller):
    """."""

    def __init__(self):
        self._model = "ir.model"

    class UsersApi(http.Controller):

        @http.route('/api/signup', type="http", auth="none", methods=["POST"], csrf=False)
        def auth_signup(self, *args, **kw):
            qcontext = AuthSignupHome().get_auth_signup_qcontext()
            qcontext.update({
                'name': kw.get('first_name') + " " + kw.get('last_name'),
                'login': kw.get('email'),
                'password': kw.get('password'),
                'confirm_password': kw.get('confirm_password'),
                'phone': kw.get('phone'),
            })

            if not qcontext.get('token') and not qcontext.get('signup_enabled'):
                raise werkzeug.exceptions.NotFound()

            if 'error' not in qcontext and request.httprequest.method == 'POST':
                try:
                    AuthSignupHome().do_signup(qcontext)
                    qcontext["message"] = _("Your account successfully created.")
                    # Send an account creation confirmation email
                    if qcontext.get('token'):
                        user_sudo = request.env['res.users'].sudo().search([('login', '=', qcontext.get('login'))])
                        template = request.env.ref('auth_signup.mail_template_user_signup_account_created',
                                                   raise_if_not_found=False)
                        if user_sudo and template:
                            template.sudo().with_context(
                                lang=user_sudo.lang,
                                auth_login=werkzeug.url_encode({'auth_login': user_sudo.email}),
                            ).send_mail(user_sudo.id, force_send=True)
                    # else:
                        # request.env["res.users"].with_context(create_user=True).sudo().reset_password(qcontext.get('login'))
                        # qcontext["message"] = _("Check your email to activate your account!")

                    return valid_response(qcontext['message'])
                except UserError as e:
                    qcontext['error'] = e.name or e.value
                except (SignupError, AssertionError) as e:
                    if request.env["res.users"].sudo().search([("login", "=", qcontext.get("login"))]):
                        qcontext["error"] = _("Another user is already registered using this email address.")
                    else:
                        _logger.error("%s", e)
                        qcontext['error'] = _("Could not create a new account.")

                return invalid_response("Error", qcontext['error'], 500)

        @validate_token
        @http.route('/api/reset_password', type="http", auth="none", methods=["POST"], csrf=False)
        def auth_reset_password(self, *args, **kw):
            qcontext = AuthSignupHome().get_auth_signup_qcontext()
            qcontext.update({
                'login': kw.get('login')
            })

            if not qcontext.get('token') and not qcontext.get('reset_password_enabled'):
                raise werkzeug.exceptions.NotFound()

            if 'error' not in qcontext and request.httprequest.method == 'POST':
                try:
                    if qcontext.get('token'):
                        AuthSignupHome().do_signup(qcontext)
                        #return self.web_login(*args, **kw)
                        qcontext['message'] = _("Signup successfully with the new token")
                        return valid_response(qcontext['message'])
                    else:
                        login = qcontext.get('login')
                        assert login, _("No login provided.")
                        _logger.info(
                            "Password reset attempt for <%s> by user <%s> from %s",
                            login, request.env.user.login, request.httprequest.remote_addr)
                        # request.env['res.users'].sudo().reset_password(login)
                        # qcontext['message'] = _("An email has been sent with credentials to reset your password")
                        # return valid_response(qcontext['message'])

                        # Reset password
                        is_updated = False
                        prefix = "RP_"
                        password_characters = string.ascii_letters + string.digits + string.punctuation
                        new_password = ''.join(random.choice(password_characters) for i in range(10))
                        user = request.env['res.users'].sudo().search([('id', '=', request.env.user.id)], limit=1)
                        if user:
                            is_updated = user.sudo().write({'password': prefix + new_password})
                        if is_updated:
                            return valid_response({"new_password": prefix + new_password})
                except UserError as e:
                    qcontext['error'] = e.name or e.value
                except SignupError:
                    qcontext['error'] = _("Could not reset your password")
                    _logger.exception('error when resetting password')
                except Exception as e:
                    qcontext['error'] = str(e)

                return invalid_response("Error", qcontext['error'], 500)

        @validate_token
        @http.route('/api/change_password', type="http", auth="none", methods=["POST"], csrf=False)
        def auth_change_password(self, *args, **kw):
            qcontext = AuthSignupHome().get_auth_signup_qcontext()
            qcontext.update({
                'login': kw.get('login'),
                'old_pwd': kw.get('old_pwd'),
                'new_password': kw.get('new_password'),
                'confirm_pwd': kw.get('confirm_pwd'),
                'db': kw.get('db'),
            })

            if not qcontext.get('token') and not qcontext.get('reset_password_enabled'):
                raise werkzeug.exceptions.NotFound()

            if 'error' not in qcontext and request.httprequest.method == 'POST':
                try:
                    if qcontext.get('token'):
                        AuthSignupHome().do_signup(qcontext)
                        # return self.web_login(*args, **kw)
                        qcontext['message'] = _("Signup successfully with the new token")
                        return valid_response(qcontext['message'])
                    else:
                        login = qcontext.get('login')
                        assert login, _("No login provided.")
                        _logger.info(
                            "Password change attempt for <%s> by user <%s> from %s",
                            login, request.env.user.login, request.httprequest.remote_addr)

                        old_password = qcontext.get('old_pwd')
                        new_password = qcontext.get('new_password')
                        confirm_password = qcontext.get('confirm_pwd')
                        db = qcontext.get('db')
                        if not (old_password.strip() and new_password.strip() and confirm_password.strip()):
                            return invalid_response("Error", _('You cannot leave any password empty.'), 400)
                        if new_password != confirm_password:
                            return invalid_response("Error", _('The new password and its confirmation must be identical.'), 400)

                        qcontext['error'] = _("Error, password not changed !")

                        # Login in odoo database:
                        request.session.authenticate(db, login, old_password)
                        uid = request.session.uid
                        # odoo login failed:
                        if not uid:
                            info = "authentication failed"
                            error = "authentication failed"
                            _logger.error(info)
                            return invalid_response(info, error, 401)

                        user = request.env['res.users'].sudo().search([('id', '=', uid)], limit=1)
                        if user and user.sudo().write({'password': new_password}):
                            qcontext['message'] = _("Password successfully changed.")
                            return valid_response(qcontext['message'])

                except UserError as e:
                    qcontext['error'] = e.name or e.value
                except AccessDenied as e:
                    qcontext['error'] = e.args[0]
                    if qcontext['error'] == AccessDenied().args[0]:
                        qcontext['error'] = _('The old password you provided is incorrect, your password was not changed.')
                except Exception as e:
                    qcontext['error'] = str(e)

                return invalid_response("Error", qcontext['error'], 500)

        @http.route('/api/create_user', type="http", auth="none", methods=["POST"], csrf=False)
        def create_user(self, **user_data):
            _logger.info("@@@@@@@@@@@@@@@@@@@ Calling Create User API")
            values = {
                'name': user_data.get('first_name') + " " + user_data.get('last_name'),
                'login': user_data.get('email'),
                'password': user_data.get('password'),
                'confirm_password': user_data.get('confirm_password'),
                'phone': user_data.get('phone')
            }
            try:
                if request.env["res.users"].sudo().search([("login", "=", values.get("login"))]):
                    return invalid_response("Error", _("Another user is already registered using this email address."), 400)
                # sudo_users = request.env["res.users"].with_context(create_user=True).sudo()
                # is_created = sudo_users.signup(values, values.get("token"))
                # sudo_users.reset_password(values.get("login"))
                # if is_created:
                    # return valid_response(_("Check your email to activate your account!"))
                # else:
                    # return invalid_response("Error", _("Could not create a new account."))

                # Wallet Invitation
                if (user_data.get("invitation_code")):
                    invitation_request = request.env["smartpay_operations.request"].sudo().search(
                        [('request_type', '=', 'wallet_invitation'), ('name', '=', user_data.get("invitation_code")),
                        ('mobile_number', '=', values.get("phone")), ("stage_id", "=", 1)], order="id DESC", limit=1)
                    if not invitation_request:
                        return invalid_response("request_not_found", _("Invitation Code (%s) for mobile number (%s) does not exist!") % (
                            user_data.get("invitation_code"), values.get("phone")), 400)

                AuthSignupHome().do_signup(values)

                if (user_data.get("invitation_code")):
                    invited_user = request.env['res.users'].sudo().search([("login", "=", values.get("login"))])

                    # Bonus for both inviter and invited user
                    # wallet_transaction_sudo = request.env['website.wallet.transaction'].sudo()
                    irc_param = request.env['ir.config_parameter'].sudo()
                    # wallet_bouns_notify_mode = irc_param.get_param("smartpay_operations.wallet_bouns_notify_mode")
                    bounce_expense_account_id = irc_param.get_param("smartpay_operations.bounce_expense_account_id")
                    bounce_expense_account = request.env['account.account'].sudo().browse(int(bounce_expense_account_id)).exists()

                    bonus_wallet_type_id = self.env.ref('smartpay_operations.wallet_type_bonus')
                    inviter_bonus = float(irc_param.get_param("smartpay_operations.inviter_bonus"))
                    if inviter_bonus > 0:
                        '''
                        inviter_bonus_currency_id = int(irc_param.get_param("smartpay_operations.inviter_bonus_currency_id"))
                        label = _('Bonus for inviter user')
                        partner_wallet_id = invitation_request.partner_id.get_transaction_wallet(type=bonus_wallet_type_id)
                        partner_id_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                        inviter_wallet_create = wallet_transaction_sudo.create(
                            {'wallet_type': 'credit', 'partner_id': invitation_request.partner_id.id,
                             'request_id': invitation_request.id,
                             'reference': 'request', 'label': label,
                             'amount': inviter_bonus, 'currency_id': inviter_bonus_currency_id,
                             'wallet_balance_before': partner_id_wallet_balance,
                             'wallet_balance_after': partner_id_wallet_balance + inviter_bonus,
                             'status': 'done'})
                        request.env.cr.commit()

                        invitation_request.partner_id.update(
                            {'wallet_balance': partner_id_wallet_balance 
                            + inviter_bonus})
                        request.env.cr.commit()

                        # Notify Inviter
                        if wallet_bouns_notify_mode == 'inbox':
                            request.env['mail.thread'].sudo().message_notify(
                                subject=label,
                                body=_('<p>%s %s successfully added to your wallet.</p>') % (inviter_bonus,_(inviter_bonus_currency_id.name)),
                                partner_ids=[(4, invitation_request.partner_id.id)],
                            )
                        elif wallet_bouns_notify_mode == 'email':
                            inviter_wallet_create.wallet_transaction_email_send()
                        elif wallet_bouns_notify_mode == 'sms' and invitation_request.partner_id.mobile:
                            inviter_wallet_create.sms_send_wallet_transaction(wallet_bouns_notify_mode, 'wallet_bouns',
                                                                              invitation_request.partner_id.mobile,
                                                                              invitation_request.partner_id.name, label,
                                                                              '%s %s' % (inviter_bonus,_(inviter_bonus_currency_id.name)),
                                                                              invitation_request.partner_id.country_id.phone_code or '2')
                        '''
                        inviter_bonus_currency_id = self.env['res.currency'].browse(int(irc_param.get_param("smartpay_operations.inviter_bonus_currency_id"))).exists()
                        inviter_wallet_id = invitation_request.partner_id.get_transaction_wallet(type=bonus_wallet_type_id)
                        if not inviter_wallet_id:
                            return invalid_response("wallet_not_found",
                                                    _("No Matched Wallet found for partner [%s] %s") % (
                                                        invitation_request.partner_id.ref,
                                                        invitation_request.partner_id.name), 400)
                        wallet_transaction_id, wallet_balance_after = inviter_wallet_id.create_wallet_transaction(
                            'credit', invitation_request.partner_id, 'request', _('Bonus for inviter user'),
                            inviter_bonus, inviter_bonus_currency_id, invitation_request,
                            'smartpay_operations.wallet_bouns_notify_mode', 'wallet_bouns',
                            _('<p>%s %s successfully added to your wallet.</p>') % (inviter_bonus,_(inviter_bonus_currency_id.name)),
                            bounce_expense_account, 'Invitation Bouns'
                        )

                    invited_user_bonus = float(irc_param.get_param("smartpay_operations.invited_user_bonus"))
                    if invited_user_bonus > 0:
                        '''
                        invited_user_bonus_currency_id = int(irc_param.get_param("smartpay_operations.invited_user_bonus_currency_id"))
                        label = _('Bonus for invited user')
                        invited_wallet_create = wallet_transaction_sudo.create(
                            {'wallet_type': 'credit', 'partner_id': invited_user.partner_id.id,
                             'request_id': invitation_request.id,
                             'reference': 'request', 'label': label,
                             'amount': invited_user_bonus, 'currency_id': invited_user_bonus_currency_id,
                             'wallet_balance_before': 0.0,
                             'wallet_balance_after': invited_user_bonus,
                             'status': 'done'})
                        request.env.cr.commit()

                        invited_user.partner_id.update({'wallet_balance': invited_user_bonus})
                        request.env.cr.commit()
                        invitation_request.sudo().write({'wallet_transaction_id': invited_wallet_create.id})
                        request.env.cr.commit()

                        # Notify invited User
                        if wallet_bouns_notify_mode == 'inbox':
                            request.env['mail.thread'].sudo().message_notify(
                                subject=label,
                                body=_('<p>%s %s bonus successfully added to your wallet.</p>') % (invited_user_bonus,_(invited_user_bonus_currency_id.name)),
                                partner_ids=[(4, invited_user.partner_id.id)],
                            )
                        elif wallet_bouns_notify_mode == 'email':
                            invited_wallet_create.wallet_transaction_email_send()
                        elif wallet_bouns_notify_mode == 'sms' and invited_user.partner_id.mobile:
                            inviter_wallet_create.sms_send_wallet_transaction(wallet_bouns_notify_mode,
                                                                              'wallet_bouns',
                                                                              invited_user.partner_id.mobile,
                                                                              invited_user.name, label,
                                                                              '%s %s' % (invited_user_bonus,
                                                                                         _(invited_user_bonus_currency_id.name)),
                                                                              invited_user.partner_id.country_id.phone_code or '2')
                        '''
                        invited_user_bonus_currency_id = self.env['res.currency'].browse(int(irc_param.get_param("smartpay_operations.invited_user_bonus_currency_id"))).exists()
                        invited_user_wallet_id = invited_user.partner_id.get_transaction_wallet(type=bonus_wallet_type_id)
                        wallet_transaction_id, wallet_balance_after = invited_user_wallet_id.create_wallet_transaction(
                            'credit', invited_user.partner_id, 'request', _('Bonus for invited user'),
                            invited_user_bonus, invited_user_bonus_currency_id, invitation_request,
                            'smartpay_operations.wallet_bouns_notify_mode', 'wallet_bouns',
                            _('<p>%s %s successfully added to your wallet.</p>') % (invited_user_bonus, _(invited_user_bonus_currency_id.name)),
                            bounce_expense_account, 'Invitation Bouns'
                        )

                    '''
                    if inviter_bonus > 0 or invited_user_bonus > 0:
                        # Create journal entry for increase AR balance for both inviter and invited user.
                        inviter_user_receivable_account = invitation_request.partner_id.property_account_receivable_id
                        invited_user_receivable_account = invited_user.partner_id.property_account_receivable_id
                        account_move = request.env['account.move'].sudo().create({
                            'journal_id': request.env['account.journal'].sudo().search([('type', '=', 'general')], limit=1).id,
                        })

                        bonus_total_amount = 0
                        if inviter_bonus > 0:
                            bonus_total_amount += inviter_bonus
                            request.env['account.move.line'].with_context(check_move_validity=False).sudo().create({
                                'name': invitation_request.name + ': Invitation Bouns',
                                'move_id': account_move.id,
                                'account_id': inviter_user_receivable_account.id,
                                'partner_id': invitation_request.partner_id.id,
                                'credit': inviter_bonus,
                            })
                        if invited_user_bonus > 0:
                            bonus_total_amount += invited_user_bonus
                            request.env['account.move.line'].with_context(check_move_validity=False).sudo().create({
                                'name': invitation_request.name + ': Invitation Bouns',
                                'move_id': account_move.id,
                                'account_id': invited_user_receivable_account.id,
                                'partner_id': invited_user.partner_id.id,
                                'credit': invited_user_bonus,
                            })

                        request.env['account.move.line'].with_context(check_move_validity=False).sudo().create({
                            'name': invitation_request.name + ': Invitation Bouns',
                            'move_id': account_move.id,
                            'account_id': bounce_expense_account.id,
                            'debit': bonus_total_amount,
                        })
                        account_move.post()
                    '''

                    invitation_request.sudo().write({'stage_id': 5})

                return valid_response(_("Congratulation. Your Account successfully created."))
            except Exception as e:
                _logger.error("%s", e)
                return invalid_response("Error", _("Could not create a new account.") + " ==> " + str(e), 500)

        @validate_token
        @http.route('/api/get_user_profile', type="http", auth="none", methods=["POST"], csrf=False)
        def get_user_profile(self, **payload):
            _logger.info("@@@@@@@@@@@@@@@@@@@ Calling Get User Profile API")
            return restful_main().get('res.users', request.env.user.id, **payload)

        @validate_token
        @http.route('/api/update_user_profile', type="http", auth="none", methods=["POST"], csrf=False)
        def update_user_profile(self, **user_data):
            _logger.info("@@@@@@@@@@@@@@@@@@@ Calling Update User Profile API")
            return restful_main().put('res.users', request.env.user.id, **user_data)

        @validate_token
        @http.route('/api/get_user_sales_person', type="http", auth="none", methods=["POST"], csrf=False)
        def get_user_sales_person(self, **payload):
            _logger.info("@@@@@@@@@@@@@@@@@@@ Calling Get User Sales Person API")
            return restful_main().get('res.users', request.env.user.partner_id.user_id.id, **payload)

        @validate_token
        @http.route('/api/deactive_user', type="http", auth="none", methods=["POST"], csrf=False)
        def deactive_user(self, **user_data):
            _logger.info("@@@@@@@@@@@@@@@@@@@ Calling Deactivate User API")
            is_updated = False
            user = request.env['res.users'].sudo().search([('id', '=', request.env.user.id)], limit=1)
            if user:
                is_updated = user.sudo().write({'active': False})

            if is_updated:
                return valid_response(_('User Deactivated Successfully'))
            else:
                return invalid_response("Error", _("The User didn't deactivated"), 500)

        @http.route('/api/test', type="http", auth="none", methods=["GET"], csrf=False)
        def test(self, **user_data):
            _logger.info("@@@@@@@@@@@@@@@@@@@ Calling Test API")
            return valid_response(_('Tested Successfully'))

    class RequestApiTemp(http.Controller):

        @validate_token
        @validate_machine
        @http.route('/api/create_machine_request', type="http", auth="none", methods=["POST"], csrf=False)
        def create_machine_request(self, **request_data):
            _logger.info("@@@@@@@@@@@@@@@@@@@ Calling Machine Request API")
            request_data['machine_serial'] = request.httprequest.headers.get("machine_serial")

            if not request_data.get('request_type') or request_data.get('request_type') not in _REQUEST_TYPES_IDS:
                return invalid_response("request_type", _("request type invalid"), 400)

            if request_data.get('request_type') == 'recharge_wallet':
                if not request_data.get('trans_number'):
                    return invalid_response("receipt_number_not_found", _("missing deposit receipt number in request data"), 400)
                if not request_data.get('trans_date'):
                    return invalid_response("date_not_found", _("missing deposit date in request data"), 400)
                if not request_data.get('trans_amount'):
                    return invalid_response("amount_not_found", _("missing deposit amount in request data"), 400)
                if not any(hasattr(field_value, 'filename') for field_name, field_value in request_data.items()):
                    return invalid_response("receipt_not_found", _("missing deposit receipt attachment in request data"), 400)

                open_request = request.env["smartpay_operations.request"].sudo().search(
                    [('request_type', '=', 'recharge_wallet'), ("partner_id", "=", request.env.user.partner_id.id),
                     ("stage_id", "=", 1)], order="id DESC", limit=1)
                if open_request:
                    open_request_in_minute = open_request.filtered(lambda r: r.create_date >= date_time.now() - timedelta(minutes=1))
                    if open_request_in_minute:
                        return invalid_response("request_already_exist",
                                                _("You have a wallet recharge request in progress with REQ Number (%s)")
                                                % (open_request_in_minute.name), 400)
                    else:
                        open_request.update({'stage_id': 3})

                request_data['product_id'] = request.env["product.product"].sudo().search([('name', '=', 'Wallet Recharge')]).id

            if not request_data.get('product_id') and request_data.get('request_type') not in ('general_inquiry', 'pay_invoice', 'wallet_invitation'):
                return invalid_response("service_not_found", _("missing service in request data"), 400)
            elif request_data.get('request_type') not in ('general_inquiry', 'pay_invoice', 'wallet_invitation'):
                service = request.env["product.product"].sudo().search([("id", "=", request_data.get('product_id')), ("type", "=", "service")],
                                                                       order="id DESC", limit=1)
                if not service:
                    return invalid_response("service", _("service invalid"), 400)

            if request_data.get('request_type') == 'wallet_invitation':
                if not request_data.get('mobile_number'):
                    return invalid_response("mobile_number_not_found", _("missing mobile number for invited user in request data"), 400)

                open_request = request.env["smartpay_operations.request"].sudo().search(
                    [('request_type', '=', 'wallet_invitation'), ('mobile_number', '=', request_data.get('mobile_number')),
                     ('partner_id', '=', request.env.user.partner_id.id), ("stage_id", "=", 1)], order="id DESC", limit=1)
                if open_request:
                    return invalid_response("request_already_exist",
                                            _("You have a wallet invitation request in progress for mobile number (%s) with REQ Number (%s)") % (
                                                request_data.get('mobile_number'), open_request.name), 400)

                done_request = request.env["smartpay_operations.request"].sudo().search(
                    [('request_type', '=', 'wallet_invitation'),
                     ('mobile_number', '=', request_data.get('mobile_number')), ("stage_id", "=", 5)],
                    order="id DESC", limit=1)
                if done_request:
                    return invalid_response("request_already_exist",
                                            _("The mobile number (%s) already has a wallet") % (
                                                request_data.get('mobile_number')), 400)

            if request_data.get('request_type') == 'pay_invoice':
                if not request_data.get('trans_amount'):
                    return invalid_response("amount_not_found", _("missing invoice amount in request data"), 400)

            if request_data.get('request_type') == 'service_bill_inquiry' or request_data.get('request_type') == 'pay_service_bill':
                # Tamayoz TODO: how to check billingAcct when provider in ('fawry', 'khales')
                # if not request_data.get('billingAcct'):
                    # return invalid_response("billingAcct_not_found", _("missing billing account in request data"), 400)

                provider_provider = request_data.get('provider')
                if request_data.get('request_type') == 'pay_service_bill':
                    if provider_provider == 'fawry' or provider_provider == 'khales':
                        if not request_data.get('currency_id'):
                            return invalid_response("curCode_not_found",
                                                    _("missing bill currency code in request data"), 400)
                        if not request_data.get('pmtMethod'):
                            return invalid_response("pmtMethod_not_found",
                                                    _("missing payment method in request data"), 400)

                    if provider_provider == 'khales':
                        if not request_data.get('pmtType'):
                            return invalid_response("pmtType_not_found", _("missing payment type in request data"), 400)
                        '''
                        if not request_data.get('billerId'):
                            return invalid_response("billerId_not_found", _("missing biller id in request data"), 400)
                        '''
                        if not request_data.get('ePayBillRecID'):
                            return invalid_response("ePayBillRecID_not_found", _("missing ePay Bill Rec ID in request data"), 400)
                        # if not request_data.get('pmtId'):
                            # return invalid_response("pmtId_not_found", _("missing payment id in request data"), 400)
                        if not request_data.get('feesAmt'):
                            return invalid_response("feesAmt_not_found", _("missing fees amount in request data"), 400)
                        # if not request_data.get('pmtRefInfo'):
                            # return invalid_response("pmtRefInfo_not_found", _("missing payment Ref Info in request data"), 400)
                        payAmtTemp = float(request_data.get('trans_amount'))
                        payAmts = request_data.get('payAmts')
                        if payAmts:
                            payAmts = ast.literal_eval(payAmts)
                            for payAmt in payAmts:
                                payAmtTemp -= float(payAmt.get('AmtDue'))
                            if payAmtTemp != 0:
                                return invalid_response("payAmts_not_match",
                                                        _("The sum of payAmts must be equals trans_amount"), 400)
                        feesAmtTemp = request_data.get('feesAmt') or 0.00
                        feesAmts = request_data.get('feesAmts')
                        if feesAmts:
                            feesAmts = ast.literal_eval(feesAmts)
                            for feeAmt in feesAmts:
                                feesAmtTemp -= float(feeAmt.get('Amt'))
                            if feesAmtTemp != 0:
                                return invalid_response("feesAmts_not_match",
                                                        _("The sum of feesAmts must be equals feesAmt"), 400)

                    if ((provider_provider == 'fawry' and request_data.get('pmtType') == "POST") or provider_provider == 'khales') \
                            and not request_data.get('billRefNumber'):
                        return invalid_response("billRefNumber_not_found", _("missing bill reference number in request data"), 400)

                    # Provider is mandatory because the service fee is different per provider.
                    # So the user must send provider that own the bill inquiry request for prevent pay bill
                    # with total amount different of total amount in bill inquiry
                    if provider_provider:
                        provider = request.env['payment.acquirer'].sudo().search([("provider", "=", provider_provider)])
                        # if provider: # Tamayoz Note: Comment this condition for solving service_providerinfo assign before initilizing
                        service_providerinfo = request.env['product.supplierinfo'].sudo().search([
                            ('product_tmpl_id', '=', service.product_tmpl_id.id),
                            ('name', '=', provider.related_partner.id)
                        ])
                        if not service_providerinfo:
                            return invalid_response(
                                "Incompatible_provider_service", _("%s is not a provider for (%s) service") % (
                                    provider_provider, service.name or '-'), 400)
                        elif provider_provider in ('fawry', 'masary'):
                            inquiryTransactionId = request_data.get('inquiryTransactionId')
                            if (json.loads(service_providerinfo.biller_info, strict=False).get('inquiry_required') # Tamayoz TODO: Rename inquiry_required in standard API
                                # or json.loads(service_providerinfo.biller_info, strict=False).get('SupportPmtReverse')
                            ) \
                                    and not inquiryTransactionId:
                                return invalid_response("inquiryTransactionId_not_found", _("missing inquiry transaction id in request data"), 400)
                    else:
                        return invalid_response("provider_not_found",
                                                _("missing provider in request data"), 400)

                    trans_amount = float(request_data.get('trans_amount'))
                    if not trans_amount:
                        return invalid_response("amount_not_found",
                                                _("missing bill amount in request data"), 400)
                    else:
                        # Calculate Fees
                        provider_fees_calculated_amount = 0.0
                        provider_fees_actual_amount = 0.0
                        merchant_cashback_amount = 0.0
                        customer_cashback_amount = 0.0
                        extra_fees_amount = 0.0
                        commissions = request.env['product.supplierinfo.commission'].sudo().search_read(
                            domain=[('vendor', '=', service_providerinfo.name.id),
                                    ('vendor_product_code', '=', service_providerinfo.product_code)],
                            fields=['Amount_Range_From', 'Amount_Range_To',
                                    'Extra_Fee_Amt', 'Extra_Fee_Prc',
                                    'Mer_Fee_Amt', 'Mer_Fee_Prc', 'Mer_Fee_Prc_MinAmt', 'Mer_Fee_Prc_MaxAmt',
                                    'Mer_Comm_Full_Fix_Amt', 'Cust_Comm_Full_Fix_Amt',
                                    'Bill_Merchant_Comm_Prc', 'Bill_Customer_Comm_Prc']
                        )
                        for commission in commissions:
                            if commission['Amount_Range_From'] <= trans_amount \
                                    and commission['Amount_Range_To'] >= trans_amount:
                                if commission['Mer_Comm_Full_Fix_Amt'] > 0:
                                    merchant_cashback_amount = commission['Mer_Comm_Full_Fix_Amt']
                                    customer_cashback_amount = commission['Cust_Comm_Full_Fix_Amt']
                                elif commission['Bill_Merchant_Comm_Prc'] > 0:
                                    merchant_cashback_amount = trans_amount * commission[
                                        'Bill_Merchant_Comm_Prc'] / 100
                                    customer_cashback_amount = trans_amount * commission[
                                        'Bill_Customer_Comm_Prc'] / 100
                                if commission['Extra_Fee_Amt'] > 0:
                                    extra_fees_amount = commission['Extra_Fee_Amt']
                                elif commission['Extra_Fee_Prc'] > 0:
                                    extra_fees_amount = trans_amount * commission['Extra_Fee_Prc'] / 100
                                if commission['Mer_Fee_Amt'] > 0:
                                    provider_fees_calculated_amount = commission['Mer_Fee_Amt']
                                elif commission['Mer_Fee_Prc'] > 0:
                                    # Fees amount = FA + [Percentage * Payment Amount]
                                    # Fees amount ====================> provider_fees_calculated_amount
                                    # FA =============================> provider_fees_calculated_amount
                                    # [Percentage * Payment Amount] ==> provider_fees_prc_calculated_amount
                                    provider_fees_prc_calculated_amount = trans_amount * commission[
                                        'Mer_Fee_Prc'] / 100
                                    if provider_fees_prc_calculated_amount < commission['Mer_Fee_Prc_MinAmt']:
                                        provider_fees_prc_calculated_amount = commission['Mer_Fee_Prc_MinAmt']
                                    elif provider_fees_prc_calculated_amount > commission['Mer_Fee_Prc_MaxAmt'] \
                                            and commission['Mer_Fee_Prc_MaxAmt'] > 0:
                                        provider_fees_prc_calculated_amount = commission['Mer_Fee_Prc_MaxAmt']
                                    provider_fees_calculated_amount += provider_fees_prc_calculated_amount
                                elif provider_provider == 'khales':
                                    provider_fees_calculated_amount = float(request_data.get('feesAmt'))
                                break
                        calculated_payment_amount = trans_amount + provider_fees_calculated_amount + extra_fees_amount
                        machine_wallet_reservation_id = False
                        unlink_wallet_reservation = False
                        if not json.loads(service_providerinfo.biller_info, strict=False).get('CorrBillTypeCode') or json.loads(service_providerinfo.biller_info, strict=False).get('Type') == 'CASHININT':
                            if service.has_sale_limit:
                                limit_fees_amounts = {}
                                for sale_limit_id in service.sale_limit_ids:
                                    limit_type = sale_limit_id.limit_type
                                    limit_amount = sale_limit_id.limit_amount
                                    partner_sale_limit_id = request.env['res.partner.product.sale.limit'].sudo().search(
                                        [('partner_id','=',request.env.user.partner_id.id),
                                         ('product_tmpl_id', '=', service.product_tmpl_id.id),
                                         ('limit_type','=',limit_type)], limit=1)
                                    if partner_sale_limit_id:
                                        limit_amount = partner_sale_limit_id.limit_amount
                                    timetuple = date_time.now().timetuple()
                                    sale_limit_domain = [('partner_id', '=', request.env.user.partner_id.id),
                                                         ('product_id', '=', service.id),
                                                         ('limit_type', '=', limit_type),
                                                         ('year', '=', timetuple.tm_year)]
                                    if limit_type == 'daily':
                                        sale_limit_domain += [('day', '=', timetuple.tm_yday)]
                                    elif limit_type == 'weekly':
                                        sale_limit_domain += [('week', '=', date_time.now().isocalendar()[1])]
                                    elif limit_type == 'monthly':
                                        sale_limit_domain += [('month', '=', timetuple.tm_mon)]
                                    sale_limit = request.env['res.partner.sale.limit'].sudo().search(sale_limit_domain,
                                        order="id DESC", limit=1)
                                    calculated_sold_amount = calculated_payment_amount
                                    if sale_limit:
                                        calculated_sold_amount += sale_limit.sold_amount
                                    if limit_amount < calculated_sold_amount:
                                        over_limit_fees_ids = []
                                        if partner_sale_limit_id:
                                            if partner_sale_limit_id.over_limit_fees_policy == 'product_over_limit_fees' and partner_sale_limit_id.product_over_limit_fees_ids:
                                                over_limit_fees_ids = partner_sale_limit_id.product_over_limit_fees_ids
                                                limit_amount = over_limit_fees_ids.sorted(lambda l: l.sale_amount_to, reverse=True)[0].sale_amount_to + partner_sale_limit_id.limit_amount
                                            if partner_sale_limit_id.over_limit_fees_policy == 'custom_over_limit_fees' and partner_sale_limit_id.over_limit_fees_ids:
                                                over_limit_fees_ids = partner_sale_limit_id.over_limit_fees_ids
                                                limit_amount = over_limit_fees_ids.sorted(lambda l: l.sale_amount_to, reverse=True)[0].sale_amount_to + partner_sale_limit_id.limit_amount
                                        else:
                                            if sale_limit_id.has_over_limit_fees and sale_limit_id.over_limit_fees_ids:
                                                over_limit_fees_ids = sale_limit_id.over_limit_fees_ids
                                                limit_amount = over_limit_fees_ids.sorted(lambda l: l.sale_amount_to, reverse=True)[0].sale_amount_to + sale_limit_id.limit_amount

                                        if limit_amount < calculated_sold_amount:
                                            return invalid_response("%s_limit_exceeded" % limit_type,
                                                                    _("%s limit exceeded for service (%s)") % (
                                                                        limit_type, service.name), 400)

                                        limit_fees_amount = 0
                                        for over_limit_fees_id in over_limit_fees_ids:
                                            if over_limit_fees_id['sale_amount_from'] <= trans_amount and over_limit_fees_id['sale_amount_to'] >= trans_amount:
                                                if over_limit_fees_id['fees_amount'] > 0:
                                                    limit_fees_amount = over_limit_fees_id['fees_amount']
                                                elif over_limit_fees_id['fees_amount_percentage'] > 0:
                                                    limit_fees_amount = trans_amount * over_limit_fees_id['fees_amount_percentage'] / 100
                                                break
                                        if limit_fees_amount > 0:
                                            limit_fees_amounts.update({limit_type: limit_fees_amount})
                                            calculated_payment_amount += limit_fees_amount

                            if request_data.get("wallet_id"):
                                partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(wallet_id=request_data.get("wallet_id"),
                                                                                                       service=service,
                                                                                                       trans_amount=calculated_payment_amount)
                            else:
                                partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(service=service,
                                                                                                       trans_amount=calculated_payment_amount)
                            if not partner_wallet_id:
                                return invalid_response("wallet_not_found",
                                                        _("No Matched Wallet found for partner [%s] %s") % (
                                                        request.env.user.partner_id.ref,
                                                        request.env.user.partner_id.name), 400)
                            # Check Wallet Transaction limits
                            if partner_wallet_id.type.has_trans_limit:
                                wallet_limit_fees_amounts = {}
                                for trans_limit_id in partner_wallet_id.type.trans_limit_ids:
                                    wallet_limit_type = trans_limit_id.limit_type
                                    wallet_limit_amount = trans_limit_id.limit_amount
                                    wallet_trans_limit_id = request.env['wallet.wallet.type.trans.limit'].sudo().search(
                                        [('wallet_id','=',partner_wallet_id.id),
                                         # ('wallet_type_id', '=', partner_wallet_id.type.id),
                                         ('limit_type','=',wallet_limit_type)], limit=1)
                                    if wallet_trans_limit_id:
                                        wallet_limit_amount = wallet_trans_limit_id.limit_amount
                                    timetuple = date_time.now().timetuple()
                                    trans_limit_domain = [('wallet_id', '=', partner_wallet_id.id),
                                                         # ('wallet_type_id', '=', partner_wallet_id.type.id),
                                                         ('limit_type', '=', wallet_limit_type),
                                                         ('year', '=', timetuple.tm_year)]
                                    if wallet_limit_type == 'daily':
                                        trans_limit_domain += [('day', '=', timetuple.tm_yday)]
                                    elif wallet_limit_type == 'weekly':
                                        trans_limit_domain += [('week', '=', date_time.now().isocalendar()[1])]
                                    elif wallet_limit_type == 'monthly':
                                        trans_limit_domain += [('month', '=', timetuple.tm_mon)]
                                    trans_limit = request.env['wallet.trans.limit'].sudo().search(trans_limit_domain,
                                        order="id DESC", limit=1)
                                    calculated_trans_amount = calculated_payment_amount
                                    if trans_limit:
                                        calculated_trans_amount += trans_limit.trans_amount
                                    if wallet_limit_amount < calculated_trans_amount:
                                        wallet_over_limit_fees_ids = []
                                        if wallet_trans_limit_id:
                                            if wallet_trans_limit_id.over_limit_fees_policy == 'wallet_type_over_limit_fees' and wallet_trans_limit_id.wallet_type_over_limit_fees_ids:
                                                wallet_over_limit_fees_ids = wallet_trans_limit_id.wallet_type_over_limit_fees_ids
                                                wallet_limit_amount = wallet_over_limit_fees_ids.sorted(lambda l: l.trans_amount_to, reverse=True)[0].trans_amount_to + wallet_trans_limit_id.limit_amount
                                            if wallet_trans_limit_id.over_limit_fees_policy == 'custom_over_limit_fees' and wallet_trans_limit_id.over_limit_fees_ids:
                                                wallet_over_limit_fees_ids = wallet_trans_limit_id.over_limit_fees_ids
                                                wallet_limit_amount = wallet_over_limit_fees_ids.sorted(lambda l: l.trans_amount_to, reverse=True)[0].trans_amount_to + wallet_trans_limit_id.limit_amount
                                        else:
                                            if trans_limit_id.has_over_limit_fees and trans_limit_id.over_limit_fees_ids:
                                                wallet_over_limit_fees_ids = trans_limit_id.over_limit_fees_ids
                                                wallet_limit_amount = wallet_over_limit_fees_ids.sorted(lambda l: l.trans_amount_to, reverse=True)[0].trans_amount_to + trans_limit_id.limit_amount

                                        if wallet_limit_amount < calculated_trans_amount:
                                            return invalid_response("%s_limit_exceeded" % wallet_limit_type,
                                                                    _("%s limit exceeded for wallet type (%s)") % (
                                                                        wallet_limit_type, partner_wallet_id.type.name), 400)

                                        wallet_limit_fees_amount = 0
                                        for wallet_over_limit_fees_id in wallet_over_limit_fees_ids:
                                            if wallet_over_limit_fees_id['trans_amount_from'] <= trans_amount and wallet_over_limit_fees_id['trans_amount_to'] >= trans_amount:
                                                if wallet_over_limit_fees_id['fees_amount'] > 0:
                                                    wallet_limit_fees_amount = wallet_over_limit_fees_id['fees_amount']
                                                elif wallet_over_limit_fees_id['fees_amount_percentage'] > 0:
                                                    wallet_limit_fees_amount = trans_amount * wallet_over_limit_fees_id['fees_amount_percentage'] / 100
                                                break
                                        if wallet_limit_fees_amount > 0:
                                            wallet_limit_fees_amounts.update({wallet_limit_type: wallet_limit_fees_amount})
                                            calculated_payment_amount += wallet_limit_fees_amount

                            unlink_wallet_reservation = False
                            machine_wallet_reservation_id, machine_wallet_balance, machine_wallet_available_amount = \
                                partner_wallet_id.update_wallet_reserved_balance(
                                    _('Pay Service Bill for %s service') % (service.name), calculated_payment_amount,
                                    request.env.user.company_id.currency_id, 'request'
                                )
                            # # machine_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                            # machine_wallet_available_amount = partner_wallet_id.available_amount if partner_wallet_id else 0
                            # if machine_wallet_available_amount < calculated_payment_amount:
                            if not machine_wallet_reservation_id:
                                return invalid_response("machine_balance_not_enough",
                                                        _("Machine Wallet Available Balance (%s) less than the payment amount (%s)") % (
                                                            machine_wallet_available_amount, calculated_payment_amount), 400)

            request_data['partner_id'] = request.env.user.partner_id.id
            model_name = 'smartpay_operations.request'
            model_record = request.env['ir.model'].sudo().search([('model', '=', model_name)])

            try:
                data = WebsiteForm().extract_data(model_record, request_data)
            # If we encounter an issue while extracting data
            except ValidationError as e:
                # I couldn't find a cleaner way to pass data to an exception
                return invalid_response("Error", _("Could not submit you request.") + " ==> " + str(e), 500)

            try:
                id_record = WebsiteForm().insert_record(request, model_record, data['record'], data['custom'], data.get('meta'))
                if id_record:
                    WebsiteForm().insert_attachment(model_record, id_record, data['attachments'])
                    request.env.cr.commit()
                    machine_request = model_record.env[model_name].sudo().browse(id_record)
                else:
                    return invalid_response("Error", _("Could not submit you request."), 500)

            # Some fields have additional SQL constraints that we can't check generically
            # Ex: crm.lead.probability which is a float between 0 and 1
            # TODO: How to get the name of the erroneous field ?
            except IntegrityError as e:
                return invalid_response("Error", _("Could not submit you request.") + " ==> " + str(e), 500)

            if request_data.get('request_type') == 'recharge_wallet':
                return valid_response({"message": _("Recharge your wallet request was submit successfully."),
                                        "request_number": machine_request.name
                                       })
            elif request_data.get('request_type') == 'wallet_invitation':
                return valid_response({"message": _("Wallet inivitation request for mobile number (%s) was submit successfully.") % (
                                                request_data.get('mobile_number')),
                                        "request_number": machine_request.name
                                       })
            elif request_data.get('request_type') == 'service_bill_inquiry':
                lang = request_data.get('lang')
                billingAcct = request_data.get('billingAcct')
                extraBillingAcctKeys = request_data.get('extraBillingAcctKeys')
                if extraBillingAcctKeys:
                    extraBillingAcctKeys = ast.literal_eval(extraBillingAcctKeys)
                customProperties = request_data.get('customProperties')
                if customProperties:
                    customProperties = ast.literal_eval(customProperties)

                provider_response = {}
                error = {}
                for provider_info in service.seller_ids:
                    provider = request.env['payment.acquirer'].sudo().search(
                        [("related_partner", "=", provider_info.name.id)])
                    if provider:
                        if provider.server_state == 'offline':
                            error.update({provider.provider + "_response": {'error_message': _("Service Not Available")}})
                            break
                        trans_amount = 0.0
                        provider_channel = False
                        machine_channels = request.env['payment.acquirer.channel'].sudo().search([("acquirer_id", "=", provider.id),
                                                                                                  ("type", "in", ("machine", "internet"))], limit=1)
                        if machine_channels:
                            provider_channel = machine_channels[0]
                        if provider.provider == "fawry":
                            provider_response = provider.get_fawry_bill_details(lang, provider_info.product_code,
                                                                                billingAcct, extraBillingAcctKeys,
                                                                                provider_channel, customProperties,
                                                                                machine_request.name)
                            if provider_response.get('Success'):
                                billRecType = provider_response.get('Success')
                                provider_response_json = suds_to_json(billRecType)
                                for BillSummAmt in billRecType['BillInfo']['BillSummAmt']:
                                    if BillSummAmt['BillSummAmtCode'] == 'TotalAmtDue':
                                        trans_amount += float(BillSummAmt['CurAmt']['Amt'])
                                        break
                        elif provider.provider == "khales":
                            provider_response = {}
                            biller_info_json_dict = json.loads(provider_info.with_context(lang=request.env.user.lang).biller_info, strict=False)
                            # Handel billingAcct format if exist
                            if biller_info_json_dict.get('BillTypeAcctFormat') and biller_info_json_dict.get('BillTypeAcctFormatSpliter'):
                                formatedBillingAcct = []
                                keysToBeRemoved = []
                                for format in biller_info_json_dict.get('BillTypeAcctFormat').split(biller_info_json_dict.get('BillTypeAcctFormatSpliter')):
                                    if format == 'billingAcct':
                                        formatedBillingAcct.append(billingAcct)
                                    else:
                                        is_extra_key = False
                                        for extraBillingAcctKey in extraBillingAcctKeys:
                                            if extraBillingAcctKey.get("Key") == format:
                                                formatedBillingAcct.append(extraBillingAcctKey.get("Value"))
                                                keysToBeRemoved.append(extraBillingAcctKey)
                                                is_extra_key = True
                                                break
                                        if not is_extra_key:
                                            formatedBillingAcct.append(format)
                                extraBillingAcctKeys = [x for x in extraBillingAcctKeys if x not in keysToBeRemoved]
                                billingAcct = biller_info_json_dict.get('BillTypeAcctFormatSpliter').join(formatedBillingAcct)

                            '''
                            machine_serial = None
                            if len(request.env.user.machine_serial) > 16:  # Ingenico POS
                                machine_serial = request.env.user.machine_serial
                                machine_serial = machine_serial[len(machine_serial) - 16:len(machine_serial)]
                            '''
                            machine_serial = request.env.user.machine_serial
                            if machine_serial and len(machine_serial) > 16:
                                machine_serial = machine_serial[len(machine_serial) - 16:len(machine_serial)]
                            bill_response = provider.get_khales_bill_details(lang, machine_serial or machine_request.name,
                                                                             provider_info.product_code, biller_info_json_dict.get('Code'),
                                                                             billingAcct, extraBillingAcctKeys, provider_channel, machine_request.name)
                            if bill_response.get('Success'):
                                billRecType = bill_response.get('Success')
                                payAmts = billRecType['BillInfo']['CurAmt']
                                if payAmts and isinstance(payAmts, OrderedDict):
                                    payAmts = [payAmts]
                                    billRecType['BillInfo']['CurAmt'] = payAmts
                                success_response = {"bill_response": suds_to_json(billRecType)}
                                # for payAmt in payAmts:
                                    # trans_amount += float(payAmt.get("AmtDue"))
                                trans_amount += float(payAmts[0].get("AmtDue"))
                                if biller_info_json_dict.get('PmtType') == 'POST':
                                    ePayBillRecID = billRecType['EPayBillRecID']
                                    fees_response = provider.get_khales_fees(lang, machine_serial or machine_request.name,
                                                                             ePayBillRecID, payAmts[0], provider_channel, machine_request.name)
                                    provider_fees_calculated_amount = 0.0
                                    if fees_response.get('Success'):
                                        feeInqRsType = fees_response.get('Success')
                                        provider_fees_calculated_amount = float(feeInqRsType['FeesAmt']['Amt'])
                                        # success_response.update({"fees_response": suds_to_json(feeInqRsType)})
                                    else:
                                        feeInqRsType = {"EPayBillRecID": ePayBillRecID, "FeesAmt": {"Amt": "0.0", "CurCode": "818"}}

                                    if provider_fees_calculated_amount == 0:
                                        service_providerinfo = request.env['product.supplierinfo'].sudo().search([
                                            ('product_tmpl_id', '=', service.product_tmpl_id.id),
                                            ('name', '=', provider.related_partner.id)
                                        ])
                                        commissions = request.env[
                                            'product.supplierinfo.commission'].sudo().search_read(
                                            domain=[('vendor', '=', service_providerinfo.name.id),
                                                    (
                                                        'vendor_product_code', '=', service_providerinfo.product_code)],
                                            fields=['Amount_Range_From', 'Amount_Range_To',
                                                    'Extra_Fee_Amt', 'Extra_Fee_Prc',
                                                    'Mer_Fee_Amt', 'Mer_Fee_Prc', 'Mer_Fee_Prc_MinAmt',
                                                    'Mer_Fee_Prc_MaxAmt']
                                        )
                                        for commission in commissions:
                                            if commission['Amount_Range_From'] <= trans_amount \
                                                    and commission['Amount_Range_To'] >= trans_amount:
                                                if commission['Extra_Fee_Amt'] > 0:
                                                    extra_fees_amount = commission['Extra_Fee_Amt']
                                                elif commission['Extra_Fee_Prc'] > 0:
                                                    extra_fees_amount = trans_amount * commission[
                                                        'Extra_Fee_Prc'] / 100
                                                if commission['Mer_Fee_Amt'] > 0:
                                                    provider_fees_calculated_amount = commission['Mer_Fee_Amt']
                                                elif commission['Mer_Fee_Prc'] > 0:
                                                    # Fees amount = FA + [Percentage * Payment Amount]
                                                    # Fees amount ====================> provider_fees_calculated_amount
                                                    # FA =============================> provider_fees_calculated_amount
                                                    # [Percentage * Payment Amount] ==> provider_fees_prc_calculated_amount
                                                    provider_fees_prc_calculated_amount = trans_amount * commission[
                                                        'Mer_Fee_Prc'] / 100
                                                    if provider_fees_prc_calculated_amount < commission[
                                                        'Mer_Fee_Prc_MinAmt']:
                                                        provider_fees_prc_calculated_amount = commission[
                                                            'Mer_Fee_Prc_MinAmt']
                                                    elif provider_fees_prc_calculated_amount > commission[
                                                        'Mer_Fee_Prc_MaxAmt'] \
                                                            and commission['Mer_Fee_Prc_MaxAmt'] > 0:
                                                        provider_fees_prc_calculated_amount = commission[
                                                            'Mer_Fee_Prc_MaxAmt']
                                                    provider_fees_calculated_amount += provider_fees_prc_calculated_amount
                                                break
                                        feeInqRsType['FeesAmt']['Amt'] = "%s" % ((math.floor(provider_fees_calculated_amount * 100)) / 100.0)

                                    success_response.update({"fees_response": suds_to_json(feeInqRsType)})
                                provider_response = {'Success': success_response}

                                provider_response_json = provider_response.get('Success')
                            else:
                                provider_response = bill_response
                        elif provider.provider == "masary":
                            provider_response = provider.get_masary_bill_details(lang, int(provider_info.product_code),
                                                                                extraBillingAcctKeys, provider_channel, machine_request.name)
                            if provider_response.get('Success'):
                                billData = provider_response.get('Success')
                                provider_response_json = billData
                                if billData.get('amount'):
                                    trans_amount += float(billData.get('amount'))
                                # elif billData.get('min_amount'):
                                    # trans_amount += float(billData.get('min_amount'))

                        if provider_response.get('Success'):
                            commissions = request.env['product.supplierinfo.commission'].sudo().search_read(
                                domain=[('vendor', '=', provider_info.name.id), ('vendor_product_code', '=', provider_info.product_code)],
                                fields=['Amount_Range_From', 'Amount_Range_To', 'Extra_Fee_Amt', 'Extra_Fee_Prc']
                            )
                            extra_fees_amount = 0.0
                            for commission in commissions:
                                if commission['Amount_Range_From'] <= trans_amount \
                                        and commission['Amount_Range_To'] >= trans_amount:
                                    if commission['Extra_Fee_Amt'] > 0:
                                        extra_fees_amount = commission['Extra_Fee_Amt']
                                    elif commission['Extra_Fee_Prc'] > 0:
                                        extra_fees_amount = trans_amount * commission['Extra_Fee_Prc'] / 100
                                    break
                            machine_request.update(
                                {"provider_id": provider.id, "provider_response": provider_response_json,
                                 "trans_amount": trans_amount, "extra_fees_amount": extra_fees_amount,
                                 "extra_fees": commissions, "stage_id": 5})
                            request.env.cr.commit()
                            return valid_response(
                                {"message": _("Service Bill Inquiry request was submit successfully."),
                                 "request_number": machine_request.name,
                                 "provider": provider.provider,
                                 "provider_response": provider_response_json,
                                 "extra_fees_amount": extra_fees_amount,
                                 # "extra_fees": commissions
                                 })
                        else:
                            error.update({provider.provider + "_response": provider_response or ''})
                    else:
                        error.update({provider_info.name.name + "_response": _("%s is not a provider for (%s) service") % (
                        provider_info.name.name, service.name)})

                machine_request.update({
                    "provider_response": error or _("(%s) service has not any provider.") % (service.name),
                    "stage_id": 5
                })
                request.env.cr.commit()
                error_key = "user_error"
                error_msg = _("(%s) service has not any provider.") % (service.name)
                if provider:
                    if error.get(provider.provider + "_response").get("error_message"):
                        error_msg = error.get(provider.provider + "_response").get("error_message")
                    elif error.get(provider.provider + "_response").get("error_message_to_be_translated"):
                        error_msg = error.get(provider.provider + "_response").get("error_message_to_be_translated")
                        error_key = "Error"
                elif error.get(provider_info.name.name + "_response"):
                    error_msg = error.get(provider_info.name.name + "_response")
                return invalid_response(error_key, error_msg, 400)

            elif request_data.get('request_type') == 'pay_service_bill':
                if machine_wallet_reservation_id:
                    machine_wallet_reservation_id.update({'request_id': machine_request.id})
                    request.env.cr.commit()
                lang = request_data.get('lang')
                billingAcct = request_data.get('billingAcct')

                extraBillingAcctKeys = request_data.get('extraBillingAcctKeys')
                if extraBillingAcctKeys:
                    extraBillingAcctKeys = ast.literal_eval(extraBillingAcctKeys)

                notifyMobile = request_data.get('notifyMobile')
                billRefNumber = request_data.get('billRefNumber')
                billerId = request_data.get('billerId')
                pmtType = request_data.get('pmtType')

                trans_amount = request_data.get('trans_amount')
                curCode = request_data.get('currency_id')
                payAmts = request_data.get('payAmts')
                if payAmts:
                    payAmts = ast.literal_eval(payAmts)
                else:
                    payAmts = [{'Sequence': '1', 'AmtDue': trans_amount, 'CurCode': curCode}]
                pmtMethod = request_data.get('pmtMethod')

                ePayBillRecID = request_data.get('ePayBillRecID')
                pmtId = request_data.get('pmtId') or machine_request.name
                feesAmt = request_data.get('feesAmt') or 0.00
                feesAmts = request_data.get('feesAmts')
                if feesAmts:
                    feesAmts = ast.literal_eval(feesAmts)
                else:
                    feesAmts = [{'Amt': feesAmt, 'CurCode': curCode}]
                pmtRefInfo = request_data.get('pmtRefInfo')

                providers_info = []
                '''
                provider_provider = request_data.get('provider')
                if provider_provider:
                    provider = request.env['payment.acquirer'].sudo().search([("provider", "=", provider_provider)])
                    if provider:
                        service_providerinfo = request.env['product.supplierinfo'].sudo().search([
                            ('product_tmpl_id', '=', service.product_tmpl_id.id),
                            ('name', '=', provider.related_partner.id)
                        ])
                        if service_providerinfo:
                            providers_info.append(service_providerinfo)
                if not provider_provider or len(providers_info) == 0:
                    providers_info = service.seller_ids
                '''
                providers_info.append(service_providerinfo)

                provider_response = {}
                provider_response_json = {}
                '''
                provider_fees_calculated_amount = 0.0
                provider_fees_actual_amount = 0.0
                merchant_cashback_amount = 0.0
                customer_cashback_amount = 0.0
                extra_fees_amount = 0.0
                '''
                error = {}
                for provider_info in providers_info:
                    biller_info_json_dict = json.loads(provider_info.with_context(lang=request.env.user.lang).biller_info, strict=False)
                    '''
                    # Get Extra Fees
                    commissions = request.env['product.supplierinfo.commission'].sudo().search_read(
                        domain=[('vendor', '=', provider_info.name.id),
                                ('vendor_product_code', '=', provider_info.product_code)],
                        fields=['Amount_Range_From', 'Amount_Range_To',
                                'Extra_Fee_Amt', 'Extra_Fee_Prc',
                                'Mer_Fee_Amt', 'Mer_Fee_Prc', 'Mer_Fee_Prc_MinAmt', 'Mer_Fee_Prc_MaxAmt',
                                'Mer_Comm_Full_Fix_Amt', 'Cust_Comm_Full_Fix_Amt',
                                'Bill_Merchant_Comm_Prc', 'Bill_Customer_Comm_Prc']
                    )
                    for commission in commissions:
                        if commission['Amount_Range_From'] <= machine_request.trans_amount \
                                and commission['Amount_Range_To'] >= machine_request.trans_amount:
                            if commission['Mer_Comm_Full_Fix_Amt'] > 0:
                                merchant_cashback_amount = commission['Mer_Comm_Full_Fix_Amt']
                                customer_cashback_amount = commission['Cust_Comm_Full_Fix_Amt']
                            elif commission['Bill_Merchant_Comm_Prc'] > 0:
                                merchant_cashback_amount = machine_request.trans_amount * commission[
                                    'Bill_Merchant_Comm_Prc'] / 100
                                customer_cashback_amount = machine_request.trans_amount * commission[
                                    'Bill_Customer_Comm_Prc'] / 100
                            if commission['Extra_Fee_Amt'] > 0:
                                extra_fees_amount = commission['Extra_Fee_Amt']
                            elif commission['Extra_Fee_Prc'] > 0:
                                extra_fees_amount = machine_request.trans_amount * commission['Extra_Fee_Prc'] / 100
                            if commission['Mer_Fee_Amt'] > 0:
                                provider_fees_calculated_amount = commission['Mer_Fee_Amt']
                            elif commission['Mer_Fee_Prc'] > 0:
                                # Fees amount = FA + [Percentage * Payment Amount]
                                # Fees amount ====================> provider_fees_calculated_amount
                                # FA =============================> provider_fees_calculated_amount
                                # [Percentage * Payment Amount] ==> provider_fees_prc_calculated_amount
                                provider_fees_prc_calculated_amount = machine_request.trans_amount * commission['Mer_Fee_Prc'] / 100
                                if provider_fees_prc_calculated_amount < commission['Mer_Fee_Prc_MinAmt']:
                                    provider_fees_prc_calculated_amount = commission['Mer_Fee_Prc_MinAmt']
                                elif provider_fees_prc_calculated_amount > commission['Mer_Fee_Prc_MaxAmt'] \
                                        and commission['Mer_Fee_Prc_MaxAmt'] > 0:
                                    provider_fees_prc_calculated_amount = commission['Mer_Fee_Prc_MaxAmt']
                                provider_fees_calculated_amount += provider_fees_prc_calculated_amount
                            elif provider_provider == 'khales':
                                provider_fees_calculated_amount = float(request_data.get('feesAmt'))
                            break
                    calculated_payment_amount = machine_request.trans_amount + provider_fees_calculated_amount + extra_fees_amount
                    if request_data.get("wallet_id"):
                        partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(wallet_id=request_data.get("wallet_id"),
                                                                                               service=service,
                                                                                               trans_amount=calculated_payment_amount)
                    else:
                        partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(service=service,
                                                                                               trans_amount=calculated_payment_amount)
                    unlink_wallet_reservation = False
                    machine_wallet_reservation_id, machine_wallet_balance, machine_wallet_available_amount = partner_wallet_id.update_wallet_reserved_balance(
                            _('Pay Service Bill for %s service') % (service.name), calculated_payment_amount,
                            request.env.user.company_id.currency_id, 'request'
                        )
                    # # machine_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                    # machine_wallet_available_amount = partner_wallet_id.available_amount if partner_wallet_id else 0
                    # if machine_wallet_available_amount < calculated_payment_amount 
                    if not machine_wallet_reservation_id
                        and (not json.loads(service_providerinfo.biller_info, strict=False).get('CorrBillTypeCode') or json.loads(service_providerinfo.biller_info, strict=False).get('Type') == 'CASHININT'):
                        error.update({"machine_balance_not_enough":
                                                _("Machine Wallet Available Balance (%s) less than the payment amount (%s)") % (machine_wallet_available_amount,
                                                                                                                      calculated_payment_amount)})
                    '''

                    machine_request.update({'provider_fees_calculated_amount': provider_fees_calculated_amount})
                    request.env.cr.commit()
                    provider = request.env['payment.acquirer'].sudo().search([("related_partner", "=", provider_info.name.id)])
                    if provider:
                        try:
                            if provider.server_state == 'offline':
                                error.update({provider.provider + "_response": {'error_message': _("Service Not Available")}})
                                break
                            provider_channel = False
                            machine_channels = request.env['payment.acquirer.channel'].sudo().search([("acquirer_id", "=", provider.id),
                                                                                                      ("type", "in", ("machine", "internet"))], limit=1)
                            if machine_channels:
                                provider_channel = machine_channels[0]
                            if provider.provider == "fawry":
                                # Tamayoz TODO: Provider Server Timeout Handling
                                machine_request.update({'action_status': 'in_progress'}) # ==> current 'payment_status': is 'new'
                                request.env.cr.commit()
                                provider_response = provider.pay_fawry_bill(lang, provider_info.product_code,
                                                                            billingAcct, extraBillingAcctKeys,
                                                                            trans_amount, curCode, pmtMethod,
                                                                            notifyMobile, billRefNumber,
                                                                            billerId, pmtType, provider_channel,
                                                                            inquiryTransactionId, machine_request.name,
                                                                            biller_info_json_dict.get('SupportPmtReverse'),
                                                                            biller_info_json_dict.get('AllowRetry'))
                                if provider_response.get('Success'):
                                    if provider_response.get('Success').get('timeout'):
                                        machine_request.update({'payment_status': 'timeout'}) # ==> current 'action_status': is 'in_progress'
                                        if biller_info_json_dict.get('PmtType') == 'VOCH':
                                            provider_response = {"error_code": "0", "error_message": None,
                                                                 "error_message_to_be_translated": "FW Server timeout:\n",}
                                            if biller_info_json_dict.get('SupportPmtReverse'):
                                                provider_response.update({"TO_CANCEL": "VOCH"})
                                            else:
                                                provider_response.update({"TO_REVIEW": "VOCH"})
                                    else:
                                        machine_request.update({'action_status': 'completed'}) # ==> current 'payment_status': is 'new'
                                    request.env.cr.commit()
                                    if not provider_response.get('error_code'):
                                        provider_response_json = suds_to_json(provider_response.get('Success')['pmtInfoValType']).replace('REQUEST_NUMBER', machine_request.name)
                                        msgRqHdr_response_json = suds_to_json(provider_response.get('Success')['msgRqHdrType'])
                                        # Get customProperties
                                        msgRqHdr_response_json_dict = json.loads(msgRqHdr_response_json, strict=False)
                                        customProperties = msgRqHdr_response_json_dict.get('CustomProperties')
                                        cardMetadata = ''
                                        if customProperties:
                                            # Get CardMetadata
                                            for customProperty in customProperties['CustomProperty']:
                                                if customProperty['Key'] == 'CardMetadata':
                                                    cardMetadata = customProperty['Value']
                                                    break
                                        # Get Provider Fees
                                        provider_response_json_dict = json.loads(provider_response_json, strict=False)
                                        # provider_response_json_dict['PmtInfo']['CurAmt']['Amt'] == machine_request.trans_amount
                                        provider_fees_actual_amount = provider_response_json_dict['PmtInfo']['FeesAmt']['Amt'] or float(feesAmt)
                                        machine_request.update({'provider_fees_amount': provider_fees_actual_amount})
                                        request.env.cr.commit()
                                        # Get Provider Payment Trans ID
                                        for payment in provider_response_json_dict['PmtTransId']:
                                            if payment['PmtIdType'] == 'FCRN':
                                                provider_payment_trans_id = payment['PmtId']
                                                break
                            elif provider.provider == "khales":
                                if not billerId:
                                    billerId = biller_info_json_dict.get('Code')
                                # Handel billingAcct format if exist
                                if biller_info_json_dict.get('BillTypeAcctFormat') and biller_info_json_dict.get('BillTypeAcctFormatSpliter'):
                                    formatedBillingAcct = []
                                    keysToBeRemoved = []
                                    for format in biller_info_json_dict.get('BillTypeAcctFormat').split(biller_info_json_dict.get('BillTypeAcctFormatSpliter')):
                                        if format == 'billingAcct':
                                            formatedBillingAcct.append(billingAcct)
                                        else:
                                            is_extra_key = False
                                            for extraBillingAcctKey in extraBillingAcctKeys:
                                                if extraBillingAcctKey.get("Key") == format:
                                                    formatedBillingAcct.append(extraBillingAcctKey.get("Value"))
                                                    keysToBeRemoved.append(extraBillingAcctKey)
                                                    is_extra_key = True
                                                    break
                                            if not is_extra_key:
                                                formatedBillingAcct.append(format)
                                    extraBillingAcctKeys = [x for x in extraBillingAcctKeys if x not in keysToBeRemoved]
                                    billingAcct = biller_info_json_dict.get('BillTypeAcctFormatSpliter').join(formatedBillingAcct)
                                # Tamayoz TODO: Provider Server Timeout Handling
                                # Tamayoz TODO: Remove the next temporary line
                                pmtMethod = "CARD"  # TEMP CODE
                                machine_request.update({'action_status': 'in_progress'}) # ==> current 'payment_status': is 'new'
                                request.env.cr.commit()
                                '''
                                machine_serial = None
                                if len(request.env.user.machine_serial) > 16:  # Ingenico POS
                                    machine_serial = request.env.user.machine_serial
                                    machine_serial = machine_serial[len(machine_serial) - 16:len(machine_serial)]
                                '''
                                machine_serial = request.env.user.machine_serial
                                if machine_serial and len(machine_serial) > 16:
                                    machine_serial = machine_serial[len(machine_serial) - 16:len(machine_serial)]
                                provider_response = provider.pay_khales_bill(lang, machine_serial or machine_request.name,
                                                                             billingAcct, extraBillingAcctKeys, billerId, ePayBillRecID,
                                                                             payAmts, pmtId, pmtType, feesAmts,
                                                                             billRefNumber, pmtMethod, pmtRefInfo,
                                                                             provider_channel, machine_request.name,
                                                                             biller_info_json_dict.get('SupportPmtReverse'),
                                                                             biller_info_json_dict.get('AllowRetry'))
                                if provider_response.get('Success'):
                                    if provider_response.get('Success').get('timeout'):
                                        machine_request.update({'payment_status': 'timeout'}) # ==> current 'action_status': is 'in_progress'
                                        if biller_info_json_dict.get('PmtType') == 'VOCH':
                                            provider_response = {"error_code": "0", "error_message": None,
                                                                 "error_message_to_be_translated": "KH Server timeout:\n",}
                                            if biller_info_json_dict.get('SupportPmtReverse'):
                                                provider_response.update({"TO_CANCEL": "VOCH"})
                                            else:
                                                provider_response.update({"TO_REVIEW": "VOCH"})
                                    else:
                                        machine_request.update({'action_status': 'completed'}) # ==> current 'payment_status': is 'new'
                                    request.env.cr.commit()
                                    if not provider_response.get('error_code'):
                                        provider_response_json = suds_to_json(provider_response.get('Success'))
                                        # Add required parameters for cancel payment scenario
                                        # parsing JSON string:
                                        provider_response_json_dict = json.loads(provider_response_json)
                                        pmtId = provider_response_json_dict['PmtRecAdviceStatus']['PmtTransId']['PmtId']
                                        # appending the data
                                        provider_response_json_dict.update({'billingAcct': billingAcct, 'billRefNumber': billRefNumber,
                                                                            'billerId': billerId, 'pmtType': pmtType, 'trans_amount': trans_amount,
                                                                            'curCode': curCode, 'pmtMethod': pmtMethod, 'ePayBillRecID': ePayBillRecID,
                                                                            'pmtId': pmtId, 'feesAmt': feesAmt, 'pmtRefInfo': pmtRefInfo})
                                        if payAmts:
                                            provider_response_json_dict.update({'payAmts': payAmts})
                                        if feesAmts:
                                            provider_response_json_dict.update({'feesAmts': feesAmts})
                                        # the result is a JSON string:
                                        provider_response_json = json.dumps(provider_response_json_dict)
                                        # Provider Fees
                                        provider_fees_actual_amount = float(feesAmt)
                                        machine_request.update({'provider_fees_amount': provider_fees_actual_amount})
                                        request.env.cr.commit()
                                        # Provider Payment Trans ID
                                        provider_payment_trans_id = pmtId
                            elif provider.provider == "masary":
                                machine_request.update({'action_status': 'in_progress'}) # ==> current 'payment_status': is 'new'
                                request.env.cr.commit()
                                provider_response = provider.pay_masary_bill(lang, int(provider_info.product_code),
                                                                             float(trans_amount), float(feesAmt),
                                                                             inquiryTransactionId, 1, # quantity
                                                                             extraBillingAcctKeys, provider_channel, machine_request.name)
                                if provider_response.get('Success'):
                                    if provider_response.get('Success').get('timeout'):
                                        machine_request.update({'payment_status': 'timeout'}) # ==> current 'action_status': is 'in_progress'
                                        if biller_info_json_dict.get('PmtType') == 'VOCH':
                                            provider_response = {"error_code": "0", "error_message": None,
                                                                 "error_message_to_be_translated": "KH Server timeout:\n",}
                                            if biller_info_json_dict.get('SupportPmtReverse'):
                                                provider_response.update({"TO_CANCEL": "VOCH"})
                                            else:
                                                provider_response.update({"TO_REVIEW": "VOCH"})
                                    else:
                                        machine_request.update({'action_status': 'completed'}) # ==> current 'payment_status': is 'new'
                                    request.env.cr.commit()
                                    if not provider_response.get('error_code'):
                                        provider_response_json = provider_response.get('Success')
                                        # Get Provider Fees
                                        # provider_response_json_dict = json.loads(provider_response_json, strict=False)
                                        provider_response_json_dict = provider_response_json
                                        transactionId = provider_response_json_dict['transaction_id']
                                        # provider_fees_actual_amount = provider_response_json_dict['details_list']['???']
                                        provider_fees_actual_amount = float(feesAmt)
                                        machine_request.update({'provider_fees_amount': provider_fees_actual_amount})
                                        request.env.cr.commit()
                                        # Provider Payment Trans ID
                                        provider_payment_trans_id = transactionId
                            if provider_response.get('Success'):
                                try:
                                    machine_wallet_create = False
                                    # provider_invoice_id = False
                                    # refund = False
                                    # customer_invoice_id = False
                                    # credit_note = False
                                    machine_request_response = {"request_number": machine_request.name,
                                                                "request_datetime": machine_request.create_date + timedelta(hours=2),
                                                                "provider": provider.provider,
                                                                "provider_response": provider_response_json
                                                                }

                                    if provider.provider == "fawry":
                                        if cardMetadata:
                                            machine_request_response.update({"cardMetadata": cardMetadata})

                                    provider_actual_amount = machine_request.trans_amount + provider_fees_actual_amount
                                    customer_actual_amount = provider_actual_amount + extra_fees_amount
                                    if not biller_info_json_dict.get('CorrBillTypeCode') or biller_info_json_dict.get('Type') == 'CASHININT':
                                        # Deduct Transaction Amount from Machine Wallet Balance
                                        '''
                                        wallet_transaction_sudo = request.env['website.wallet.transaction'].sudo()
                                        label = _('Pay Service Bill for %s service') % (service.name)
                                        if request_data.get("wallet_id"):
                                            partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(wallet_id=request_data.get("wallet_id"),
                                                                                                                   service=service,
                                                                                                                   trans_amount=customer_actual_amount)
                                        else:
                                            partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(service=service,
                                                                                                                   trans_amount=customer_actual_amount)
                                        partner_id_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                                        machine_wallet_create = wallet_transaction_sudo.create(
                                            {'wallet_type': 'debit', 'partner_id': request.env.user.partner_id.id,
                                             'request_id': machine_request.id,
                                             'reference': 'request',
                                             'label': label,
                                             'amount': customer_actual_amount, 'currency_id': machine_request.currency_id.id,
                                             'wallet_balance_before': partner_id_wallet_balance,
                                             'wallet_balance_after': partner_id_wallet_balance - customer_actual_amount,
                                             'status': 'done'})
                                        request.env.cr.commit()

                                        request.env.user.partner_id.update(
                                            {'wallet_balance': partner_id_wallet_balance - customer_actual_amount})
                                        request.env.cr.commit()
                                        '''
                                        machine_wallet_create, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                                            'debit', request.env.user.partner_id, 'request',
                                            _('Pay Service Bill for %s service') % (service.name),
                                            customer_actual_amount, machine_request.currency_id, machine_request,
                                            'smartpay_operations.wallet_pay_service_bill_notify_mode', 'wallet_pay_service',
                                              _('<p>%s %s successfully deducted from your wallet.</p>') % (
                                            customer_actual_amount, _(machine_request.currency_id.name))
                                        )

                                        if provider_response.get('Success').get('timeout'):
                                            if not biller_info_json_dict.get('Timeout') and not biller_info_json_dict.get('SupportPmtReverse'):
                                                machine_request.update({'payment_status': 'in_queue'})
                                            elif biller_info_json_dict.get('Timeout') == 'PENDING':
                                                machine_request.update({'payment_status': 'pending'})
                                            elif biller_info_json_dict.get('SupportPmtReverse'):
                                                # if biller_info_json_dict.get('PmtType') == 'VOCH':
                                                    # machine_request.update({'payment_status': 'to_cancel'})
                                                # else:
                                                if biller_info_json_dict.get('PmtType') != 'VOCH':
                                                    machine_request.update({'payment_status': 'to_refund'})
                                            # else:
                                                # machine_request.update({'payment_status': 'done'}) # Tamayoz: No need to handel "else" case
                                            machine_request.update({'action_status': 'new'})
                                        elif provider_response.get('Success').get('pending'):
                                            machine_request.update({'payment_status': 'pending', 'action_status': 'new'})
                                        else:
                                            machine_request.update({'payment_status': 'done', 'action_status': 'completed'}) # ==> current 'action_status': is 'completed'
                                        request.env.cr.commit()

                                        # Log Sold Limit
                                        if service.has_sale_limit:
                                            for sale_limit_id in service.sale_limit_ids:
                                                limit_type = sale_limit_id.limit_type
                                                timetuple = date_time.now().timetuple()
                                                sale_limit_domain = [
                                                    ('partner_id', '=', request.env.user.partner_id.id),
                                                    ('product_id', '=', service.id),
                                                    ('limit_type', '=', limit_type),
                                                    ('year', '=', timetuple.tm_year)]
                                                if limit_type == 'daily':
                                                    sale_limit_domain += [('day', '=', timetuple.tm_yday)]
                                                elif limit_type == 'weekly':
                                                    sale_limit_domain += [('week', '=', date_time.now().isocalendar()[1])]
                                                elif limit_type == 'monthly':
                                                    sale_limit_domain += [('month', '=', timetuple.tm_mon)]
                                                sale_limit = request.env['res.partner.sale.limit'].sudo().search(
                                                    sale_limit_domain,
                                                    order="id DESC", limit=1)
                                                if sale_limit:
                                                    sale_limit.update({'sold_amount': sale_limit.sold_amount + customer_actual_amount}) # calculated_payment_amount
                                                else:
                                                    sale_limit_values = {
                                                        'partner_id': request.env.user.partner_id.id,
                                                        'product_id': service.id,
                                                        'limit_type': limit_type,
                                                        'year': timetuple.tm_year,
                                                        'sold_amount': customer_actual_amount
                                                    }
                                                    if limit_type == 'daily':
                                                        sale_limit_values.update({'day': timetuple.tm_yday})
                                                    elif limit_type == 'weekly':
                                                        sale_limit_values.update({'week': date_time.now().isocalendar()[1]})
                                                    elif limit_type == 'monthly':
                                                        sale_limit_values.update({'month': timetuple.tm_mon})
                                                    sale_limit = request.env['res.partner.sale.limit'].sudo().create(sale_limit_values)

                                                # Log Sold Over Limit Fees
                                                if limit_fees_amounts.get(limit_type):
                                                    wallet_transaction_id, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                                                        'debit', request.env.user.partner_id, 'request',
                                                        _('%s over limit fees for %s service') % (limit_type ,service.name),
                                                        limit_fees_amounts.get(limit_type), machine_request.currency_id, machine_request,
                                                        'smartpay_operations.wallet_pay_service_bill_notify_mode', 'wallet_pay_service',
                                                        _('<p>%s %s successfully deducted from your wallet.</p>') % (
                                                            limit_fees_amounts.get(limit_type), _(machine_request.currency_id.name))
                                                    )
                                                    sale_limit_fees = request.env['res.partner.sale.limit.fees'].sudo().create({'user_request_id': machine_request.id,
                                                                                                                                'limit_type': limit_type,
                                                                                                                                'fees_amount': limit_fees_amounts.get(limit_type),
                                                                                                                                'wallet_transaction_id': wallet_transaction_id.id})
                                        # Log Wallet Transaction Limit
                                        if partner_wallet_id.type.has_trans_limit:
                                            for trans_limit_id in partner_wallet_id.type.trans_limit_ids:
                                                wallet_limit_type = trans_limit_id.limit_type
                                                timetuple = date_time.now().timetuple()
                                                trans_limit_domain = [
                                                    ('wallet_id', '=', partner_wallet_id.id),
                                                    # ('wallet_type_id', '=', partner_wallet_id.type.id),
                                                    ('limit_type', '=', wallet_limit_type),
                                                    ('year', '=', timetuple.tm_year)]
                                                if wallet_limit_type == 'daily':
                                                    trans_limit_domain += [('day', '=', timetuple.tm_yday)]
                                                elif wallet_limit_type == 'weekly':
                                                    trans_limit_domain += [('week', '=', date_time.now().isocalendar()[1])]
                                                elif wallet_limit_type == 'monthly':
                                                    trans_limit_domain += [('month', '=', timetuple.tm_mon)]
                                                trans_limit = request.env['wallet.trans.limit'].sudo().search(trans_limit_domain, order="id DESC", limit=1)
                                                if trans_limit:
                                                    trans_limit.update({'trans_amount': trans_limit.trans_amount + customer_actual_amount})  # calculated_payment_amount
                                                else:
                                                    trans_limit_values = {
                                                        'wallet_id': partner_wallet_id.id,
                                                        # 'wallet_type_id': partner_wallet_id.type.id,
                                                        'limit_type': wallet_limit_type,
                                                        'year': timetuple.tm_year,
                                                        'trans_amount': customer_actual_amount
                                                    }
                                                    if wallet_limit_type == 'daily':
                                                        trans_limit_values.update({'day': timetuple.tm_yday})
                                                    elif wallet_limit_type == 'weekly':
                                                        trans_limit_values.update({'week': date_time.now().isocalendar()[1]})
                                                    elif wallet_limit_type == 'monthly':
                                                        trans_limit_values.update({'month': timetuple.tm_mon})
                                                    trans_limit = request.env['wallet.trans.limit'].sudo().create(trans_limit_values)

                                                # Log Transaction Over Limit Fees
                                                if wallet_limit_fees_amounts.get(wallet_limit_type):
                                                    wallet_transaction_id, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                                                        'debit', request.env.user.partner_id, 'request',
                                                        _('%s over limit fees for %s wallet type') % (
                                                        wallet_limit_type, partner_wallet_id.type.name),
                                                        wallet_limit_fees_amounts.get(wallet_limit_type),
                                                        machine_request.currency_id, machine_request,
                                                        'smartpay_operations.wallet_pay_service_bill_notify_mode',
                                                        'wallet_pay_service',
                                                        _('<p>%s %s successfully deducted from your wallet.</p>') % (
                                                            wallet_limit_fees_amounts.get(wallet_limit_type),
                                                            _(machine_request.currency_id.name))
                                                    )
                                                    trans_limit_fees = request.env['wallet.trans.limit.fees'].sudo().create(
                                                        {'user_request_id': machine_request.id,
                                                         'limit_type': wallet_limit_type,
                                                         'fees_amount': wallet_limit_fees_amounts.get(wallet_limit_type),
                                                         'wallet_transaction_id': wallet_transaction_id.id})

                                        machine_wallet_reservation_id.sudo().unlink()
                                        request.env.cr.commit()
                                        unlink_wallet_reservation = True

                                        '''
                                        # Notify customer
                                        irc_param = request.env['ir.config_parameter'].sudo()
                                        wallet_pay_service_bill_notify_mode = irc_param.get_param("smartpay_operations.wallet_pay_service_bill_notify_mode")
                                        if wallet_pay_service_bill_notify_mode == 'inbox':
                                            request.env['mail.thread'].sudo().message_notify(
                                                subject=label,
                                                body=_('<p>%s %s successfully deducted from your wallet.</p>') % (
                                                    customer_actual_amount, _(machine_request.currency_id.name)),
                                                partner_ids=[(4, request.env.user.partner_id.id)],
                                            )
                                        elif wallet_pay_service_bill_notify_mode == 'email':
                                            machine_wallet_create.wallet_transaction_email_send()
                                        elif wallet_pay_service_bill_notify_mode == 'sms' and request.env.user.partner_id.mobile:
                                            machine_wallet_create.sms_send_wallet_transaction(wallet_pay_service_bill_notify_mode,
                                                                                              'wallet_pay_service',
                                                                                              request.env.user.partner_id.mobile,
                                                                                              request.env.user.name, label,
                                                                                              '%s %s' % (customer_actual_amount,
                                                                                                         _(machine_request.currency_id.name)),
                                                                                              request.env.user.partner_id.country_id.phone_code or '2')
                                        '''

                                        payment_info = {"service": service.with_context(lang=request.env.user.lang).name, "provider": provider.provider,
                                                        "request_number": machine_request.name,
                                                        "request_datetime": machine_request.create_date + timedelta(hours=2),
                                                        "label": biller_info_json_dict.get("BillTypeAcctLabel"),
                                                        "billing_acct": billingAcct, "ref_number": provider_payment_trans_id,
                                                        "amount": trans_amount,
                                                        "fees": (provider_fees_actual_amount + extra_fees_amount),
                                                        "total": customer_actual_amount}

                                    machine_request.update(
                                        {'extra_fees_amount': extra_fees_amount,
                                         'wallet_transaction_id': machine_wallet_create and machine_wallet_create.id or False,
                                         'trans_date': date.today(),
                                         'provider_id': provider.id,
                                         'provider_response': provider_response_json, "stage_id": 5})
                                    if biller_info_json_dict.get('CorrBillTypeCode'):
                                        machine_request.update(
                                            {'description': _(
                                                 'Initiation Service Payment request (%s) was submit successfully @ %s') % (
                                                                machine_request.name,
                                                                str(date_time.now() + timedelta(hours=2)))
                                             })
                                    request.env.cr.commit()
                                    machine_request_response.update({'extra_fees_amount': extra_fees_amount})

                                    # VouchPIN Decryption if exist
                                    if provider_response_json_dict.get('VouchInfo'):
                                        decrypted_bytes = bytes(provider_response_json_dict['VouchInfo']['VouchPIN'],
                                                                encoding='utf-8')
                                        # text = base64.decodestring(decrypted_bytes) #
                                        text = base64.b64decode(decrypted_bytes)  #
                                        cipher = DES3.new(SECRET_KEY, DES3.MODE_ECB)
                                        VouchPIN = cipher.decrypt(text)
                                        VouchPIN = UNPAD(VouchPIN)
                                        VouchPIN = VouchPIN.decode('utf-8')  # unpad and decode bytes to str
                                        machine_request_response.update({'vouch_pin': VouchPIN})
                                        if not biller_info_json_dict.get('CorrBillTypeCode'):
                                            payment_info.update({"vouch_pin": VouchPIN,
                                                                 "vouch_sn": provider_response_json_dict['VouchInfo']['VouchSN']})
                                            if provider_response_json_dict['VouchInfo'].get('VouchDesc'):
                                                payment_info.update({"vouch_desc": provider_response_json_dict['VouchInfo']['VouchDesc']})

                                    # ExtraBillInfo
                                    # ePayBillRecID : RBINQRQ-220627-619014259490-GT-99959 (Khales)
                                    # billRefNumber : 6bb67311-dde8-47f8-b8f3-3cf8fe5a4be6 (Fawry)
                                    if (provider.provider == 'fawry' and billRefNumber) or (provider.provider == 'khales' and ePayBillRecID):
                                        inquiryTransactionId = request_data.get('inquiryTransactionId')
                                        if inquiryTransactionId:
                                            inquiry_request = request.env["smartpay_operations.request"].sudo().search(
                                                [('name', '=', inquiryTransactionId)], limit=1)
                                        else:
                                            inquiry_request = request.env["smartpay_operations.request"].sudo().search(
                                                [('request_type', '=', 'service_bill_inquiry'),
                                                 ('partner_id', '=', request.env.user.partner_id.id),
                                                 ('product_id', '=', service.id),
                                                 ('create_date', '<=', date_time.now()),
                                                 ('create_date', '>=', date_time.now() - timedelta(minutes=15)),
                                                 ('provider_response', 'ilike',
                                                  '"BillRefNumber": "%s"' % (billRefNumber) if provider.provider == "fawry"
                                                  else '"EPayBillRecID": "%s"' % (ePayBillRecID) # provider.provider == "khales"
                                                  )], limit=1)

                                        if inquiry_request:
                                            inquiry_request_provider_response = inquiry_request.provider_response.replace(
                                                "'bill_response'", '"bill_response"').replace("'fees_response'", '"fees_response"').replace("'", "")
                                            inquiry_request_provider_response_json_dict = json.loads(inquiry_request_provider_response)

                                            # Fawry
                                            if inquiry_request_provider_response_json_dict.get('BillInfo') and \
                                                    inquiry_request_provider_response_json_dict.get('BillInfo').get('ExtraBillInfo'):
                                                payment_info.update({"extra_bill_info": inquiry_request_provider_response_json_dict['BillInfo']['ExtraBillInfo']})

                                            # Khales
                                            if inquiry_request_provider_response_json_dict.get('bill_response') and \
                                                    inquiry_request_provider_response_json_dict.get('bill_response').get('Msg'):
                                                for msg in inquiry_request_provider_response_json_dict.get('bill_response').get('Msg'):
                                                    if msg.get('LanguagePref') == 'ar-eg':  # en-gb
                                                        payment_info.update({"extra_bill_info": msg.get('Text')})
                                                        break

                                    if not biller_info_json_dict.get('CorrBillTypeCode') or biller_info_json_dict.get('Type') == 'CASHININT':
                                        # Wallet Transaction Info with payment info
                                        machine_wallet_create.update({"wallet_transaction_info": json.dumps({"payment_info": payment_info}, default=default)})
                                        request.env.cr.commit()

                                    '''
                                    # Create Vendor (Provider) Invoices
                                    provider_invoice_ids = ()
                                    # 1- Create Vendor bill
                                    provider_journal_id = request.env['account.journal'].sudo().search([('type', '=', 'purchase'),
                                                                                              ('company_id', '=', request.env.user.company_id.id)], limit=1)
                                    name = provider.provider + ': [' + provider_info.product_code + '] ' + provider_info.product_name
                                    provider_invoice_vals = machine_request.with_context(name=name,
                                                                                         provider_payment_trans_id=provider_payment_trans_id,
                                                                                         journal_id=provider_journal_id.id,
                                                                                         invoice_date=date.today(),
                                                                                         invoice_type='in_invoice',
                                                                                         partner_id=provider_info.name.id)._prepare_invoice()
                                    provider_invoice_id = request.env['account.invoice'].sudo().create(provider_invoice_vals)
                                    invoice_line = provider_invoice_id._prepare_invoice_line_from_request(request=machine_request,
                                                                                                          name=name,
                                                                                                          qty=1,
                                                                                                          price_unit=provider_actual_amount)
                                    new_line = request.env['account.invoice.line'].sudo().new(invoice_line)
                                    new_line._set_additional_fields(provider_invoice_id)
                                    provider_invoice_id.invoice_line_ids += new_line
                                    provider_invoice_id.action_invoice_open()
                                    provider_invoice_ids += (tuple(provider_invoice_id.ids),)
                                    provider_invoice_id.pay_and_reconcile(request.env['account.journal'].sudo().search(
                                        [('type', '=', 'cash'),
                                         ('company_id', '=', request.env.user.company_id.id),
                                         ('provider_id', '=', provider.id)], limit=1),
                                        provider_actual_amount)
                                    request.env.cr.commit()
                                    # 2- Create Vendor Refund with commision amount
                                    if merchant_cashback_amount > 0:
                                        refund = request.env['account.invoice.refund'].with_context(
                                            active_ids=provider_invoice_id.ids).sudo().create({
                                            'filter_refund': 'refund',
                                            'description': name,
                                            'date': provider_invoice_id.date_invoice,
                                        })
                                        result = refund.invoice_refund()
                                        refund_id = result.get('domain')[1][2]
                                        refund = request.env['account.invoice'].sudo().browse(refund_id)
                                        refund.update({'reference': provider_payment_trans_id, 'request_id': machine_request.id})
                                        refund_line = refund.invoice_line_ids[0]
                                        refund_line.update({'price_unit': merchant_cashback_amount, 'request_id': machine_request.id})
                                        refund.refresh()
                                        refund.action_invoice_open()
                                        provider_invoice_ids += (tuple(refund.ids),)
                                    machine_request.update({'provider_invoice_ids': provider_invoice_ids})
                                    request.env.cr.commit()

                                    # Create Customer Invoices
                                    customer_invoice_ids = ()
                                    # 1- Create Customer Invoice
                                    customer_journal_id = request.env['account.journal'].sudo().search([('type', '=', 'sale'),
                                                                                              ('company_id', '=', request.env.user.company_id.id)], limit=1)
                                    customer_invoice_vals = machine_request.with_context(name=provider_payment_trans_id,
                                                                                         journal_id=customer_journal_id.id,
                                                                                         invoice_date=date.today(),
                                                                                         invoice_type='out_invoice',
                                                                                         partner_id=request.env.user.partner_id.id)._prepare_invoice()
                                    customer_invoice_id = request.env['account.invoice'].sudo().create(customer_invoice_vals)
                                    machine_request.invoice_line_create(invoice_id=customer_invoice_id.id, name=name,
                                                                        qty=1, price_unit=customer_actual_amount)
                                    customer_invoice_id.action_invoice_open()
                                    customer_invoice_ids += (tuple(customer_invoice_id.ids),)
                                    # Auto Reconcile customer invoice with prepaid wallet recharge payments and previous cashback credit note
                                    domain = [('account_id', '=', customer_invoice_id.account_id.id),
                                              ('partner_id', '=',
                                               customer_invoice_id.env['res.partner']._find_accounting_partner(customer_invoice_id.partner_id).id),
                                              ('reconciled', '=', False),
                                              '|',
                                              '&', ('amount_residual_currency', '!=', 0.0), ('currency_id', '!=', None),
                                              '&', ('amount_residual_currency', '=', 0.0), '&', ('currency_id', '=', None),
                                              ('amount_residual', '!=', 0.0)]
                                    domain.extend([('credit', '>', 0), ('debit', '=', 0)])
                                    lines = customer_invoice_id.env['account.move.line'].sudo().search(domain)
                                    for line in lines:
                                        # get the outstanding residual value in invoice currency
                                        if line.currency_id and line.currency_id == customer_invoice_id.currency_id:
                                            amount_residual_currency = abs(line.amount_residual_currency)
                                        else:
                                            currency = line.company_id.currency_id
                                            amount_residual_currency = currency._convert(abs(line.amount_residual),
                                                                                         customer_invoice_id.currency_id,
                                                                                         customer_invoice_id.company_id,
                                                                                         line.date or fields.Date.today())
                                        if float_is_zero(amount_residual_currency, precision_rounding=customer_invoice_id.currency_id.rounding):
                                            continue

                                        customer_invoice_id.assign_outstanding_credit(line.id)
                                        if customer_invoice_id.state == 'paid':
                                            break
                                    request.env.cr.commit()

                                    # 2- Create Customer Credit Note with commission amount for only customers have commission
                                    if request.env.user.commission and customer_cashback_amount > 0:
                                        credit_note = request.env['account.invoice.refund'].with_context(
                                            active_ids=customer_invoice_id.ids).sudo().create({
                                            'filter_refund': 'refund',
                                            'description': provider_payment_trans_id,
                                            'date': customer_invoice_id.date_invoice,
                                        })
                                        result = credit_note.invoice_refund()
                                        credit_note_id = result.get('domain')[1][2]
                                        credit_note = request.env['account.invoice'].sudo().browse(credit_note_id)
                                        credit_note.update({'request_id': machine_request.id})
                                        credit_note_line = credit_note.invoice_line_ids[0]
                                        credit_note_line.update({'price_unit': customer_cashback_amount, 'request_id': machine_request.id})
                                        credit_note.refresh()
                                        """  Don't validate the customer credit note until the vendor refund reconciliation
                                        After vendor refund reconciliation, validate the customer credit note with
                                        the net amount of vendor refund sent in provider cashback statement then
                                        increase the customer wallet with the same net amount. """
                                        # credit_note.action_invoice_open()
                                        customer_invoice_ids += (tuple(credit_note.ids),)
                                    machine_request.update({'customer_invoice_ids': customer_invoice_ids})
                                    request.env.cr.commit()
                                    '''
                                    if provider.provider == "khales":
                                        # Add required parameters for cancel payment scenario
                                        machine_request_response.update({'billingAcct': billingAcct, 'billRefNumber': billRefNumber,
                                                                         'billerId': billerId, 'pmtType': pmtType, 'trans_amount': trans_amount,
                                                                         'curCode': curCode, 'pmtMethod': pmtMethod, 'ePayBillRecID': ePayBillRecID,
                                                                         'pmtId': pmtId, 'feesAmt': feesAmt, 'pmtRefInfo': pmtRefInfo})
                                        if payAmts:
                                            machine_request_response.update({'payAmts': payAmts})
                                        if feesAmts:
                                            machine_request_response.update({'feesAmts': feesAmts})
                                    if not biller_info_json_dict.get('CorrBillTypeCode') or biller_info_json_dict.get('Type') == 'CASHININT':
                                        machine_request_response.update({"message": _("Pay Service Bill request was submit successfully with amount %s %s. Your Machine Wallet Balance is %s %s")
                                                                                % (customer_actual_amount,
                                                                                   machine_request.currency_id.name,
                                                                                   wallet_balance_after,
                                                                                   machine_request.currency_id.name)})
                                    else:
                                        machine_request_response.update({"message": _("Pay Service Bill Initiation request was submit successfully with amount %s %s.")
                                                                                    % (customer_actual_amount,
                                                                                       machine_request.currency_id.name)})

                                    # Cancel
                                    # request_number = {"request_number": machine_request.name}
                                    # self.cancel_request(**request_number)

                                    if not unlink_wallet_reservation and machine_wallet_reservation_id:
                                        machine_wallet_reservation_id.sudo().unlink()
                                        request.env.cr.commit()
                                        unlink_wallet_reservation = True
                                    return valid_response(machine_request_response)
                                except Exception as e:
                                    try:
                                        _logger.error("%s", e, exc_info=True)
                                        machine_request_update = {'extra_fees_amount': extra_fees_amount,
                                                                  'trans_date': date.today(),
                                                                  'provider_id': provider.id,
                                                                  'provider_response': provider_response_json, "stage_id": 5,
                                                                  'description': _("After the Pay Service Request submit successfuly with provider, Error is occur:") + " ==> " + str(e)}
                                        if machine_wallet_create:
                                            machine_request_update.update({'wallet_transaction_id': machine_wallet_create.id})
                                        '''
                                        provider_invoice_ids = ()
                                        if provider_invoice_id or refund:
                                            if provider_invoice_id:
                                                provider_invoice_ids += (tuple(provider_invoice_id.ids),)
                                            if refund:
                                                provider_invoice_ids += (tuple(refund.ids),)
                                            machine_request_update.update({'provider_invoice_ids': provider_invoice_ids})
                                        customer_invoice_ids = ()
                                        if customer_invoice_id or credit_note:
                                            if customer_invoice_id:
                                                customer_invoice_ids += (tuple(customer_invoice_id.ids),)
                                            if credit_note:
                                                customer_invoice_ids += (tuple(credit_note.ids),)
                                            machine_request_update.update({'customer_invoice_ids': customer_invoice_ids})
                                        '''
                                        machine_request.update(machine_request_update)
                                        request.env.cr.commit()
                                    except Exception as e1:
                                        _logger.error("%s", e1, exc_info=True)
                                        if machine_request and not machine_request.description:
                                            machine_request.update({'description': _("After the Pay Service Request submit successfuly with provider, Error is occur:") + " ==> " + str(e)})
                                            request.env.cr.commit()

                                    if not unlink_wallet_reservation and machine_wallet_reservation_id:
                                        machine_wallet_reservation_id.sudo().unlink()
                                        request.env.cr.commit()
                                        unlink_wallet_reservation = True
                                    return invalid_response(machine_request_response, _("After the Pay Service Request submit successfuly with provider, Error is occur:") + " ==> " + str(e),
                                                            500)
                            else:
                                machine_request.update({'payment_status': 'canceled' if provider_response.get('CANCEL_SUCCESS') else ('to_cancel' if provider_response.get('TO_CANCEL') else ('to_review' if provider_response.get('TO_REVIEW') else 'failure')), 'action_status': 'new' if provider_response.get('TO_CANCEL') or provider_response.get('TO_REVIEW') else 'completed'})  # ==> current 'action_status': is 'completed'
                                request.env.cr.commit()
                                error.update({provider.provider + "_response": provider_response or ''})
                        except Exception as e2:
                            _logger.error("%s", e2, exc_info=True)
                            # _logger.error(traceback.format_exc())
                            if machine_request and not machine_request.description:
                                machine_request.update({'description': _("Error is occur:") + " ==> " + str(e2)})
                                request.env.cr.commit()
                            if not unlink_wallet_reservation and machine_wallet_reservation_id:
                                machine_wallet_reservation_id.sudo().unlink()
                                request.env.cr.commit()
                                unlink_wallet_reservation = True
                            return invalid_response("Error", _("Error is occur:") + " ==> " + str(e2), 500)
                    else:
                        error.update({provider_info.name.name + "_response": _("%s is not a provider for (%s) service") % (
                            provider_info.name.name, service.name)})

                machine_request.update({
                    'provider_response': error or _('(%s) service has not any provider.') % (service.name),
                    'stage_id': 5
                })
                request.env.cr.commit()
                error_key = "user_error"
                error_msg = _("(%s) service has not any provider.") % (service.name)
                if provider:
                    if error.get(provider.provider + "_response").get("error_message"):
                        error_msg = error.get(provider.provider + "_response").get("error_message")
                    elif error.get(provider.provider + "_response").get("error_message_to_be_translated"):
                        error_msg = error.get(provider.provider + "_response").get("error_message_to_be_translated")
                        error_key = "Error"
                elif error.get(provider_info.name.name + "_response"):
                    error_msg = error.get(provider_info.name.name + "_response")
                if not unlink_wallet_reservation and machine_wallet_reservation_id:
                    machine_wallet_reservation_id.sudo().unlink()
                    request.env.cr.commit()
                    unlink_wallet_reservation = True
                return invalid_response(error_key, error_msg, 400)

            elif request_data.get('request_type') == 'pay_invoice':
                return valid_response({"message": _("Pay invoice request was submit successfully."),
                                       "request_number": machine_request.name
                                       })
            else:
                return valid_response({"message": _("Your request was submit successfully."),
                                       "request_number":machine_request.name
                                       })

        @validate_token
        @http.route('/api/create_mobile_request', type="http", auth="none", methods=["POST"], csrf=False)
        def create_mobile_request(self, **request_data):
            _logger.info("@@@@@@@@@@@@@@@@@@@ Calling Mobile Request API")

            if not request_data.get('request_type') or request_data.get('request_type') not in _REQUEST_TYPES_IDS:
                return invalid_response("request_type", _("request type invalid"), 400)

            if request_data.get('request_type') == 'recharge_wallet':
                if not request_data.get('trans_amount'):
                    return invalid_response("amount_not_found", _("missing amount in request data"), 400)
                open_request = request.env["smartpay_operations.request"].sudo().search(
                    [('request_type', '=', 'recharge_wallet'),("partner_id", "=", request.env.user.partner_id.id), ("stage_id", "=", 1)],
                    order="id DESC", limit=1)
                if open_request:
                    open_request_in_minute = open_request.filtered(lambda r: r.create_date >= date_time.now() - timedelta(minutes=1))
                    if open_request_in_minute:
                        return invalid_response("request_already_exist",
                                                _("You have a wallet recharge request in progress with REQ Number (%s)")
                                                % (open_request_in_minute.name), 400)
                    else:
                        open_request.update({'stage_id': 3})
                request_data['product_id'] = request.env["product.product"].sudo().search([('name', '=', 'Wallet Recharge')]).id

            if not request_data.get('product_id') and request_data.get('request_type') not in ('general_inquiry', 'wallet_invitation'):
                return invalid_response("service_not_found", _("missing service in request data"), 400)
            elif request_data.get('request_type') not in ('general_inquiry', 'wallet_invitation'):
                service = request.env["product.product"].sudo().search([("id", "=", request_data.get('product_id')), ("type", "=", "service")],
                                                                       order="id DESC", limit=1)
                if not service:
                    return invalid_response("service", _("service invalid"), 400)

            if request_data.get('request_type') == 'wallet_invitation':
                if not request_data.get('mobile_number'):
                    return invalid_response("mobile_number_not_found", _("missing mobile number for invited user in request data"), 400)

                open_request = request.env["smartpay_operations.request"].sudo().search(
                    [('request_type', '=', 'wallet_invitation'), ('mobile_number', '=', request_data.get('mobile_number')),
                     ('partner_id', '=', request.env.user.partner_id.id), ("stage_id", "=", 1)], order="id DESC", limit=1)
                if open_request:
                    return invalid_response("request_already_exist",
                                            _("You have a wallet invitation request in progress for mobile number (%s) with REQ Number (%s)") % (
                                                request_data.get('mobile_number'), open_request.name), 400)

                done_request = request.env["smartpay_operations.request"].sudo().search(
                    [('request_type', '=', 'wallet_invitation'),
                     ('mobile_number', '=', request_data.get('mobile_number')), ("stage_id", "=", 5)],
                    order="id DESC", limit=1)
                if done_request:
                    return invalid_response("request_already_exist",
                                            _("The mobile number (%s) already has a wallet") % (
                                                request_data.get('mobile_number')), 400)

            if request_data.get('request_type') == 'service_bill_inquiry' or request_data.get('request_type') == 'pay_service_bill':
                if not request_data.get('billingAcct'):
                    return invalid_response("billingAcct_not_found", _("missing billing account in request data"), 400)

                provider_provider = request_data.get('provider')
                if request_data.get('request_type') == 'pay_service_bill':
                    if not request_data.get('currency_id'):
                        return invalid_response("curCode_not_found",
                                                _("missing bill currency code in request data"), 400)
                    if not request_data.get('pmtMethod'):
                        return invalid_response("pmtMethod_not_found",
                                                _("missing payment method in request data"), 400)

                    if provider_provider == 'khales':
                        if not request_data.get('pmtType'):
                            return invalid_response("pmtType_not_found", _("missing payment type in request data"), 400)
                        '''
                        if not request_data.get('billerId'):
                            return invalid_response("billerId_not_found", _("missing biller id in request data"), 400)
                        '''
                        if not request_data.get('ePayBillRecID'):
                            return invalid_response("ePayBillRecID_not_found", _("missing ePay Bill Rec ID in request data"), 400)
                        if not request_data.get('pmtId'):
                            return invalid_response("pmtId_not_found", _("missing payment id in request data"), 400)
                        if not request_data.get('feesAmt'):
                            return invalid_response("feesAmt_not_found", _("missing fees amount in request data"), 400)
                        # if not request_data.get('pmtRefInfo'):
                            # return invalid_response("pmtRefInfo_not_found", _("missing payment Ref Info in request data"), 400)
                        payAmtTemp = float(request_data.get('trans_amount'))
                        payAmts = request_data.get('payAmts')
                        if payAmts:
                            payAmts = ast.literal_eval(payAmts)
                            for payAmt in payAmts:
                                payAmtTemp -= float(payAmt.get('AmtDue'))
                            if payAmtTemp != 0:
                                return invalid_response("payAmts_not_match",
                                                        _("The sum of payAmts must be equals trans_amount"), 400)

                        feesAmtTemp = request_data.get('feesAmt') or 0.00
                        feesAmts = request_data.get('feesAmts')
                        if feesAmts:
                            feesAmts = ast.literal_eval(feesAmts)
                            for feeAmt in feesAmts:
                                feesAmtTemp -= float(feeAmt.get('Amt'))
                            if feesAmtTemp != 0:
                                return invalid_response("feesAmts_not_match",
                                                        _("The sum of feesAmts must be equals feesAmt"), 400)

                    if ((provider_provider == 'fawry' and request_data.get('pmtType') == "POST") or provider_provider == 'khales') \
                            and not request_data.get('billRefNumber'):
                        return invalid_response("billRefNumber_not_found", _("missing bill reference number in request data"), 400)

                    # Provider is mandatory because the service fee is different per provider.
                    # So the user must send provider that own the bill inquiry request for prevent pay bill
                    # with total amount different of total amount in bill inquiry
                    if provider_provider:
                        provider = request.env['payment.acquirer'].sudo().search([("provider", "=", provider_provider)])
                        # if provider: # Tamayoz Note: Comment this condition for solving service_providerinfo assign before initilizing
                        service_providerinfo = request.env['product.supplierinfo'].sudo().search([
                            ('product_tmpl_id', '=', service.product_tmpl_id.id),
                            ('name', '=', provider.related_partner.id)
                        ])
                        if not service_providerinfo:
                            return invalid_response(
                                "Incompatible_provider_service", _("%s is not a provider for (%s) service") % (
                                    provider_provider, service.name or '-'), 400)
                        elif provider_provider in ('fawry', 'masary'):
                            inquiryTransactionId = request_data.get('inquiryTransactionId')
                            if (json.loads(service_providerinfo.biller_info, strict=False).get('inquiry_required') # Tamayoz TODO: Rename inquiry_required in standard API
                                # or json.loads(service_providerinfo.biller_info, strict=False).get('SupportPmtReverse')
                            ) \
                                    and not inquiryTransactionId:
                                return invalid_response("inquiryTransactionId_not_found", _("missing inquiry transaction id in request data"), 400)
                    else:
                        return invalid_response("provider_not_found",
                                                _("missing provider in request data"), 400)

                    trans_amount = float(request_data.get('trans_amount'))
                    if not trans_amount:
                        return invalid_response("amount_not_found",
                                                _("missing bill amount in request data"), 400)
                    else:
                        # Calculate Fees
                        provider_fees_calculated_amount = 0.0
                        provider_fees_actual_amount = 0.0
                        merchant_cashback_amount = 0.0
                        customer_cashback_amount = 0.0
                        extra_fees_amount = 0.0
                        commissions = request.env['product.supplierinfo.commission'].sudo().search_read(
                            domain=[('vendor', '=', service_providerinfo.name.id),
                                    ('vendor_product_code', '=', service_providerinfo.product_code)],
                            fields=['Amount_Range_From', 'Amount_Range_To',
                                    'Extra_Fee_Amt', 'Extra_Fee_Prc',
                                    'Mer_Fee_Amt', 'Mer_Fee_Prc', 'Mer_Fee_Prc_MinAmt', 'Mer_Fee_Prc_MaxAmt',
                                    'Mer_Comm_Full_Fix_Amt', 'Cust_Comm_Full_Fix_Amt',
                                    'Bill_Merchant_Comm_Prc', 'Bill_Customer_Comm_Prc']
                        )
                        for commission in commissions:
                            if commission['Amount_Range_From'] <= trans_amount \
                                    and commission['Amount_Range_To'] >= trans_amount:
                                if commission['Mer_Comm_Full_Fix_Amt'] > 0:
                                    merchant_cashback_amount = commission['Mer_Comm_Full_Fix_Amt']
                                    customer_cashback_amount = commission['Cust_Comm_Full_Fix_Amt']
                                elif commission['Bill_Merchant_Comm_Prc'] > 0:
                                    merchant_cashback_amount = trans_amount * commission[
                                        'Bill_Merchant_Comm_Prc'] / 100
                                    customer_cashback_amount = trans_amount * commission[
                                        'Bill_Customer_Comm_Prc'] / 100
                                if commission['Extra_Fee_Amt'] > 0:
                                    extra_fees_amount = commission['Extra_Fee_Amt']
                                elif commission['Extra_Fee_Prc'] > 0:
                                    extra_fees_amount = trans_amount * commission['Extra_Fee_Prc'] / 100
                                if commission['Mer_Fee_Amt'] > 0:
                                    provider_fees_calculated_amount = commission['Mer_Fee_Amt']
                                elif commission['Mer_Fee_Prc'] > 0:
                                    # Fees amount = FA + [Percentage * Payment Amount]
                                    # Fees amount ====================> provider_fees_calculated_amount
                                    # FA =============================> provider_fees_calculated_amount
                                    # [Percentage * Payment Amount] ==> provider_fees_prc_calculated_amount
                                    provider_fees_prc_calculated_amount = trans_amount * commission[
                                        'Mer_Fee_Prc'] / 100
                                    if provider_fees_prc_calculated_amount < commission['Mer_Fee_Prc_MinAmt']:
                                        provider_fees_prc_calculated_amount = commission['Mer_Fee_Prc_MinAmt']
                                    elif provider_fees_prc_calculated_amount > commission['Mer_Fee_Prc_MaxAmt'] \
                                            and commission['Mer_Fee_Prc_MaxAmt'] > 0:
                                        provider_fees_prc_calculated_amount = commission['Mer_Fee_Prc_MaxAmt']
                                    provider_fees_calculated_amount += provider_fees_prc_calculated_amount
                                elif provider_provider == 'khales':
                                    provider_fees_calculated_amount = float(request_data.get('feesAmt'))
                                break
                        calculated_payment_amount = trans_amount + provider_fees_calculated_amount + extra_fees_amount

                        if service.has_sale_limit:
                            limit_fees_amounts = {}
                            for sale_limit_id in service.sale_limit_ids:
                                limit_type = sale_limit_id.limit_type
                                limit_amount = sale_limit_id.limit_amount
                                partner_sale_limit_id = request.env['res.partner.product.sale.limit'].sudo().search(
                                    [('partner_id', '=', request.env.user.partner_id.id),
                                     ('product_tmpl_id', '=', service.product_tmpl_id.id),
                                     ('limit_type', '=', limit_type)], limit=1)
                                if partner_sale_limit_id:
                                    limit_amount = partner_sale_limit_id.limit_amount
                                timetuple = date_time.now().timetuple()
                                sale_limit_domain = [('partner_id', '=', request.env.user.partner_id.id),
                                                     ('product_id', '=', service.id),
                                                     ('limit_type', '=', limit_type),
                                                     ('year', '=', timetuple.tm_year)]
                                if limit_type == 'daily':
                                    sale_limit_domain += [('day', '=', timetuple.tm_yday)]
                                elif limit_type == 'weekly':
                                    sale_limit_domain += [('week', '=', date_time.now().isocalendar()[1])]
                                elif limit_type == 'monthly':
                                    sale_limit_domain += [('month', '=', timetuple.tm_mon)]
                                sale_limit = request.env['res.partner.sale.limit'].sudo().search(sale_limit_domain,
                                                                                                 order="id DESC",
                                                                                                 limit=1)
                                calculated_sold_amount = calculated_payment_amount
                                if sale_limit:
                                    calculated_sold_amount += sale_limit.sold_amount
                                if limit_amount < calculated_sold_amount:
                                    over_limit_fees_ids = []
                                    if partner_sale_limit_id:
                                        if partner_sale_limit_id.over_limit_fees_policy == 'product_over_limit_fees' and partner_sale_limit_id.product_over_limit_fees_ids:
                                            over_limit_fees_ids = partner_sale_limit_id.product_over_limit_fees_ids
                                            limit_amount = over_limit_fees_ids.sorted(lambda l: l.sale_amount_to, reverse=True)[0].sale_amount_to + partner_sale_limit_id.limit_amount
                                        if partner_sale_limit_id.over_limit_fees_policy == 'custom_over_limit_fees' and partner_sale_limit_id.over_limit_fees_ids:
                                            over_limit_fees_ids = partner_sale_limit_id.over_limit_fees_ids
                                            limit_amount = over_limit_fees_ids.sorted(lambda l: l.sale_amount_to, reverse=True)[0].sale_amount_to + partner_sale_limit_id.limit_amount
                                    else:
                                        if sale_limit_id.has_over_limit_fees and sale_limit_id.over_limit_fees_ids:
                                            over_limit_fees_ids = sale_limit_id.over_limit_fees_ids
                                            limit_amount = over_limit_fees_ids.sorted(lambda l: l.sale_amount_to, reverse=True)[0].sale_amount_to + sale_limit_id.limit_amount

                                    if limit_amount < calculated_sold_amount:
                                        return invalid_response("%s_limit_exceeded" % limit_type,
                                                                _("%s limit exceeded for service (%s)") % (
                                                                    limit_type, service.name), 400)

                                    limit_fees_amount = 0
                                    for over_limit_fees_id in over_limit_fees_ids:
                                        if over_limit_fees_id['sale_amount_from'] <= trans_amount and over_limit_fees_id['sale_amount_to'] >= trans_amount:
                                            if over_limit_fees_id['fees_amount'] > 0:
                                                limit_fees_amount = over_limit_fees_id['fees_amount']
                                            elif over_limit_fees_id['fees_amount_percentage'] > 0:
                                                limit_fees_amount = trans_amount * over_limit_fees_id['fees_amount_percentage'] / 100
                                            break
                                    if limit_fees_amount > 0:
                                        limit_fees_amounts.update({limit_type: limit_fees_amount})
                                        calculated_payment_amount += limit_fees_amount

                        if request_data.get("wallet_id"):
                            partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(wallet_id=request_data.get("wallet_id"),
                                                                                                   service=service,
                                                                                                   trans_amount=calculated_payment_amount)
                        else:
                            partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(service=service,
                                                                                                   trans_amount=calculated_payment_amount)
                        if not partner_wallet_id:
                            return invalid_response("wallet_not_found",
                                                    _("No Matched Wallet found for partner [%s] %s") % (
                                                        request.env.user.partner_id.ref,
                                                        request.env.user.partner_id.name), 400)

                        # Check Wallet Transaction limits
                        if partner_wallet_id.type.has_trans_limit:
                            wallet_limit_fees_amounts = {}
                            for trans_limit_id in partner_wallet_id.type.trans_limit_ids:
                                wallet_limit_type = trans_limit_id.limit_type
                                wallet_limit_amount = trans_limit_id.limit_amount
                                wallet_trans_limit_id = request.env['wallet.wallet.type.trans.limit'].sudo().search(
                                    [('wallet_id', '=', partner_wallet_id.id),
                                     # ('wallet_type_id', '=', partner_wallet_id.type.id),
                                     ('limit_type', '=', wallet_limit_type)], limit=1)
                                if wallet_trans_limit_id:
                                    wallet_limit_amount = wallet_trans_limit_id.limit_amount
                                timetuple = date_time.now().timetuple()
                                trans_limit_domain = [('wallet_id', '=', partner_wallet_id.id),
                                                      # ('wallet_type_id', '=', partner_wallet_id.type.id),
                                                      ('limit_type', '=', wallet_limit_type),
                                                      ('year', '=', timetuple.tm_year)]
                                if wallet_limit_type == 'daily':
                                    trans_limit_domain += [('day', '=', timetuple.tm_yday)]
                                elif wallet_limit_type == 'weekly':
                                    trans_limit_domain += [('week', '=', date_time.now().isocalendar()[1])]
                                elif wallet_limit_type == 'monthly':
                                    trans_limit_domain += [('month', '=', timetuple.tm_mon)]
                                trans_limit = request.env['wallet.trans.limit'].sudo().search(trans_limit_domain,
                                                                                              order="id DESC", limit=1)
                                calculated_trans_amount = calculated_payment_amount
                                if trans_limit:
                                    calculated_trans_amount += trans_limit.trans_amount
                                if wallet_limit_amount < calculated_trans_amount:
                                    wallet_over_limit_fees_ids = []
                                    if wallet_trans_limit_id:
                                        if wallet_trans_limit_id.over_limit_fees_policy == 'wallet_type_over_limit_fees' and wallet_trans_limit_id.wallet_type_over_limit_fees_ids:
                                            wallet_over_limit_fees_ids = wallet_trans_limit_id.wallet_type_over_limit_fees_ids
                                            wallet_limit_amount = wallet_over_limit_fees_ids.sorted(lambda l: l.trans_amount_to, reverse=True)[0].trans_amount_to + wallet_trans_limit_id.limit_amount
                                        if wallet_trans_limit_id.over_limit_fees_policy == 'custom_over_limit_fees' and wallet_trans_limit_id.over_limit_fees_ids:
                                            wallet_over_limit_fees_ids = wallet_trans_limit_id.over_limit_fees_ids
                                            wallet_limit_amount = wallet_over_limit_fees_ids.sorted(lambda l: l.trans_amount_to, reverse=True)[0].trans_amount_to + wallet_trans_limit_id.limit_amount
                                    else:
                                        if trans_limit_id.has_over_limit_fees and trans_limit_id.over_limit_fees_ids:
                                            wallet_over_limit_fees_ids = trans_limit_id.over_limit_fees_ids
                                            wallet_limit_amount = wallet_over_limit_fees_ids.sorted(lambda l: l.trans_amount_to, reverse=True)[0].trans_amount_to + trans_limit_id.limit_amount

                                    if wallet_limit_amount < calculated_trans_amount:
                                        return invalid_response("%s_limit_exceeded" % wallet_limit_type,
                                                                _("%s limit exceeded for wallet type (%s)") % (
                                                                    wallet_limit_type, partner_wallet_id.type.name), 400)

                                    wallet_limit_fees_amount = 0
                                    for wallet_over_limit_fees_id in wallet_over_limit_fees_ids:
                                        if wallet_over_limit_fees_id['trans_amount_from'] <= trans_amount and wallet_over_limit_fees_id['trans_amount_to'] >= trans_amount:
                                            if wallet_over_limit_fees_id['fees_amount'] > 0:
                                                wallet_limit_fees_amount = wallet_over_limit_fees_id['fees_amount']
                                            elif wallet_over_limit_fees_id['fees_amount_percentage'] > 0:
                                                wallet_limit_fees_amount = trans_amount * wallet_over_limit_fees_id['fees_amount_percentage'] / 100
                                            break
                                    if wallet_limit_fees_amount > 0:
                                        wallet_limit_fees_amounts.update({wallet_limit_type: wallet_limit_fees_amount})
                                        calculated_payment_amount += wallet_limit_fees_amount

                        unlink_wallet_reservation = False
                        mobile_wallet_reservation_id, mobile_wallet_balance, mobile_wallet_available_amount = \
                            partner_wallet_id.update_wallet_reserved_balance(
                                _('Pay Service Bill for %s service') % (service.name), calculated_payment_amount,
                                request.env.user.company_id.currency_id, 'request'
                            )
                        # # mobile_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                        # mobile_wallet_available_amount = partner_wallet_id.available_amount if partner_wallet_id else 0
                        # if mobile_wallet_available_amount < calculated_payment_amount:
                        if not mobile_wallet_reservation_id:
                            return invalid_response("mobile_balance_not_enough",
                                                    _("Mobile Wallet Available Balance (%s) less than the payment amount (%s)") % (
                                                        mobile_wallet_available_amount, calculated_payment_amount), 400)

            request_data['partner_id'] = request.env.user.partner_id.id
            model_name = 'smartpay_operations.request'
            model_record = request.env['ir.model'].sudo().search([('model', '=', model_name)])

            try:
                data = WebsiteForm().extract_data(model_record, request_data)
            # If we encounter an issue while extracting data
            except ValidationError as e:
                # I couldn't find a cleaner way to pass data to an exception
                return invalid_response("Error", _("Could not submit you request.") + " ==> " + str(e), 500)

            try:
                id_record = WebsiteForm().insert_record(request, model_record, data['record'], data['custom'], data.get('meta'))
                if id_record:
                    WebsiteForm().insert_attachment(model_record, id_record, data['attachments'])
                    request.env.cr.commit()
                    user_request = model_record.env[model_name].sudo().browse(id_record)
                else:
                    return invalid_response("Error", _("Could not submit you request."), 500)

            # Some fields have additional SQL constraints that we can't check generically
            # Ex: crm.lead.probability which is a float between 0 and 1
            # TODO: How to get the name of the erroneous field ?
            except IntegrityError as e:
                return invalid_response("Error", _("Could not submit you request.") + " ==> " + str(e), 500)

            if request_data.get('request_type') == 'recharge_wallet':
                return valid_response({"message": _("Recharge your wallet request was submit successfully."),
                                       "request_number": user_request.name
                                       })
            elif request_data.get('request_type') == 'wallet_invitation':
                return valid_response({"message": _("Wallet inivitation request for mobile number (%s) was submit successfully.") % (
                                                request_data.get('mobile_number')),
                                        "request_number": user_request.name
                                       })

            elif request_data.get('request_type') == 'service_bill_inquiry':
                lang = request_data.get('lang')
                billingAcct = request_data.get('billingAcct')
                extraBillingAcctKeys = request_data.get('extraBillingAcctKeys')
                if extraBillingAcctKeys:
                    extraBillingAcctKeys = ast.literal_eval(extraBillingAcctKeys)
                customProperties = request_data.get('customProperties')
                if customProperties:
                    customProperties = ast.literal_eval(customProperties)

                provider_response = {}
                error = {}
                for provider_info in service.seller_ids:
                    provider = request.env['payment.acquirer'].sudo().search([("related_partner", "=", provider_info.name.id)])
                    if provider:
                        if provider.server_state == 'offline':
                            error.update({provider.provider + "_response": {'error_message': _("Service Not Available")}})
                            break
                        trans_amount = 0.0
                        provider_channel = False
                        machine_channels = request.env['payment.acquirer.channel'].sudo().search([("acquirer_id", "=", provider.id),
                                                                                                  ("type", "in", ("machine", "internet"))], limit=1)
                        if machine_channels:
                            provider_channel = machine_channels[0]

                        if provider.provider == "fawry":
                            provider_response = provider.get_fawry_bill_details(lang, provider_info.product_code,
                                                                                billingAcct, extraBillingAcctKeys,
                                                                                provider_channel, customProperties,
                                                                                user_request.name)
                            if provider_response.get('Success'):
                                billRecType = provider_response.get('Success')
                                provider_response_json = suds_to_json(billRecType)
                                for BillSummAmt in billRecType['BillInfo']['BillSummAmt']:
                                    if BillSummAmt['BillSummAmtCode'] == 'TotalAmtDue':
                                        trans_amount += float(BillSummAmt['CurAmt']['Amt'])
                                        break
                        elif provider.provider == "khales":
                            provider_response = {}
                            biller_info_json_dict = json.loads(provider_info.with_context(lang=request.env.user.lang).biller_info, strict=False)
                            # Handel billingAcct format if exist
                            if biller_info_json_dict.get('BillTypeAcctFormat') and biller_info_json_dict.get('BillTypeAcctFormatSpliter'):
                                formatedBillingAcct = []
                                keysToBeRemoved = []
                                for format in biller_info_json_dict.get('BillTypeAcctFormat').split(biller_info_json_dict.get('BillTypeAcctFormatSpliter')):
                                    if format == 'billingAcct':
                                        formatedBillingAcct.append(billingAcct)
                                    else:
                                        is_extra_key = False
                                        for extraBillingAcctKey in extraBillingAcctKeys:
                                            if extraBillingAcctKey.get("Key") == format:
                                                formatedBillingAcct.append(extraBillingAcctKey.get("Value"))
                                                keysToBeRemoved.append(extraBillingAcctKey)
                                                is_extra_key = True
                                                break
                                        if not is_extra_key:
                                            formatedBillingAcct.append(format)
                                extraBillingAcctKeys = [x for x in extraBillingAcctKeys if x not in keysToBeRemoved]
                                billingAcct = biller_info_json_dict.get('BillTypeAcctFormatSpliter').join(formatedBillingAcct)

                            '''
                            machine_serial = None
                            if len(request.env.user.machine_serial) > 16:  # Ingenico POS
                                machine_serial = request.env.user.machine_serial
                                machine_serial = machine_serial[len(machine_serial) - 16:len(machine_serial)]
                            '''
                            machine_serial = request.env.user.machine_serial
                            if machine_serial and len(machine_serial) > 16:
                                machine_serial = machine_serial[len(machine_serial) - 16:len(machine_serial)]
                            bill_response = provider.get_khales_bill_details(lang, machine_serial or user_request.name,
                                                                             provider_info.product_code, biller_info_json_dict.get('Code'),
                                                                             billingAcct, extraBillingAcctKeys, provider_channel, user_request.name)
                            if bill_response.get('Success'):
                                billRecType = bill_response.get('Success')
                                payAmts = billRecType['BillInfo']['CurAmt']
                                if payAmts and isinstance(payAmts, OrderedDict):
                                    payAmts = [payAmts]
                                    billRecType['BillInfo']['CurAmt'] = payAmts
                                success_response = {"bill_response": suds_to_json(billRecType)}
                                # for payAmt in payAmts:
                                    # trans_amount += float(payAmt.get("AmtDue"))
                                trans_amount += float(payAmts[0].get("AmtDue"))
                                if biller_info_json_dict.get('PmtType') == 'POST':
                                    ePayBillRecID = billRecType['EPayBillRecID']
                                    fees_response = provider.get_khales_fees(lang, machine_serial or user_request.name,
                                                                             ePayBillRecID, payAmts[0], provider_channel, user_request.name)
                                    provider_fees_calculated_amount = 0.0
                                    if fees_response.get('Success'):
                                        feeInqRsType = fees_response.get('Success')
                                        provider_fees_calculated_amount = float(feeInqRsType['FeesAmt']['Amt'])
                                        # success_response.update({"fees_response": suds_to_json(feeInqRsType)})
                                    else:
                                        feeInqRsType = {"EPayBillRecID": ePayBillRecID,
                                                        "FeesAmt": {"Amt": "0.0", "CurCode": "818"}}

                                    if provider_fees_calculated_amount == 0:
                                        service_providerinfo = request.env['product.supplierinfo'].sudo().search([
                                            ('product_tmpl_id', '=', service.product_tmpl_id.id),
                                            ('name', '=', provider.related_partner.id)
                                        ])
                                        commissions = request.env[
                                            'product.supplierinfo.commission'].sudo().search_read(
                                            domain=[('vendor', '=', service_providerinfo.name.id),
                                                    (
                                                        'vendor_product_code', '=', service_providerinfo.product_code)],
                                            fields=['Amount_Range_From', 'Amount_Range_To',
                                                    'Extra_Fee_Amt', 'Extra_Fee_Prc',
                                                    'Mer_Fee_Amt', 'Mer_Fee_Prc', 'Mer_Fee_Prc_MinAmt',
                                                    'Mer_Fee_Prc_MaxAmt']
                                        )
                                        for commission in commissions:
                                            if commission['Amount_Range_From'] <= trans_amount \
                                                    and commission['Amount_Range_To'] >= trans_amount:
                                                if commission['Extra_Fee_Amt'] > 0:
                                                    extra_fees_amount = commission['Extra_Fee_Amt']
                                                elif commission['Extra_Fee_Prc'] > 0:
                                                    extra_fees_amount = trans_amount * commission[
                                                        'Extra_Fee_Prc'] / 100
                                                if commission['Mer_Fee_Amt'] > 0:
                                                    provider_fees_calculated_amount = commission['Mer_Fee_Amt']
                                                elif commission['Mer_Fee_Prc'] > 0:
                                                    # Fees amount = FA + [Percentage * Payment Amount]
                                                    # Fees amount ====================> provider_fees_calculated_amount
                                                    # FA =============================> provider_fees_calculated_amount
                                                    # [Percentage * Payment Amount] ==> provider_fees_prc_calculated_amount
                                                    provider_fees_prc_calculated_amount = trans_amount * commission[
                                                        'Mer_Fee_Prc'] / 100
                                                    if provider_fees_prc_calculated_amount < commission[
                                                        'Mer_Fee_Prc_MinAmt']:
                                                        provider_fees_prc_calculated_amount = commission[
                                                            'Mer_Fee_Prc_MinAmt']
                                                    elif provider_fees_prc_calculated_amount > commission[
                                                        'Mer_Fee_Prc_MaxAmt'] \
                                                            and commission['Mer_Fee_Prc_MaxAmt'] > 0:
                                                        provider_fees_prc_calculated_amount = commission[
                                                            'Mer_Fee_Prc_MaxAmt']
                                                    provider_fees_calculated_amount += provider_fees_prc_calculated_amount
                                                break
                                        feeInqRsType['FeesAmt']['Amt'] = "%s" % ((math.floor(provider_fees_calculated_amount * 100)) / 100.0)

                                    success_response.update({"fees_response": suds_to_json(feeInqRsType)})
                                provider_response = {'Success': success_response}

                                provider_response_json = provider_response.get('Success')
                            else:
                                provider_response = bill_response
                        elif provider.provider == "masary":
                            provider_response = provider.get_masary_bill_details(lang, int(provider_info.product_code),
                                                                                extraBillingAcctKeys, provider_channel, user_request.name)
                            if provider_response.get('Success'):
                                billData = provider_response.get('Success')
                                provider_response_json = billData
                                if billData.get('amount'):
                                    trans_amount += float(billData.get('amount'))
                                # elif billData.get('min_amount'):
                                    # trans_amount += float(billData.get('min_amount'))

                        if provider_response.get('Success'):
                            # if not provider_response_json:
                                # provider_response_json = suds_to_json(provider_response.get('Success'))
                            commissions = request.env['product.supplierinfo.commission'].sudo().search_read(
                                domain=[('vendor', '=', provider_info.name.id), ('vendor_product_code', '=', provider_info.product_code)],
                                fields=['Amount_Range_From', 'Amount_Range_To', 'Extra_Fee_Amt', 'Extra_Fee_Prc']
                            )
                            extra_fees_amount = 0.0
                            for commission in commissions:
                                if commission['Amount_Range_From'] <= trans_amount \
                                        and commission['Amount_Range_To'] >= trans_amount:
                                    if commission['Extra_Fee_Amt'] > 0:
                                        extra_fees_amount = commission['Extra_Fee_Amt']
                                    elif commission['Extra_Fee_Prc'] > 0:
                                        extra_fees_amount = trans_amount * commission['Extra_Fee_Prc'] / 100
                                    break
                            user_request.update(
                                {"provider_id": provider.id, "provider_response": provider_response_json,
                                 "trans_amount": trans_amount, "extra_fees_amount": extra_fees_amount,
                                 "extra_fees": commissions, "stage_id": 5})
                            request.env.cr.commit()
                            return valid_response(
                                {"message": _("Service Bill Inquiry request was submit successfully."),
                                 "request_number": user_request.name,
                                 "provider": provider.provider,
                                 "provider_response": provider_response_json,
                                 "extra_fees_amount": extra_fees_amount,
                                 # "extra_fees": commissions
                                 })
                        else:
                            error.update({provider.provider + "_response": provider_response or ''})
                    else:
                        error.update({provider_info.name.name + "_response": _("%s is not a provider for (%s) service") % (
                            provider_info.name.name, service.name)})

                user_request.update({
                    "provider_response": error or _("(%s) service has not any provider.") % (service.name),
                    "stage_id": 5
                })
                request.env.cr.commit()
                error_key = "user_error"
                error_msg = _("(%s) service has not any provider.") % (service.name)
                if provider:
                    if error.get(provider.provider + "_response").get("error_message"):
                        error_msg = error.get(provider.provider + "_response").get("error_message")
                    elif error.get(provider.provider + "_response").get("error_message_to_be_translated"):
                        error_msg = error.get(provider.provider + "_response").get("error_message_to_be_translated")
                        error_key = "Error"
                elif error.get(provider_info.name.name + "_response"):
                    error_msg = error.get(provider_info.name.name + "_response")
                return invalid_response(error_key, error_msg, 400)

            elif request_data.get('request_type') == 'pay_service_bill':
                if mobile_wallet_reservation_id:
                    mobile_wallet_reservation_id.update({'request_id': user_request.id})
                    request.env.cr.commit()
                lang = request_data.get('lang')
                billingAcct = request_data.get('billingAcct')

                extraBillingAcctKeys = request_data.get('extraBillingAcctKeys')
                if extraBillingAcctKeys:
                    extraBillingAcctKeys = ast.literal_eval(extraBillingAcctKeys)

                notifyMobile = request_data.get('notifyMobile')
                billRefNumber = request_data.get('billRefNumber')
                billerId = request_data.get('billerId')
                pmtType = request_data.get('pmtType')

                trans_amount = request_data.get('trans_amount')
                curCode = request_data.get('currency_id')
                payAmts = request_data.get('payAmts')
                if payAmts:
                    payAmts = ast.literal_eval(payAmts)
                else:
                    payAmts = [{'Sequence':'1', 'AmtDue':trans_amount, 'CurCode':curCode}]
                pmtMethod = request_data.get('pmtMethod')

                ePayBillRecID = request_data.get('ePayBillRecID')
                pmtId = request_data.get('pmtId') or user_request.name
                feesAmt = request_data.get('feesAmt') or 0.00
                feesAmts = request_data.get('feesAmts')
                if feesAmts:
                    feesAmts = ast.literal_eval(feesAmts)
                else:
                    feesAmts = [{'Amt': feesAmt, 'CurCode': curCode}]
                pmtRefInfo = request_data.get('pmtRefInfo')

                providers_info = []
                '''
                provider_provider = request_data.get('provider')
                if provider_provider:
                    provider = request.env['payment.acquirer'].sudo().search([("provider", "=", provider_provider)])
                    if provider:
                        service_providerinfo = request.env['product.supplierinfo'].sudo().search([
                            ('product_tmpl_id', '=', service.product_tmpl_id.id),
                            ('name', '=', provider.related_partner.id)
                        ])
                        if service_providerinfo:
                            providers_info.append(service_providerinfo)
                if not provider_provider or len(providers_info) == 0:
                    providers_info = service.seller_ids
                '''
                providers_info.append(service_providerinfo)

                provider_response = {}
                provider_response_json = {}
                '''
                provider_fees_calculated_amount = 0.0
                provider_fees_actual_amount = 0.0
                merchant_cashback_amount = 0.0
                customer_cashback_amount = 0.0
                extra_fees_amount = 0.0
                '''
                error = {}
                for provider_info in providers_info:
                    biller_info_json_dict = json.loads(provider_info.with_context(lang=request.env.user.lang).biller_info, strict=False)
                    '''
                    # Get Extra Fees
                    commissions = request.env['product.supplierinfo.commission'].sudo().search_read(
                        domain=[('vendor', '=', provider_info.name.id),
                                ('vendor_product_code', '=', provider_info.product_code)],
                        fields=['Amount_Range_From', 'Amount_Range_To',
                                'Extra_Fee_Amt', 'Extra_Fee_Prc',
                                'Mer_Fee_Amt', 'Mer_Fee_Prc', 'Mer_Fee_Prc_MinAmt', 'Mer_Fee_Prc_MaxAmt',
                                'Mer_Comm_Full_Fix_Amt', 'Cust_Comm_Full_Fix_Amt',
                                'Bill_Merchant_Comm_Prc', 'Bill_Customer_Comm_Prc']
                    )
                    for commission in commissions:
                        if commission['Amount_Range_From'] <= machine_request.trans_amount \
                                and commission['Amount_Range_To'] >= machine_request.trans_amount:
                            if commission['Mer_Comm_Full_Fix_Amt'] > 0:
                                merchant_cashback_amount = commission['Mer_Comm_Full_Fix_Amt']
                                customer_cashback_amount = commission['Cust_Comm_Full_Fix_Amt']
                            elif commission['Bill_Merchant_Comm_Prc'] > 0:
                                merchant_cashback_amount = machine_request.trans_amount * commission[
                                    'Bill_Merchant_Comm_Prc'] / 100
                                customer_cashback_amount = machine_request.trans_amount * commission[
                                    'Bill_Customer_Comm_Prc'] / 100
                            if commission['Extra_Fee_Amt'] > 0:
                                extra_fees_amount = commission['Extra_Fee_Amt']
                            elif commission['Extra_Fee_Prc'] > 0:
                                extra_fees_amount = machine_request.trans_amount * commission['Extra_Fee_Prc'] / 100
                            if commission['Mer_Fee_Amt'] > 0:
                                provider_fees_calculated_amount = commission['Mer_Fee_Amt']
                            elif commission['Mer_Fee_Prc'] > 0:
                                # Fees amount = FA + [Percentage * Payment Amount]
                                # Fees amount ====================> provider_fees_calculated_amount
                                # FA =============================> provider_fees_calculated_amount
                                # [Percentage * Payment Amount] ==> provider_fees_prc_calculated_amount
                                provider_fees_prc_calculated_amount = machine_request.trans_amount * commission['Mer_Fee_Prc'] / 100
                                if provider_fees_prc_calculated_amount < commission['Mer_Fee_Prc_MinAmt']:
                                    provider_fees_prc_calculated_amount = commission['Mer_Fee_Prc_MinAmt']
                                elif provider_fees_prc_calculated_amount > commission['Mer_Fee_Prc_MaxAmt'] \
                                        and commission['Mer_Fee_Prc_MaxAmt'] > 0:
                                    provider_fees_prc_calculated_amount = commission['Mer_Fee_Prc_MaxAmt']
                                provider_fees_calculated_amount += provider_fees_prc_calculated_amount
                            elif provider_provider == 'khales':
                                provider_fees_calculated_amount = float(request_data.get('feesAmt'))
                            break
                    calculated_payment_amount = machine_request.trans_amount + provider_fees_calculated_amount + extra_fees_amount
                    if request_data.get("wallet_id"):
                        partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(wallet_id=request_data.get("wallet_id"),
                                                                                               service=service,
                                                                                               trans_amount=calculated_payment_amount)
                    else:
                        partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(service=service,
                                                                                               trans_amount=calculated_payment_amount)
                    unlink_wallet_reservation = False
                    mobile_wallet_reservation_id, mobile_wallet_balance, mobile_wallet_available_amount = partner_wallet_id.update_wallet_reserved_balance(
                            _('Pay Service Bill for %s service') % (service.name), calculated_payment_amount,
                            request.env.user.company_id.currency_id, 'request'
                        )
                    # # mobile_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                    # mobile_wallet_available_amount = partner_wallet_id.available_amount if partner_wallet_id else 0
                    # if mobile_wallet_available_amount < calculated_payment_amount:
                    if not mobile_wallet_reservation_id:
                        error.update({"mobile_balance_not_enough":
                                                _("Mobile Wallet Available Balance (%s) less than the payment amount (%s)") % (mobile_wallet_available_amount,
                                                                                                                      calculated_payment_amount)})
                    '''

                    user_request.update({'provider_fees_calculated_amount': provider_fees_calculated_amount})
                    request.env.cr.commit()
                    provider = request.env['payment.acquirer'].sudo().search([("related_partner", "=", provider_info.name.id)])
                    if provider:
                        try:
                            if provider.server_state == 'offline':
                                error.update({provider.provider + "_response": {'error_message': _("Service Not Available")}})
                                break
                            provider_channel = False
                            machine_channels = request.env['payment.acquirer.channel'].sudo().search([("acquirer_id", "=", provider.id),
                                                                                                      ("type", "in", ("mobile", "internet"))], limit=1)
                            if machine_channels:
                                provider_channel = machine_channels[0]
                            if provider.provider == "fawry":
                                # Tamayoz TODO: Provider Server Timeout Handling
                                user_request.update({'action_status': 'in_progress'})  # ==> current 'payment_status': is 'new'
                                request.env.cr.commit()
                                provider_response = provider.pay_fawry_bill(lang, provider_info.product_code,
                                                                            billingAcct, extraBillingAcctKeys,
                                                                            trans_amount, curCode, pmtMethod,
                                                                            notifyMobile, billRefNumber,
                                                                            billerId, pmtType, provider_channel,
                                                                            inquiryTransactionId, user_request.name,
                                                                            biller_info_json_dict.get('SupportPmtReverse'),
                                                                            biller_info_json_dict.get('AllowRetry'))
                                if provider_response.get('Success'):
                                    if provider_response.get('Success').get('timeout'):
                                        user_request.update({'payment_status': 'timeout'}) # ==> current 'action_status': is 'in_progress'
                                        if biller_info_json_dict.get('PmtType') == 'VOCH':
                                            provider_response = {"error_code": "0", "error_message": None,
                                                                 "error_message_to_be_translated": "FW Server timeout:\n",}
                                            if biller_info_json_dict.get('SupportPmtReverse'):
                                                provider_response.update({"TO_CANCEL": "VOCH"})
                                            else:
                                                provider_response.update({"TO_REVIEW": "VOCH"})
                                    else:
                                        user_request.update({'action_status': 'completed'}) # ==> current 'payment_status': is 'new'
                                    request.env.cr.commit()
                                    if not provider_response.get('error_code'):
                                        provider_response_json = suds_to_json(provider_response.get('Success')['pmtInfoValType'])
                                        msgRqHdr_response_json = suds_to_json(provider_response.get('Success')['msgRqHdrType'])
                                        # Get customProperties
                                        msgRqHdr_response_json_dict = json.loads(msgRqHdr_response_json, strict=False)
                                        customProperties = msgRqHdr_response_json_dict.get('CustomProperties')
                                        cardMetadata = ''
                                        if customProperties:
                                            # Get CardMetadata
                                            for customProperty in customProperties['CustomProperty']:
                                                if customProperty['Key'] == 'CardMetadata':
                                                    cardMetadata = customProperty['Value']
                                                    break
                                        # Get Provider Fees
                                        provider_response_json_dict = json.loads(provider_response_json, strict=False)
                                        # provider_response_json_dict['PmtInfo']['CurAmt']['Amt'] == user_request.trans_amount
                                        provider_fees_actual_amount = provider_response_json_dict['PmtInfo']['FeesAmt']['Amt']
                                        user_request.update({'provider_fees_amount': provider_fees_actual_amount})
                                        request.env.cr.commit()
                                        # Get Provider Payment Trans ID
                                        for payment in provider_response_json_dict['PmtTransId']:
                                            if payment['PmtIdType'] == 'FCRN':
                                                provider_payment_trans_id = payment['PmtId']
                                                break

                            elif provider.provider == "khales":
                                if not billerId:
                                    billerId = biller_info_json_dict.get('Code')
                                # Handel billingAcct format if exist
                                if biller_info_json_dict.get('BillTypeAcctFormat') and biller_info_json_dict.get('BillTypeAcctFormatSpliter'):
                                    formatedBillingAcct = []
                                    keysToBeRemoved = []
                                    for format in biller_info_json_dict.get('BillTypeAcctFormat').split(biller_info_json_dict.get('BillTypeAcctFormatSpliter')):
                                        if format == 'billingAcct':
                                            formatedBillingAcct.append(billingAcct)
                                        else:
                                            is_extra_key = False
                                            for extraBillingAcctKey in extraBillingAcctKeys:
                                                if extraBillingAcctKey.get("Key") == format:
                                                    formatedBillingAcct.append(extraBillingAcctKey.get("Value"))
                                                    keysToBeRemoved.append(extraBillingAcctKey)
                                                    is_extra_key = True
                                                    break
                                            if not is_extra_key:
                                                formatedBillingAcct.append(format)
                                    extraBillingAcctKeys = [x for x in extraBillingAcctKeys if
                                                            x not in keysToBeRemoved]
                                    billingAcct = biller_info_json_dict.get('BillTypeAcctFormatSpliter').join(formatedBillingAcct)
                                # Tamayoz TODO: Provider Server Timeout Handling
                                # Tamayoz TODO: Remove the next temporary line
                                pmtMethod = "CARD"  # TEMP CODE
                                user_request.update({'action_status': 'in_progress'})  # ==> current 'payment_status': is 'new'
                                request.env.cr.commit()
                                '''
                                machine_serial = None
                                if len(request.env.user.machine_serial) > 16:  # Ingenico POS
                                    machine_serial = request.env.user.machine_serial
                                    machine_serial = machine_serial[len(machine_serial) - 16:len(machine_serial)]
                                '''
                                machine_serial = request.env.user.machine_serial
                                if machine_serial and len(machine_serial) > 16:
                                    machine_serial = machine_serial[len(machine_serial) - 16:len(machine_serial)]
                                provider_response = provider.pay_khales_bill(lang, machine_serial or user_request.name,
                                                                             billingAcct, extraBillingAcctKeys, billerId, ePayBillRecID,
                                                                             payAmts, pmtId, pmtType, feesAmts,
                                                                             billRefNumber, pmtMethod, pmtRefInfo,
                                                                             provider_channel, user_request.name,
                                                                             biller_info_json_dict.get('SupportPmtReverse'),
                                                                             biller_info_json_dict.get('AllowRetry'))
                                if provider_response.get('Success'):
                                    if provider_response.get('Success').get('timeout'):
                                        user_request.update({'payment_status': 'timeout'}) # ==> current 'action_status': is 'in_progress'
                                        if biller_info_json_dict.get('PmtType') == 'VOCH':
                                            provider_response = {"error_code": "0", "error_message": None,
                                                                 "error_message_to_be_translated": "KH Server timeout:\n",}
                                            if biller_info_json_dict.get('SupportPmtReverse'):
                                                provider_response.update({"TO_CANCEL": "VOCH"})
                                            else:
                                                provider_response.update({"TO_REVIEW": "VOCH"})
                                    else:
                                        user_request.update({'action_status': 'completed'}) # ==> current 'payment_status': is 'new'
                                    request.env.cr.commit()
                                    if not provider_response.get('error_code'):
                                        provider_response_json = suds_to_json(provider_response.get('Success'))
                                        # Add required parameters for cancel payment scenario
                                        # parsing JSON string:
                                        provider_response_json_dict = json.loads(provider_response_json)
                                        pmtId = provider_response_json_dict['PmtRecAdviceStatus']['PmtTransId']['PmtId']
                                        # appending the data
                                        provider_response_json_dict.update({'billingAcct': billingAcct, 'billRefNumber': billRefNumber,
                                                                            'billerId': billerId, 'pmtType': pmtType, 'trans_amount': trans_amount,
                                                                            'curCode': curCode, 'pmtMethod': pmtMethod, 'ePayBillRecID': ePayBillRecID,
                                                                            'pmtId': pmtId, 'feesAmt': feesAmt, 'pmtRefInfo': pmtRefInfo})
                                        if payAmts:
                                            provider_response_json_dict.update({'payAmts': payAmts})
                                        if feesAmts:
                                            provider_response_json_dict.update({'feesAmts': feesAmts})
                                        # the result is a JSON string:
                                        provider_response_json = json.dumps(provider_response_json_dict)
                                        # Provider Fees
                                        provider_fees_actual_amount = float(feesAmt)
                                        user_request.update({'provider_fees_amount': provider_fees_actual_amount})
                                        request.env.cr.commit()
                                        # Provider Payment Trans ID
                                        provider_payment_trans_id = pmtId
                            elif provider.provider == "masary":
                                user_request.update({'action_status': 'in_progress'})  # ==> current 'payment_status': is 'new'
                                request.env.cr.commit()
                                provider_response = provider.pay_masary_bill(lang, int(provider_info.product_code),
                                                                             float(trans_amount), float(feesAmt),
                                                                             inquiryTransactionId, 1,  # quantity
                                                                             extraBillingAcctKeys, provider_channel, user_request.name)
                                if provider_response.get('Success'):
                                    if provider_response.get('Success').get('timeout'):
                                        user_request.update({'payment_status': 'timeout'}) # ==> current 'action_status': is 'in_progress'
                                        if biller_info_json_dict.get('PmtType') == 'VOCH':
                                            provider_response = {"error_code": "0", "error_message": None,
                                                                 "error_message_to_be_translated": "KH Server timeout:\n",}
                                            if biller_info_json_dict.get('SupportPmtReverse'):
                                                provider_response.update({"TO_CANCEL": "VOCH"})
                                            else:
                                                provider_response.update({"TO_REVIEW": "VOCH"})
                                    else:
                                        user_request.update({'action_status': 'completed'}) # ==> current 'payment_status': is 'new'
                                    request.env.cr.commit()
                                    if not provider_response.get('error_code'):
                                        provider_response_json = provider_response.get('Success')
                                        # Get Provider Fees
                                        # provider_response_json_dict = json.loads(provider_response_json, strict=False)
                                        provider_response_json_dict = provider_response_json
                                        transactionId = provider_response_json_dict['transaction_id']
                                        # provider_fees_actual_amount = provider_response_json_dict['details_list']['???']
                                        provider_fees_actual_amount = float(feesAmt)
                                        user_request.update({'provider_fees_amount': provider_fees_actual_amount})
                                        request.env.cr.commit()
                                        # Provider Payment Trans ID
                                        provider_payment_trans_id = transactionId

                            if provider_response.get('Success'):
                                try:
                                    mobile_wallet_create = False
                                    # provider_invoice_id = False
                                    # refund = False
                                    # customer_invoice_id = False
                                    # credit_note = False
                                    user_request_response = {"request_number": user_request.name,
                                                             "request_datetime": user_request.create_date + timedelta(hours=2),
                                                             "provider": provider.provider,
                                                             "provider_response": provider_response_json
                                                             }

                                    if provider.provider == "fawry":
                                        if cardMetadata:
                                            user_request_response.update({"cardMetadata": cardMetadata})

                                    provider_actual_amount = user_request.trans_amount + provider_fees_actual_amount
                                    customer_actual_amount = provider_actual_amount + extra_fees_amount

                                    if not biller_info_json_dict.get('CorrBillTypeCode') or biller_info_json_dict.get('Type') == 'CASHININT':
                                        # Deduct Transaction Amount from Mobile Wallet Balance
                                        '''
                                        wallet_transaction_sudo = request.env['website.wallet.transaction'].sudo()
                                        label = _('Pay Service Bill for %s service') % (service.name)
                                        if request_data.get("wallet_id"):
                                            partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(wallet_id=request_data.get("wallet_id"),
                                                                                                                   service=service,
                                                                                                                   trans_amount=customer_actual_amount)
                                        else:
                                            partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(service=service,
                                                                                                                   trans_amount=customer_actual_amount)
                                        partner_id_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                                        mobile_wallet_create = wallet_transaction_sudo.create(
                                            {'wallet_type': 'debit', 'partner_id': request.env.user.partner_id.id,
                                             'request_id': user_request.id,
                                             'reference': 'request',
                                             'label': label,
                                             'amount': customer_actual_amount, 'currency_id': user_request.currency_id.id,
                                             'wallet_balance_before': partner_id_wallet_balance,
                                             'wallet_balance_after': partner_id_wallet_balance - customer_actual_amount,
                                             'status': 'done'})
                                        request.env.cr.commit()

                                        request.env.user.partner_id.update(
                                            {'wallet_balance': partner_id_wallet_balance - customer_actual_amount})
                                        request.env.cr.commit()
                                        '''
                                        mobile_wallet_create, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                                            'debit', request.env.user.partner_id, 'request',
                                            _('Pay Service Bill for %s service') % (service.name),
                                            customer_actual_amount, user_request.currency_id, user_request,
                                            'smartpay_operations.wallet_pay_service_bill_notify_mode', 'wallet_pay_service',
                                              _('<p>%s %s successfully deducted from your wallet.</p>') % (
                                            customer_actual_amount, _(user_request.currency_id.name))
                                        )

                                        if provider_response.get('Success').get('timeout'):
                                            if not biller_info_json_dict.get('Timeout') and not biller_info_json_dict.get('SupportPmtReverse'):
                                                user_request.update({'payment_status': 'in_queue'})
                                            elif biller_info_json_dict.get('Timeout') == 'PENDING':
                                                user_request.update({'payment_status': 'pending'})
                                            elif biller_info_json_dict.get('SupportPmtReverse'):
                                                # if biller_info_json_dict.get('PmtType') == 'VOCH':
                                                    # user_request.update({'payment_status': 'to_cancel'})
                                                # else:
                                                if biller_info_json_dict.get('PmtType') != 'VOCH':
                                                    user_request.update({'payment_status': 'to_refund'})
                                            # else:
                                                # user_request.update({'payment_status': 'done'}) # Tamayoz: No need to handel "else" case
                                            user_request.update({'action_status': 'new'})
                                        elif provider_response.get('Success').get('pending'):
                                            user_request.update({'payment_status': 'pending', 'action_status': 'new'})
                                        else:
                                            user_request.update({'payment_status': 'done', 'action_status': 'completed'}) # ==> current 'action_status': is 'completed'
                                        request.env.cr.commit()

                                        # Log Sold Limit
                                        if service.has_sale_limit:
                                            for sale_limit_id in service.sale_limit_ids:
                                                limit_type = sale_limit_id.limit_type
                                                timetuple = date_time.now().timetuple()
                                                sale_limit_domain = [
                                                    ('partner_id', '=', request.env.user.partner_id.id),
                                                    ('product_id', '=', service.id),
                                                    ('limit_type', '=', limit_type),
                                                    ('year', '=', timetuple.tm_year)]
                                                if limit_type == 'daily':
                                                    sale_limit_domain += [('day', '=', timetuple.tm_yday)]
                                                elif limit_type == 'weekly':
                                                    sale_limit_domain += [('week', '=', date_time.now().isocalendar()[1])]
                                                elif limit_type == 'monthly':
                                                    sale_limit_domain += [('month', '=', timetuple.tm_mon)]
                                                sale_limit = request.env['res.partner.sale.limit'].sudo().search(
                                                    sale_limit_domain,
                                                    order="id DESC", limit=1)
                                                if sale_limit:
                                                    sale_limit.update({'sold_amount': sale_limit.sold_amount + customer_actual_amount})  # calculated_payment_amount
                                                else:
                                                    sale_limit_values = {
                                                        'partner_id': request.env.user.partner_id.id,
                                                        'product_id': service.id,
                                                        'limit_type': limit_type,
                                                        'year': timetuple.tm_year,
                                                        'sold_amount': customer_actual_amount
                                                    }
                                                    if limit_type == 'daily':
                                                        sale_limit_values.update({'day': timetuple.tm_yday})
                                                    elif limit_type == 'weekly':
                                                        sale_limit_values.update(
                                                            {'week': date_time.now().isocalendar()[1]})
                                                    elif limit_type == 'monthly':
                                                        sale_limit_values.update({'month': timetuple.tm_mon})
                                                    sale_limit = request.env['res.partner.sale.limit'].sudo().create(sale_limit_values)

                                                # Log Sold Over Limit Fees
                                                if limit_fees_amounts.get(limit_type):
                                                    wallet_transaction_id, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                                                        'debit', request.env.user.partner_id, 'request',
                                                        _('%s over limit fees for %s service') % (limit_type, service.name),
                                                        limit_fees_amounts.get(limit_type), user_request.currency_id, user_request,
                                                        'smartpay_operations.wallet_pay_service_bill_notify_mode', 'wallet_pay_service',
                                                        _('<p>%s %s successfully deducted from your wallet.</p>') % (
                                                            limit_fees_amounts.get(limit_type), _(user_request.currency_id.name))
                                                    )
                                                    sale_limit_fees = request.env['res.partner.sale.limit.fees'].sudo().create({'user_request_id': user_request.id,
                                                                                                                                'limit_type': limit_type,
                                                                                                                                'fees_amount': limit_fees_amounts.get(limit_type),
                                                                                                                                'wallet_transaction_id': wallet_transaction_id.id})
                                        # Log Wallet Transaction Limit
                                        if partner_wallet_id.type.has_trans_limit:
                                            for trans_limit_id in partner_wallet_id.type.trans_limit_ids:
                                                wallet_limit_type = trans_limit_id.limit_type
                                                timetuple = date_time.now().timetuple()
                                                trans_limit_domain = [
                                                    ('wallet_id', '=', partner_wallet_id.id),
                                                    # ('wallet_type_id', '=', partner_wallet_id.type.id),
                                                    ('limit_type', '=', wallet_limit_type),
                                                    ('year', '=', timetuple.tm_year)]
                                                if wallet_limit_type == 'daily':
                                                    trans_limit_domain += [('day', '=', timetuple.tm_yday)]
                                                elif wallet_limit_type == 'weekly':
                                                    trans_limit_domain += [('week', '=', date_time.now().isocalendar()[1])]
                                                elif wallet_limit_type == 'monthly':
                                                    trans_limit_domain += [('month', '=', timetuple.tm_mon)]
                                                trans_limit = request.env['wallet.trans.limit'].sudo().search(trans_limit_domain,
                                                                                        order="id DESC", limit=1)
                                                if trans_limit:
                                                    trans_limit.update({'trans_amount': trans_limit.trans_amount + customer_actual_amount})  # calculated_payment_amount
                                                else:
                                                    trans_limit_values = {
                                                        'wallet_id': partner_wallet_id.id,
                                                        # 'wallet_type_id': partner_wallet_id.type.id,
                                                        'limit_type': wallet_limit_type,
                                                        'year': timetuple.tm_year,
                                                        'trans_amount': customer_actual_amount
                                                    }
                                                    if wallet_limit_type == 'daily':
                                                        trans_limit_values.update({'day': timetuple.tm_yday})
                                                    elif wallet_limit_type == 'weekly':
                                                        trans_limit_values.update({'week': date_time.now().isocalendar()[1]})
                                                    elif wallet_limit_type == 'monthly':
                                                        trans_limit_values.update({'month': timetuple.tm_mon})
                                                    trans_limit = request.env['wallet.trans.limit'].sudo().create(trans_limit_values)

                                                # Log Transaction Over Limit Fees
                                                if wallet_limit_fees_amounts.get(wallet_limit_type):
                                                    wallet_transaction_id, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                                                        'debit', request.env.user.partner_id, 'request',
                                                        _('%s over limit fees for %s wallet type') % (
                                                            wallet_limit_type, partner_wallet_id.type.name),
                                                        wallet_limit_fees_amounts.get(wallet_limit_type),
                                                        user_request.currency_id, user_request,
                                                        'smartpay_operations.wallet_pay_service_bill_notify_mode',
                                                        'wallet_pay_service',
                                                        _('<p>%s %s successfully deducted from your wallet.</p>') % (
                                                            wallet_limit_fees_amounts.get(wallet_limit_type),
                                                            _(user_request.currency_id.name))
                                                    )
                                                    trans_limit_fees = request.env['wallet.trans.limit.fees'].sudo().create(
                                                        {'user_request_id': user_request.id,
                                                         'limit_type': wallet_limit_type,
                                                         'fees_amount': wallet_limit_fees_amounts.get(wallet_limit_type),
                                                         'wallet_transaction_id': wallet_transaction_id.id})

                                        mobile_wallet_reservation_id.sudo().unlink()
                                        request.env.cr.commit()
                                        unlink_wallet_reservation = True

                                        '''
                                        # Notify user
                                        irc_param = request.env['ir.config_parameter'].sudo()
                                        wallet_pay_service_bill_notify_mode = irc_param.get_param("smartpay_operations.wallet_pay_service_bill_notify_mode")
                                        if wallet_pay_service_bill_notify_mode == 'inbox':
                                            request.env['mail.thread'].sudo().message_notify(
                                                subject=label,
                                                body=_('<p>%s %s successfully deducted from your wallet.</p>') % (
                                                    customer_actual_amount, _(user_request.currency_id.name)),
                                                partner_ids=[(4, request.env.user.partner_id.id)],
                                            )
                                        elif wallet_pay_service_bill_notify_mode == 'email':
                                            mobile_wallet_create.wallet_transaction_email_send()
                                        elif wallet_pay_service_bill_notify_mode == 'sms' and request.env.user.partner_id.mobile:
                                            mobile_wallet_create.sms_send_wallet_transaction(wallet_pay_service_bill_notify_mode,
                                                                                             'wallet_pay_service',
                                                                                             request.env.user.partner_id.mobile,
                                                                                             request.env.user.name, label,
                                                                                             '%s %s' % (customer_actual_amount,
                                                                                                        _(user_request.currency_id.name)),
                                                                                             request.env.user.partner_id.country_id.phone_code or '2')
                                        '''

                                        payment_info = {"service": service.with_context(lang=request.env.user.lang).name, "provider": provider.provider,
                                                        "request_number": user_request.name,
                                                        "request_datetime": user_request.create_date + timedelta(hours=2),
                                                        "label": biller_info_json_dict.get("BillTypeAcctLabel"),
                                                        "billing_acct": billingAcct, "ref_number": provider_payment_trans_id,
                                                        "amount": trans_amount,
                                                        "fees": (provider_fees_actual_amount + extra_fees_amount),
                                                        "total": customer_actual_amount}

                                    user_request.update(
                                        {'extra_fees_amount': extra_fees_amount,
                                         'wallet_transaction_id': mobile_wallet_create and mobile_wallet_create.id or False,
                                         'trans_date': date.today(),
                                         'provider_id': provider.id,
                                         'provider_response': provider_response_json, "stage_id": 5})
                                    if biller_info_json_dict.get('CorrBillTypeCode'):
                                        user_request.update(
                                            {'description': _(
                                                 'Initiation Service Payment request (%s) was submit successfully @ %s') % (
                                                                user_request.name,
                                                                str(date_time.now() + timedelta(hours=2)))
                                             })
                                    request.env.cr.commit()
                                    user_request_response.update({'extra_fees_amount': extra_fees_amount})

                                    # VouchPIN Decryption if exist
                                    if provider_response_json_dict.get('VouchInfo'):
                                        decrypted_bytes = bytes(provider_response_json_dict['VouchInfo']['VouchPIN'],
                                                                encoding='utf-8')
                                        # text = base64.decodestring(decrypted_bytes) #
                                        text = base64.b64decode(decrypted_bytes)  #
                                        cipher = DES3.new(SECRET_KEY, DES3.MODE_ECB)
                                        VouchPIN = cipher.decrypt(text)
                                        VouchPIN = UNPAD(VouchPIN)
                                        VouchPIN = VouchPIN.decode('utf-8')  # unpad and decode bytes to str
                                        user_request_response.update({'vouch_pin': VouchPIN})
                                        if not biller_info_json_dict.get('CorrBillTypeCode') or biller_info_json_dict.get('Type') == 'CASHININT':
                                            payment_info.update({"vouch_pin": VouchPIN,
                                                                 "vouch_sn": provider_response_json_dict['VouchInfo']['VouchSN']})
                                            if provider_response_json_dict['VouchInfo'].get('VouchDesc'):
                                                payment_info.update({"vouch_desc": provider_response_json_dict['VouchInfo']['VouchDesc']})

                                    # ExtraBillInfo
                                    # ePayBillRecID : RBINQRQ-220627-619014259490-GT-99959 (Khales)
                                    # billRefNumber : 6bb67311-dde8-47f8-b8f3-3cf8fe5a4be6 (Fawry)
                                    if (provider.provider == 'fawry' and billRefNumber) or (provider.provider == 'khales' and ePayBillRecID):
                                        inquiryTransactionId = request_data.get('inquiryTransactionId')
                                        if inquiryTransactionId:
                                            inquiry_request = request.env["smartpay_operations.request"].sudo().search(
                                                [('name', '=', inquiryTransactionId)], limit=1)
                                        else:
                                            inquiry_request = request.env["smartpay_operations.request"].sudo().search(
                                                [('request_type', '=', 'service_bill_inquiry'),
                                                 ('partner_id', '=', request.env.user.partner_id.id),
                                                 ('product_id', '=', service.id),
                                                 ('create_date', '<=', date_time.now()),
                                                 ('create_date', '>=', date_time.now() - timedelta(minutes=15)),
                                                 ('provider_response', 'ilike',
                                                  '"BillRefNumber": "%s"' % (billRefNumber) if provider.provider == "fawry"
                                                  else '"EPayBillRecID": "%s"' % (ePayBillRecID) # provider.provider == "khales"
                                                  )], limit=1)

                                        if inquiry_request:
                                            inquiry_request_provider_response = inquiry_request.provider_response.replace(
                                                "'bill_response'", '"bill_response"').replace("'fees_response'",'"fees_response"').replace("'", "")
                                            inquiry_request_provider_response_json_dict = json.loads(inquiry_request_provider_response)

                                            # Fawry
                                            if inquiry_request_provider_response_json_dict.get('BillInfo') and \
                                                    inquiry_request_provider_response_json_dict.get('BillInfo').get('ExtraBillInfo'):
                                                payment_info.update({"extra_bill_info": inquiry_request_provider_response_json_dict['BillInfo']['ExtraBillInfo']})

                                            # Khales
                                            if inquiry_request_provider_response_json_dict.get('bill_response') and \
                                                    inquiry_request_provider_response_json_dict.get('bill_response').get('Msg'):
                                                for msg in inquiry_request_provider_response_json_dict.get('bill_response').get('Msg'):
                                                    if msg.get('LanguagePref') == 'ar-eg':  # en-gb
                                                        payment_info.update({"extra_bill_info": msg.get('Text')})
                                                        break

                                    if not biller_info_json_dict.get('CorrBillTypeCode') or biller_info_json_dict.get('Type') == 'CASHININT':
                                        # Wallet Transaction Info with payment info
                                        mobile_wallet_create.update({"wallet_transaction_info": json.dumps({"payment_info": payment_info}, default=default)})
                                        request.env.cr.commit()

                                    '''
                                    # Create Vendor (Provider) Invoices
                                    provider_invoice_ids = ()
                                    # 1- Create Vendor bill
                                    provider_journal_id = request.env['account.journal'].sudo().search([('type', '=', 'purchase'),
                                                                                              ('company_id', '=', request.env.user.company_id.id)], limit=1)
                                    name = provider.provider + ': [' + provider_info.product_code + '] ' + provider_info.product_name
                                    provider_invoice_vals = user_request.with_context(name=name,
                                                                                      provider_payment_trans_id=provider_payment_trans_id,
                                                                                      journal_id=provider_journal_id.id,
                                                                                      invoice_date=date.today(),
                                                                                      invoice_type='in_invoice',
                                                                                      partner_id=provider_info.name.id)._prepare_invoice()
                                    provider_invoice_id = request.env['account.invoice'].sudo().create(provider_invoice_vals)
                                    invoice_line = provider_invoice_id._prepare_invoice_line_from_request(request=user_request,
                                                                                                          name=name,
                                                                                                          qty=1,
                                                                                                          price_unit=provider_actual_amount)
                                    new_line = request.env['account.invoice.line'].sudo().new(invoice_line)
                                    new_line._set_additional_fields(provider_invoice_id)
                                    provider_invoice_id.invoice_line_ids += new_line
                                    provider_invoice_id.action_invoice_open()
                                    provider_invoice_ids += (tuple(provider_invoice_id.ids),)
                                    provider_invoice_id.pay_and_reconcile(request.env['account.journal'].sudo().search(
                                        [('type', '=', 'cash'),
                                         ('company_id', '=', request.env.user.company_id.id),
                                         ('provider_id', '=', provider.id)], limit=1),
                                        provider_actual_amount)
                                    request.env.cr.commit()
                                    # 2- Create Vendor Refund with commision amount
                                    if merchant_cashback_amount > 0:
                                        refund = request.env['account.invoice.refund'].with_context(
                                            active_ids=provider_invoice_id.ids).sudo().create({
                                            'filter_refund': 'refund',
                                            'description': name,
                                            'date': provider_invoice_id.date_invoice,
                                        })
                                        result = refund.invoice_refund()
                                        refund_id = result.get('domain')[1][2]
                                        refund = request.env['account.invoice'].sudo().browse(refund_id)
                                        refund.update({'reference': provider_payment_trans_id, 'request_id': user_request.id})
                                        refund_line = refund.invoice_line_ids[0]
                                        refund_line.update({'price_unit': merchant_cashback_amount, 'request_id': user_request.id})
                                        refund.refresh()
                                        refund.action_invoice_open()
                                        provider_invoice_ids += (tuple(refund.ids),)
                                    user_request.update({'provider_invoice_ids': provider_invoice_ids})
                                    request.env.cr.commit()

                                    # Create Customer Invoices
                                    customer_invoice_ids = ()
                                    # 1- Create Customer Invoice
                                    customer_journal_id = request.env['account.journal'].sudo().search([('type', '=', 'sale'),
                                                                                              ('company_id', '=', request.env.user.company_id.id)], limit=1)
                                    customer_invoice_vals = user_request.with_context(name=provider_payment_trans_id,
                                                                                      journal_id=customer_journal_id.id,
                                                                                      invoice_date=date.today(),
                                                                                      invoice_type='out_invoice',
                                                                                      partner_id=request.env.user.partner_id.id)._prepare_invoice()
                                    customer_invoice_id = request.env['account.invoice'].sudo().create(customer_invoice_vals)
                                    user_request.invoice_line_create(invoice_id=customer_invoice_id.id, name=name,
                                                                        qty=1, price_unit=customer_actual_amount)
                                    customer_invoice_id.action_invoice_open()
                                    customer_invoice_ids += (tuple(customer_invoice_id.ids),)
                                    # Auto Reconcile customer invoice with prepaid wallet recharge payments and previous cashback credit note
                                    domain = [('account_id', '=', customer_invoice_id.account_id.id),
                                              ('partner_id', '=',
                                               customer_invoice_id.env['res.partner']._find_accounting_partner(
                                                   customer_invoice_id.partner_id).id),
                                              ('reconciled', '=', False),
                                              '|',
                                              '&', ('amount_residual_currency', '!=', 0.0), ('currency_id', '!=', None),
                                              '&', ('amount_residual_currency', '=', 0.0), '&', ('currency_id', '=', None),
                                              ('amount_residual', '!=', 0.0)]
                                    domain.extend([('credit', '>', 0), ('debit', '=', 0)])
                                    lines = customer_invoice_id.env['account.move.line'].sudo().search(domain)
                                    for line in lines:
                                        # get the outstanding residual value in invoice currency
                                        if line.currency_id and line.currency_id == customer_invoice_id.currency_id:
                                            amount_residual_currency = abs(line.amount_residual_currency)
                                        else:
                                            currency = line.company_id.currency_id
                                            amount_residual_currency = currency._convert(abs(line.amount_residual),
                                                                                         customer_invoice_id.currency_id,
                                                                                         customer_invoice_id.company_id,
                                                                                         line.date or fields.Date.today())
                                        if float_is_zero(amount_residual_currency,
                                                         precision_rounding=customer_invoice_id.currency_id.rounding):
                                            continue

                                        customer_invoice_id.assign_outstanding_credit(line.id)
                                        if customer_invoice_id.state == 'paid':
                                            break
                                    request.env.cr.commit()

                                    # 2- Create Customer Credit Note with commision amount for only mobile users have commission
                                    if request.env.user.commission and customer_cashback_amount > 0:
                                        credit_note = request.env['account.invoice.refund'].with_context(
                                            active_ids=customer_invoice_id.ids).sudo().create({
                                            'filter_refund': 'refund',
                                            'description': provider_payment_trans_id,
                                            'date': customer_invoice_id.date_invoice,
                                        })
                                        result = credit_note.invoice_refund()
                                        credit_note_id = result.get('domain')[1][2]
                                        credit_note = request.env['account.invoice'].sudo().browse(credit_note_id)
                                        credit_note.update({'request_id': user_request.id})
                                        credit_note_line = credit_note.invoice_line_ids[0]
                                        credit_note_line.update({'price_unit': customer_cashback_amount, 'request_id': user_request.id})
                                        credit_note.refresh()
                                        """  Don't validate the customer credit note until the vendor refund reconciliation
                                        After vendor refund reconciliation, validate the customer credit note with
                                        the net amount of vendor refund sent in provider cashback statement then
                                        increase the customer wallet with the same net amount. """
                                        # credit_note.action_invoice_open()
                                        customer_invoice_ids += (tuple(credit_note.ids),)
                                    user_request.update({'customer_invoice_ids': customer_invoice_ids})
                                    request.env.cr.commit()
                                    '''

                                    if provider.provider == "khales":
                                        # Add required parameters for cancel payment scenario
                                        user_request_response.update({'billingAcct': billingAcct, 'billRefNumber': billRefNumber,
                                                                      'billerId': billerId, 'pmtType': pmtType, 'trans_amount': trans_amount,
                                                                      'curCode': curCode, 'pmtMethod': pmtMethod, 'ePayBillRecID': ePayBillRecID,
                                                                      'pmtId': pmtId, 'feesAmt': feesAmt, 'pmtRefInfo': pmtRefInfo})
                                        if payAmts:
                                            user_request_response.update({'payAmts': payAmts})
                                        if feesAmts:
                                            user_request_response.update({'feesAmts': feesAmts})
                                    if not biller_info_json_dict.get('CorrBillTypeCode') or biller_info_json_dict.get('Type') == 'CASHININT':
                                        user_request_response.update({"message": _("Pay Service Bill request was submit successfully with amount %s %s. Your Machine Wallet Balance is %s %s")
                                                                            % (customer_actual_amount,
                                                                               user_request.currency_id.name,
                                                                               wallet_balance_after,
                                                                               user_request.currency_id.name)})
                                    else:
                                        user_request_response.update({"message": _("Pay Service Bill Initiation request was submit successfully with amount %s %s.")
                                                                                 % (customer_actual_amount,
                                                                                    user_request.currency_id.name)})
                                    if not unlink_wallet_reservation and mobile_wallet_reservation_id:
                                        mobile_wallet_reservation_id.sudo().unlink()
                                        request.env.cr.commit()
                                        unlink_wallet_reservation = True
                                    return valid_response(user_request_response)
                                except Exception as e:
                                    try:
                                        _logger.error("%s", e, exc_info=True)
                                        user_request_update = {'extra_fees_amount': extra_fees_amount,
                                                               'trans_date': date.today(),
                                                               'provider_id': provider.id,
                                                               'provider_response': provider_response_json,"stage_id": 5,
                                                               'description': _("After the Pay Service Request submit successfuly with provider, Error is occur:") + " ==> " + str(e)}
                                        if mobile_wallet_create:
                                            user_request_update.update({'wallet_transaction_id': mobile_wallet_create.id})
                                        '''
                                        provider_invoice_ids = ()
                                        if provider_invoice_id or refund:
                                            if provider_invoice_id:
                                                provider_invoice_ids += (tuple(provider_invoice_id.ids),)
                                            if refund:
                                                provider_invoice_ids += (tuple(refund.ids),)
                                            user_request_update.update({'provider_invoice_ids': provider_invoice_ids})
                                        customer_invoice_ids = ()
                                        if customer_invoice_id or credit_note:
                                            if customer_invoice_id:
                                                customer_invoice_ids += (tuple(customer_invoice_id.ids),)
                                            if credit_note:
                                                customer_invoice_ids += (tuple(credit_note.ids),)
                                            user_request_update.update({'customer_invoice_ids': customer_invoice_ids})
                                        '''
                                        user_request.update(user_request_update)
                                        request.env.cr.commit()
                                    except Exception as e1:
                                        _logger.error("%s", e1, exc_info=True)
                                        if user_request and not user_request.description:
                                            user_request.update({'description': _("After the Pay Service Request submit successfuly with provider, Error is occur:") + " ==> " + str(e)})
                                            request.env.cr.commit()

                                    if not unlink_wallet_reservation and mobile_wallet_reservation_id:
                                        mobile_wallet_reservation_id.sudo().unlink()
                                        request.env.cr.commit()
                                        unlink_wallet_reservation = True
                                    return invalid_response(user_request_response, _("After the Pay Service Request submit successfuly with provider, Error is occur:") + " ==> " + str(e),
                                                            500)
                            else:
                                user_request.update({'payment_status': 'canceled' if provider_response.get('CANCEL_SUCCESS') else ('to_cancel' if provider_response.get('TO_CANCEL') else ('to_review' if provider_response.get('TO_REVIEW') else 'failure')), 'action_status': 'new' if provider_response.get('TO_CANCEL') or provider_response.get('TO_REVIEW') else 'completed'})  # ==> current 'action_status': is 'completed'
                                request.env.cr.commit()
                                error.update({provider.provider + "_response": provider_response or ''})
                        except Exception as e2:
                            _logger.error("%s", e2, exc_info=True)
                            if user_request and not user_request.description:
                                user_request.update({'description': _("Error is occur:") + " ==> " + str(e2)})
                                request.env.cr.commit()
                            if not unlink_wallet_reservation and mobile_wallet_reservation_id:
                                mobile_wallet_reservation_id.sudo().unlink()
                                request.env.cr.commit()
                                unlink_wallet_reservation = True
                            return invalid_response("Error", _("Error is occur:") + " ==> " + str(e2), 500)
                    else:
                        error.update({provider_info.name.name + "_response": _("%s is not a provider for (%s) service") % (
                            provider_info.name.name, service.name)})

                user_request.update({
                    'provider_response': error or _('(%s) service has not any provider.') % (service.name),
                    'stage_id': 5
                })
                request.env.cr.commit()
                error_key = "user_error"
                error_msg = _("(%s) service has not any provider.") % (service.name)
                if provider:
                    if error.get(provider.provider + "_response").get("error_message"):
                        error_msg = error.get(provider.provider + "_response").get("error_message")
                    elif error.get(provider.provider + "_response").get("error_message_to_be_translated"):
                        error_msg = error.get(provider.provider + "_response").get("error_message_to_be_translated")
                        error_key = "Error"
                elif error.get(provider_info.name.name + "_response"):
                    error_msg = error.get(provider_info.name.name + "_response")
                if not unlink_wallet_reservation and mobile_wallet_reservation_id:
                    mobile_wallet_reservation_id.sudo().unlink()
                    request.env.cr.commit()
                    unlink_wallet_reservation = True
                return invalid_response(error_key, error_msg, 400)
            else:
                return valid_response({"message": _("Your request was submit successfully."),
                                       "request_number": user_request.name
                                       })

        @validate_token
        @http.route('/api/cancel_request', type="http", auth="none", methods=["PUT"], csrf=False)
        def cancel_request(self, **request_data):
            _logger.info("@@@@@@@@@@@@@@@@@@@ Calling Cancel Mobile Request API")
            user_request = False
            request_number = request_data.get('request_number')
            if request_number:
                user_request = request.env['smartpay_operations.request'].sudo().search([('name', '=', request_number)], limit=1)
            else: # elif request_data.get('provider') == 'khales':
                # if not request_data.get('ePayBillRecID'):
                    # return invalid_response("ePayBillRecID_request_number_not_found", _("missing Request Number or ePay Bill Rec ID in request data"), 400)
                user_request = request.env['smartpay_operations.request'].sudo().search([('request_type', '=', 'pay_service_bill'),
                                                                                         ('create_date', '<=', date_time.now()),
                                                                                         ('create_date', '>=', date_time.now() - timedelta(hours=1)),
                                                                                         ('provider_response', 'like', request_data.get('ePayBillRecID') or request_data.get('billRefNumber'))],
                                                                                        limit=1)
                # _logger.info("@@@@@@@@@@@@@@@@@@@ " + '"EPayBillRecID": "%s"' % (request_data.get('ePayBillRecID')))
            if user_request:
                request_number = user_request.name
                try:
                    service = user_request.product_id
                    provider = user_request.provider_id

                    service_providerinfo = request.env['product.supplierinfo'].sudo().search([
                        ('product_tmpl_id', '=', service.product_tmpl_id.id),
                        ('name', '=', provider.related_partner.id)
                    ])
                    biller_info_json_dict = json.loads(service_providerinfo.with_context(lang=request.env.user.lang).biller_info, strict=False)
                    isAllowCancel = biller_info_json_dict.get('SupportPmtReverse', False)

                    if user_request.request_type == 'pay_service_bill' and user_request.stage_id.id == 5 and isAllowCancel \
                            and (not user_request.description
                                 or ('Cancel Service Payment request (%s) was submit successfully' % user_request.name not in user_request.description
                                     and 'Cancel Service Payment request (%s) In progress' % user_request.name not in user_request.description
                                     and 'Correlation Service Payment request (%s) was submit successfully' % user_request.name not in user_request.description
                                     and 'Correlation Service Payment request (%s) In progress' % user_request.name not in user_request.description
                                 )):

                        user_request.update({
                            'description': _('Cancel Service Payment request (%s) In progress @ %s') % (user_request.name, str(date_time.now() + timedelta(hours=2))),
                            'payment_status': 'canceled', 'action_status': 'new'
                        })
                        request.env.cr.commit()

                        isInternalCancel = biller_info_json_dict.get('IsInternalCancel', False)
                        lang = 'ar-eg'
                        partner = user_request.partner_id
                        # trans_date = user_request.trans_date
                        trans_amount = user_request.trans_amount
                        provider_fees_amount = user_request.provider_fees_amount
                        extra_fees_amount = user_request.extra_fees_amount
                        currency = user_request.currency_id

                        provider_pay_response = user_request.provider_response
                        provider_response_json = {}
                        provider_response_json['provider_pay_response'] = provider_pay_response
                        provider_pay_response_json = json.loads(provider_pay_response)
                        billingAcct = request_data.get('billingAcct') or provider_pay_response_json.get('billingAcct') \
                                      or provider_pay_response_json.get('PmtInfo').get('BillingAcct')

                        extraBillingAcctKeys = request_data.get('extraBillingAcctKeys')
                        if extraBillingAcctKeys:
                            extraBillingAcctKeys = ast.literal_eval(extraBillingAcctKeys)
                        else:
                            extraBillingAcctKeys = provider_pay_response_json.get('extraBillingAcctKeys') or \
                                                   (provider_pay_response_json.get('PmtInfo').get('ExtraBillingAcctKeys').get('ExtraBillingAcctKey') if provider_pay_response_json.get('PmtInfo') and provider_pay_response_json.get('PmtInfo').get('ExtraBillingAcctKeys') else [])
                        notifyMobile = request_data.get('notifyMobile') or provider_pay_response_json.get('notifyMobile') or 'NCName'

                        billRefNumber = request_data.get('billRefNumber') or provider_pay_response_json.get('billRefNumber') \
                                        or provider_pay_response_json.get('PmtInfo').get('BillRefNumber')
                        billerId = request_data.get('billerId') or provider_pay_response_json.get('billerId')
                        pmtType = request_data.get('pmtType') or provider_pay_response_json.get('pmtType')
                        # trans_amount = request_data.get('trans_amount') or provider_pay_response_json.get('trans_amount')
                        curCode = request_data.get('currency_id') or provider_pay_response_json.get('curCode') \
                                  or provider_pay_response_json.get('PmtInfo').get('CurAmt').get('CurCode')
                        payAmts = request_data.get('payAmts')
                        if payAmts:
                            payAmts = ast.literal_eval(payAmts)
                        else:
                            payAmts = [{'Sequence': '1', 'AmtDue': trans_amount, 'CurCode': curCode}]
                        pmtMethod = request_data.get('pmtMethod') or provider_pay_response_json.get('pmtMethod') \
                                    or provider_pay_response_json.get('PmtInfo').get('PmtMethod')
                        ePayBillRecID = request_data.get('ePayBillRecID') or provider_pay_response_json.get('ePayBillRecID')
                        pmtId = request_data.get('pmtId') or provider_pay_response_json.get('pmtId')
                        feesAmt = request_data.get('feesAmt') or provider_pay_response_json.get('feesAmt')
                        feesAmts = request_data.get('feesAmts')
                        if feesAmts:
                            feesAmts = ast.literal_eval(feesAmts)
                        else:
                            feesAmts = [{'Amt': feesAmt, 'CurCode': curCode}]
                        pmtRefInfo = request_data.get('pmtRefInfo') or provider_pay_response_json.get('pmtRefInfo')
                        cancelReason = request_data.get('cancelReason') or '001'
                        inquiryTransactionId = request_data.get('inquiryTransactionId')

                        error = {}

                        provider_channel = False
                        machine_channels = request.env['payment.acquirer.channel'].sudo().search([("acquirer_id", "=", provider.id),
                                                                                                  ("type", "in", ("machine", "internet"))], limit=1)
                        if machine_channels:
                            provider_channel = machine_channels[0]
                        provider_cancel_response = {}
                        if isInternalCancel:
                            provider_cancel_response["Success"] = _("Internal Cancel")
                        else:
                            if provider.provider == "khales":
                                # Handel billingAcct format if exist
                                if biller_info_json_dict.get('BillTypeAcctFormat') and biller_info_json_dict.get('BillTypeAcctFormatSpliter'):
                                    formatedBillingAcct = []
                                    keysToBeRemoved = []
                                    for format in biller_info_json_dict.get('BillTypeAcctFormat').split(biller_info_json_dict.get('BillTypeAcctFormatSpliter')):
                                        if format == 'billingAcct':
                                            formatedBillingAcct.append(billingAcct)
                                        else:
                                            is_extra_key = False
                                            for extraBillingAcctKey in extraBillingAcctKeys:
                                                if extraBillingAcctKey.get("Key") == format:
                                                    formatedBillingAcct.append(extraBillingAcctKey.get("Value"))
                                                    keysToBeRemoved.append(extraBillingAcctKey)
                                                    is_extra_key = True
                                                    break
                                            if not is_extra_key:
                                                formatedBillingAcct.append(format)
                                    extraBillingAcctKeys = [x for x in extraBillingAcctKeys if x not in keysToBeRemoved]
                                    billingAcct = biller_info_json_dict.get('BillTypeAcctFormatSpliter').join(formatedBillingAcct)

                                '''
                                machine_serial = None
                                if len(request.env.user.machine_serial) > 16:  # Ingenico POS
                                    machine_serial = request.env.user.machine_serial
                                    machine_serial = machine_serial[len(machine_serial) - 16:len(machine_serial)]
                                '''
                                machine_serial = request.env.user.machine_serial
                                if machine_serial and len(machine_serial) > 16:
                                    machine_serial = machine_serial[len(machine_serial) - 16:len(machine_serial)]
                                provider_cancel_response = provider.cancel_khales_payment(lang, machine_serial or request_number,
                                                                                          billingAcct, billerId, ePayBillRecID,
                                                                                          payAmts, pmtId, pmtType, feesAmts,
                                                                                          billRefNumber, pmtMethod, pmtRefInfo,
                                                                                          cancelReason,provider_channel, request_number)
                            if provider.provider == "fawry":
                                provider_cancel_response = provider.reverse_fawry_bill(lang, service_providerinfo.product_code,
                                                                                       billingAcct, extraBillingAcctKeys,
                                                                                       trans_amount, curCode, pmtMethod,
                                                                                       notifyMobile, billRefNumber,
                                                                                       billerId, pmtType or "POST",
                                                                                       provider_channel, inquiryTransactionId,
                                                                                       request_number)
                        if provider_cancel_response.get('Success'):
                            try:
                                if isInternalCancel:
                                    provider_response_json['provider_cancel_response'] = _("Internal Cancel")
                                else:
                                    provider_cancel_response_json = suds_to_json(provider_cancel_response.get('Success'))
                                    provider_response_json['provider_cancel_response'] = provider_cancel_response_json

                                provider_actual_amount = trans_amount + provider_fees_amount
                                customer_actual_amount = provider_actual_amount + extra_fees_amount

                                if not biller_info_json_dict.get('CorrBillTypeCode') or biller_info_json_dict.get('Type') == 'CASHININT':
                                    # Refund Payment Amount to Customer Wallet Balance
                                    '''
                                    wallet_transaction_sudo = request.env['website.wallet.transaction'].sudo()
                                    label = _('Cancel Service Payment for %s service') % (service.name)
                                    partner_wallet_id = user_request.wallet_transaction_id.wallet_id or partner.get_transaction_wallet(service=service)
                                    partner_id_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                                    customer_wallet_create = wallet_transaction_sudo.create({'wallet_type': 'credit', 'partner_id': partner.id,
                                                                                             'request_id': user_request.id, 'reference': 'request',
                                                                                             'label': label, 'amount': customer_actual_amount,
                                                                                             'currency_id': currency.id,
                                                                                             'wallet_balance_before': partner_id_wallet_balance,
                                                                                             'wallet_balance_after': partner_id_wallet_balance + customer_actual_amount,
                                                                                             'status': 'done'})
                                    request.env.cr.commit()

                                    partner.update({'wallet_balance': partner_id_wallet_balance 
                                    + customer_actual_amount})
                                    request.env.cr.commit()
                                    '''
                                    partner_wallet_id = user_request.wallet_transaction_id.wallet_id or partner.get_transaction_wallet(service=service)
                                    if not partner_wallet_id:
                                        return invalid_response("wallet_not_found",
                                                                _("No Matched Wallet found for partner [%s] %s") % (
                                                                    partner.ref,
                                                                    partner.name), 400)
                                    customer_wallet_create, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                                        'credit', partner, 'request',
                                        _('Cancel Service Payment for %s service') % (service.name),
                                        customer_actual_amount, currency, user_request,
                                        'smartpay_operations.wallet_canel_service_payment_notify_mode',
                                        'wallet_cancel_service_payment',
                                        _('<p>%s %s successfully Added to your wallet.</p>') % (
                                            customer_actual_amount, _(currency.name))
                                    )

                                    # Deduct Sold Limit
                                    if service.has_sale_limit:
                                        for sale_limit_id in service.sale_limit_ids:
                                            limit_type = sale_limit_id.limit_type
                                            timetuple = date_time.now().timetuple()
                                            sale_limit_domain = [
                                                ('partner_id', '=', partner.id),
                                                ('product_id', '=', service.id),
                                                ('limit_type', '=', limit_type),
                                                ('year', '=', timetuple.tm_year)]
                                            if limit_type == 'daily':
                                                sale_limit_domain += [('day', '=', timetuple.tm_yday)]
                                            elif limit_type == 'weekly':
                                                sale_limit_domain += [
                                                    ('week', '=', date_time.now().isocalendar()[1])]
                                            elif limit_type == 'monthly':
                                                sale_limit_domain += [('month', '=', timetuple.tm_mon)]
                                            sale_limit = request.env['res.partner.sale.limit'].sudo().search(
                                                sale_limit_domain,
                                                order="id DESC", limit=1)
                                            if sale_limit:
                                                sale_limit.update({'sold_amount': sale_limit.sold_amount - customer_actual_amount})  # calculated_payment_amount

                                            # Refund Sold Over Limit Fees
                                            sale_limit_fees = request.env['res.partner.sale.limit.fees'].sudo().search([('user_request_id', '=', user_request.id),
                                                                                                                        ('limit_type', '=', limit_type),
                                                                                                                        ('refund_wallet_transaction_id', '=', False)], limit=1)
                                            if sale_limit_fees:
                                                wallet_transaction_id, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                                                    'credit', partner, 'request',
                                                    _('Refund %s over limit fees for %s service') % (limit_type, service.name),
                                                    sale_limit_fees.fees_amount, currency, user_request,
                                                    'smartpay_operations.wallet_canel_service_payment_notify_mode',
                                                    'wallet_cancel_service_payment',
                                                    _('<p>%s %s successfully Added to your wallet.</p>') % (
                                                        sale_limit_fees.fees_amount, _(currency.name))
                                                )
                                                sale_limit_fees.update({'refund_amount': sale_limit_fees.fees_amount, 'refund_wallet_transaction_id': wallet_transaction_id.id})

                                    # Deduct Transaction Limit
                                    if partner_wallet_id.type.has_trans_limit:
                                        for trans_limit_id in partner_wallet_id.type.trans_limit_ids:
                                            wallet_limit_type = trans_limit_id.limit_type
                                            timetuple = date_time.now().timetuple()
                                            trans_limit_domain = [
                                                ('wallet_id', '=', partner_wallet_id.id),
                                                # ('wallet_type_id', '=', partner_wallet_id.type.id),
                                                ('limit_type', '=', wallet_limit_type),
                                                ('year', '=', timetuple.tm_year)]
                                            if wallet_limit_type == 'daily':
                                                trans_limit_domain += [('day', '=', timetuple.tm_yday)]
                                            elif wallet_limit_type == 'weekly':
                                                trans_limit_domain += [('week', '=', date_time.now().isocalendar()[1])]
                                            elif wallet_limit_type == 'monthly':
                                                trans_limit_domain += [('month', '=', timetuple.tm_mon)]
                                            trans_limit = request.env['wallet.trans.limit'].sudo().search(
                                                trans_limit_domain, order="id DESC", limit=1)
                                            if trans_limit:
                                                trans_limit.update({'trans_amount': trans_limit.trans_amount - customer_actual_amount})  # calculated_payment_amount

                                            # Refund Transaction Over Limit Fees
                                            trans_limit_fees = request.env['wallet.trans.limit.fees'].sudo().search(
                                                [('user_request_id', '=', user_request.id),
                                                 ('limit_type', '=', wallet_limit_type),
                                                 ('refund_wallet_transaction_id', '=', False)], limit=1)
                                            if trans_limit_fees:
                                                wallet_transaction_id, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                                                    'credit', partner, 'request',
                                                    _('Refund %s over limit fees for %s wallet type') % (
                                                    wallet_limit_type, partner_wallet_id.type.name),
                                                    trans_limit_fees.fees_amount, currency, user_request,
                                                    'smartpay_operations.wallet_canel_service_payment_notify_mode',
                                                    'wallet_cancel_service_payment',
                                                    _('<p>%s %s successfully Added to your wallet.</p>') % (
                                                        trans_limit_fees.fees_amount, _(currency.name))
                                                )
                                                trans_limit_fees.update({'refund_amount': trans_limit_fees.fees_amount,
                                                                        'refund_wallet_transaction_id': wallet_transaction_id.id})

                                    '''
                                    # Notify customer
                                    irc_param = request.env['ir.config_parameter'].sudo()
                                    wallet_canel_service_payment_notify_mode = irc_param.get_param("smartpay_operations.wallet_canel_service_payment_notify_mode")
                                    if wallet_canel_service_payment_notify_mode == 'inbox':
                                        request.env['mail.thread'].sudo().message_notify(subject=label,
                                                                                      body=_('<p>%s %s successfully Added to your wallet.</p>') % (
                                                                                          customer_actual_amount, _(currency.name)),
                                                                                      partner_ids=[(4, partner.id)],
                                        )
                                    elif wallet_canel_service_payment_notify_mode == 'email':
                                        customer_wallet_create.wallet_transaction_email_send()
                                    elif wallet_canel_service_payment_notify_mode == 'sms' and partner.mobile:
                                        customer_wallet_create.sms_send_wallet_transaction(wallet_canel_service_payment_notify_mode, 'wallet_cancel_service_payment',
                                                                                           partner.mobile, partner.name, # request.env.user.name,
                                                                                           label, '%s %s' % (customer_actual_amount, _(currency.name)),
                                                                                           partner.country_id.phone_code or '2')
                                    '''

                                    # Refund provider bill for reconciliation purpose
                                    # Cancel provider refund (cashback), customer invoice and customer credit note (cashback)
                                    '''
                                    refund = False
                                    provider_invoice_ids = ()
                                    for provider_invoice_id in user_request.provider_invoice_ids:
                                        provider_invoice_ids += (tuple(provider_invoice_id.ids),)
                                        # Refund Provider Bill
                                        if provider_invoice_id.type == 'in_invoice' and len(user_request.provider_invoice_ids) == 2:
                                            refund = request.env['account.invoice.refund'].with_context(
                                                active_ids=provider_invoice_id.ids).sudo().create({
                                                'filter_refund': 'refund',
                                                'description': provider_invoice_id.name,
                                                'date': provider_invoice_id.date_invoice,
                                            })
                                            result = refund.invoice_refund()
                                            refund_id = result.get('domain')[1][2]
                                            refund = request.env['account.invoice'].sudo().browse(refund_id)
                                            refund.update({'reference': pmtId, 'request_id': user_request.id})
                                            refund_line = refund.invoice_line_ids[0]
                                            refund_line.update({'request_id': user_request.id})
                                            refund.refresh()
                                            refund.action_invoice_open()
                                            refund.pay_and_reconcile(request.env['account.journal'].sudo().search(
                                                [('type', '=', 'cash'),
                                                 ('company_id', '=', request.env.user.company_id.id),
                                                 ('provider_id', '=', provider.id)], limit=1),
                                                provider_actual_amount)
                                            provider_invoice_ids += (tuple(refund.ids),)
                                        # Cancel provider refund (cashback)
                                        if provider_invoice_id.type == 'in_refund':
                                            if provider_invoice_id.state in ('in_payment', 'paid'):
                                                provider_invoice_id.action_invoice_re_open()
                                            provider_invoice_id.action_invoice_cancel()

                                    user_request.update({'provider_invoice_ids': provider_invoice_ids})
                                    request.env.cr.commit()

                                    # customer_invoice_ids = ()
                                    for customer_invoice_id in user_request.customer_invoice_ids:
                                        # customer_invoice_ids += (tuple(customer_invoice_id.ids),)
                                        # Cancel Customer Invoice and Customer Credit Note (cashback)
                                        if len(user_request.customer_invoice_ids) == 2:
                                            if customer_invoice_id.state in ('in_payment', 'paid'):
                                                customer_invoice_id.action_invoice_re_open()
                                            customer_invoice_id.action_invoice_cancel()

                                    # user_request.update({'customer_invoice_ids': customer_invoice_ids})
                                    # request.env.cr.commit()
                                    '''

                                    user_request.update({'wallet_transaction_id': customer_wallet_create.id})

                                user_request.update({
                                    'provider_response': provider_response_json , # "stage_id": 4
                                    'description': _('Cancel Service Payment request (%s) was submit successfully @ %s') % (user_request.name, str(date_time.now() + timedelta(hours=2))),
                                    'action_status': 'completed'
                                })
                                request.env.cr.commit()

                                return valid_response({"request_number": user_request.name, "provider": provider.provider,
                                                       "provider_response": provider_response_json,
                                                       "message":
                                                           _("Cancel Service Payment request (%s) was submit successfully. Your Machine Wallet Balance is %s %s")
                                                                  % (user_request.name,
                                                                     wallet_balance_after,
                                                                     currency.name)
                                                       })
                            except Exception as e:
                                try:
                                    _logger.error("%s", e, exc_info=True)
                                    user_request_update = {'provider_response': provider_response_json, # "stage_id": 4,
                                                              'description': _(
                                                                  "After the Cancel Service Payment Request submit successfuly with provider, Error is occur:") + " ==> " + str(
                                                                  e)}
                                    if customer_wallet_create:
                                        user_request_update.update({'wallet_transaction_id': customer_wallet_create.id})
                                    '''
                                    provider_invoice_ids = ()
                                    if provider_invoice_id or refund:
                                        if provider_invoice_id:
                                            provider_invoice_ids += (tuple(provider_invoice_id.ids),)
                                        if refund:
                                            provider_invoice_ids += (tuple(refund.ids),)
                                        user_request_update.update({'provider_invoice_ids': provider_invoice_ids})
                                    '''
                                    '''
                                    customer_invoice_ids = ()
                                    if customer_invoice_id or credit_note:
                                        if customer_invoice_id:
                                            customer_invoice_ids += (tuple(customer_invoice_id.ids),)
                                        if credit_note:
                                            customer_invoice_ids += (tuple(credit_note.ids),)
                                        user_request_update.update({'customer_invoice_ids': customer_invoice_ids})
                                    '''
                                    user_request.update(user_request_update)
                                    request.env.cr.commit()
                                except Exception as e1:
                                    _logger.error("%s", e1, exc_info=True)
                                    if user_request and not user_request.description:
                                        user_request.update({'description': _(
                                                                  "After the Cancel Service Payment Request submit successfuly with provider, Error is occur:") + " ==> " + str(
                                                                  e)})
                                        request.env.cr.commit()

                                return invalid_response({"request_number": user_request.name, "provider": provider.provider,
                                                         "provider_response": provider_response_json,
                                                         "message":
                                                           _("Cancel Service Payment request (%s) was submit successfully. Your Machine Wallet Balance is %s %s")
                                                                  % (user_request.name,
                                                                     currency.name,
                                                                     wallet_balance_after,
                                                                     currency.name)
                                                         }, _(
                                    "After the Cancel Service Payment Request submit successfuly with provider, Error is occur:") + " ==> " + str(e), 500)
                        else:
                            provider_response_json["provider_cancel_response"] = provider_cancel_response
                            error.update({provider.provider + "_response": provider_response_json or ''})

                        user_request.update({'provider_response': json.dumps(error), 'description': json.dumps(error)}) # 'stage_id': 5
                        request.env.cr.commit()
                        return invalid_response("Error", error, 400)

                    elif (user_request.request_type == 'pay_service_bill' and user_request.stage_id.id == 5 and isAllowCancel
                            and ('Cancel Service Payment request (%s) was submit successfully' % user_request.name in user_request.description
                                 # or 'Cancel Service Payment request (%s) In progress' % user_request.name in user_request.description
                                 # or 'Correlation Service Payment request (%s) was submit successfully' % user_request.name in user_request.description
                                 # or 'Correlation Service Payment request (%s) In progress' % user_request.name in user_request.description
                                 )) or user_request.sudo().write({'stage_id': 4}):
                        return valid_response(_("Cancel REQ Number (%s) successfully!") % (request_number))
                except Exception as ex:
                    _logger.error("%s", ex, exc_info=True)
            else:
                return invalid_response("request_not_found", _("Request does not exist!"), 400)

            return invalid_response("request_not_canceled", _("Could not cancel REQ Number (%s)") % (request_number), 400)

        @validate_token
        @http.route('/api/correlation_request', type="http", auth="none", methods=["PUT"], csrf=False)
        def correlation_request(self, **request_data):
            _logger.info("@@@@@@@@@@@@@@@@@@@ Calling Correlation Pay Service Request API")
            user_request = False
            request_number = request_data.get('request_number')
            pmtTransIds = request_data.get('pmtTransIds')
            if request_number:
                user_request = request.env['smartpay_operations.request'].sudo().search([('name', '=', request_number)],
                                                                                        limit=1)
            else:  # elif request_data.get('provider') == 'fawry':
                # if not request_data.get('pmtTransIds'):
                    # return invalid_response("pmtTransIds_request_number_not_found", _("missing Request Number or Payment Trans Ids in request data"), 400)
                if pmtTransIds:
                    pmtTransIds = ast.literal_eval(pmtTransIds)
                    pmtTransCounts = 0
                    domain = [('request_type', '=', 'pay_service_bill'), ('create_date', '<=', date_time.now()), ('create_date', '>=', date_time.now() - timedelta(hours=1))]
                    for payment in pmtTransIds:
                        if payment['PmtIdType'] == 'FCRN' or payment['PmtIdType'] == 'BNKPTN':
                            domain += [('provider_response', 'like', '<PmtId>%s</PmtId>' % payment['PmtId'])]
                            pmtTransCounts += 1
                    if pmtTransCounts == 2:
                        user_request = request.env['smartpay_operations.request'].sudo().search(domain, limit=1)
                # _logger.info("@@@@@@@@@@@@@@@@@@@ " + '"pmtTransIds": "%s"' % (request_data.get('pmtTransIds')))
            if user_request:
                request_number = user_request.name
                try:
                    service = user_request.product_id
                    provider = user_request.provider_id

                    service_providerinfo = request.env['product.supplierinfo'].sudo().search([
                        ('product_tmpl_id', '=', service.product_tmpl_id.id),
                        ('name', '=', provider.related_partner.id)
                    ])
                    biller_info_json_dict = json.loads(service_providerinfo.with_context(lang=request.env.user.lang).biller_info, strict=False)
                    corrBillTypeCode = biller_info_json_dict.get('CorrBillTypeCode', False)

                    if user_request.request_type == 'pay_service_bill' and user_request.stage_id.id == 5 and corrBillTypeCode \
                            and (not user_request.description
                                 or ('Correlation Service Payment request (%s) was submit successfully' % user_request.name not in user_request.description
                                     and 'Correlation Service Payment request (%s) In progress' % user_request.name not in user_request.description)):

                        user_request.update({'description': _('Correlation Service Payment request (%s) In progress @ %s') % (user_request.name, str(date_time.now() + timedelta(hours=2)))})
                        request.env.cr.commit()

                        lang = 'ar-eg'
                        partner = user_request.partner_id
                        # trans_date = user_request.trans_date
                        trans_amount = user_request.trans_amount
                        provider_fees_amount = user_request.provider_fees_amount
                        extra_fees_amount = user_request.extra_fees_amount
                        currency = user_request.currency_id

                        # Check Customer Wallet Balance Maximum Balance
                        partner_wallet_id = user_request.wallet_transaction_id.wallet_id or partner.get_transaction_wallet(service=service)
                        if not partner_wallet_id:
                            return invalid_response("wallet_not_found",
                                                    _("No Matched Wallet found for partner [%s] %s") % (
                                                        partner.ref,
                                                        partner.name), 400)
                        if biller_info_json_dict.get('Type') == 'CASHOUT':
                            wallet_max_balance = partner_wallet_id.max_balance or partner_wallet_id.type_max_balance or 0.0
                            if wallet_max_balance and (partner_wallet_id.balance_amount + trans_amount) > wallet_max_balance:
                                user_request.update({'description': _(
                                    'Correlation Service Payment request (%s) failed @ (%s) due to the maximum balance of customer wallet will be exceeded')
                                                                    % (user_request.name, str(date_time.now() + timedelta(hours=2)))})
                                request.env.cr.commit()
                                return invalid_response("wallet_max_balance_exceeded", _("Wallet [%s] maximum balance exceeded!") % partner_wallet_id.name, 400)

                        provider_pay_response = user_request.provider_response
                        provider_response_json = {}
                        provider_response_json['provider_pay_response'] = provider_pay_response
                        provider_pay_response_json = json.loads(provider_pay_response)
                        billingAcct = request_data.get('billingAcct') or provider_pay_response_json.get('PmtInfo').get('BillingAcct')
                        # billerId = request_data.get('billerId') or provider_pay_response_json.get('billerId')
                        # pmtType = request_data.get('pmtType') or provider_pay_response_json.get('pmtType')
                        curCode = request_data.get('currency_id') or provider_pay_response_json.get('PmtInfo').get('CurAmt').get('CurCode')
                        # payAmts = request_data.get('payAmts')
                        # if payAmts:
                            # payAmts = ast.literal_eval(payAmts)
                        # else:
                            # payAmts = [{'Sequence': '1', 'AmtDue': trans_amount, 'CurCode': curCode}]
                        pmtMethod = request_data.get('pmtMethod') or provider_pay_response_json.get('PmtInfo').get('PmtMethod')

                        pmtId = request_data.get('pmtId') or user_request.name
                        # feesAmt = request_data.get('feesAmt') or provider_pay_response_json.get('feesAmt')
                        # feesAmts = request_data.get('feesAmts')
                        # if feesAmts:
                            # feesAmts = ast.literal_eval(feesAmts)
                        # else:
                            # feesAmts = [{'Amt': feesAmt, 'CurCode': curCode}]
                        # pmtRefInfo = request_data.get('pmtRefInfo') or provider_pay_response_json.get('pmtRefInfo')

                        if not pmtTransIds:
                            # Get Provider Payment Trans IDs
                            pmtTransIds = []
                            for payment in provider_pay_response_json['PmtTransId']:
                                if payment['PmtIdType'] == 'FCRN' or payment['PmtIdType'] == 'BNKPTN':
                                    pmtTransIds.append({'PmtId': payment['PmtId'], 'PmtIdType': payment['PmtIdType'], 'CreatedDt': payment['CreatedDt']})

                        error = {}

                        provider_channel = False
                        machine_channels = request.env['payment.acquirer.channel'].sudo().search(
                            [("acquirer_id", "=", provider.id),
                             ("type", "in", ("machine", "internet"))], limit=1)
                        if machine_channels:
                            provider_channel = machine_channels[0]
                        provider_correlation_response = {}
                        if provider.provider == "fawry":
                            # Tamayoz TODO: Provider Server Timeout Handling
                            provider_correlation_response = provider.correlation_fawry_bill(lang, corrBillTypeCode, # service_providerinfo.product_code,
                                                                                            provider_channel.fawry_acctId,# billingAcct,  # extraBillingAcctKeys,
                                                                                            0, curCode, pmtMethod,
                                                                                            # notifyMobile, billRefNumber,
                                                                                            # billerId, pmtType,
                                                                                            pmtTransIds, provider_channel,
                                                                                            request_number)
                        if provider_correlation_response.get('Success'):
                            try:
                                provider_correlation_response_json = suds_to_json(provider_correlation_response.get('Success'))
                                provider_response_json['provider_correlation_response'] = provider_correlation_response_json

                                # provider_actual_amount = trans_amount + provider_fees_amount
                                # customer_actual_amount = provider_actual_amount + extra_fees_amount
                                customer_actual_amount = trans_amount

                                wallet_balance_after = partner_wallet_id.balance_amount
                                if biller_info_json_dict.get('Type') == 'CASHOUT':
                                    # Add Payment Amount to Customer Wallet Balance
                                    '''
                                    wallet_transaction_sudo = request.env['website.wallet.transaction'].sudo()
                                    label = _('Correlation Service Payment for %s service') % (service.name)
                                    partner = request.env.user.partner_id
                                    partner_wallet_id = user_request.wallet_transaction_id.wallet_id or partner.get_transaction_wallet(service=service)
                                    partner_id_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                                    customer_wallet_create = wallet_transaction_sudo.create(
                                        {'wallet_type': 'credit', 'partner_id': partner.id,
                                         'request_id': user_request.id, 'reference': 'request',
                                         'label': label, 'amount': customer_actual_amount,
                                         'currency_id': user_request.currency_id.id,
                                         'wallet_balance_before': partner_id_wallet_balance,
                                         'wallet_balance_after': partner_id_wallet_balance + customer_actual_amount,
                                         'status': 'done'})
                                    request.env.cr.commit()

                                    partner.update({'wallet_balance': partner_id_wallet_balance
                                    + customer_actual_amount})
                                    request.env.cr.commit()

                                    # Notify customer
                                    irc_param = request.env['ir.config_parameter'].sudo()
                                    wallet_correlation_service_payment_notify_mode = irc_param.get_param(
                                        "smartpay_operations.wallet_correlation_service_payment_notify_mode")
                                    if wallet_correlation_service_payment_notify_mode == 'inbox':
                                        request.env['mail.thread'].sudo().message_notify(subject=label,
                                                                                         body=_(
                                                                                             '<p>%s %s successfully Added to your wallet.</p>') % (
                                                                                                  customer_actual_amount,
                                                                                                  _(user_request.currency_id.name)),
                                                                                         partner_ids=[(4, partner.id)],
                                                                                         )
                                    elif wallet_correlation_service_payment_notify_mode == 'email':
                                        customer_wallet_create.wallet_transaction_email_send()
                                    elif wallet_correlation_service_payment_notify_mode == 'sms' and partner.mobile:
                                        customer_wallet_create.sms_send_wallet_transaction(
                                            wallet_correlation_service_payment_notify_mode, 'wallet_correlation_service_payment',
                                            partner.mobile, partner.name,  # request.env.user.name,
                                            label,
                                            '%s %s' % (customer_actual_amount, _(user_request.currency_id.name)),
                                            partner.country_id.phone_code or '2')
                                    '''
                                    customer_wallet_create, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                                        'credit', partner, 'request',
                                        _('Correlation Service Payment for %s service') % (service.name),
                                        customer_actual_amount, currency, user_request,
                                        'smartpay_operations.wallet_correlation_service_payment_notify_mode',
                                        'wallet_correlation_service_payment',
                                        _('<p>%s %s successfully Added to your wallet.</p>') % (
                                            customer_actual_amount, _(currency.name))
                                    )

                                    user_request.update({'wallet_transaction_id': customer_wallet_create.id})

                                user_request.update(
                                    {'provider_response': provider_response_json,  # "stage_id": 4
                                     'description': _(
                                         'Correlation Service Payment request (%s) was submit successfully @ %s') % (
                                                    user_request.name, str(date_time.now() + timedelta(hours=2)))
                                     })
                                request.env.cr.commit()

                                return valid_response(
                                    {"request_number": user_request.name, "provider": provider.provider,
                                     "provider_response": provider_response_json,
                                     "message":
                                         _("Correlation Service Payment request (%s) was submit successfully. Your Machine Wallet Balance is %s %s")
                                         % (user_request.name,
                                            wallet_balance_after,
                                            currency.name)
                                     })
                            except Exception as e:
                                try:
                                    _logger.error("%s", e, exc_info=True)
                                    user_request_update = {'provider_response': provider_response_json,
                                                           # "stage_id": 4,
                                                           'description': _(
                                                               "After the Correlation Service Payment Request submit successfuly with provider, Error is occur:") + " ==> " + str(
                                                               e)}
                                    if customer_wallet_create:
                                        user_request_update.update({'wallet_transaction_id': customer_wallet_create.id})
                                    user_request.update(user_request_update)
                                    request.env.cr.commit()
                                except Exception as e1:
                                    _logger.error("%s", e1, exc_info=True)
                                    if user_request and not user_request.description:
                                        user_request.update({'description': _(
                                            "After the Correlation Service Payment Request submit successfuly with provider, Error is occur:") + " ==> " + str(
                                            e)})
                                        request.env.cr.commit()

                                return invalid_response(
                                    {"request_number": user_request.name, "provider": provider.provider,
                                     "provider_response": provider_response_json,
                                     "message":
                                         _("Correlation Service Payment request (%s) was submit successfully. Your Machine Wallet Balance is %s %s")
                                         % (user_request.name,
                                            currency.name,
                                            wallet_balance_after,
                                            currency.name)
                                     }, _(
                                        "After the Correlation Service Payment Request submit successfuly with provider, Error is occur:") + " ==> " + str(
                                        e), 500)
                        else:
                            provider_response_json["provider_correlation_response"] = provider_correlation_response
                            error.update({provider.provider + "_response": provider_response_json or ''})
                            error_code = provider_correlation_response.get('error_code')
                            if provider.provider == "fawry" and biller_info_json_dict.get('Type') == 'CASHININT' and error_code in ('21092', '21132', '26', '31004', '2601'):
                                provider_actual_amount = user_request.trans_amount + provider_fees_amount
                                customer_actual_amount = provider_actual_amount + extra_fees_amount

                                # Refund Payment Amount to Customer Wallet Balance
                                '''
                                wallet_transaction_sudo = request.env['website.wallet.transaction'].sudo()
                                label = _('Correlation Service Payment Failed for %s service') % (service.name)
                                partner_wallet_id = user_request.wallet_transaction_id.wallet_id or partner.get_transaction_wallet(service=service)
                                partner_id_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                                customer_wallet_create = wallet_transaction_sudo.create({
                                    'wallet_type': 'credit', 'partner_id': partner.id,
                                    'request_id': user_request.id, 'reference': 'request',
                                    'label': label, 'amount': customer_actual_amount,
                                    'currency_id': currency.id,
                                    'wallet_balance_before': partner_id_wallet_balance,
                                    'wallet_balance_after': partner_id_wallet_balance + customer_actual_amount,
                                    'status': 'done'
                                })
                                request.env.cr.commit()

                                partner.update({'wallet_balance': partner_id_wallet_balance
                                + customer_actual_amount})
                                request.env.cr.commit()
                                '''
                                # Tamayoz TODO: Check below TODO: if required to set refunded wallet_transaction_id and update the request when correlation CASHIN is Fail
                                partner_wallet_id = user_request.wallet_transaction_id.wallet_id or partner.get_transaction_wallet(service=service)
                                if not partner_wallet_id:
                                    return invalid_response("wallet_not_found",
                                                            _("No Matched Wallet found for partner [%s] %s") % (
                                                                partner.ref,
                                                                partner.name), 400)
                                customer_wallet_create, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                                    'credit', partner, 'request',
                                    _('Correlation Service Payment Failed for %s service') % (service.name),
                                    customer_actual_amount, currency, user_request,
                                    'smartpay_operations.wallet_canel_service_payment_notify_mode',
                                    'wallet_cancel_service_payment',
                                    _('<p>%s %s successfully Added to your wallet.</p>') % (
                                        customer_actual_amount, _(currency.name))
                                )

                                # Deduct Sold Limit
                                if service.has_sale_limit:
                                    for sale_limit_id in service.sale_limit_ids:
                                        limit_type = sale_limit_id.limit_type
                                        timetuple = date_time.now().timetuple()
                                        sale_limit_domain = [
                                            ('partner_id', '=', partner.id),
                                            ('product_id', '=', service.id),
                                            ('limit_type', '=', limit_type),
                                            ('year', '=', timetuple.tm_year)]
                                        if limit_type == 'daily':
                                            sale_limit_domain += [('day', '=', timetuple.tm_yday)]
                                        elif limit_type == 'weekly':
                                            sale_limit_domain += [
                                                ('week', '=', date_time.now().isocalendar()[1])]
                                        elif limit_type == 'monthly':
                                            sale_limit_domain += [('month', '=', timetuple.tm_mon)]
                                        sale_limit = request.env['res.partner.sale.limit'].sudo().search(
                                            sale_limit_domain,
                                            order="id DESC", limit=1)
                                        if sale_limit:
                                            sale_limit.update({'sold_amount': sale_limit.sold_amount - customer_actual_amount})  # calculated_payment_amount

                                        # Refund Sold Over Limit Fees
                                        sale_limit_fees = request.env['res.partner.sale.limit.fees'].sudo().search([('user_request_id', '=', user_request.id),
                                                                                                                    ('limit_type', '=', limit_type),
                                                                                                                    ('refund_wallet_transaction_id', '=', False)], limit=1)
                                        if sale_limit_fees:
                                            wallet_transaction_id, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                                                'credit', partner, 'request',
                                                _('Refund %s over limit fees for %s service') % (limit_type, service.name),
                                                sale_limit_fees.fees_amount, currency, user_request,
                                                'smartpay_operations.wallet_canel_service_payment_notify_mode',
                                                'wallet_cancel_service_payment',
                                                _('<p>%s %s successfully Added to your wallet.</p>') % (
                                                    sale_limit_fees.fees_amount, _(currency.name))
                                            )
                                            sale_limit_fees.update({'refund_amount': sale_limit_fees.fees_amount, 'refund_wallet_transaction_id': wallet_transaction_id.id})

                                # Deduct Transaction Limit
                                if partner_wallet_id.type.has_trans_limit:
                                    for trans_limit_id in partner_wallet_id.type.trans_limit_ids:
                                        wallet_limit_type = trans_limit_id.limit_type
                                        timetuple = date_time.now().timetuple()
                                        trans_limit_domain = [
                                            ('wallet_id', '=', partner_wallet_id.id),
                                            # ('wallet_type_id', '=', partner_wallet_id.type.id),
                                            ('limit_type', '=', wallet_limit_type),
                                            ('year', '=', timetuple.tm_year)]
                                        if wallet_limit_type == 'daily':
                                            trans_limit_domain += [('day', '=', timetuple.tm_yday)]
                                        elif wallet_limit_type == 'weekly':
                                            trans_limit_domain += [('week', '=', date_time.now().isocalendar()[1])]
                                        elif wallet_limit_type == 'monthly':
                                            trans_limit_domain += [('month', '=', timetuple.tm_mon)]
                                        trans_limit = request.env['wallet.trans.limit'].sudo().search(
                                            trans_limit_domain, order="id DESC", limit=1)
                                        if trans_limit:
                                            trans_limit.update({'trans_amount': trans_limit.trans_amount - customer_actual_amount})  # calculated_payment_amount

                                        # Refund Transaction Over Limit Fees
                                        trans_limit_fees = request.env['wallet.trans.limit.fees'].sudo().search(
                                            [('user_request_id', '=', user_request.id),
                                             ('limit_type', '=', wallet_limit_type),
                                             ('refund_wallet_transaction_id', '=', False)], limit=1)
                                        if trans_limit_fees:
                                            wallet_transaction_id, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                                                'credit', partner, 'request',
                                                _('Refund %s over limit fees for %s wallet type') % (
                                                    wallet_limit_type, partner_wallet_id.type.name),
                                                trans_limit_fees.fees_amount, currency, user_request,
                                                'smartpay_operations.wallet_canel_service_payment_notify_mode',
                                                'wallet_cancel_service_payment',
                                                _('<p>%s %s successfully Added to your wallet.</p>') % (
                                                    trans_limit_fees.fees_amount, _(currency.name))
                                            )
                                            trans_limit_fees.update({'refund_amount': trans_limit_fees.fees_amount,
                                                                     'refund_wallet_transaction_id': wallet_transaction_id.id})

                                '''
                                # Notify customer
                                irc_param = request.env['ir.config_parameter'].sudo()
                                wallet_canel_service_payment_notify_mode = irc_param.get_param(
                                    "smartpay_operations.wallet_canel_service_payment_notify_mode")
                                if wallet_canel_service_payment_notify_mode == 'inbox':
                                    request.env['mail.thread'].sudo().message_notify(subject=label,
                                                                                     body=_(
                                                                                         '<p>%s %s successfully Added to your wallet.</p>') % (
                                                                                              customer_actual_amount,
                                                                                              _(currency.name)),
                                                                                     partner_ids=[(4, partner.id)],
                                                                                     )
                                elif wallet_canel_service_payment_notify_mode == 'email':
                                    customer_wallet_create.wallet_transaction_email_send()
                                elif wallet_canel_service_payment_notify_mode == 'sms' and partner.mobile:
                                    customer_wallet_create.sms_send_wallet_transaction(
                                        wallet_canel_service_payment_notify_mode, 'wallet_cancel_service_payment',
                                        partner.mobile, partner.name,  # request.env.user.name,
                                        label, '%s %s' % (customer_actual_amount, _(currency.name)),
                                        partner.country_id.phone_code or '2')
                                '''

                                # Tamayoz TODO: Check if required to set refunded wallet_transaction_id and update the request when correlation CASHIN is Fail
                                '''
                                user_request.update({'wallet_transaction_id': customer_wallet_create.id})

                                user_request.update({
                                    'provider_response': provider_response_json , # "stage_id": 4
                                    'description': _('Cancel Service Payment request (%s) was submit successfully @ %s') % (user_request.name, str(date_time.now() + timedelta(hours=2))),
                                    'action_status': 'completed'
                                })
                                request.env.cr.commit()
                                '''

                                # Refund provider bill for reconciliation purpose
                                # Cancel provider refund (cashback), customer invoice and customer credit note (cashback)
                                '''
                                refund = False
                                provider_invoice_ids = ()
                                for provider_invoice_id in user_request.provider_invoice_ids:
                                    provider_invoice_ids += (tuple(provider_invoice_id.ids),)
                                    # Refund Provider Bill
                                    if provider_invoice_id.type == 'in_invoice' and len(
                                            user_request.provider_invoice_ids) == 2:
                                        refund = request.env['account.invoice.refund'].with_context(
                                            active_ids=provider_invoice_id.ids).sudo().create({
                                            'filter_refund': 'refund',
                                            'description': provider_invoice_id.name,
                                            'date': provider_invoice_id.date_invoice,
                                        })
                                        result = refund.invoice_refund()
                                        refund_id = result.get('domain')[1][2]
                                        refund = request.env['account.invoice'].sudo().browse(refund_id)
                                        refund.update({'reference': pmtId, 'request_id': user_request.id})
                                        refund_line = refund.invoice_line_ids[0]
                                        refund_line.update({'request_id': user_request.id})
                                        refund.refresh()
                                        refund.action_invoice_open()
                                        refund.pay_and_reconcile(request.env['account.journal'].sudo().search(
                                            [('type', '=', 'cash'),
                                             ('company_id', '=', request.env.user.company_id.id),
                                             ('provider_id', '=', provider.id)], limit=1),
                                            provider_actual_amount)
                                        provider_invoice_ids += (tuple(refund.ids),)
                                    # Cancel provider refund (cashback)
                                    if provider_invoice_id.type == 'in_refund':
                                        if provider_invoice_id.state in ('in_payment', 'paid'):
                                            provider_invoice_id.action_invoice_re_open()
                                        provider_invoice_id.action_invoice_cancel()

                                user_request.update({'provider_invoice_ids': provider_invoice_ids})
                                request.env.cr.commit()

                                # customer_invoice_ids = ()
                                for customer_invoice_id in user_request.customer_invoice_ids:
                                    # customer_invoice_ids += (tuple(customer_invoice_id.ids),)
                                    # Cancel Customer Invoice and Customer Credit Note (cashback)
                                    if len(user_request.customer_invoice_ids) == 2:
                                        if customer_invoice_id.state in ('in_payment', 'paid'):
                                            customer_invoice_id.action_invoice_re_open()
                                        customer_invoice_id.action_invoice_cancel()

                                # user_request.update({'customer_invoice_ids': customer_invoice_ids})
                                # request.env.cr.commit()
                                '''

                        user_request.update({
                            'provider_response': json.dumps(error),
                            'description': json.dumps(error),
                            # 'stage_id': 5
                        })
                        request.env.cr.commit()
                        return invalid_response("Error", error, 400)

                    elif user_request.sudo().write({'stage_id': 4}):
                        return valid_response(_("Correlation REQ Number (%s) successfully!") % (request_number))
                except Exception as ex:
                    _logger.error("%s", ex, exc_info=True)
            else:
                return invalid_response("request_not_found", _("Request does not exist!"), 400)

            return invalid_response("request_not_correlation", _("Could not correlation REQ Number (%s)") % (request_number),
                                    400)

        @validate_token
        @http.route('/api/get_request', type="http", auth="none", methods=["POST"], csrf=False)
        def get_request(self, **payload):
            _logger.info("@@@@@@@@@@@@@@@@@@@ Calling Get Requests API")
            domain = payload.get("domain")
            if not domain or "name" not in domain:
                return invalid_response("request_number_missing", _("REQ Number is missing. Please Send REQ Number"), 400)
            return restful_main().get('smartpay_operations.request', None, **payload)

        @validate_token
        @http.route('/api/get_requests', type="http", auth="none", methods=["POST"], csrf=False)
        def get_requests(self, **payload):
            _logger.info("@@@@@@@@@@@@@@@@@@@ Calling Get Requests API")
            domain = []
            if payload.get("domain", None):
                domain = ast.literal_eval(payload.get("domain"))
            domain += [("partner_id.id", "=", request.env.user.partner_id.id)]
            if not any(item[0] == 'create_date' for item in domain):
                create_date = (datetime.date.today()+datetime.timedelta(days=-30)).strftime('%Y-%m-%d')
                domain += [("create_date", ">=", create_date)]
            payload.update({
                'domain': str(domain)
            })
            return restful_main().get('smartpay_operations.request', None, **payload)

        @validate_token
        @http.route('/api/get_service_fees', type="http", auth="none", methods=["POST"], csrf=False)
        def get_service_fees(self, **request_data):
            _logger.info("@@@@@@@@@@@@@@@@@@@ Calling Get Service Fees API")

            if not request_data.get('product_id'):
                return invalid_response("service_not_found", _("missing service in request data"), 400)
            else:
                service = request.env["product.product"].sudo().search(
                    [("id", "=", request_data.get('product_id')), ("type", "=", "service")],
                    order="id DESC", limit=1)
                if not service:
                    return invalid_response("service", _("service invalid"), 400)

            # Provider is mandatory because the service fee is different per provider.
            # So the user must send provider that own the bill inquiry request for prevent pay bill
            # with total amount different of total amount in bill inquiry
            provider_provider = request_data.get('provider')
            if provider_provider:
                provider = request.env['payment.acquirer'].sudo().search([("provider", "=", provider_provider)])
                # if provider: # Tamayoz Note: Comment this condition for solving service_providerinfo assign before initilizing
                if provider_provider == 'khales' and provider.server_state == 'offline':
                    return invalid_response("service_fees_not_available",
                                            _("Service Fees Not Available"), 400)
                service_providerinfo = request.env['product.supplierinfo'].sudo().search([
                    ('product_tmpl_id', '=', service.product_tmpl_id.id),
                    ('name', '=', provider.related_partner.id)
                ])
                if not service_providerinfo:
                    return invalid_response(
                        "Incompatible_provider_service", _("%s is not a provider for (%s) service") % (
                            provider_provider, service.name or '-'), 400)
            else:
                return invalid_response("provider_not_found",
                                        _("missing provider in request data"), 400)

            trans_amount = float(request_data.get('trans_amount'))
            if not trans_amount:
                return invalid_response("amount_not_found",
                                        _("missing bill amount in request data"), 400)
            else:
                # Calculate Fees
                provider_fees_calculated_amount = 0.0
                extra_fees_amount = 0.0
                if provider_provider == 'khales':
                    if not request_data.get('ePayBillRecID'):
                        return invalid_response("ePayBillRecID_not_found",
                                                _("missing ePayBillRecID in request data"), 400)
                    if not request_data.get('currency_id'):
                        return invalid_response("currency_not_found", _("missing currency in request data"), 400)

                    provider_channel = False
                    provider_channels = request.env['payment.acquirer.channel'].sudo().search(
                        [("acquirer_id", "=", provider.id)], limit=1)
                    if provider_channels:
                        provider_channel = provider_channels[0]

                    curCode = request_data.get('currency_id')
                    payAmts = request_data.get('payAmts')
                    if payAmts:
                        payAmts = ast.literal_eval(payAmts)
                        payAmtTemp = trans_amount
                        for payAmt in payAmts:
                            payAmtTemp -= float(payAmt.get('AmtDue'))
                        if payAmtTemp != 0:
                            return invalid_response("payAmts_not_match",
                                                    _("The sum of payAmts must be equals trans_amount"), 400)
                    else:
                        payAmts = [{'Sequence': '1', 'AmtDue': trans_amount, 'CurCode': curCode}]

                    '''
                    machine_serial = None
                    if len(request.env.user.machine_serial) > 16:  # Ingenico POS
                        machine_serial = request.env.user.machine_serial
                        machine_serial = machine_serial[len(machine_serial) - 16:len(machine_serial)]
                    '''
                    machine_serial = request.env.user.machine_serial
                    if machine_serial and len(machine_serial) > 16:
                        machine_serial = machine_serial[len(machine_serial) - 16:len(machine_serial)]
                    fees_response = provider.get_khales_fees('', machine_serial or '',
                                                             request_data.get('ePayBillRecID'), payAmts,
                                                             provider_channel)
                    if fees_response.get('Success'):
                        feeInqRsType = fees_response.get('Success')
                        provider_fees_calculated_amount = float(feeInqRsType['FeesAmt']['Amt'])

                if provider_fees_calculated_amount == 0 or provider_provider == 'khales':
                    calculate_provider_fees = True
                    if provider_provider == 'khales' and provider_fees_calculated_amount != 0:
                        calculate_provider_fees = False
                    commissions = request.env['product.supplierinfo.commission'].sudo().search_read(
                        domain=[('vendor', '=', service_providerinfo.name.id),
                                ('vendor_product_code', '=', service_providerinfo.product_code)],
                        fields=['Amount_Range_From', 'Amount_Range_To',
                                'Extra_Fee_Amt', 'Extra_Fee_Prc',
                                'Mer_Fee_Amt', 'Mer_Fee_Prc', 'Mer_Fee_Prc_MinAmt', 'Mer_Fee_Prc_MaxAmt']
                    )
                    for commission in commissions:
                        if commission['Amount_Range_From'] <= trans_amount \
                                and commission['Amount_Range_To'] >= trans_amount:
                            if commission['Extra_Fee_Amt'] > 0:
                                extra_fees_amount = commission['Extra_Fee_Amt']
                            elif commission['Extra_Fee_Prc'] > 0:
                                extra_fees_amount = trans_amount * commission['Extra_Fee_Prc'] / 100
                            if calculate_provider_fees:
                                if commission['Mer_Fee_Amt'] > 0:
                                    provider_fees_calculated_amount = commission['Mer_Fee_Amt']
                                elif commission['Mer_Fee_Prc'] > 0:
                                    # Fees amount = FA + [Percentage * Payment Amount]
                                    # Fees amount ====================> provider_fees_calculated_amount
                                    # FA =============================> provider_fees_calculated_amount
                                    # [Percentage * Payment Amount] ==> provider_fees_prc_calculated_amount
                                    provider_fees_prc_calculated_amount = trans_amount * commission[
                                        'Mer_Fee_Prc'] / 100
                                    if provider_fees_prc_calculated_amount < commission['Mer_Fee_Prc_MinAmt']:
                                        provider_fees_prc_calculated_amount = commission['Mer_Fee_Prc_MinAmt']
                                    elif provider_fees_prc_calculated_amount > commission['Mer_Fee_Prc_MaxAmt'] \
                                            and commission['Mer_Fee_Prc_MaxAmt'] > 0:
                                        provider_fees_prc_calculated_amount = commission['Mer_Fee_Prc_MaxAmt']
                                    provider_fees_calculated_amount += provider_fees_prc_calculated_amount
                            break
                    if calculate_provider_fees and provider_fees_calculated_amount != 0 and provider_provider == 'khales':
                        provider_fees_calculated_amount = ((math.floor(provider_fees_calculated_amount * 100)) / 100.0)

                calculated_payment_amount = trans_amount + provider_fees_calculated_amount + extra_fees_amount
                return valid_response(
                    {"message": _("Get Service Fees request was submit successfully."),
                     "provider": provider.provider,
                     "provider_service_code": service_providerinfo.product_code,
                     "provider_service_name": service_providerinfo.product_name,
                     "trans_amount": trans_amount,
                     "provider_fees_amount": provider_fees_calculated_amount,
                     "extra_fees_amount": extra_fees_amount
                     })

        @validate_token
        @http.route('/api/get_wallet_balance', type="http", auth="none", methods=["POST"], csrf=False)
        def get_wallet_balance(self, **payload):
            _logger.info("@@@@@@@@@@@@@@@@@@@ Calling Get Main Wallet Balance API")
            # return restful_main().get('res.partner', request.env.user.partner_id.id, **payload)
            wallet_id = None
            if payload.get("wallet_id"):
                wallet_id = request.env['website.wallet'].sudo().search([('id', '=', payload.get("wallet_id")), ('active', '=', True),
                                                                         ('partner_id', '=', request.env.user.partner_id.id)], limit=1)
            partner_wallet_id = wallet_id or request.env.user.partner_id.get_transaction_wallet()
            if not partner_wallet_id:
                return invalid_response("wallet_not_found",
                                        _("No Matched Wallet found for partner [%s] %s") % (
                                            request.env.user.partner_id.ref,
                                            request.env.user.partner_id.name), 400)
            wallets = []  # partner_wallets_balance
            wallet = {
                "id": partner_wallet_id.id,
                "name": partner_wallet_id.name,
                "wallet_balance": partner_wallet_id.balance_amount,
                "available_amount": partner_wallet_id.available_amount,
                "reserved_amount": partner_wallet_id.reserved_amount,
                "currency_id": _(partner_wallet_id.currency_id.name)
            }
            wallets.append(wallet)
            return valid_response(wallets)

        @validate_token
        @http.route('/api/get_my_wallets', type="http", auth="none", methods=["POST"], csrf=False)
        def get_my_wallets(self, **payload):
            _logger.info("@@@@@@@@@@@@@@@@@@@ Calling Get My Wallets Info API")
            ref = payload.get('reference')
            if ref:
                partner = request.env['res.partner'].sudo().search([('ref', '=', ref)], limit=1)
            else:
                partner = request.env.user.partner_id
            wallets = [] # partner_wallets_balance
            for wallet_id in partner.wallet_ids:
                wallet = {
                    "id": wallet_id.id,
                    "name": wallet_id.name,
                    "wallet_balance": wallet_id.balance_amount,
                    "available_amount": wallet_id.available_amount,
                    "reserved_amount": wallet_id.reserved_amount,
                    "currency_id": _(wallet_id.currency_id.name)
                }

                wallets.append(wallet)
            return valid_response(wallets)

        @validate_token
        @http.route('/api/get_my_customers_wallet_balance', type="http", auth="none", methods=["POST"], csrf=False)
        def get_my_customers_wallet_balance(self, **payload):
            _logger.info("@@@@@@@@@@@@@@@@@@@ Calling Get My Customer Main Wallet Balance API")
            domain, fields, offset, limit, order = extract_arguments(payload)
            user_id = -1
            ref = payload.get('reference')
            if ref:
                partner_id = request.env['res.partner'].sudo().search([('ref', '=', ref)], limit=1)
                if partner_id:
                    user = request.env['res.users'].sudo().search([('partner_id', '=', partner_id.id)])
                    if user:
                        user_id = user.id
            else:
                user_id = request.env.user.id
            domain += [("user_id", "=", user_id)]

            partner_sudo = request.env['res.partner'].sudo()
            my_customers = partner_sudo.search(domain, offset=offset, limit=limit, order=order)
            customers = []
            if my_customers:
                for my_customer in my_customers:
                    partner_wallet_id = my_customer.get_transaction_wallet()
                    partner_id_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                    customer = {
                        "id": my_customer.id,
                        "reference": my_customer.ref,
                        "name": my_customer.name,
                        "wallet_balance": partner_id_wallet_balance
                    }

                    customers.append(customer)

            return valid_response(customers)

        @validate_token
        @http.route('/api/get_my_customers_wallets', type="http", auth="none", methods=["POST"], csrf=False)
        def get_my_customers_wallets(self, **payload):
            _logger.info("@@@@@@@@@@@@@@@@@@@ Calling Get My Customer Wallets Info API")
            domain, fields, offset, limit, order = extract_arguments(payload)
            user_id = -1
            ref = payload.get('reference')
            if ref:
                partner_id = request.env['res.partner'].sudo().search([('ref', '=', ref)], limit=1)
                if partner_id:
                    user = request.env['res.users'].sudo().search([('partner_id', '=', partner_id.id)])
                    if user:
                        user_id = user.id
            else:
                user_id = request.env.user.id
            domain += [("user_id", "=", user_id)]

            partner_sudo = request.env['res.partner'].sudo()
            my_customers = partner_sudo.search(domain, offset=offset, limit=limit, order=order)
            customers = []
            if my_customers:
                for my_customer in my_customers:
                    wallets = []  # partner_wallets_balance
                    for wallet_id in my_customer.wallet_ids:
                        wallet = {
                            "id": wallet_id.id,
                            "name": wallet_id.name,
                            "wallet_balance": wallet_id.balance_amount,
                            "available_amount": wallet_id.available_amount,
                            "reserved_amount": wallet_id.reserved_amount,
                            "currency_id": _(wallet_id.currency_id.name)
                        }
                        wallets.append(wallet)
                    customer = {
                        "id": my_customer.id,
                        "reference": my_customer.ref,
                        "name": my_customer.name,
                        "wallet_balance": wallets
                    }

                    customers.append(customer)

            return valid_response(customers)

        @validate_token
        @http.route('/api/get_wallet_trans_summary', type="http", auth="none", methods=["POST"], csrf=False)
        def get_wallet_trans_summary(self, **payload):
            _logger.info("@@@@@@@@@@@@@@@@@@@ Calling Get Wallet Transactions Summary API")
            domain = []
            if payload.get("domain", None):
                domain = ast.literal_eval(payload.get("domain"))
            domain += [("partner_id.id", "=", request.env.user.partner_id.id), ('status','=', 'done')]
            if not any(item[0] == 'create_date' for item in domain):
                create_date = (datetime.date.today() + datetime.timedelta(days=-30)).strftime('%Y-%m-%d')
                domain += [("create_date", ">=", create_date)]
            if not any(item[0] == 'wallet_id' for item in domain):
                partner_wallet_id = request.env.user.partner_id.get_transaction_wallet()
                if not partner_wallet_id:
                    return invalid_response("wallet_not_found",
                                            _("No Matched Wallet found for partner [%s] %s") % (
                                                request.env.user.partner_id.ref,
                                                request.env.user.partner_id.name), 400)
                domain += [("wallet_id", "=", partner_wallet_id.id)]

            wallet_trans_summary = {}
            wallet_transactions = request.env['website.wallet.transaction'].sudo().search(domain, order='id')

            if len(wallet_transactions) > 0:
                opening_balance = wallet_transactions[0].wallet_balance_before or 0.0
                bonus = sum(float(amount) for amount in wallet_transactions.filtered(lambda wt: wt.wallet_type == 'credit'
                                                                                                and (_('Bonus for inviter user') in wt.label
                                                                                                     or _('Bonus for invited user') in wt.label)).mapped('amount'))
                recharge = sum(float(amount) for amount in wallet_transactions.filtered(lambda wt: wt.wallet_type == 'credit'
                                                                                                   and (_('Transfer wallet balance from') in wt.label
                                                                                                        or wt.label == _('Recharge Wallet'))).mapped('amount'))
                other_wallet_cash_out = sum(float(amount) for amount in wallet_transactions.filtered(lambda wt: wt.wallet_type == 'credit'
                                                                                                                and (_('Correlation Service Payment for') in wt.label)).mapped('amount'))
                cashback = sum(float(amount) for amount in wallet_transactions.filtered(lambda wt: wt.wallet_type == 'credit'
                                                                                                   and (_('Customer Cashback') in wt.label)).mapped('amount')) # wt.reference == 'cashback' # Tamayoz TODO: For all Cashback change reference to cashback
                refund = sum(float(amount) for amount in wallet_transactions.filtered(lambda wt: wt.wallet_type == 'credit'
                                                                                                 and (_('Correlation Service Payment Failed') in wt.label
                                                                                                      or _('Cancel Service Payment for') in wt.label)).mapped('amount'))
                collect_invoice = sum(float(amount) for amount in wallet_transactions.filtered(lambda wt: wt.wallet_type == 'credit'
                                                                                                          and (_('Collect invoice payment from') in wt.label)).mapped('amount'))
                add_correction = sum(float(amount) for amount in wallet_transactions.filtered(lambda wt: wt.wallet_type == 'credit'
                                                                                                         and wt.reference == 'manual').mapped('amount')) # Other labels
                trans_payments = sum(float(amount) for amount in wallet_transactions.filtered(lambda wt: wt.wallet_type == 'debit'
                                                                                                         and (_('Pay Service Bill for') in wt.label)).mapped('amount'))
                reverse_cashback = sum(float(amount) for amount in wallet_transactions.filtered(lambda wt: wt.wallet_type == 'debit'
                                                                                                           and (_('Reverse Customer Cashback') in wt.label)).mapped('amount'))  # wt.reference == 'cashback' # Tamayoz TODO: For all Cashback change reference to cashback
                transfer_balance = sum(float(amount) for amount in wallet_transactions.filtered(lambda wt: wt.wallet_type == 'debit'
                                                                                                           and (_('Transfer wallet balance to') in wt.label)).mapped('amount'))
                installments = sum(float(amount) for amount in wallet_transactions.filtered(lambda wt: wt.wallet_type == 'debit'
                                                                                                       and wt.reference == 'manual' # Tamayoz TODO: Collect payment for invoice must be change reference from manual to collection
                                                                                                       and (_('Collect payment for invoice') in wt.label)).mapped('amount'))
                pay_invoice = sum(float(amount) for amount in wallet_transactions.filtered(lambda wt: wt.wallet_type == 'debit'
                                                                                                      and (_('Pay invoice to') in wt.label)).mapped('amount'))
                deduct_correction = sum(float(amount) for amount in wallet_transactions.filtered(lambda wt: wt.wallet_type == 'debit'
                                                                                                            and wt.reference == 'manual'
                                                                                                            and (_('Collect payment for invoice') not in wt.label)).mapped('amount'))  # Other label
                ending_balance = wallet_transactions[len(wallet_transactions) - 1].wallet_balance_after or 0.00
                wallet_trans_summary.update({
                    "open": {
                        "opening_balance": {"label": _("Opening Balance"), "value": opening_balance} # رصيد افتتاحي
                    },
                    "credit": {
                        "bonus": {"label": _("Bonus"), "value": bonus}, # بونص ترحيبى
                        "recharge": {"label": _("Recharge"), "value": recharge}, # اضافة للرصيد
                        "other_wallet_cash_out": {"label": _("Other Wallet Cash Out"), "value": other_wallet_cash_out}, # سحب من محفظة اخرى
                        "cashback": {"label": _("Cashback"), "value": cashback},  # اضافة عمولات
                        "refund": {"label": _("Refund"), "value": refund}, # استرجاع عمليات فاشلة
                        "collect_invoice": {"label": _("Collect Invoice"), "value": collect_invoice},  # فواتير التاجر
                        "add_correction": {"label": _("Addition Correction"), "value": add_correction} # تصحيح اضافة
                    },
                    "debit": {
                        "trans_payments": {"label": _("Transaction Payments"), "value": trans_payments}, # مدفوعات العملاء
                        "reverse_cashback": {"label": _("Reverse Cashback"), "value": reverse_cashback},  # خصم عمولات
                        "transfer_balance": {"label": _("Transfer Balance"), "value": transfer_balance}, # تحويل رصيد
                        "installments": {"label": _("Installments"), "value": installments}, # اقساط
                        "pay_invoice": {"label": _("Pay Invoice"), "value": pay_invoice}, # فواتير التاجر
                        "deduct_correction": {"label": _("Deduction Correction"), "value": deduct_correction} # تصحيح خصم
                    },
                    "end": {
                        "ending_balance": {"label": _("Ending Balance"), "value": ending_balance} # الرصيد الختامي
                    }
                })

            return valid_response(wallet_trans_summary)

        @validate_token
        @http.route('/api/get_wallet_trans', type="http", auth="none", methods=["POST"], csrf=False)
        def get_wallet_trans(self, **payload):
            _logger.info("@@@@@@@@@@@@@@@@@@@ Calling Get Wallet Transactions API")
            domain = []
            if payload.get("domain", None):
                domain = ast.literal_eval(payload.get("domain"))
            domain += [("partner_id.id", "=", request.env.user.partner_id.id), ('status','=', 'done')]
            if not any(item[0] == 'create_date' for item in domain):
                create_date = (datetime.date.today()+datetime.timedelta(days=-30)).strftime('%Y-%m-%d')
                domain += [("create_date", ">=", create_date)]
            if not any(item[0] == 'wallet_id' for item in domain):
                partner_wallet_id = request.env.user.partner_id.get_transaction_wallet()
                if not partner_wallet_id:
                    return invalid_response("wallet_not_found",
                                            _("No Matched Wallet found for partner [%s] %s") % (
                                                request.env.user.partner_id.ref,
                                                request.env.user.partner_id.name), 400)
                domain += [("wallet_id", "=", partner_wallet_id.id)]

            payload.update({
                'domain': str(domain)
            })
            return restful_main().get('website.wallet.transaction', None, **payload)

        @validate_token
        @validate_machine
        @http.route('/api/recharge_mobile_wallet', type="http", auth="none", methods=["POST"], csrf=False)
        def recharge_mobile_wallet(self, **request_data):
            _logger.info("@@@@@@@@@@@@@@@@@@@ Calling Recharge Mobile Wallet Request API")
            if not request_data.get('request_number'):
                if request_data.get('transfer_to') and request_data.get('trans_amount'):
                    # current_user = request.env.user
                    # current_user_access_token = request.httprequest.headers.get("access_token")
                    # current_user_machine_serial = request.httprequest.headers.get("machine_serial")
                    # Create Recharge Mobile Wallet Request
                    transfer_to_user = request.env['res.users'].sudo().search(['|',
                                                                               ('login', '=', request_data.get('transfer_to')),
                                                                               ('ref', '=', request_data.get('transfer_to'))], limit=1)[0]
                    if not transfer_to_user:
                        return invalid_response("request_code_invalid", _("invalid transfer user in request data"), 400)

                    _token = request.env["api.access_token"]
                    token = ''
                    access_token = (
                        _token
                            .sudo()
                            .search([("user_id", "=", transfer_to_user.id)], order="id DESC", limit=1)
                    )
                    if access_token:
                        access_token = access_token[0]
                        if access_token.has_expired():
                            # return invalid_response("token_expired", _("transfer to user token expired"), 400)
                            access_token.update({'expires': date_time.now() + timedelta(minutes=15)})
                            request.env.cr.commit()
                        token = access_token.token
                    else:
                        # return invalid_response("account_deactivate", _("transfer to user account is deactivated"), 400)
                        token = _token.find_one_or_create_token(user_id=transfer_to_user.id, create=True)
                        request.env.cr.commit()

                    base_url = request.env['ir.config_parameter'].sudo().get_param('smartpay.base.url', default='web.base.url')
                    headers = {
                        'content-type': 'application/x-www-form-urlencoded',
                        'charset': 'utf-8',
                        'access_token': token
                    }
                    data = {
                        'request_type': 'recharge_wallet',
                        'trans_amount': request_data.get('trans_amount')
                    }

                    res = requests.post('{}/api/create_mobile_request'.format(base_url), headers=headers, data=data)
                    content = json.loads(res.content.decode('utf-8'))
                    # res = self.create_mobile_request(**data)
                    _logger.info("@@@@@@@@@@@@@@@@@@@ Recharge Mobile Wallet Response: " + str(content))
                    if content.get('data'):
                        request_number = content.get('data').get('request_number') #json.loads(res.response[0].decode('utf-8')).get('request_number')
                        if not request_number:
                            return invalid_response("recharge_request_not created", _("wallet recharge request not cteated"), 400)
                        request_data.update({'request_number': request_number})
                        request.env.cr.commit()
                    else:
                        return invalid_response('Error: %s' % content.get('response'), _(content.get('message')), 400)
                    '''
                    request.httprequest.headers = {
                        'content-type': 'application/x-www-form-urlencoded',
                        'charset': 'utf-8',
                        'access_token': current_user_access_token,
                        'access_token': current_user_machine_serial
                    }
                    request.session.uid = current_user.id
                    request.uid = current_user.id
                    '''
                else:
                    return invalid_response("request_code_missing", _("missing request number in request data"), 400)
            user_request = request.env['smartpay_operations.request'].sudo().search(
                [('name', '=', request_data.get('request_number')), ('request_type', '=', "recharge_wallet")], limit=1)
            if user_request:
                if user_request.stage_id.id != 1:
                    return invalid_response("request_not_found",
                                            _("REQ Number (%s) invalid!") % (request_data.get('request_number')), 400)
                if request_data.get("wallet_id"):
                    partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(wallet_id=request_data.get("wallet_id"),
                                                                                           # service=user_request.product_id,
                                                                                           trans_amount=user_request.trans_amount,
                                                                                           allow_transfer_to=True)
                else:
                    partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(# service=user_request.product_id,
                                                                                           trans_amount=user_request.trans_amount,
                                                                                           allow_transfer_to=True)
                if not partner_wallet_id:
                    return invalid_response("wallet_not_found",
                                            _("No Matched Wallet found for partner [%s] %s") % (
                                                request.env.user.partner_id.ref,
                                                request.env.user.partner_id.name), 400)
                # Check minimum and maximum transfer amount
                min_transfer_amount = partner_wallet_id.type.min_transfer_amount
                max_transfer_amount = partner_wallet_id.type.max_transfer_amount
                if min_transfer_amount and user_request.trans_amount < min_transfer_amount:
                    return invalid_response("min_transfer_amount_exceeded",
                                            _("Minimum transfer amount (%s) exceeded!") % min_transfer_amount, 400)
                if max_transfer_amount and user_request.trans_amount > max_transfer_amount:
                    return invalid_response("max_transfer_amount_exceeded",
                                            _("Maximum transfer amount (%s) exceeded!") % max_transfer_amount, 400)
                if partner_wallet_id.type.allowed_transfer_ids:
                    allowed_type_ids = partner_wallet_id.type.allowed_transfer_ids.mapped('wallet_type_dest_id')
                    if all(wallet.type.id not in allowed_type_ids.ids for wallet in user_request.partner_id.wallet_ids):
                        return invalid_response("machine_allowed_transfer_not_matched",
                                                _("Machine Wallet does not allowed for transfer to Customer Wallet Types"), 400)
                unlink_wallet_reservation = False
                machine_wallet_reservation_id, machine_wallet_balance, machine_wallet_available_amount = \
                    partner_wallet_id.update_wallet_reserved_balance(
                        _('Transfer wallet balance to %s') % (user_request.partner_id.name), user_request.trans_amount,
                        user_request.currency_id, 'request', user_request
                    )
                # # machine_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                # machine_wallet_available_amount = partner_wallet_id.available_amount if partner_wallet_id else 0
                # if machine_wallet_available_amount < user_request.trans_amount:
                if not machine_wallet_reservation_id:
                    user_request.update({'stage_id': 3})
                    return invalid_response("machine_balance_not_enough",
                                            _("Machine Wallet Available Balance less than the request amount"), 400)

                # Transfer Balance from Machine Wallet to Mobile Wallet
                '''
                wallet_transaction_sudo = request.env['website.wallet.transaction'].sudo()
                label = _('Transfer wallet balance from %s') % (request.env.user.partner_id.name)
                partner_wallet_id = user_request.partner_id.get_transaction_wallet()
                partner_id_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                mobile_wallet_create = wallet_transaction_sudo.create(
                    {'wallet_type': 'credit', 'partner_id': user_request.partner_id.id, 'request_id': user_request.id,
                     'reference': 'request', 'label': label,
                     'amount': user_request.trans_amount, 'currency_id': user_request.currency_id.id,
                     'wallet_balance_before': partner_id_wallet_balance,
                     'wallet_balance_after': partner_id_wallet_balance + user_request.trans_amount,
                     'status': 'done'})
                request.env.cr.commit()

                user_request.partner_id.update(
                    {'wallet_balance': partner_id_wallet_balance
                    + user_request.trans_amount})
                request.env.cr.commit()

                # Notify Mobile User
                irc_param = request.env['ir.config_parameter'].sudo()
                wallet_transfer_balance_notify_mode = irc_param.get_param("smartpay_operations.wallet_transfer_balance_notify_mode")
                if wallet_transfer_balance_notify_mode == 'inbox':
                    request.env['mail.thread'].sudo().message_notify(
                        subject=label,
                        body=_('<p>%s %s successfully added to your wallet.</p>') % (
                            user_request.trans_amount, _(user_request.currency_id.name)),
                        partner_ids=[(4, user_request.partner_id.id)],
                    )
                elif wallet_transfer_balance_notify_mode == 'email':
                    mobile_wallet_create.wallet_transaction_email_send()
                elif wallet_transfer_balance_notify_mode == 'sms' and user_request.partner_id.mobile:
                    mobile_wallet_create.sms_send_wallet_transaction(wallet_transfer_balance_notify_mode,
                                                                     'wallet_transfer_balance',
                                                                     user_request.partner_id.mobile,
                                                                     user_request.partner_id.name, label,
                                                                     '%s %s' % (user_request.trans_amount,
                                                                                _(user_request.currency_id.name)),
                                                                     user_request.partner_id.country_id.phone_code or '2')
                '''
                machine_customer_receivable_account = request.env.user.partner_id.property_account_receivable_id
                user_wallet_id = None
                if request_data.get("wallet_dest_id"):
                    user_wallet_id = request.env['website.wallet'].sudo().search(
                        [('id', '=', request_data.get("wallet_dest_id")), ('active', '=', True),
                         ('partner_id', '=', user_request.partner_id.id)], limit=1)
                if partner_wallet_id.type.allowed_transfer_ids:
                    allowed_type_ids = partner_wallet_id.type.allowed_transfer_ids.mapped('wallet_type_dest_id')
                    mobile_wallet_id = user_wallet_id.filtered(lambda w: w.type.id in allowed_type_ids.ids) if user_wallet_id else user_request.partner_id.wallet_ids.filtered(lambda w: w.type.id in allowed_type_ids.ids)[0]
                else:
                    mobile_wallet_id = user_wallet_id or user_request.partner_id.get_transaction_wallet()
                if not mobile_wallet_id:
                    machine_wallet_reservation_id.sudo().unlink()
                    request.env.cr.commit()
                    return invalid_response("wallet_not_found",
                                            _("No Matched Wallet found for partner [%s] %s") % (
                                                user_request.partner_id.ref,
                                                user_request.partner_id.name), 400)
                mobile_wallet_create, wallet_balance_after = mobile_wallet_id.create_wallet_transaction(
                    'credit', user_request.partner_id, 'request',
                    _('Transfer wallet balance from %s') % (request.env.user.partner_id.name),
                    user_request.trans_amount, user_request.currency_id,  user_request,
                    'smartpay_operations.wallet_transfer_balance_notify_mode', 'wallet_transfer_balance',
                    _('<p>%s %s successfully added to your wallet.</p>') % (
                    user_request.trans_amount, _(user_request.currency_id.name)),
                    machine_customer_receivable_account, 'Transfer Wallet Balance', request.env.user.partner_id
                )
                # Check Customer Wallet Balance Maximum Balance
                if not mobile_wallet_create:
                    # user_request.sudo().write({'stage_id': 5})
                    machine_wallet_reservation_id.sudo().unlink()
                    request.env.cr.commit()
                    return invalid_response("wallet_max_balance_exceeded", _("Wallet [%s] maximum balance exceeded!") % partner_wallet_id.name, 400)

                '''
                label = _('Transfer wallet balance to %s') % (user_request.partner_id.name)
                if request_data.get("wallet_id"):
                    partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(wallet_id=request_data.get("wallet_id"),
                                                                                           # service=user_request.product_id,
                                                                                           trans_amount=user_request.trans_amount)
                else:
                    partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(# service=user_request.product_id,
                                                                                           trans_amount=user_request.trans_amount)
                partner_id_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                machine_wallet_create = wallet_transaction_sudo.create(
                    {'wallet_type': 'debit', 'partner_id': request.env.user.partner_id.id, 'request_id': user_request.id,
                     'reference': 'request', 'label': label,
                     'amount': user_request.trans_amount, 'currency_id': user_request.currency_id.id,
                     'wallet_balance_before': partner_id_wallet_balance,
                     'wallet_balance_after': partner_id_wallet_balance - user_request.trans_amount,
                     'status': 'done'})
                request.env.cr.commit()

                request.env.user.partner_id.update(
                    {'wallet_balance': partner_id_wallet_balance 
                    - user_request.trans_amount})
                request.env.cr.commit()
                user_request.sudo().write({'wallet_transaction_id': machine_wallet_create.id, 'stage_id': 5})
                request.env.cr.commit()

                # Notify customer
                if wallet_transfer_balance_notify_mode == 'inbox':
                    request.env['mail.thread'].sudo().message_notify(
                        subject=label,
                        body=_('<p>%s %s successfully deducted from your wallet.</p>') % (
                            user_request.trans_amount, _(user_request.currency_id.name)),
                        partner_ids=[(4, request.env.user.partner_id.id)],
                    )
                elif wallet_transfer_balance_notify_mode == 'email':
                    machine_wallet_create.wallet_transaction_email_send()
                elif wallet_transfer_balance_notify_mode == 'sms' and request.env.user.partner_id.mobile:
                    machine_wallet_create.sms_send_wallet_transaction(wallet_transfer_balance_notify_mode,
                                                                      'wallet_transfer_balance',
                                                                      request.env.user.partner_id.mobile,
                                                                      request.env.user.name, label,
                                                                      '%s %s' % (user_request.trans_amount,
                                                                                 _(user_request.currency_id.name)),
                                                                      request.env.user.partner_id.country_id.phone_code or '2')
                '''
                machine_wallet_create, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                    'debit', request.env.user.partner_id, 'request',
                    _('Transfer wallet balance to %s') % (user_request.partner_id.name),
                    user_request.trans_amount, user_request.currency_id, user_request,
                    'smartpay_operations.wallet_transfer_balance_notify_mode', 'wallet_transfer_balance',
                    _('<p>%s %s successfully deducted from your wallet.</p>') % (
                       user_request.trans_amount, _(user_request.currency_id.name))
                )
                user_request.sudo().write({'wallet_transaction_id': machine_wallet_create.id, 'stage_id': 5})
                machine_wallet_reservation_id.sudo().unlink()
                request.env.cr.commit()
                unlink_wallet_reservation = True

                '''
                # Create journal entry for transfer AR balance from machine customer to mobile user.
                machine_customer_receivable_account = request.env.user.partner_id.property_account_receivable_id
                mobile_user_receivable_account = user_request.partner_id.property_account_receivable_id
                account_move = request.env['account.move'].sudo().create({
                    'journal_id': request.env['account.journal'].sudo().search([('type', '=', 'general')], limit=1).id,
                })
                request.env['account.move.line'].with_context(check_move_validity=False).sudo().create({
                    'name': user_request.name + ': Transfer Wallet Balance',
                    'move_id': account_move.id,
                    'account_id': machine_customer_receivable_account.id,
                    'partner_id': request.env.user.partner_id.id,
                    'debit': user_request.trans_amount,
                })
                request.env['account.move.line'].with_context(check_move_validity=False).sudo().create({
                    'name': user_request.name + ': Transfer Wallet Balance',
                    'move_id': account_move.id,
                    'account_id': mobile_user_receivable_account.id,
                    'partner_id': user_request.partner_id.id,
                    'credit': user_request.trans_amount,
                })
                account_move.post()
                '''

                return valid_response(_(
                    "Wallet for User (%s) recharged successfully with amount %s %s. Your Machine Wallet Balance is %s %s") %
                                      (user_request.partner_id.name, user_request.trans_amount,
                                       user_request.currency_id.name,
                                       wallet_balance_after,
                                       user_request.currency_id.name))
            else:
                return invalid_response("request_not_found", _("REQ Number (%s) does not exist!") % (
                request_data.get('request_number')), 400)

        @validate_token
        @http.route('/api/pay_invoice', type="http", auth="none", methods=["POST"], csrf=False)
        def pay_invoice(self, **request_data):
            _logger.info("@@@@@@@@@@@@@@@@@@@ Calling Pay Invoice Request API")
            if not request_data.get('request_number'):
                return invalid_response("request_code_missing", _("missing request number in request data"), 400)
            customer_request = request.env['smartpay_operations.request'].sudo().search(
                [('name', '=', request_data.get('request_number')), ('request_type', '=', "pay_invoice")], limit=1)
            if customer_request:
                if customer_request.stage_id.id != 1:
                    return invalid_response("request_not_found",
                                            _("REQ Number (%s) invalid!") % (request_data.get('request_number')), 400)
                if request_data.get("wallet_id"):
                    partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(wallet_id=request_data.get("wallet_id"),
                                                                                           service=customer_request.product_id,
                                                                                           trans_amount=customer_request.trans_amount)
                else:
                    partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(service=customer_request.product_id,
                                                                                           trans_amount=customer_request.trans_amount)
                if not partner_wallet_id:
                    return invalid_response("wallet_not_found",
                                            _("No Matched Wallet found for partner [%s] %s") % (
                                                request.env.user.partner_id.ref,
                                                request.env.user.partner_id.name), 400)
                # Check minimum and maximum transfer amount
                min_transfer_amount = partner_wallet_id.type.min_transfer_amount
                max_transfer_amount = partner_wallet_id.type.max_transfer_amount
                if min_transfer_amount and customer_request.trans_amount < min_transfer_amount:
                    return invalid_response("min_transfer_amount_exceeded",
                                            _("Minimum transfer amount (%s) exceeded!") % min_transfer_amount, 400)
                if max_transfer_amount and customer_request.trans_amount > max_transfer_amount:
                    return invalid_response("max_transfer_amount_exceeded",
                                            _("Maximum transfer amount (%s) exceeded!") % max_transfer_amount, 400)
                unlink_wallet_reservation = False
                mobile_wallet_reservation_id, mobile_wallet_balance, mobile_wallet_available_amount = \
                    partner_wallet_id.update_wallet_reserved_balance(
                        _('Pay invoice to %s') % (customer_request.partner_id.name), customer_request.trans_amount,
                        customer_request.currency_id, 'request', customer_request
                    )
                # # mobile_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                # mobile_wallet_available_amount = partner_wallet_id.available_amount if partner_wallet_id else 0
                # if mobile_wallet_available_amount < customer_request.trans_amount:
                if not mobile_wallet_reservation_id:
                    return invalid_response("mobile_balance_not_enough",
                                            _("Mobile Wallet Available Balance less than the request amount"), 400)

                # Transfer Balance from Mobile Wallet to Machine Wallet
                '''
                wallet_transaction_sudo = request.env['website.wallet.transaction'].sudo()
                label = _('Collect invoice payment from %s') % (request.env.user.partner_id.name)
                partner_wallet_id = customer_request.partner_id.get_transaction_wallet()
                partner_id_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                machine_wallet_create = wallet_transaction_sudo.create(
                    {'wallet_type': 'credit', 'partner_id': customer_request.partner_id.id, 'request_id': customer_request.id,
                     'reference': 'request', 'label': label,
                     'amount': customer_request.trans_amount, 'currency_id': customer_request.currency_id.id,
                     'wallet_balance_before': partner_id_wallet_balance,
                     'wallet_balance_after': partner_id_wallet_balance + customer_request.trans_amount,
                     'status': 'done'})
                request.env.cr.commit()

                customer_request.partner_id.update(
                    {'wallet_balance': partner_id_wallet_balance 
                    + customer_request.trans_amount})
                request.env.cr.commit()

                # Notify Customer
                irc_param = request.env['ir.config_parameter'].sudo()
                wallet_pay_invoice_notify_mode = irc_param.get_param("smartpay_operations.wallet_pay_invoice_notify_mode")
                if wallet_pay_invoice_notify_mode == 'inbox':
                    request.env['mail.thread'].sudo().message_notify(
                        subject=label,
                        body=_('<p>%s %s successfully added to your wallet.</p>') % (
                            customer_request.trans_amount, _(customer_request.currency_id.name)),
                        partner_ids=[(4, customer_request.partner_id.id)],
                    )
                elif wallet_pay_invoice_notify_mode == 'email':
                    machine_wallet_create.wallet_transaction_email_send()
                elif wallet_pay_invoice_notify_mode == 'sms' and customer_request.partner_id.mobile:
                    machine_wallet_create.sms_send_wallet_transaction(wallet_pay_invoice_notify_mode,
                                                                      'wallet_pay_invoice',
                                                                      customer_request.partner_id.mobile,
                                                                      customer_request.partner_id.name, label,
                                                                      '%s %s' % (customer_request.trans_amount,
                                                                                 _(customer_request.currency_id.name)),
                                                                      customer_request.partner_id.country_id.phone_code or '2')
                '''
                mobile_user_receivable_account = request.env.user.partner_id.property_account_receivable_id
                customer_wallet_id = None
                if request_data.get("wallet_dest_id"):
                    customer_wallet_id = request.env['website.wallet'].sudo().search(
                        [('id', '=', request_data.get("wallet_dest_id")), ('active', '=', True),
                         ('partner_id', '=', customer_request.partner_id.id)], limit=1)
                '''
                if partner_wallet_id.type.allowed_transfer_ids:
                    allowed_type_ids = partner_wallet_id.type.allowed_transfer_ids.mapped('wallet_type_dest_id')
                    machine_wallet_id = customer_wallet_id.filtered(
                        lambda w: w.type.id in allowed_type_ids.ids) if customer_wallet_id else \
                        customer_request.partner_id.wallet_ids.filtered(lambda w: w.type.id in allowed_type_ids.ids)[0]
                else:
                    machine_wallet_id = customer_wallet_id or customer_request.partner_id.get_transaction_wallet()
                '''
                machine_wallet_id = customer_wallet_id or customer_request.partner_id.get_transaction_wallet()
                if not machine_wallet_id:
                    return invalid_response("wallet_not_found",
                                            _("No Matched Wallet found for partner [%s] %s") % (
                                                customer_request.partner_id.ref,
                                                customer_request.partner_id.name), 400)
                machine_wallet_create, wallet_balance_after = machine_wallet_id.create_wallet_transaction(
                    'credit', customer_request.partner_id.id, 'request',
                    _('Collect invoice payment from %s') % (request.env.user.partner_id.name),
                    customer_request.trans_amount, customer_request.currency_id, customer_request,
                    'smartpay_operations.wallet_pay_invoice_notify_mode', 'wallet_pay_invoice',
                    _('<p>%s %s successfully added to your wallet.</p>') % (
                        customer_request.trans_amount, _(customer_request.currency_id.name)),
                    mobile_user_receivable_account, 'Pay Invoice', request.env.user.partner_id
                )
                # Check Customer Wallet Balance Maximum Balance
                if not machine_wallet_create:
                    # user_request.sudo().write({'stage_id': 5})
                    mobile_wallet_reservation_id.sudo().unlink()
                    request.env.cr.commit()
                    return invalid_response("wallet_max_balance_exceeded", _("Wallet [%s] maximum balance exceeded!") % partner_wallet_id.name, 400)

                '''
                label = _('Pay invoice to %s') % (customer_request.partner_id.name)
                if request_data.get("wallet_id"):
                    partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(wallet_id=request_data.get("wallet_id"),
                                                                                           service=customer_request.product_id,
                                                                                           trans_amount=customer_request.trans_amount)
                else:
                    partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(service=customer_request.product_id,
                                                                                           trans_amount=customer_request.trans_amount)
                partner_id_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                mobile_wallet_create = wallet_transaction_sudo.create(
                    {'wallet_type': 'debit', 'partner_id': request.env.user.partner_id.id, 'request_id': customer_request.id,
                     'reference': 'request', 'label': label,
                     'amount': customer_request.trans_amount, 'currency_id': customer_request.currency_id.id,
                     'wallet_balance_before': partner_id_wallet_balance,
                     'wallet_balance_after': partner_id_wallet_balance - customer_request.trans_amount,
                     'status': 'done'})
                request.env.cr.commit()

                request.env.user.partner_id.update(
                    {'wallet_balance': partner_id_wallet_balance
                    - customer_request.trans_amount})
                request.env.cr.commit()
                customer_request.sudo().write({'wallet_transaction_id': mobile_wallet_create.id, 'stage_id': 5})
                request.env.cr.commit()

                # Notify User
                if wallet_pay_invoice_notify_mode == 'inbox':
                    request.env['mail.thread'].sudo().message_notify(
                        subject=label,
                        body=_('<p>%s %s successfully deducted from your wallet.</p>') % (
                            customer_request.trans_amount, _(customer_request.currency_id.name)),
                        partner_ids=[(4, request.env.user.partner_id.id)],
                    )
                elif wallet_pay_invoice_notify_mode == 'email':
                    mobile_wallet_create.wallet_transaction_email_send()
                elif wallet_pay_invoice_notify_mode == 'sms' and request.env.user.partner_id.mobile:
                    mobile_wallet_create.sms_send_wallet_transaction(wallet_pay_invoice_notify_mode,
                                                                      'wallet_pay_invoice',
                                                                      request.env.user.partner_id.mobile,
                                                                      request.env.user.name, label,
                                                                      '%s %s' % (customer_request.trans_amount,
                                                                                 _(customer_request.currency_id.name)),
                                                                      request.env.user.partner_id.country_id.phone_code or '2')
                '''
                mobile_wallet_create, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                    'debit', request.env.user.partner_id, 'request',
                    _('Pay invoice to %s') % (customer_request.partner_id.name),
                    customer_request.trans_amount, customer_request.currency_id, customer_request,
                    'smartpay_operations.wallet_pay_invoice_notify_mode', 'wallet_pay_invoice',
                    _('<p>%s %s successfully deducted from your wallet.</p>') % (
                        customer_request.trans_amount, _(customer_request.currency_id.name))
                )
                customer_request.sudo().write({'wallet_transaction_id': mobile_wallet_create.id, 'stage_id': 5})
                mobile_wallet_reservation_id.sudo().unlink()
                request.env.cr.commit()
                unlink_wallet_reservation = True

                '''
                # Create journal entry for transfer AR balance from mobile user to machine customer.
                mobile_user_receivable_account = request.env.user.partner_id.property_account_receivable_id
                machine_customer_receivable_account = customer_request.partner_id.property_account_receivable_id
                account_move = request.env['account.move'].sudo().create({
                    'journal_id': request.env['account.journal'].sudo().search([('type', '=', 'general')], limit=1).id,
                })
                request.env['account.move.line'].with_context(check_move_validity=False).sudo().create({
                    'name': customer_request.name + ': Pay Invoice',
                    'move_id': account_move.id,
                    'account_id': mobile_user_receivable_account.id,
                    'partner_id': request.env.user.partner_id.id,
                    'debit': customer_request.trans_amount,
                })
                request.env['account.move.line'].with_context(check_move_validity=False).sudo().create({
                    'name': customer_request.name + ': Pay Invoice',
                    'move_id': account_move.id,
                    'account_id': machine_customer_receivable_account.id,
                    'partner_id': customer_request.partner_id.id,
                    'credit': customer_request.trans_amount,
                })
                account_move.post()
                '''

                return valid_response(_(
                    "Invoice request (%s) paid successfully with amount %s %s. Your Mobile Wallet Balance is %s %s") %
                                      (customer_request.name, customer_request.trans_amount,
                                       customer_request.currency_id.name,
                                       wallet_balance_after,
                                       customer_request.currency_id.name))
            else:
                return invalid_response("request_not_found", _("REQ Number (%s) does not exist!") % (
                    request_data.get('request_number')), 400)

        ###############################################
        ######### Fawry Integration Requests ##########
        ###############################################
        @validate_token
        @http.route('/api/get_sevice_categories', type="http", auth="none", methods=["POST"], csrf=False)
        def get_sevice_categories(self, **payload):
            _logger.info("@@@@@@@@@@@@@@@@@@@ Calling Get Sevice Category API")
            domain, fields, offset, limit, order = extract_arguments(payload)
            domain += [("parent_id", "=", request.env.ref("tm_base_gateway.product_category_services").id), ("product_count", "!=", 0)]
            # if not any(item[0] == 'tag_ids' for item in domain):
            for item in domain:
                if item[0] == 'tag_ids':
                    domain.pop(domain.index(item))
                    break
            user = request.env['res.users'].sudo().search([('id', '=', request.env.user.id)], limit=1)
            if user.allowed_product_tag_ids:
                domain += [('tag_ids', 'in', user.allowed_product_tag_ids.ids)]
            else:
                domain += [('tag_ids', 'in', (0))]

            lang = payload.get("lang", "en_US")
            ir_translation_sudo = request.env['ir.translation'].sudo()
            product_category_sudo = request.env['product.category'].sudo()
            '''
            service_categories = product_category_sudo.search_read(domain=domain,
                                                                     fields=fields,
                                                                     offset=offset,
                                                                     limit=limit,
                                                                     order=order,
                                                                     )
            '''
            service_categories = product_category_sudo.search(domain, offset=offset, limit=limit, order=order)
            categories = []
            if service_categories:
                for service_category in service_categories:
                    category = {
                        "id": service_category.id,
                        # "image": service_category.image_medium and service_category.image_medium.decode('ascii') or False,
                        # "name": service_category.name
                    }

                    if service_category.image_medium:
                        category.update({"image": "/web/image?model=%s&field=image_medium&id=%s" % ("product.category", service_category.id)})

                    '''
                    ir_translation_ids = ir_translation_sudo.search_read(
                        domain=[("name", "=", "product.category,name"), ("res_id", "=", service_category.id)],
                        fields=["lang", "source", "value"], order="res_id")
                    if ir_translation_ids:
                        category_trans = []
                        for ir_translation in ir_translation_ids:
                            category_trans.append({
                                "lang": ir_translation["lang"],
                                "name": ir_translation["value"]
                            })
                        category.update({"name_translate": category_trans})
                    '''

                    if lang == "en_US":
                        category.update({"name": service_category.name})
                    else:
                        ir_translation_id = ir_translation_sudo.search(
                            [("name", "=", "product.category,name"), ("res_id", "=", service_category.id), ("lang", "=", lang)],
                            limit=1)
                        if ir_translation_id:
                            category.update({"name": ir_translation_id.value})

                    categories.append(category)

            return valid_response(categories)
            # return invalid_response("service_categories_not_found",  _("Could not get Service Categories"), 400)

        @validate_token
        @http.route('/api/get_sevice_billers', type="http", auth="none", methods=["POST"], csrf=False)
        def get_sevice_billers(self, **payload):
            _logger.info("@@@@@@@@@@@@@@@@@@@ Calling Get Sevice Biller API")
            domain, fields, offset, limit, order = extract_arguments(payload)
            domain += [("product_count", "!=", 0)]
            # if not any(item[0] == 'tag_ids' for item in domain):
            for item in domain:
                if item[0] == 'tag_ids':
                    domain.pop(domain.index(item))
                    break
            user = request.env['res.users'].sudo().search([('id', '=', request.env.user.id)], limit=1)
            if user.allowed_product_tag_ids:
                domain += [('tag_ids', 'in', user.allowed_product_tag_ids.ids)]
            else:
                domain += [('tag_ids', 'in', (0))]

            lang = payload.get("lang", "en_US")
            ir_translation_sudo = request.env['ir.translation'].sudo()
            product_category_sudo = request.env['product.category'].sudo()
            '''
            service_billers = product_category_sudo.search_read(domain=domain,
                                                                     fields=fields,
                                                                     offset=offset,
                                                                     limit=limit,
                                                                     order=order,
                                                                     )
            '''
            service_billers = product_category_sudo.search(domain, offset=offset, limit=limit, order=order)
            billers = []
            if service_billers:
                for service_biller in service_billers:
                    biller = {
                        "id": service_biller.id,
                        "categ_id": service_biller.parent_id.id,
                        "categ_name": service_biller.parent_id.name,
                        # "image": service_biller.image_medium and service_biller.image_medium.decode('ascii') or False,
                        # "name": service_biller.name
                    }

                    if service_biller.image_medium:
                        biller.update({"image": "/web/image?model=%s&field=image_medium&id=%s" % ("product.category", service_biller.id)})

                    '''
                    ir_translation_ids = ir_translation_sudo.search_read(
                        domain=[("name", "=", "product.category,name"), ("res_id", "=", service_biller.id)],
                        fields=["lang", "source", "value"], order="res_id")
                    if ir_translation_ids:
                        biller_trans = []
                        for ir_translation in ir_translation_ids:
                            biller_trans.append({
                                "lang": ir_translation["lang"],
                                "name": ir_translation["value"]
                            })
                        biller.update({"name_translate": biller_trans})
                    '''

                    if lang == "en_US":
                        biller.update({"name": service_biller.name})
                    else:
                        ir_translation_id = ir_translation_sudo.search(
                            [("name", "=", "product.category,name"), ("res_id", "=", service_biller.id), ("lang", "=", lang)],
                            limit=1)
                        if ir_translation_id:
                            biller.update({"name": ir_translation_id.value})

                    billers.append(biller)

            return valid_response(billers)
            # return invalid_response("service_billers_not_found", _("Could not get Service Billers"), 400)

        @validate_token
        @http.route('/api/get_sevices', type="http", auth="none", methods=["POST"], csrf=False)
        def get_sevices(self, **payload):
            _logger.info("@@@@@@@@@@@@@@@@@@@ Calling Get Sevices API")
            domain, fields, offset, limit, order = extract_arguments(payload)
            # if not any(item[0] == 'tag_ids' for item in domain):
            for item in domain:
                if item[0] == 'tag_ids':
                    domain.pop(domain.index(item))
                    break
            user = request.env['res.users'].sudo().search([('id', '=', request.env.user.id)], limit=1)
            if user.allowed_product_tag_ids:
                domain += [('tag_ids', 'in', user.allowed_product_tag_ids.ids)]
            else:
                domain += [('tag_ids', 'in', (0))]

            lang = payload.get("lang", "en_US")
            biller_info_sudo = request.env['product.supplierinfo'].sudo()
            ir_translation_sudo = request.env['ir.translation'].sudo()
            product_template_sudo = request.env['product.template'].sudo()
            '''
            service_ids = product_template_sudo.search_read(domain=domain,
                                                                     fields=fields,
                                                                     offset=offset,
                                                                     limit=limit,
                                                                     order=order,
                                                                     )
            '''
            service_ids = product_template_sudo.search(domain, offset=offset, limit=limit, order=order)
            services = []
            if service_ids:
                for service_id in service_ids:
                    service = {
                        "id": service_id.product_variant_id.id,
                        "categ_id": service_id.categ_id.id,
                        "categ_name": service_id.categ_id.name,
                        # "image": service_id.image_medium and service_id.image_medium.decode('ascii') or False,
                        # "name": service_id.name
                    }

                    if service_id.image_medium:
                        service.update({"image": "/web/image?model=%s&field=image_medium&id=%s" % ("product.template", service_id.id)})

                    '''
                    ir_translation_ids = ir_translation_sudo.search_read(
                        domain=[("name", "=", "product.template,name"), ("res_id", "=", service_id.id)],
                        fields=["lang", "source", "value"], order="res_id")
                    if ir_translation_ids:
                        service_trans = []
                        for ir_translation in ir_translation_ids:
                            service_trans.append({
                                "lang": ir_translation["lang"],
                                "name": ir_translation["value"]
                            })
                        service.update({"name_translate": service_trans})
                    '''

                    biller_info_id = biller_info_sudo.search(
                        [("product_tmpl_id.type", "=", "service"),
                                ("product_tmpl_id.id", "=", service_id.id)],
                        limit=1)

                    if lang == "en_US":
                        service.update({"name": service_id.name})

                        if biller_info_id:
                            biller_info_dict = json.loads(biller_info_id.biller_info.replace("'", '"').replace('True', 'true').replace('False', 'false'), strict=False)
                            if biller_info_dict.get('ServiceTypeLogo'):
                                biller_info_dict.pop('ServiceTypeLogo')
                            if biller_info_dict.get('BillTypeLogo'):
                                biller_info_dict.pop('BillTypeLogo')
                            service.update({"biller_info": json.dumps(biller_info_dict, default=default)})
                    else:
                        ir_translation_id = ir_translation_sudo.search(
                            [("name", "=", "product.template,name"), ("res_id", "=", service_id.id),
                                    ("lang", "=", lang)],
                            limit=1)
                        if ir_translation_id:
                            service.update({"name": ir_translation_id.value})

                        ir_translation_id = ir_translation_sudo.search(
                            [("name", "=", "product.supplierinfo,biller_info"), ("res_id", "=", biller_info_id.id),
                                    ("lang", "=", lang)],
                            limit=1)
                        if ir_translation_id:
                            biller_info_dict = json.loads(ir_translation_id.value.replace("'", '"').replace('True', 'true').replace('False', 'false'), strict=False)
                            if biller_info_dict.get('ServiceTypeLogo'):
                                biller_info_dict.pop('ServiceTypeLogo')
                            if biller_info_dict.get('BillTypeLogo'):
                                biller_info_dict.pop('BillTypeLogo')
                            service.update({"biller_info": json.dumps(biller_info_dict, default=default)})

                    services.append(service)

            return valid_response(services)
            # return invalid_response("services_not_found", _("Could not get Services"), 400)

        @validate_token
        @http.route('/api/get_all_sevices', type="http", auth="none", methods=["POST"], csrf=False)
        def get_all_sevices(self, **payload):
            _logger.info("@@@@@@@@@@@@@@@@@@@ Calling Get All Sevices API")
            domain, fields, offset, limit, order = extract_arguments(payload)
            domain += [("parent_id", "=", request.env.ref("tm_base_gateway.product_category_services").id),
                       ("product_count", "!=", 0)]
            # if not any(item[0] == 'tag_ids' for item in domain):
            for item in domain:
                if item[0] == 'tag_ids':
                    domain.pop(domain.index(item))
                    break
            user = request.env['res.users'].sudo().search([('id', '=', request.env.user.id)], limit=1)
            if user.allowed_product_tag_ids:
                domain += [('tag_ids', 'in', user.allowed_product_tag_ids.ids)]
            else:
                domain += [('tag_ids', 'in', (0))]

            lang = payload.get("lang", "en_US")
            ir_translation_sudo = request.env['ir.translation'].sudo()
            product_category_sudo = request.env['product.category'].sudo()

            service_categories = product_category_sudo.search(domain, offset=offset, limit=limit, order=order)
            categories = []
            for service_category in service_categories:
                category = {
                    "id": service_category.id
                }

                if service_category.image_medium:
                    category.update({"image": "/web/image?model=%s&field=image_medium&id=%s" % ("product.category", service_category.id)})

                if lang == "en_US":
                    category.update({"name": service_category.name})
                else:
                    ir_translation_id = ir_translation_sudo.search(
                        [("name", "=", "product.category,name"), ("res_id", "=", service_category.id),
                         ("lang", "=", lang)],
                        limit=1)
                    if ir_translation_id:
                        category.update({"name": ir_translation_id.value})

                # Get billers
                _logger.info("@@@@@@@@@@@@@@@@@@@ Get Billers")
                domain, fields, offset, limit, order = extract_arguments(payload)
                domain += [("parent_id.id", "=", service_category.id), ("product_count", "!=", 0)]

                service_billers = product_category_sudo.search(domain, offset=offset, limit=limit, order=order)
                billers = []
                for service_biller in service_billers:
                    biller = {
                        "id": service_biller.id,
                        "categ_id": service_biller.parent_id.id,
                        "categ_name": service_biller.parent_id.name
                    }

                    if service_biller.image_medium:
                        biller.update({"image": "/web/image?model=%s&field=image_medium&id=%s" % ("product.category", service_biller.id)})

                    if lang == "en_US":
                        biller.update({"name": service_biller.name})
                    else:
                        ir_translation_id = ir_translation_sudo.search(
                            [("name", "=", "product.category,name"), ("res_id", "=", service_biller.id),
                             ("lang", "=", lang)],
                            limit=1)
                        if ir_translation_id:
                            biller.update({"name": ir_translation_id.value})

                    # Get Services
                    _logger.info("@@@@@@@@@@@@@@@@@@@ Get Sevices")
                    domain, fields, offset, limit, order = extract_arguments(payload)
                    domain += [("type", "=", "service"), ("categ_id.id", "=", service_biller.id)]

                    biller_info_sudo = request.env['product.supplierinfo'].sudo()
                    product_template_sudo = request.env['product.template'].sudo()

                    service_ids = product_template_sudo.search(domain, offset=offset, limit=limit, order=order)
                    services = []
                    for service_id in service_ids:
                        service = {
                            "id": service_id.product_variant_id.id,
                            "categ_id": service_id.categ_id.id,
                            "categ_name": service_id.categ_id.name
                        }

                        if service_id.image_medium:
                            service.update({"image": "/web/image?model=%s&field=image_medium&id=%s" % (
                            "product.template", service_id.id)})

                        biller_info_id = biller_info_sudo.search(
                            [("product_tmpl_id.type", "=", "service"),
                             ("product_tmpl_id.id", "=", service_id.id)],
                            limit=1)

                        if lang == "en_US":
                            service.update({"name": service_id.name})

                            if biller_info_id:
                                biller_info_dict = json.loads(biller_info_id.biller_info.replace("'", '"').replace('True', 'true').replace('False', 'false'), strict=False)
                                if biller_info_dict.get('ServiceTypeLogo'):
                                    biller_info_dict.pop('ServiceTypeLogo')
                                if biller_info_dict.get('BillTypeLogo'):
                                    biller_info_dict.pop('BillTypeLogo')
                                service.update({"biller_info": json.dumps(biller_info_dict, default=default)})
                        else:
                            ir_translation_id = ir_translation_sudo.search(
                                [("name", "=", "product.template,name"), ("res_id", "=", service_id.id),
                                 ("lang", "=", lang)],
                                limit=1)
                            if ir_translation_id:
                                service.update({"name": ir_translation_id.value})

                            ir_translation_id = ir_translation_sudo.search(
                                [("name", "=", "product.supplierinfo,biller_info"),
                                 ("res_id", "=", biller_info_id.id),
                                 ("lang", "=", lang)],
                                limit=1)
                            if ir_translation_id:
                                biller_info_dict = json.loads(ir_translation_id.value.replace("'", '"').replace('True', 'true').replace('False', 'false'), strict=False)
                                if biller_info_dict.get('ServiceTypeLogo'):
                                    biller_info_dict.pop('ServiceTypeLogo')
                                if biller_info_dict.get('BillTypeLogo'):
                                    biller_info_dict.pop('BillTypeLogo')
                                service.update({"biller_info": json.dumps(biller_info_dict, default=default)})

                        services.append(service)

                    biller.update({"services": services})
                    billers.append(biller)

                category.update({"billers": billers})
                categories.append(category)

            return valid_response(categories)
            # return invalid_response("service_categories_not_found",  _("Could not get Service Categories"), 400)

    class RequestApi(http.Controller):

        @validate_token
        @validate_machine
        @http.route('/api/createMachineRequest', type="http", auth="none", methods=["POST"], csrf=False)
        def createMachineRequest(self, **request_data):
            _logger.info(">>>>>>>>>>>>>>>>>>>> Calling Machine Request API")

            if not request_data.get('request_type') or request_data.get('request_type') not in _REQUEST_TYPES_IDS:
                return invalid_response("request_type", _("request type invalid"), 400)

            if request_data.get('request_type') == 'recharge_wallet':
                if not request_data.get('trans_number'):
                    return invalid_response("receipt_number_not_found", _("missing deposit receipt number in request data"), 400)
                if not request_data.get('trans_date'):
                    return invalid_response("date_not_found", _("missing deposit date in request data"), 400)
                if not request_data.get('trans_amount'):
                    return invalid_response("amount_not_found", _("missing deposit amount in request data"), 400)
                if not any(hasattr(field_value, 'filename') for field_name, field_value in request_data.items()):
                    return invalid_response("receipt_not_found", _("missing deposit receipt attachment in request data"), 400)

                open_request = request.env["smartpay_operations.request"].sudo().search(
                    [('request_type', '=', 'recharge_wallet'), ("partner_id", "=", request.env.user.partner_id.id),
                     ("stage_id", "=", 1)], order="id DESC", limit=1)
                if open_request:
                    open_request_in_minute = open_request.filtered(
                        lambda r: r.create_date >= date_time.now() - timedelta(minutes=1))
                    if open_request_in_minute:
                        return invalid_response("request_already_exist",
                                                _("You have a wallet recharge request in progress with REQ Number (%s)")
                                                % (open_request_in_minute.name), 400)
                    else:
                        open_request.update({'stage_id': 3})

                request_data['product_id'] = request.env["product.product"].sudo().search([('name', '=', 'Wallet Recharge')]).id

            if not request_data.get('product_id') and (
                    request_data.get('request_type') in ('recharge_wallet', 'service_bill_inquiry') or
                    (request_data.get('request_type') == 'pay_service_bill' and not request_data.get('inquiry_request_number'))
            ):
                return invalid_response("service_not_found", _("missing service in request data"), 400)
            elif request_data.get('request_type') in ('recharge_wallet', 'service_bill_inquiry', 'pay_service_bill'):
                product_id = request_data.get('product_id')
                inquiry_request_number = request_data.get('inquiry_request_number')
                if not product_id and inquiry_request_number:
                    inquiry_request = request.env["smartpay_operations.request"].sudo().search(
                        [('name', '=', inquiry_request_number)], limit=1)
                    if inquiry_request:
                        product_id = inquiry_request.product_id.id
                    else:
                        return invalid_response("inquiry_request_not_found", _("Inquiry Request does not exist!"), 400)
                service = request.env["product.product"].sudo().search([("id", "=", product_id), ("type", "=", "service")],
                                                                       order="id DESC", limit=1)
                if not service:
                    return invalid_response("service", _("service invalid"), 400)

            if request_data.get('request_type') == 'wallet_invitation':
                if not request_data.get('mobile_number'):
                    return invalid_response("mobile_number_not_found", _("missing mobile number for invited user in request data"), 400)

                open_request = request.env["smartpay_operations.request"].sudo().search(
                    [('request_type', '=', 'wallet_invitation'), ('mobile_number', '=', request_data.get('mobile_number')),
                     ('partner_id', '=', request.env.user.partner_id.id), ("stage_id", "=", 1)], order="id DESC", limit=1)
                if open_request:
                    return invalid_response("request_already_exist",
                                            _("You have a wallet invitation request in progress for mobile number (%s) with REQ Number (%s)") % (
                                                request_data.get('mobile_number'), open_request.name), 400)

                done_request = request.env["smartpay_operations.request"].sudo().search(
                    [('request_type', '=', 'wallet_invitation'),
                     ('mobile_number', '=', request_data.get('mobile_number')), ("stage_id", "=", 5)],
                    order="id DESC", limit=1)
                if done_request:
                    return invalid_response("request_already_exist",
                                            _("The mobile number (%s) already has a wallet") % (
                                                request_data.get('mobile_number')), 400)

            if request_data.get('request_type') == 'pay_invoice':
                if not request_data.get('trans_amount'):
                    return invalid_response("amount_not_found", _("missing invoice amount in request data"), 400)

            provider_provider = request_data.get('provider')
            if request_data.get('request_type') == 'service_bill_inquiry':
                if not request_data.get('billingAcct'):
                    return invalid_response("billingAcct_not_found", _("missing billing account in request data"), 400)
                # TODO: extraBillingAcctKeys required with condition
                # if not request_data.get('extraBillingAcctKeys'):
                    # return invalid_response("extraBillingAcctKeys_not_found", _("missing extra billing account keys in request data"), 400)

            if request_data.get('request_type') == 'pay_service_bill':
                # Common: provider billRefNumber trans_amount pmtType currency_id pmtMethod
                # Fawry: extraBillingAcctKeys notifyMobile
                # Khales: ePayBillRecID '''payAmts''' feesAmt pmtRefInfo
                if inquiry_request_number:
                    billingAcct = inquiry_request.billing_acct
                    ePayBillRecID = inquiry_request.e_pay_bill_rec_id
                    trans_amount = inquiry_request.trans_amount
                else:
                    lang = request_data.get('lang')
                    billingAcct = request_data.get('billingAcct') #

                    extraBillingAcctKeys = request_data.get('extraBillingAcctKeys')
                    if extraBillingAcctKeys:
                        extraBillingAcctKeys = ast.literal_eval(extraBillingAcctKeys)

                    notifyMobile = request_data.get('notifyMobile')
                    billRefNumber = request_data.get('billRefNumber')
                    billerId = request_data.get('billerId')
                    pmtType = request_data.get('pmtType')

                    trans_amount = request_data.get('trans_amount') #
                    curCode = request_data.get('currency_id')
                    payAmts = request_data.get('payAmts')
                    if payAmts:
                        payAmts = ast.literal_eval(payAmts)
                    else:
                        payAmts = [{'Sequence': '1', 'AmtDue': trans_amount, 'CurCode': curCode}]
                    pmtMethod = request_data.get('pmtMethod')

                    ePayBillRecID = request_data.get('ePayBillRecID') #
                    pmtId = request_data.get('pmtId')
                    feesAmt = request_data.get('feesAmt') or 0.00
                    feesAmts = request_data.get('feesAmts')
                    if feesAmts:
                        feesAmts = ast.literal_eval(feesAmts)
                    else:
                        feesAmts = [{'Amt': feesAmt, 'CurCode': curCode}]
                    pmtRefInfo = request_data.get('pmtRefInfo')

                if not billingAcct:
                    return invalid_response("billingAcct_not_found", _("missing billing account in request data"), 400)

                if provider_provider == 'khales':
                    '''
                    if not request_data.get('billerId'):
                        return invalid_response("billerId_not_found", _("missing biller id in request data"), 400)
                    '''
                    if not ePayBillRecID:
                        return invalid_response("ePayBillRecID_not_found", _("missing ePay Bill Rec ID in request data"), 400)
                    # if not request_data.get('pmtId'):
                        # return invalid_response("pmtId_not_found", _("missing payment id in request data"), 400)
                    if not request_data.get('feesAmt'):
                        return invalid_response("feesAmt_not_found", _("missing fees amount in request data"), 400)
                    # if not request_data.get('pmtRefInfo'):
                        # return invalid_response("pmtRefInfo_not_found", _("missing payment Ref Info in request data"), 400)
                    payAmtTemp = float(request_data.get('trans_amount'))
                    payAmts = request_data.get('payAmts')
                    if payAmts:
                        payAmts = ast.literal_eval(payAmts)
                        for payAmt in payAmts:
                            payAmtTemp -= float(payAmt.get('AmtDue'))
                        if payAmtTemp != 0:
                            return invalid_response("payAmts_not_match",
                                                    _("The sum of payAmts must be equals trans_amount"), 400)
                    feesAmtTemp = request_data.get('feesAmt') or 0.00
                    feesAmts = request_data.get('feesAmts')
                    if feesAmts:
                        feesAmts = ast.literal_eval(feesAmts)
                        for feeAmt in feesAmts:
                            feesAmtTemp -= float(feeAmt.get('Amt'))
                        if feesAmtTemp != 0:
                            return invalid_response("feesAmts_not_match",
                                                    _("The sum of feesAmts must be equals feesAmt"), 400)

                if ((provider_provider == 'fawry' and request_data.get('pmtType') == "POST") or provider_provider == 'khales') \
                        and not request_data.get('billRefNumber'):
                    return invalid_response("billRefNumber_not_found", _("missing bill reference number in request data"), 400)

                # Provider is mandatory because the service fee is different per provider.
                # So the user must send provider that own the bill inquiry request for prevent pay bill
                # with total amount different of total amount in bill inquiry
                if provider_provider:
                    provider = request.env['payment.acquirer'].sudo().search([("provider", "=", provider_provider)])
                    # if provider: # Tamayoz Note: Comment this condition for solving service_providerinfo assign before initilizing
                    service_providerinfo = request.env['product.supplierinfo'].sudo().search([
                        ('product_tmpl_id', '=', service.product_tmpl_id.id),
                        ('name', '=', provider.related_partner.id)
                    ])
                    if not service_providerinfo:
                        return invalid_response(
                            "Incompatible_provider_service", _("%s is not a provider for (%s) service") % (
                                provider_provider, service.name or '-'), 400)
                    elif provider_provider in ('fawry', 'masary'):
                        inquiryTransactionId = request_data.get('inquiryTransactionId')
                        if (json.loads(service_providerinfo.biller_info, strict=False).get('inquiry_required')  # Tamayoz TODO: Rename inquiry_required in standard API
                            # or json.loads(service_providerinfo.biller_info, strict=False).get('SupportPmtReverse')
                        ) \
                                and not inquiryTransactionId:
                            return invalid_response("inquiryTransactionId_not_found",
                                                    _("missing inquiry transaction id in request data"), 400)
                else:
                    return invalid_response("provider_not_found",
                                            _("missing provider in request data"), 400)

                trans_amount = float(request_data.get('trans_amount'))
                if not trans_amount:
                    return invalid_response("amount_not_found",
                                            _("missing bill amount in request data"), 400)
                else:
                    # Calculate Fees
                    provider_fees_calculated_amount = 0.0
                    provider_fees_actual_amount = 0.0
                    merchant_cashback_amount = 0.0
                    customer_cashback_amount = 0.0
                    extra_fees_amount = 0.0
                    commissions = request.env['product.supplierinfo.commission'].sudo().search_read(
                        domain=[('vendor', '=', service_providerinfo.name.id),
                                ('vendor_product_code', '=', service_providerinfo.product_code)],
                        fields=['Amount_Range_From', 'Amount_Range_To',
                                'Extra_Fee_Amt', 'Extra_Fee_Prc',
                                'Mer_Fee_Amt', 'Mer_Fee_Prc', 'Mer_Fee_Prc_MinAmt', 'Mer_Fee_Prc_MaxAmt',
                                'Mer_Comm_Full_Fix_Amt', 'Cust_Comm_Full_Fix_Amt',
                                'Bill_Merchant_Comm_Prc', 'Bill_Customer_Comm_Prc']
                    )
                    for commission in commissions:
                        if commission['Amount_Range_From'] <= trans_amount \
                                and commission['Amount_Range_To'] >= trans_amount:
                            if commission['Mer_Comm_Full_Fix_Amt'] > 0:
                                merchant_cashback_amount = commission['Mer_Comm_Full_Fix_Amt']
                                customer_cashback_amount = commission['Cust_Comm_Full_Fix_Amt']
                            elif commission['Bill_Merchant_Comm_Prc'] > 0:
                                merchant_cashback_amount = trans_amount * commission[
                                    'Bill_Merchant_Comm_Prc'] / 100
                                customer_cashback_amount = trans_amount * commission[
                                    'Bill_Customer_Comm_Prc'] / 100
                            if commission['Extra_Fee_Amt'] > 0:
                                extra_fees_amount = commission['Extra_Fee_Amt']
                            elif commission['Extra_Fee_Prc'] > 0:
                                extra_fees_amount = trans_amount * commission['Extra_Fee_Prc'] / 100
                            if commission['Mer_Fee_Amt'] > 0:
                                provider_fees_calculated_amount = commission['Mer_Fee_Amt']
                            elif commission['Mer_Fee_Prc'] > 0:
                                # Fees amount = FA + [Percentage * Payment Amount]
                                # Fees amount ====================> provider_fees_calculated_amount
                                # FA =============================> provider_fees_calculated_amount
                                # [Percentage * Payment Amount] ==> provider_fees_prc_calculated_amount
                                provider_fees_prc_calculated_amount = trans_amount * commission[
                                    'Mer_Fee_Prc'] / 100
                                if provider_fees_prc_calculated_amount < commission['Mer_Fee_Prc_MinAmt']:
                                    provider_fees_prc_calculated_amount = commission['Mer_Fee_Prc_MinAmt']
                                elif provider_fees_prc_calculated_amount > commission['Mer_Fee_Prc_MaxAmt'] \
                                        and commission['Mer_Fee_Prc_MaxAmt'] > 0:
                                    provider_fees_prc_calculated_amount = commission['Mer_Fee_Prc_MaxAmt']
                                provider_fees_calculated_amount += provider_fees_prc_calculated_amount
                            elif provider_provider == 'khales':
                                provider_fees_calculated_amount = float(request_data.get('feesAmt'))
                            break
                    calculated_payment_amount = trans_amount + provider_fees_calculated_amount + extra_fees_amount
                    if not json.loads(service_providerinfo.biller_info, strict=False).get(
                            'CorrBillTypeCode') or json.loads(service_providerinfo.biller_info, strict=False).get(
                            'Type') == 'CASHININT':
                        if service.has_sale_limit:
                            limit_fees_amounts = {}
                            for sale_limit_id in service.sale_limit_ids:
                                limit_type = sale_limit_id.limit_type
                                limit_amount = sale_limit_id.limit_amount
                                partner_sale_limit_id = request.env['res.partner.product.sale.limit'].sudo().search(
                                    [('partner_id', '=', request.env.user.partner_id.id),
                                     ('product_tmpl_id', '=', service.product_tmpl_id.id),
                                     ('limit_type', '=', limit_type)], limit=1)
                                if partner_sale_limit_id:
                                    limit_amount = partner_sale_limit_id.limit_amount
                                timetuple = date_time.now().timetuple()
                                sale_limit_domain = [('partner_id', '=', request.env.user.partner_id.id),
                                                     ('product_id', '=', service.id),
                                                     ('limit_type', '=', limit_type),
                                                     ('year', '=', timetuple.tm_year)]
                                if limit_type == 'daily':
                                    sale_limit_domain += [('day', '=', timetuple.tm_yday)]
                                elif limit_type == 'weekly':
                                    sale_limit_domain += [('week', '=', date_time.now().isocalendar()[1])]
                                elif limit_type == 'monthly':
                                    sale_limit_domain += [('month', '=', timetuple.tm_mon)]
                                sale_limit = request.env['res.partner.sale.limit'].sudo().search(sale_limit_domain,
                                                                                                 order="id DESC",
                                                                                                 limit=1)
                                calculated_sold_amount = calculated_payment_amount
                                if sale_limit:
                                    calculated_sold_amount += sale_limit.sold_amount
                                if limit_amount < calculated_sold_amount:
                                    over_limit_fees_ids = []
                                    if partner_sale_limit_id:
                                        if partner_sale_limit_id.over_limit_fees_policy == 'product_over_limit_fees' and partner_sale_limit_id.product_over_limit_fees_ids:
                                            over_limit_fees_ids = partner_sale_limit_id.product_over_limit_fees_ids
                                            limit_amount = over_limit_fees_ids.sorted(lambda l: l.sale_amount_to, reverse=True)[0].sale_amount_to + partner_sale_limit_id.limit_amount
                                        if partner_sale_limit_id.over_limit_fees_policy == 'custom_over_limit_fees' and partner_sale_limit_id.over_limit_fees_ids:
                                            over_limit_fees_ids = partner_sale_limit_id.over_limit_fees_ids
                                            limit_amount = over_limit_fees_ids.sorted(lambda l: l.sale_amount_to, reverse=True)[0].sale_amount_to + partner_sale_limit_id.limit_amount
                                    else:
                                        if sale_limit_id.has_over_limit_fees and sale_limit_id.over_limit_fees_ids:
                                            over_limit_fees_ids = sale_limit_id.over_limit_fees_ids
                                            limit_amount = over_limit_fees_ids.sorted(lambda l: l.sale_amount_to, reverse=True)[0].sale_amount_to + sale_limit_id.limit_amount

                                    if limit_amount < calculated_sold_amount:
                                        return invalid_response("%s_limit_exceeded" % limit_type,
                                                                _("%s limit exceeded for service (%s)") % (
                                                                    limit_type, service.name), 400)

                                    limit_fees_amount = 0
                                    for over_limit_fees_id in over_limit_fees_ids:
                                        if over_limit_fees_id['sale_amount_from'] <= trans_amount and over_limit_fees_id['sale_amount_to'] >= trans_amount:
                                            if over_limit_fees_id['fees_amount'] > 0:
                                                limit_fees_amount = over_limit_fees_id['fees_amount']
                                            elif over_limit_fees_id['fees_amount_percentage'] > 0:
                                                limit_fees_amount = trans_amount * over_limit_fees_id['fees_amount_percentage'] / 100
                                            break
                                    if limit_fees_amount > 0:
                                        limit_fees_amounts.update({limit_type: limit_fees_amount})
                                        calculated_payment_amount += limit_fees_amount

                        if request_data.get("wallet_id"):
                            partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(wallet_id=request_data.get("wallet_id"),
                                                                                                   service=service,
                                                                                                   trans_amount=calculated_payment_amount)
                        else:
                            partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(service=service,
                                                                                                   trans_amount=calculated_payment_amount)
                        if not partner_wallet_id:
                            return invalid_response("wallet_not_found",
                                                    _("No Matched Wallet found for partner [%s] %s") % (
                                                        request.env.user.partner_id.ref,
                                                        request.env.user.partner_id.name), 400)

                        # Check Wallet Transaction limits
                        if partner_wallet_id.type.has_trans_limit:
                            wallet_limit_fees_amounts = {}
                            for trans_limit_id in partner_wallet_id.type.trans_limit_ids:
                                wallet_limit_type = trans_limit_id.limit_type
                                wallet_limit_amount = trans_limit_id.limit_amount
                                wallet_trans_limit_id = request.env['wallet.wallet.type.trans.limit'].sudo().search(
                                    [('wallet_id', '=', partner_wallet_id.id),
                                     # ('wallet_type_id', '=', partner_wallet_id.type.id),
                                     ('limit_type', '=', wallet_limit_type)], limit=1)
                                if wallet_trans_limit_id:
                                    wallet_limit_amount = wallet_trans_limit_id.limit_amount
                                timetuple = date_time.now().timetuple()
                                trans_limit_domain = [('wallet_id', '=', partner_wallet_id.id),
                                                      # ('wallet_type_id', '=', partner_wallet_id.type.id),
                                                      ('limit_type', '=', wallet_limit_type),
                                                      ('year', '=', timetuple.tm_year)]
                                if wallet_limit_type == 'daily':
                                    trans_limit_domain += [('day', '=', timetuple.tm_yday)]
                                elif wallet_limit_type == 'weekly':
                                    trans_limit_domain += [('week', '=', date_time.now().isocalendar()[1])]
                                elif wallet_limit_type == 'monthly':
                                    trans_limit_domain += [('month', '=', timetuple.tm_mon)]
                                trans_limit = request.env['wallet.trans.limit'].sudo().search(trans_limit_domain,
                                                                                              order="id DESC", limit=1)
                                calculated_trans_amount = calculated_payment_amount
                                if trans_limit:
                                    calculated_trans_amount += trans_limit.trans_amount
                                if wallet_limit_amount < calculated_trans_amount:
                                    wallet_over_limit_fees_ids = []
                                    if wallet_trans_limit_id:
                                        if wallet_trans_limit_id.over_limit_fees_policy == 'wallet_type_over_limit_fees' and wallet_trans_limit_id.wallet_type_over_limit_fees_ids:
                                            wallet_over_limit_fees_ids = wallet_trans_limit_id.wallet_type_over_limit_fees_ids
                                            wallet_limit_amount = wallet_over_limit_fees_ids.sorted(lambda l: l.trans_amount_to, reverse=True)[0].trans_amount_to + wallet_trans_limit_id.limit_amount
                                        if wallet_trans_limit_id.over_limit_fees_policy == 'custom_over_limit_fees' and wallet_trans_limit_id.over_limit_fees_ids:
                                            wallet_over_limit_fees_ids = wallet_trans_limit_id.over_limit_fees_ids
                                            wallet_limit_amount = wallet_over_limit_fees_ids.sorted(lambda l: l.trans_amount_to, reverse=True)[0].trans_amount_to + wallet_trans_limit_id.limit_amount
                                    else:
                                        if trans_limit_id.has_over_limit_fees and trans_limit_id.over_limit_fees_ids:
                                            wallet_over_limit_fees_ids = trans_limit_id.over_limit_fees_ids
                                            wallet_limit_amount = wallet_over_limit_fees_ids.sorted(lambda l: l.trans_amount_to, reverse=True)[0].trans_amount_to + trans_limit_id.limit_amount

                                    if wallet_limit_amount < calculated_trans_amount:
                                        return invalid_response("%s_limit_exceeded" % wallet_limit_type,
                                                                _("%s limit exceeded for wallet type (%s)") % (
                                                                    wallet_limit_type, partner_wallet_id.type.name), 400)

                                    wallet_limit_fees_amount = 0
                                    for wallet_over_limit_fees_id in wallet_over_limit_fees_ids:
                                        if wallet_over_limit_fees_id['trans_amount_from'] <= trans_amount and wallet_over_limit_fees_id['trans_amount_to'] >= trans_amount:
                                            if wallet_over_limit_fees_id['fees_amount'] > 0:
                                                wallet_limit_fees_amount = wallet_over_limit_fees_id['fees_amount']
                                            elif wallet_over_limit_fees_id['fees_amount_percentage'] > 0:
                                                wallet_limit_fees_amount = trans_amount * wallet_over_limit_fees_id['fees_amount_percentage'] / 100
                                            break
                                    if wallet_limit_fees_amount > 0:
                                        wallet_limit_fees_amounts.update({wallet_limit_type: wallet_limit_fees_amount})
                                        calculated_payment_amount += wallet_limit_fees_amount
                        
                        unlink_wallet_reservation = False
                        machine_wallet_reservation_id, machine_wallet_balance, machine_wallet_available_amount = partner_wallet_id.update_wallet_reserved_balance(
                            _('Pay Service Bill for %s service') % (service.name), calculated_payment_amount,
                            request.env.user.company_id.currency_id, 'request'
                        )
                        # # machine_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                        # machine_wallet_available_amount = partner_wallet_id.available_amount if partner_wallet_id else 0
                        # if machine_wallet_available_amount < calculated_payment_amount:
                        if not machine_wallet_reservation_id:
                            return invalid_response("machine_balance_not_enough",
                                                    _("Machine Wallet Available Balance (%s) less than the payment amount (%s)") % (
                                                        machine_wallet_available_amount, calculated_payment_amount), 400)


            request_data['partner_id'] = request.env.user.partner_id.id
            model_name = 'smartpay_operations.request'
            model_record = request.env['ir.model'].sudo().search([('model', '=', model_name)])

            try:
                data = WebsiteForm().extract_data(model_record, request_data)
            # If we encounter an issue while extracting data
            except ValidationError as e:
                # I couldn't find a cleaner way to pass data to an exception
                return invalid_response("Error", _("Could not submit you request.") + " ==> " + str(e), 500)

            try:
                id_record = WebsiteForm().insert_record(request, model_record, data['record'], data['custom'], data.get('meta'))
                if id_record:
                    WebsiteForm().insert_attachment(model_record, id_record, data['attachments'])
                    request.env.cr.commit()
                    machine_request = model_record.env[model_name].sudo().browse(id_record)
                else:
                    return invalid_response("Error", _("Could not submit you request."), 500)

            # Some fields have additional SQL constraints that we can't check generically
            # Ex: crm.lead.probability which is a float between 0 and 1
            # TODO: How to get the name of the erroneous field ?
            except IntegrityError as e:
                return invalid_response("Error", _("Could not submit you request.") + " ==> " + str(e), 500)

            if request_data.get('request_type') == 'recharge_wallet':
                return valid_response({"message": _("Recharge your wallet request was submit successfully."),
                                        "request_number": machine_request.name
                                       })
            elif request_data.get('request_type') == 'wallet_invitation':
                return valid_response({"message": _("Wallet inivitation request for mobile number (%s) was submit successfully.") % (
                                                request_data.get('mobile_number')),
                                        "request_number": machine_request.name
                                       })
            elif request_data.get('request_type') == 'service_bill_inquiry':
                lang = request_data.get('lang')
                billingAcct = request_data.get('billingAcct')
                extraBillingAcctKeys = request_data.get('extraBillingAcctKeys')
                if extraBillingAcctKeys:
                    extraBillingAcctKeys = ast.literal_eval(extraBillingAcctKeys)
                customProperties = request_data.get('customProperties')
                if customProperties:
                    customProperties = ast.literal_eval(customProperties)

                provider_response = {}
                error = {}
                for provider_info in service.seller_ids:
                    provider = request.env['payment.acquirer'].sudo().search(
                        [("related_partner", "=", provider_info.name.id)])
                    if provider:
                        if provider.server_state == 'offline':
                            error.update({provider.provider + "_response": {'error_message': _("Service Not Available")}})
                            break
                        trans_amount = 0.0
                        provider_channel = False
                        machine_channels = request.env['payment.acquirer.channel'].sudo().search([("acquirer_id", "=", provider.id),
                                                                                                  ("type", "in", ("machine", "internet"))], limit=1)
                        if machine_channels:
                            provider_channel = machine_channels[0]
                        if provider.provider == "fawry":
                            provider_response = provider.get_fawry_bill_details(lang, provider_info.product_code,
                                                                                billingAcct, extraBillingAcctKeys,
                                                                                provider_channel, customProperties,
                                                                                machine_request.name)
                            if provider_response.get('Success'):
                                billRecType = provider_response.get('Success')
                                provider_response_json = suds_to_json(billRecType)
                                for BillSummAmt in billRecType['BillInfo']['BillSummAmt']:
                                    if BillSummAmt['BillSummAmtCode'] == 'TotalAmtDue':
                                        trans_amount += float(BillSummAmt['CurAmt']['Amt'])
                                        break
                        elif provider.provider == "khales":
                            provider_response = {}
                            biller_info_json_dict = json.loads(provider_info.with_context(lang=request.env.user.lang).biller_info, strict=False)
                            # Handel billingAcct format if exist
                            if biller_info_json_dict.get('BillTypeAcctFormat') and biller_info_json_dict.get('BillTypeAcctFormatSpliter'):
                                formatedBillingAcct = []
                                keysToBeRemoved = []
                                for format in biller_info_json_dict.get('BillTypeAcctFormat').split(biller_info_json_dict.get('BillTypeAcctFormatSpliter')):
                                    if format == 'billingAcct':
                                        formatedBillingAcct.append(billingAcct)
                                    else:
                                        is_extra_key = False
                                        for extraBillingAcctKey in extraBillingAcctKeys:
                                            if extraBillingAcctKey.get("Key") == format:
                                                formatedBillingAcct.append(extraBillingAcctKey.get("Value"))
                                                keysToBeRemoved.append(extraBillingAcctKey)
                                                is_extra_key = True
                                                break
                                        if not is_extra_key:
                                            formatedBillingAcct.append(format)
                                extraBillingAcctKeys = [x for x in extraBillingAcctKeys if x not in keysToBeRemoved]
                                billingAcct = biller_info_json_dict.get('BillTypeAcctFormatSpliter').join(formatedBillingAcct)

                            '''
                            machine_serial = None
                            if len(request.env.user.machine_serial) > 16:  # Ingenico POS
                                machine_serial = request.env.user.machine_serial
                                machine_serial = machine_serial[len(machine_serial) - 16:len(machine_serial)]
                            '''
                            machine_serial = request.env.user.machine_serial
                            if machine_serial and len(machine_serial) > 16:
                                machine_serial = machine_serial[len(machine_serial) - 16:len(machine_serial)]
                            bill_response = provider.get_khales_bill_details(lang, machine_serial or machine_request.name,
                                                                             provider_info.product_code, biller_info_json_dict.get('Code'),
                                                                             billingAcct, extraBillingAcctKeys, provider_channel, machine_request.name)
                            if bill_response.get('Success'):
                                billRecType = bill_response.get('Success')
                                payAmts = billRecType['BillInfo']['CurAmt']
                                if payAmts and isinstance(payAmts, OrderedDict):
                                    payAmts = [payAmts]
                                    billRecType['BillInfo']['CurAmt'] = payAmts
                                success_response = {"bill_response": suds_to_json(billRecType)}
                                # for payAmt in payAmts:
                                    # trans_amount += float(payAmt.get("AmtDue"))
                                trans_amount += float(payAmts[0].get("AmtDue"))
                                if biller_info_json_dict.get('PmtType') == 'POST':
                                    ePayBillRecID = billRecType['EPayBillRecID']
                                    fees_response = provider.get_khales_fees(lang, machine_serial or machine_request.name,
                                                                             ePayBillRecID, payAmts[0], provider_channel, machine_request.name)
                                    provider_fees_calculated_amount = 0.0
                                    if fees_response.get('Success'):
                                        feeInqRsType = fees_response.get('Success')
                                        provider_fees_calculated_amount = float(feeInqRsType['FeesAmt']['Amt'])
                                        # success_response.update({"fees_response": suds_to_json(feeInqRsType)})
                                    else:
                                        feeInqRsType = {"EPayBillRecID": ePayBillRecID,
                                                        "FeesAmt": {"Amt": "0.0", "CurCode": "818"}}

                                    if provider_fees_calculated_amount == 0:
                                        service_providerinfo = request.env['product.supplierinfo'].sudo().search([
                                            ('product_tmpl_id', '=', service.product_tmpl_id.id),
                                            ('name', '=', provider.related_partner.id)
                                        ])
                                        commissions = request.env[
                                            'product.supplierinfo.commission'].sudo().search_read(
                                            domain=[('vendor', '=', service_providerinfo.name.id),
                                                    (
                                                        'vendor_product_code', '=', service_providerinfo.product_code)],
                                            fields=['Amount_Range_From', 'Amount_Range_To',
                                                    'Extra_Fee_Amt', 'Extra_Fee_Prc',
                                                    'Mer_Fee_Amt', 'Mer_Fee_Prc', 'Mer_Fee_Prc_MinAmt',
                                                    'Mer_Fee_Prc_MaxAmt']
                                        )
                                        for commission in commissions:
                                            if commission['Amount_Range_From'] <= trans_amount \
                                                    and commission['Amount_Range_To'] >= trans_amount:
                                                if commission['Extra_Fee_Amt'] > 0:
                                                    extra_fees_amount = commission['Extra_Fee_Amt']
                                                elif commission['Extra_Fee_Prc'] > 0:
                                                    extra_fees_amount = trans_amount * commission[
                                                        'Extra_Fee_Prc'] / 100
                                                if commission['Mer_Fee_Amt'] > 0:
                                                    provider_fees_calculated_amount = commission['Mer_Fee_Amt']
                                                elif commission['Mer_Fee_Prc'] > 0:
                                                    # Fees amount = FA + [Percentage * Payment Amount]
                                                    # Fees amount ====================> provider_fees_calculated_amount
                                                    # FA =============================> provider_fees_calculated_amount
                                                    # [Percentage * Payment Amount] ==> provider_fees_prc_calculated_amount
                                                    provider_fees_prc_calculated_amount = trans_amount * commission[
                                                        'Mer_Fee_Prc'] / 100
                                                    if provider_fees_prc_calculated_amount < commission[
                                                        'Mer_Fee_Prc_MinAmt']:
                                                        provider_fees_prc_calculated_amount = commission[
                                                            'Mer_Fee_Prc_MinAmt']
                                                    elif provider_fees_prc_calculated_amount > commission[
                                                        'Mer_Fee_Prc_MaxAmt'] \
                                                            and commission['Mer_Fee_Prc_MaxAmt'] > 0:
                                                        provider_fees_prc_calculated_amount = commission[
                                                            'Mer_Fee_Prc_MaxAmt']
                                                    provider_fees_calculated_amount += provider_fees_prc_calculated_amount
                                                break
                                        feeInqRsType['FeesAmt']['Amt'] = "%s" % ((math.floor(provider_fees_calculated_amount * 100)) / 100.0)

                                    success_response.update({"fees_response": suds_to_json(feeInqRsType)})
                                provider_response = {'Success': success_response}

                                provider_response_json = provider_response.get('Success')
                            else:
                                provider_response = bill_response
                        elif provider.provider == "masary":
                            provider_response = provider.get_masary_bill_details(lang, int(provider_info.product_code),
                                                                                extraBillingAcctKeys, provider_channel, machine_request.name)
                            if provider_response.get('Success'):
                                billData = provider_response.get('Success')
                                provider_response_json = billData
                                if billData.get('amount'):
                                    trans_amount += float(billData.get('amount'))
                                # elif billData.get('min_amount'):
                                    # trans_amount += float(billData.get('min_amount'))

                        if provider_response.get('Success'):
                            commissions = request.env['product.supplierinfo.commission'].sudo().search_read(
                                domain=[('vendor', '=', provider_info.name.id), ('vendor_product_code', '=', provider_info.product_code)],
                                fields=['Amount_Range_From', 'Amount_Range_To', 'Extra_Fee_Amt', 'Extra_Fee_Prc']
                            )
                            extra_fees_amount = 0.0
                            for commission in commissions:
                                if commission['Amount_Range_From'] <= trans_amount \
                                        and commission['Amount_Range_To'] >= trans_amount:
                                    if commission['Extra_Fee_Amt'] > 0:
                                        extra_fees_amount = commission['Extra_Fee_Amt']
                                    elif commission['Extra_Fee_Prc'] > 0:
                                        extra_fees_amount = trans_amount * commission['Extra_Fee_Prc'] / 100
                                    break
                            machine_request.update(
                                {"provider_id": provider.id, "provider_response": provider_response_json,
                                 "trans_amount": trans_amount, "extra_fees_amount": extra_fees_amount,
                                 "extra_fees": commissions, "stage_id": 5})
                            request.env.cr.commit()
                            return valid_response(
                                {"message": _("Service Bill Inquiry request was submit successfully."),
                                 "request_number": machine_request.name,
                                 "provider": provider.provider,
                                 "provider_response": provider_response_json,
                                 "extra_fees_amount": extra_fees_amount,
                                 # "extra_fees": commissions
                                 })
                        else:
                            error.update({provider.provider + "_response": provider_response or ''})
                    else:
                        error.update({provider_info.name.name + "_response": _("%s is not a provider for (%s) service") % (
                        provider_info.name.name, service.name)})

                machine_request.update({
                    "provider_response": error or _("(%s) service has not any provider.") % (service.name),
                    "stage_id": 5
                })
                request.env.cr.commit()
                error_key = "user_error"
                error_msg = _("(%s) service has not any provider.") % (service.name)
                if provider:
                    if error.get(provider.provider + "_response").get("error_message"):
                        error_msg = error.get(provider.provider + "_response").get("error_message")
                    elif error.get(provider.provider + "_response").get("error_message_to_be_translated"):
                        error_msg = error.get(provider.provider + "_response").get("error_message_to_be_translated")
                        error_key = "Error"
                elif error.get(provider_info.name.name + "_response"):
                    error_msg = error.get(provider_info.name.name + "_response")
                return invalid_response(error_key, error_msg, 400)

            elif request_data.get('request_type') == 'pay_service_bill':
                if machine_wallet_reservation_id:
                    machine_wallet_reservation_id.update({'request_id': machine_request.id})
                    request.env.cr.commit()
                lang = request_data.get('lang')
                billingAcct = request_data.get('billingAcct')

                extraBillingAcctKeys = request_data.get('extraBillingAcctKeys')
                if extraBillingAcctKeys:
                    extraBillingAcctKeys = ast.literal_eval(extraBillingAcctKeys)

                notifyMobile = request_data.get('notifyMobile')
                billRefNumber = request_data.get('billRefNumber')
                billerId = request_data.get('billerId')
                pmtType = request_data.get('pmtType')

                trans_amount = request_data.get('trans_amount')
                curCode = request_data.get('currency_id')
                payAmts = request_data.get('payAmts')
                if payAmts:
                    payAmts = ast.literal_eval(payAmts)
                else:
                    payAmts = [{'Sequence': '1', 'AmtDue': trans_amount, 'CurCode': curCode}]
                pmtMethod = request_data.get('pmtMethod')

                ePayBillRecID = request_data.get('ePayBillRecID')
                pmtId = request_data.get('pmtId') or machine_request.name
                feesAmt = request_data.get('feesAmt') or 0.00
                feesAmts = request_data.get('feesAmts')
                if feesAmts:
                    feesAmts = ast.literal_eval(feesAmts)
                else:
                    feesAmts = [{'Amt': feesAmt, 'CurCode': curCode}]
                pmtRefInfo = request_data.get('pmtRefInfo')

                providers_info = []
                '''
                provider_provider = request_data.get('provider')
                if provider_provider:
                    provider = request.env['payment.acquirer'].sudo().search([("provider", "=", provider_provider)])
                    if provider:
                        service_providerinfo = request.env['product.supplierinfo'].sudo().search([
                            ('product_tmpl_id', '=', service.product_tmpl_id.id),
                            ('name', '=', provider.related_partner.id)
                        ])
                        if service_providerinfo:
                            providers_info.append(service_providerinfo)
                if not provider_provider or len(providers_info) == 0:
                    providers_info = service.seller_ids
                '''
                providers_info.append(service_providerinfo)

                provider_response = {}
                provider_response_json = {}
                '''
                provider_fees_calculated_amount = 0.0
                provider_fees_actual_amount = 0.0
                merchant_cashback_amount = 0.0
                customer_cashback_amount = 0.0
                extra_fees_amount = 0.0
                '''
                error = {}
                for provider_info in providers_info:
                    biller_info_json_dict = json.loads(provider_info.with_context(lang=request.env.user.lang).biller_info, strict=False)
                    '''
                    # Get Extra Fees
                    commissions = request.env['product.supplierinfo.commission'].sudo().search_read(
                        domain=[('vendor', '=', provider_info.name.id),
                                ('vendor_product_code', '=', provider_info.product_code)],
                        fields=['Amount_Range_From', 'Amount_Range_To',
                                'Extra_Fee_Amt', 'Extra_Fee_Prc',
                                'Mer_Fee_Amt', 'Mer_Fee_Prc', 'Mer_Fee_Prc_MinAmt', 'Mer_Fee_Prc_MaxAmt',
                                'Mer_Comm_Full_Fix_Amt', 'Cust_Comm_Full_Fix_Amt',
                                'Bill_Merchant_Comm_Prc', 'Bill_Customer_Comm_Prc']
                    )
                    for commission in commissions:
                        if commission['Amount_Range_From'] <= machine_request.trans_amount \
                                and commission['Amount_Range_To'] >= machine_request.trans_amount:
                            if commission['Mer_Comm_Full_Fix_Amt'] > 0:
                                merchant_cashback_amount = commission['Mer_Comm_Full_Fix_Amt']
                                customer_cashback_amount = commission['Cust_Comm_Full_Fix_Amt']
                            elif commission['Bill_Merchant_Comm_Prc'] > 0:
                                merchant_cashback_amount = machine_request.trans_amount * commission[
                                    'Bill_Merchant_Comm_Prc'] / 100
                                customer_cashback_amount = machine_request.trans_amount * commission[
                                    'Bill_Customer_Comm_Prc'] / 100
                            if commission['Extra_Fee_Amt'] > 0:
                                extra_fees_amount = commission['Extra_Fee_Amt']
                            elif commission['Extra_Fee_Prc'] > 0:
                                extra_fees_amount = machine_request.trans_amount * commission['Extra_Fee_Prc'] / 100
                            if commission['Mer_Fee_Amt'] > 0:
                                provider_fees_calculated_amount = commission['Mer_Fee_Amt']
                            elif commission['Mer_Fee_Prc'] > 0:
                                # Fees amount = FA + [Percentage * Payment Amount]
                                # Fees amount ====================> provider_fees_calculated_amount
                                # FA =============================> provider_fees_calculated_amount
                                # [Percentage * Payment Amount] ==> provider_fees_prc_calculated_amount
                                provider_fees_prc_calculated_amount = machine_request.trans_amount * commission['Mer_Fee_Prc'] / 100
                                if provider_fees_prc_calculated_amount < commission['Mer_Fee_Prc_MinAmt']:
                                    provider_fees_prc_calculated_amount = commission['Mer_Fee_Prc_MinAmt']
                                elif provider_fees_prc_calculated_amount > commission['Mer_Fee_Prc_MaxAmt'] \
                                        and commission['Mer_Fee_Prc_MaxAmt'] > 0:
                                    provider_fees_prc_calculated_amount = commission['Mer_Fee_Prc_MaxAmt']
                                provider_fees_calculated_amount += provider_fees_prc_calculated_amount
                            elif provider_provider == 'khales':
                                provider_fees_calculated_amount = float(request_data.get('feesAmt'))
                            break
                    calculated_payment_amount = machine_request.trans_amount + provider_fees_calculated_amount + extra_fees_amount
                    if request_data.get("wallet_id"):
                        partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(wallet_id=request_data.get("wallet_id"),
                                                                                               service=service,
                                                                                               trans_amount=calculated_payment_amount)
                    else:
                        partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(service=service,
                                                                                               trans_amount=calculated_payment_amount)
                    unlink_wallet_reservation = False
                    machine_wallet_reservation_id, machine_wallet_balance, machine_wallet_available_amount = partner_wallet_id.update_wallet_reserved_balance(
                            _('Pay Service Bill for %s service') % (service.name), calculated_payment_amount,
                            request.env.user.company_id.currency_id, 'request'
                        )
                    # # machine_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                    # machine_wallet_available_amount = partner_wallet_id.available_amount if partner_wallet_id else 0
                    # if machine_wallet_available_amount < calculated_payment_amount 
                    if not machine_wallet_reservation_id    
                        and (not json.loads(service_providerinfo.biller_info, strict=False).get('CorrBillTypeCode') or json.loads(service_providerinfo.biller_info, strict=False).get('Type') == 'CASHININT'):
                        error.update({"machine_balance_not_enough":
                                                _("Machine Wallet Available Balance (%s) less than the payment amount (%s)") % (machine_wallet_available_amount,
                                                                                                                      calculated_payment_amount)})
                    '''

                    machine_request.update({'provider_fees_calculated_amount': provider_fees_calculated_amount})
                    request.env.cr.commit()
                    provider = request.env['payment.acquirer'].sudo().search([("related_partner", "=", provider_info.name.id)])
                    if provider:
                        try:
                            if provider.server_state == 'offline':
                                error.update({provider.provider + "_response": {'error_message': _("Service Not Available")}})
                                break
                            provider_channel = False
                            machine_channels = request.env['payment.acquirer.channel'].sudo().search([("acquirer_id", "=", provider.id),
                                                                                                      ("type", "in", ("machine", "internet"))], limit=1)
                            if machine_channels:
                                provider_channel = machine_channels[0]
                            if provider.provider == "fawry":
                                # Tamayoz TODO: Provider Server Timeout Handling
                                machine_request.update({'action_status': 'in_progress'})  # ==> current 'payment_status': is 'new'
                                request.env.cr.commit()
                                provider_response = provider.pay_fawry_bill(lang, provider_info.product_code,
                                                                            billingAcct, extraBillingAcctKeys,
                                                                            trans_amount, curCode, pmtMethod,
                                                                            notifyMobile, billRefNumber,
                                                                            billerId, pmtType, provider_channel,
                                                                            inquiryTransactionId, machine_request.name,
                                                                            biller_info_json_dict.get('SupportPmtReverse'),
                                                                            biller_info_json_dict.get('AllowRetry'))
                                if provider_response.get('Success'):
                                    if provider_response.get('Success').get('timeout'):
                                        machine_request.update({'payment_status': 'timeout'}) # ==> current 'action_status': is 'in_progress'
                                        if biller_info_json_dict.get('PmtType') == 'VOCH':
                                            provider_response = {"error_code": "0", "error_message": None,
                                                                 "error_message_to_be_translated": "FW Server timeout:\n",}
                                            if biller_info_json_dict.get('SupportPmtReverse'):
                                                provider_response.update({"TO_CANCEL": "VOCH"})
                                            else:
                                                provider_response.update({"TO_REVIEW": "VOCH"})
                                    else:
                                        machine_request.update({'action_status': 'completed'}) # ==> current 'payment_status': is 'new'
                                    request.env.cr.commit()
                                    if not provider_response.get('error_code'):
                                        provider_response_json = suds_to_json(provider_response.get('Success')['pmtInfoValType'])
                                        msgRqHdr_response_json = suds_to_json(provider_response.get('Success')['msgRqHdrType'])
                                        # Get customProperties
                                        msgRqHdr_response_json_dict = json.loads(msgRqHdr_response_json, strict=False)
                                        customProperties = msgRqHdr_response_json_dict.get('CustomProperties')
                                        cardMetadata = ''
                                        if customProperties:
                                            # Get CardMetadata
                                            for customProperty in customProperties['CustomProperty']:
                                                if customProperty['Key'] == 'CardMetadata':
                                                    cardMetadata = customProperty['Value']
                                                    break
                                        # Get Provider Fees
                                        provider_response_json_dict = json.loads(provider_response_json, strict=False)
                                        # provider_response_json_dict['PmtInfo']['CurAmt']['Amt'] == machine_request.trans_amount
                                        provider_fees_actual_amount = provider_response_json_dict['PmtInfo']['FeesAmt']['Amt']
                                        machine_request.update({'provider_fees_amount': provider_fees_actual_amount})
                                        request.env.cr.commit()
                                        # Get Provider Payment Trans ID
                                        for payment in provider_response_json_dict['PmtTransId']:
                                            if payment['PmtIdType'] == 'FCRN':
                                                provider_payment_trans_id = payment['PmtId']
                                                break
                            elif provider.provider == "khales":
                                if not billerId:
                                    billerId = biller_info_json_dict.get('Code')
                                # Handel billingAcct format if exist
                                if biller_info_json_dict.get('BillTypeAcctFormat') and biller_info_json_dict.get('BillTypeAcctFormatSpliter'):
                                    formatedBillingAcct = []
                                    keysToBeRemoved = []
                                    for format in biller_info_json_dict.get('BillTypeAcctFormat').split(biller_info_json_dict.get('BillTypeAcctFormatSpliter')):
                                        if format == 'billingAcct':
                                            formatedBillingAcct.append(billingAcct)
                                        else:
                                            is_extra_key = False
                                            for extraBillingAcctKey in extraBillingAcctKeys:
                                                if extraBillingAcctKey.get("Key") == format:
                                                    formatedBillingAcct.append(extraBillingAcctKey.get("Value"))
                                                    keysToBeRemoved.append(extraBillingAcctKey)
                                                    is_extra_key = True
                                                    break
                                            if not is_extra_key:
                                                formatedBillingAcct.append(format)
                                    extraBillingAcctKeys = [x for x in extraBillingAcctKeys if
                                                            x not in keysToBeRemoved]
                                    billingAcct = biller_info_json_dict.get('BillTypeAcctFormatSpliter').join(formatedBillingAcct)
                                # Tamayoz TODO: Provider Server Timeout Handling
                                # Tamayoz TODO: Remove the next temporary line
                                pmtMethod = "CARD"  # TEMP CODE
                                machine_request.update({'action_status': 'in_progress'})  # ==> current 'payment_status': is 'new'
                                request.env.cr.commit()
                                '''
                                machine_serial = None
                                if len(request.env.user.machine_serial) > 16:  # Ingenico POS
                                    machine_serial = request.env.user.machine_serial
                                    machine_serial = machine_serial[len(machine_serial) - 16:len(machine_serial)]
                                '''
                                machine_serial = request.env.user.machine_serial
                                if machine_serial and len(machine_serial) > 16:
                                    machine_serial = machine_serial[len(machine_serial) - 16:len(machine_serial)]
                                provider_response = provider.pay_khales_bill(lang, machine_serial or machine_request.name,
                                                                             billingAcct, extraBillingAcctKeys, billerId, ePayBillRecID,
                                                                             payAmts, pmtId, pmtType, feesAmts,
                                                                             billRefNumber, pmtMethod, pmtRefInfo,
                                                                             provider_channel, machine_request.name,
                                                                             biller_info_json_dict.get('SupportPmtReverse'),
                                                                             biller_info_json_dict.get('AllowRetry'))
                                if provider_response.get('Success'):
                                    if provider_response.get('Success').get('timeout'):
                                        machine_request.update({'payment_status': 'timeout'}) # ==> current 'action_status': is 'in_progress'
                                        if biller_info_json_dict.get('PmtType') == 'VOCH':
                                            provider_response = {"error_code": "0", "error_message": None,
                                                                 "error_message_to_be_translated": "KH Server timeout:\n",}
                                            if biller_info_json_dict.get('SupportPmtReverse'):
                                                provider_response.update({"TO_CANCEL": "VOCH"})
                                            else:
                                                provider_response.update({"TO_REVIEW": "VOCH"})
                                    else:
                                        machine_request.update({'action_status': 'completed'}) # ==> current 'payment_status': is 'new'
                                    request.env.cr.commit()
                                    if not provider_response.get('error_code'):
                                        provider_response_json = suds_to_json(provider_response.get('Success'))
                                        # Add required parameters for cancel payment scenario
                                        # parsing JSON string:
                                        provider_response_json_dict = json.loads(provider_response_json)
                                        pmtId = provider_response_json_dict['PmtRecAdviceStatus']['PmtTransId']['PmtId']
                                        # appending the data
                                        provider_response_json_dict.update({'billingAcct': billingAcct, 'billRefNumber': billRefNumber,
                                                                            'billerId': billerId, 'pmtType': pmtType, 'trans_amount': trans_amount,
                                                                            'curCode': curCode, 'pmtMethod': pmtMethod, 'ePayBillRecID': ePayBillRecID,
                                                                            'pmtId': pmtId, 'feesAmt': feesAmt, 'pmtRefInfo': pmtRefInfo})
                                        if payAmts:
                                            provider_response_json_dict.update({'payAmts': payAmts})
                                        if feesAmts:
                                            provider_response_json_dict.update({'feesAmts': feesAmts})
                                        # the result is a JSON string:
                                        provider_response_json = json.dumps(provider_response_json_dict)
                                        # Provider Fees
                                        provider_fees_actual_amount = float(feesAmt)
                                        machine_request.update({'provider_fees_amount': provider_fees_actual_amount})
                                        request.env.cr.commit()
                                        # Provider Payment Trans ID
                                        provider_payment_trans_id = pmtId
                            elif provider.provider == "masary":
                                machine_request.update({'action_status': 'in_progress'}) # ==> current 'payment_status': is 'new'
                                request.env.cr.commit()
                                provider_response = provider.pay_masary_bill(lang, int(provider_info.product_code),
                                                                             float(trans_amount), float(feesAmt),
                                                                             inquiryTransactionId, 1, # quantity
                                                                             extraBillingAcctKeys, provider_channel, machine_request.name)
                                if provider_response.get('Success'):
                                    if provider_response.get('Success').get('timeout'):
                                        machine_request.update({'payment_status': 'timeout'}) # ==> current 'action_status': is 'in_progress'
                                        if biller_info_json_dict.get('PmtType') == 'VOCH':
                                            provider_response = {"error_code": "0", "error_message": None,
                                                                 "error_message_to_be_translated": "KH Server timeout:\n",}
                                            if biller_info_json_dict.get('SupportPmtReverse'):
                                                provider_response.update({"TO_CANCEL": "VOCH"})
                                            else:
                                                provider_response.update({"TO_REVIEW": "VOCH"})
                                    else:
                                        machine_request.update({'action_status': 'completed'}) # ==> current 'payment_status': is 'new'
                                    request.env.cr.commit()
                                    if not provider_response.get('error_code'):
                                        provider_response_json = provider_response.get('Success')
                                        # Get Provider Fees
                                        # provider_response_json_dict = json.loads(provider_response_json, strict=False)
                                        provider_response_json_dict = provider_response_json
                                        transactionId = provider_response_json_dict['transaction_id']
                                        # provider_fees_actual_amount = provider_response_json_dict['details_list']['???']
                                        provider_fees_actual_amount = float(feesAmt)
                                        machine_request.update({'provider_fees_amount': provider_fees_actual_amount})
                                        request.env.cr.commit()
                                        # Provider Payment Trans ID
                                        provider_payment_trans_id = transactionId

                            if provider_response.get('Success'):
                                try:
                                    machine_wallet_create = False
                                    # provider_invoice_id = False
                                    # refund = False
                                    # customer_invoice_id = False
                                    # credit_note = False
                                    machine_request_response = {"request_number": machine_request.name,
                                                                "request_datetime": machine_request.create_date + timedelta(hours=2),
                                                                "provider": provider.provider,
                                                                "provider_response": provider_response_json
                                                                }

                                    if provider.provider == "fawry":
                                        if cardMetadata:
                                            machine_request_response.update({"cardMetadata": cardMetadata})

                                    provider_actual_amount = machine_request.trans_amount + provider_fees_actual_amount
                                    customer_actual_amount = provider_actual_amount + extra_fees_amount

                                    if not biller_info_json_dict.get('CorrBillTypeCode') or biller_info_json_dict.get('Type') == 'CASHININT':
                                        # Deduct Transaction Amount from Machine Wallet Balance
                                        '''
                                        wallet_transaction_sudo = request.env['website.wallet.transaction'].sudo()
                                        label = _('Pay Service Bill for %s service') % (service.name)
                                        if request_data.get("wallet_id"):
                                            partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(wallet_id=request_data.get("wallet_id"),
                                                                                                                   service=service,
                                                                                                                   trans_amount=customer_actual_amount)
                                        else:
                                            partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(service=service,
                                                                                                                   trans_amount=customer_actual_amount)
                                        partner_id_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                                        machine_wallet_create = wallet_transaction_sudo.create(
                                            {'wallet_type': 'debit', 'partner_id': request.env.user.partner_id.id,
                                             'request_id': machine_request.id,
                                             'reference': 'request',
                                             'label': label,
                                             'amount': customer_actual_amount, 'currency_id': machine_request.currency_id.id,
                                             'wallet_balance_before': partner_id_wallet_balance,
                                             'wallet_balance_after': partner_id_wallet_balance - customer_actual_amount,
                                             'status': 'done'})
                                        request.env.cr.commit()

                                        request.env.user.partner_id.update(
                                            {'wallet_balance': partner_id_wallet_balance - customer_actual_amount})
                                        request.env.cr.commit()
                                        '''

                                        machine_wallet_create, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                                            'debit', request.env.user.partner_id, 'request',
                                            _('Pay Service Bill for %s service') % (service.name),
                                            customer_actual_amount, machine_request.currency_id, machine_request,
                                            'smartpay_operations.wallet_pay_service_bill_notify_mode', 'wallet_pay_service',
                                            _('<p>%s %s successfully deducted from your wallet.</p>') % (
                                                customer_actual_amount, _(machine_request.currency_id.name))
                                        )

                                        if provider_response.get('Success').get('timeout'):
                                            if not biller_info_json_dict.get('Timeout') and not biller_info_json_dict.get('SupportPmtReverse'):
                                                machine_request.update({'payment_status': 'in_queue'})
                                            elif biller_info_json_dict.get('Timeout') == 'PENDING':
                                                machine_request.update({'payment_status': 'pending'})
                                            elif biller_info_json_dict.get('SupportPmtReverse'):
                                                # if biller_info_json_dict.get('PmtType') == 'VOCH':
                                                    # machine_request.update({'payment_status': 'to_cancel'})
                                                # else:
                                                if biller_info_json_dict.get('PmtType') != 'VOCH':
                                                    machine_request.update({'payment_status': 'to_refund'})
                                            # else:
                                                # machine_request.update({'payment_status': 'done'}) # Tamayoz: No need to handel "else" case
                                            machine_request.update({'action_status': 'new'})
                                        elif provider_response.get('Success').get('pending'):
                                            machine_request.update({'payment_status': 'pending', 'action_status': 'new'})
                                        else:
                                            machine_request.update({'payment_status': 'done', 'action_status': 'completed'}) # ==> current 'action_status': is 'completed'
                                        request.env.cr.commit()

                                        # Log Sold Limit
                                        if service.has_sale_limit:
                                            for sale_limit_id in service.sale_limit_ids:
                                                limit_type = sale_limit_id.limit_type
                                                timetuple = date_time.now().timetuple()
                                                sale_limit_domain = [
                                                    ('partner_id', '=', request.env.user.partner_id.id),
                                                    ('product_id', '=', service.id),
                                                    ('limit_type', '=', limit_type),
                                                    ('year', '=', timetuple.tm_year)]
                                                if limit_type == 'daily':
                                                    sale_limit_domain += [('day', '=', timetuple.tm_yday)]
                                                elif limit_type == 'weekly':
                                                    sale_limit_domain += [
                                                        ('week', '=', date_time.now().isocalendar()[1])]
                                                elif limit_type == 'monthly':
                                                    sale_limit_domain += [('month', '=', timetuple.tm_mon)]
                                                sale_limit = request.env['res.partner.sale.limit'].sudo().search(
                                                    sale_limit_domain,
                                                    order="id DESC", limit=1)
                                                if sale_limit:
                                                    sale_limit.update({'sold_amount': sale_limit.sold_amount + customer_actual_amount})  # calculated_payment_amount
                                                else:
                                                    sale_limit_values = {
                                                        'partner_id': request.env.user.partner_id.id,
                                                        'product_id': service.id,
                                                        'limit_type': limit_type,
                                                        'year': timetuple.tm_year,
                                                        'sold_amount': customer_actual_amount
                                                    }
                                                    if limit_type == 'daily':
                                                        sale_limit_values.update({'day': timetuple.tm_yday})
                                                    elif limit_type == 'weekly':
                                                        sale_limit_values.update(
                                                            {'week': date_time.now().isocalendar()[1]})
                                                    elif limit_type == 'monthly':
                                                        sale_limit_values.update({'month': timetuple.tm_mon})
                                                    sale_limit = request.env['res.partner.sale.limit'].sudo().create(sale_limit_values)

                                                # Log Sold Over Limit Fees
                                                if limit_fees_amounts.get(limit_type):
                                                    wallet_transaction_id, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                                                        'debit', request.env.user.partner_id, 'request',
                                                        _('%s over limit fees for %s service') % (limit_type, service.name),
                                                        limit_fees_amounts.get(limit_type), machine_request.currency_id, machine_request,
                                                        'smartpay_operations.wallet_pay_service_bill_notify_mode', 'wallet_pay_service',
                                                        _('<p>%s %s successfully deducted from your wallet.</p>') % (
                                                            limit_fees_amounts.get(limit_type), _(machine_request.currency_id.name))
                                                    )
                                                    sale_limit_fees = request.env['res.partner.sale.limit.fees'].sudo().create({'user_request_id': machine_request.id,
                                                                                                                                'limit_type': limit_type,
                                                                                                                                'fees_amount': limit_fees_amounts.get(limit_type),
                                                                                                                                'wallet_transaction_id': wallet_transaction_id.id})
                                        # Log Wallet Transaction Limit
                                        if partner_wallet_id.type.has_trans_limit:
                                            for trans_limit_id in partner_wallet_id.type.trans_limit_ids:
                                                wallet_limit_type = trans_limit_id.limit_type
                                                timetuple = date_time.now().timetuple()
                                                trans_limit_domain = [
                                                    ('wallet_id', '=', partner_wallet_id.id),
                                                    # ('wallet_type_id', '=', partner_wallet_id.type.id),
                                                    ('limit_type', '=', wallet_limit_type),
                                                    ('year', '=', timetuple.tm_year)]
                                                if wallet_limit_type == 'daily':
                                                    trans_limit_domain += [('day', '=', timetuple.tm_yday)]
                                                elif wallet_limit_type == 'weekly':
                                                    trans_limit_domain += [('week', '=', date_time.now().isocalendar()[1])]
                                                elif wallet_limit_type == 'monthly':
                                                    trans_limit_domain += [('month', '=', timetuple.tm_mon)]
                                                trans_limit = request.env['wallet.trans.limit'].sudo().search(
                                                    trans_limit_domain, order="id DESC", limit=1)
                                                if trans_limit:
                                                    trans_limit.update({'trans_amount': trans_limit.trans_amount + customer_actual_amount})  # calculated_payment_amount
                                                else:
                                                    trans_limit_values = {
                                                        'wallet_id': partner_wallet_id.id,
                                                        # 'wallet_type_id': partner_wallet_id.type.id,
                                                        'limit_type': wallet_limit_type,
                                                        'year': timetuple.tm_year,
                                                        'trans_amount': customer_actual_amount
                                                    }
                                                    if wallet_limit_type == 'daily':
                                                        trans_limit_values.update({'day': timetuple.tm_yday})
                                                    elif wallet_limit_type == 'weekly':
                                                        trans_limit_values.update({'week': date_time.now().isocalendar()[1]})
                                                    elif wallet_limit_type == 'monthly':
                                                        trans_limit_values.update({'month': timetuple.tm_mon})
                                                    trans_limit = request.env['wallet.trans.limit'].sudo().create(trans_limit_values)

                                                # Log Transaction Over Limit Fees
                                                if wallet_limit_fees_amounts.get(wallet_limit_type):
                                                    wallet_transaction_id, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                                                        'debit', request.env.user.partner_id, 'request',
                                                        _('%s over limit fees for %s wallet type') % (
                                                            wallet_limit_type, partner_wallet_id.type.name),
                                                        wallet_limit_fees_amounts.get(wallet_limit_type),
                                                        machine_request.currency_id, machine_request,
                                                        'smartpay_operations.wallet_pay_service_bill_notify_mode',
                                                        'wallet_pay_service',
                                                        _('<p>%s %s successfully deducted from your wallet.</p>') % (
                                                            wallet_limit_fees_amounts.get(wallet_limit_type),
                                                            _(machine_request.currency_id.name))
                                                    )
                                                    trans_limit_fees = request.env['wallet.trans.limit.fees'].sudo().create(
                                                        {'user_request_id': machine_request.id,
                                                         'limit_type': wallet_limit_type,
                                                         'fees_amount': wallet_limit_fees_amounts.get(wallet_limit_type),
                                                         'wallet_transaction_id': wallet_transaction_id.id})

                                        machine_wallet_reservation_id.sudo().unlink()
                                        request.env.cr.commit()
                                        unlink_wallet_reservation = True

                                        '''
                                        # Notify customer
                                        irc_param = request.env['ir.config_parameter'].sudo()
                                        wallet_pay_service_bill_notify_mode = irc_param.get_param("smartpay_operations.wallet_pay_service_bill_notify_mode")
                                        if wallet_pay_service_bill_notify_mode == 'inbox':
                                            request.env['mail.thread'].sudo().message_notify(
                                                subject=label,
                                                body=_('<p>%s %s successfully deducted from your wallet.</p>') % (
                                                    customer_actual_amount, _(machine_request.currency_id.name)),
                                                partner_ids=[(4, request.env.user.partner_id.id)],
                                            )
                                        elif wallet_pay_service_bill_notify_mode == 'email':
                                            machine_wallet_create.wallet_transaction_email_send()
                                        elif wallet_pay_service_bill_notify_mode == 'sms' and request.env.user.partner_id.mobile:
                                            machine_wallet_create.sms_send_wallet_transaction(wallet_pay_service_bill_notify_mode,
                                                                                              'wallet_pay_service',
                                                                                              request.env.user.partner_id.mobile,
                                                                                              request.env.user.name, label,
                                                                                              '%s %s' % (customer_actual_amount,
                                                                                                         _(machine_request.currency_id.name)),
                                                                                              request.env.user.partner_id.country_id.phone_code or '2')
                                        '''

                                        payment_info = {"service": service.with_context(lang=request.env.user.lang).name, "provider": provider.provider,
                                                        "request_number": machine_request.name,
                                                        "request_datetime": machine_request.create_date + timedelta(hours=2),
                                                        "label": biller_info_json_dict.get("BillTypeAcctLabel"),
                                                        "billing_acct": billingAcct, "ref_number": provider_payment_trans_id,
                                                        "amount": trans_amount,
                                                        "fees": (provider_fees_actual_amount + extra_fees_amount),
                                                        "total": customer_actual_amount}

                                    machine_request.update(
                                        {'extra_fees_amount': extra_fees_amount,
                                         'wallet_transaction_id': machine_wallet_create and machine_wallet_create.id or False,
                                         'trans_date': date.today(),
                                         'provider_id': provider.id,
                                         'provider_response': provider_response_json, "stage_id": 5})
                                    if biller_info_json_dict.get('CorrBillTypeCode'):
                                        machine_request.update(
                                            {'description': _(
                                                 'Initiation Service Payment request (%s) was submit successfully @ %s') % (
                                                                machine_request.name,
                                                                str(date_time.now() + timedelta(hours=2)))
                                             })
                                    request.env.cr.commit()
                                    machine_request_response.update({'extra_fees_amount': extra_fees_amount})

                                    # VouchPIN Decryption if exist
                                    if provider_response_json_dict.get('VouchInfo'):
                                        decrypted_bytes = bytes(provider_response_json_dict['VouchInfo']['VouchPIN'],
                                                                encoding='utf-8')
                                        # text = base64.decodestring(decrypted_bytes) #
                                        text = base64.b64decode(decrypted_bytes)  #
                                        cipher = DES3.new(SECRET_KEY, DES3.MODE_ECB)
                                        VouchPIN = cipher.decrypt(text)
                                        VouchPIN = UNPAD(VouchPIN)
                                        VouchPIN = VouchPIN.decode('utf-8')  # unpad and decode bytes to str
                                        machine_request_response.update({'vouch_pin': VouchPIN})
                                        if not biller_info_json_dict.get('CorrBillTypeCode') or biller_info_json_dict.get('Type') == 'CASHININT':
                                            payment_info.update({"vouch_pin": VouchPIN,
                                                                 "vouch_sn": provider_response_json_dict['VouchInfo']['VouchSN']})
                                            if provider_response_json_dict['VouchInfo'].get('VouchDesc'):
                                                payment_info.update({"vouch_desc": provider_response_json_dict['VouchInfo']['VouchDesc']})


                                    # ExtraBillInfo
                                    # ePayBillRecID : RBINQRQ-220627-619014259490-GT-99959 (Khales)
                                    # billRefNumber : 6bb67311-dde8-47f8-b8f3-3cf8fe5a4be6 (Fawry)
                                    if (provider.provider == 'fawry' and billRefNumber) or (provider.provider == 'khales' and ePayBillRecID):
                                        inquiryTransactionId = request_data.get('inquiryTransactionId')
                                        if inquiryTransactionId:
                                            inquiry_request = request.env["smartpay_operations.request"].sudo().search(
                                                [('name', '=', inquiryTransactionId)], limit=1)
                                        else:
                                            inquiry_request = request.env["smartpay_operations.request"].sudo().search(
                                                [('request_type', '=', 'service_bill_inquiry'),
                                                 ('partner_id', '=', request.env.user.partner_id.id),
                                                 ('product_id', '=', service.id),
                                                 ('create_date', '<=', date_time.now()),
                                                 ('create_date', '>=', date_time.now() - timedelta(minutes=15)),
                                                 ('provider_response', 'ilike',
                                                  '"BillRefNumber": "%s"' % (billRefNumber) if provider.provider == "fawry"
                                                  else '"EPayBillRecID": "%s"' % (ePayBillRecID) # provider.provider == "khales"
                                             )], limit=1)

                                        if inquiry_request:
                                            inquiry_request_provider_response = inquiry_request.provider_response.replace(
                                                "'bill_response'", '"bill_response"').replace("'fees_response'", '"fees_response"').replace("'", "")
                                            inquiry_request_provider_response_json_dict = json.loads(inquiry_request_provider_response)

                                            # Fawry
                                            if inquiry_request_provider_response_json_dict.get('BillInfo') and \
                                                    inquiry_request_provider_response_json_dict.get('BillInfo').get('ExtraBillInfo'):
                                                payment_info.update({"extra_bill_info": inquiry_request_provider_response_json_dict['BillInfo']['ExtraBillInfo']})

                                            # Khales
                                            if inquiry_request_provider_response_json_dict.get('bill_response') and \
                                                    inquiry_request_provider_response_json_dict.get('bill_response').get('Msg'):
                                                for msg in inquiry_request_provider_response_json_dict.get('bill_response').get('Msg'):
                                                    if msg.get('LanguagePref') == 'ar-eg':  # en-gb
                                                        payment_info.update({"extra_bill_info": msg.get('Text')})
                                                        break

                                    if not biller_info_json_dict.get('CorrBillTypeCode') or biller_info_json_dict.get('Type') == 'CASHININT':
                                        # Wallet Transaction Info with payment info
                                        machine_wallet_create.update({"wallet_transaction_info": json.dumps({"payment_info": payment_info}, default=default)})
                                        request.env.cr.commit()

                                    '''
                                    # Create Vendor (Provider) Invoices
                                    provider_invoice_ids = ()
                                    # 1- Create Vendor bill
                                    provider_journal_id = request.env['account.journal'].sudo().search([('type', '=', 'purchase'),
                                                                                              ('company_id', '=', request.env.user.company_id.id)], limit=1)
                                    name = provider.provider + ': [' + provider_info.product_code + '] ' + provider_info.product_name
                                    provider_invoice_vals = machine_request.with_context(name=name,
                                                                                         provider_payment_trans_id=provider_payment_trans_id,
                                                                                         journal_id=provider_journal_id.id,
                                                                                         invoice_date=date.today(),
                                                                                         invoice_type='in_invoice',
                                                                                         partner_id=provider_info.name.id)._prepare_invoice()
                                    provider_invoice_id = request.env['account.invoice'].sudo().create(provider_invoice_vals)
                                    invoice_line = provider_invoice_id._prepare_invoice_line_from_request(request=machine_request,
                                                                                                          name=name,
                                                                                                          qty=1,
                                                                                                          price_unit=provider_actual_amount)
                                    new_line = request.env['account.invoice.line'].sudo().new(invoice_line)
                                    new_line._set_additional_fields(provider_invoice_id)
                                    provider_invoice_id.invoice_line_ids += new_line
                                    provider_invoice_id.action_invoice_open()
                                    provider_invoice_ids += (tuple(provider_invoice_id.ids),)
                                    provider_invoice_id.pay_and_reconcile(request.env['account.journal'].sudo().search(
                                        [('type', '=', 'cash'),
                                         ('company_id', '=', request.env.user.company_id.id),
                                         ('provider_id', '=', provider.id)], limit=1),
                                        provider_actual_amount)
                                    request.env.cr.commit()
                                    # 2- Create Vendor Refund with commision amount
                                    if merchant_cashback_amount > 0:
                                        refund = request.env['account.invoice.refund'].with_context(
                                            active_ids=provider_invoice_id.ids).sudo().create({
                                            'filter_refund': 'refund',
                                            'description': name,
                                            'date': provider_invoice_id.date_invoice,
                                        })
                                        result = refund.invoice_refund()
                                        refund_id = result.get('domain')[1][2]
                                        refund = request.env['account.invoice'].sudo().browse(refund_id)
                                        refund.update({'reference': provider_payment_trans_id, 'request_id': machine_request.id})
                                        refund_line = refund.invoice_line_ids[0]
                                        refund_line.update({'price_unit': merchant_cashback_amount, 'request_id': machine_request.id})
                                        refund.refresh()
                                        refund.action_invoice_open()
                                        provider_invoice_ids += (tuple(refund.ids),)
                                    machine_request.update({'provider_invoice_ids': provider_invoice_ids})
                                    request.env.cr.commit()

                                    # Create Customer Invoices
                                    customer_invoice_ids = ()
                                    # 1- Create Customer Invoice
                                    customer_journal_id = request.env['account.journal'].sudo().search([('type', '=', 'sale'),
                                                                                              ('company_id', '=', request.env.user.company_id.id)], limit=1)
                                    customer_invoice_vals = machine_request.with_context(name=provider_payment_trans_id,
                                                                                         journal_id=customer_journal_id.id,
                                                                                         invoice_date=date.today(),
                                                                                         invoice_type='out_invoice',
                                                                                         partner_id=request.env.user.partner_id.id)._prepare_invoice()
                                    customer_invoice_id = request.env['account.invoice'].sudo().create(customer_invoice_vals)
                                    machine_request.invoice_line_create(invoice_id=customer_invoice_id.id, name=name,
                                                                        qty=1, price_unit=customer_actual_amount)
                                    customer_invoice_id.action_invoice_open()
                                    customer_invoice_ids += (tuple(customer_invoice_id.ids),)
                                    # Auto Reconcile customer invoice with prepaid wallet recharge payments and previous cashback credit note
                                    domain = [('account_id', '=', customer_invoice_id.account_id.id),
                                              ('partner_id', '=',
                                               customer_invoice_id.env['res.partner']._find_accounting_partner(customer_invoice_id.partner_id).id),
                                              ('reconciled', '=', False),
                                              '|',
                                              '&', ('amount_residual_currency', '!=', 0.0), ('currency_id', '!=', None),
                                              '&', ('amount_residual_currency', '=', 0.0), '&', ('currency_id', '=', None),
                                              ('amount_residual', '!=', 0.0)]
                                    domain.extend([('credit', '>', 0), ('debit', '=', 0)])
                                    lines = customer_invoice_id.env['account.move.line'].sudo().search(domain)
                                    for line in lines:
                                        # get the outstanding residual value in invoice currency
                                        if line.currency_id and line.currency_id == customer_invoice_id.currency_id:
                                            amount_residual_currency = abs(line.amount_residual_currency)
                                        else:
                                            currency = line.company_id.currency_id
                                            amount_residual_currency = currency._convert(abs(line.amount_residual),
                                                                                         customer_invoice_id.currency_id,
                                                                                         customer_invoice_id.company_id,
                                                                                         line.date or fields.Date.today())
                                        if float_is_zero(amount_residual_currency, precision_rounding=customer_invoice_id.currency_id.rounding):
                                            continue

                                        customer_invoice_id.assign_outstanding_credit(line.id)
                                        if customer_invoice_id.state == 'paid':
                                            break
                                    request.env.cr.commit()

                                    # 2- Create Customer Credit Note with commision amount for only customers have commission
                                    if request.env.user.commission and customer_cashback_amount > 0:
                                        credit_note = request.env['account.invoice.refund'].with_context(
                                            active_ids=customer_invoice_id.ids).sudo().create({
                                            'filter_refund': 'refund',
                                            'description': provider_payment_trans_id,
                                            'date': customer_invoice_id.date_invoice,
                                        })
                                        result = credit_note.invoice_refund()
                                        credit_note_id = result.get('domain')[1][2]
                                        credit_note = request.env['account.invoice'].sudo().browse(credit_note_id)
                                        credit_note.update({'request_id': machine_request.id})
                                        credit_note_line = credit_note.invoice_line_ids[0]
                                        credit_note_line.update({'price_unit': customer_cashback_amount, 'request_id': machine_request.id})
                                        credit_note.refresh()
                                        """  Don't validate the customer credit note until the vendor refund reconciliation
                                        After vendor refund reconciliation, validate the customer credit note with
                                        the net amount of vendor refund sent in provider cashback statement then
                                        increase the customer wallet with the same net amount. """
                                        # credit_note.action_invoice_open()
                                        customer_invoice_ids += (tuple(credit_note.ids),)
                                    machine_request.update({'customer_invoice_ids': customer_invoice_ids})
                                    request.env.cr.commit()
                                    '''

                                    if provider.provider == "khales":
                                        # Add required parameters for cancel payment scenario
                                        machine_request_response.update({'billingAcct': billingAcct, 'billRefNumber': billRefNumber,
                                                                         'billerId': billerId, 'pmtType': pmtType, 'trans_amount': trans_amount,
                                                                         'curCode': curCode, 'pmtMethod': pmtMethod, 'ePayBillRecID': ePayBillRecID,
                                                                         'pmtId': pmtId, 'feesAmt': feesAmt, 'pmtRefInfo': pmtRefInfo})
                                        if payAmts:
                                            machine_request_response.update({'payAmts': payAmts})
                                        if feesAmts:
                                            machine_request_response.update({'feesAmts': feesAmts})
                                    if not biller_info_json_dict.get('CorrBillTypeCode') or biller_info_json_dict.get('Type') == 'CASHININT':
                                        machine_request_response.update({"message": _("Pay Service Bill request was submit successfully with amount %s %s. Your Machine Wallet Balance is %s %s")
                                                                                % (customer_actual_amount,
                                                                                   machine_request.currency_id.name,
                                                                                   wallet_balance_after,
                                                                                   machine_request.currency_id.name)})
                                    else:
                                        machine_request_response.update({"message": _("Pay Service Bill Initiation request was submit successfully with amount %s %s.")
                                                                                    % (customer_actual_amount,
                                                                                       machine_request.currency_id.name)})

                                    # Cancel
                                    # request_number = {"request_number": machine_request.name}
                                    # self.cancel_request(**request_number)

                                    if not unlink_wallet_reservation and machine_wallet_reservation_id:
                                        machine_wallet_reservation_id.sudo().unlink()
                                        request.env.cr.commit()
                                        unlink_wallet_reservation = True
                                    return valid_response(machine_request_response)
                                except Exception as e:
                                    try:
                                        _logger.error("%s", e, exc_info=True)
                                        machine_request_update = {'extra_fees_amount': extra_fees_amount,
                                                                  'trans_date': date.today(),
                                                                  'provider_id': provider.id,
                                                                  'provider_response': provider_response_json, "stage_id": 5,
                                                                  'description': _("After the Pay Service Request submit successfuly with provider, Error is occur:") + " ==> " + str(e)}
                                        if machine_wallet_create:
                                            machine_request_update.update({'wallet_transaction_id': machine_wallet_create.id})
                                        '''
                                        provider_invoice_ids = ()
                                        if provider_invoice_id or refund:
                                            if provider_invoice_id:
                                                provider_invoice_ids += (tuple(provider_invoice_id.ids),)
                                            if refund:
                                                provider_invoice_ids += (tuple(refund.ids),)
                                            machine_request_update.update({'provider_invoice_ids': provider_invoice_ids})
                                        customer_invoice_ids = ()
                                        if customer_invoice_id or credit_note:
                                            if customer_invoice_id:
                                                customer_invoice_ids += (tuple(customer_invoice_id.ids),)
                                            if credit_note:
                                                customer_invoice_ids += (tuple(credit_note.ids),)
                                            machine_request_update.update({'customer_invoice_ids': customer_invoice_ids})
                                        '''
                                        machine_request.update(machine_request_update)
                                        request.env.cr.commit()
                                    except Exception as e1:
                                        _logger.error("%s", e1, exc_info=True)
                                        if machine_request and not machine_request.description:
                                            machine_request.update({'description': _("After the Pay Service Request submit successfuly with provider, Error is occur:") + " ==> " + str(e)})
                                            request.env.cr.commit()

                                    if not unlink_wallet_reservation and machine_wallet_reservation_id:
                                        machine_wallet_reservation_id.sudo().unlink()
                                        request.env.cr.commit()
                                        unlink_wallet_reservation = True
                                    return invalid_response(machine_request_response, _("After the Pay Service Request submit successfuly with provider, Error is occur:") + " ==> " + str(e),
                                                            500)
                            else:
                                machine_request.update({'payment_status': 'canceled' if provider_response.get('CANCEL_SUCCESS') else ('to_cancel' if provider_response.get('TO_CANCEL') else ('to_review' if provider_response.get('TO_REVIEW') else 'failure')), 'action_status': 'new' if provider_response.get('TO_CANCEL') or provider_response.get('TO_REVIEW') else 'completed'})  # ==> current 'action_status': is 'completed'
                                request.env.cr.commit()
                                error.update({provider.provider + "_response": provider_response or ''})
                        except Exception as e2:
                            _logger.error("%s", e2, exc_info=True)
                            if machine_request and not machine_request.description:
                                machine_request.update({'description': _("Error is occur:") + " ==> " + str(e2)})
                                request.env.cr.commit()
                            if not unlink_wallet_reservation and machine_wallet_reservation_id:
                                machine_wallet_reservation_id.sudo().unlink()
                                request.env.cr.commit()
                                unlink_wallet_reservation = True
                            return invalid_response("Error", _("Error is occur:") + " ==> " + str(e2), 500)
                    else:
                        error.update({provider_info.name.name + "_response": _("%s is not a provider for (%s) service") % (
                            provider_info.name.name, service.name)})

                machine_request.update({
                    'provider_response': error or _('(%s) service has not any provider.') % (service.name),
                    'stage_id': 5
                })
                request.env.cr.commit()
                error_key = "user_error"
                error_msg = _("(%s) service has not any provider.") % (service.name)
                if provider:
                    if error.get(provider.provider + "_response").get("error_message"):
                        error_msg = error.get(provider.provider + "_response").get("error_message")
                    elif error.get(provider.provider + "_response").get("error_message_to_be_translated"):
                        error_msg = error.get(provider.provider + "_response").get("error_message_to_be_translated")
                        error_key = "Error"
                elif error.get(provider_info.name.name + "_response"):
                    error_msg = error.get(provider_info.name.name + "_response")
                if not unlink_wallet_reservation and machine_wallet_reservation_id:
                    machine_wallet_reservation_id.sudo().unlink()
                    request.env.cr.commit()
                    unlink_wallet_reservation = True
                return invalid_response(error_key, error_msg, 400)

            elif request_data.get('request_type') == 'pay_invoice':
                return valid_response({"message": _("Pay invoice request was submit successfully."),
                                       "request_number": machine_request.name
                                       })
            else:
                return valid_response({"message": _("Your request was submit successfully."),
                                       "request_number":machine_request.name
                                       })

        @validate_token
        @http.route('/api/createMobileRequest', type="http", auth="none", methods=["POST"], csrf=False)
        def createMobileRequest(self, **request_data):
            _logger.info(">>>>>>>>>>>>>>>>>>> Calling Mobile Request API")

            if not request_data.get('request_type') or request_data.get('request_type') not in _REQUEST_TYPES_IDS:
                return invalid_response("request_type", _("request type invalid"), 400)

            if request_data.get('request_type') == 'recharge_wallet':
                if not request_data.get('trans_amount'):
                    return invalid_response("amount_not_found", _("missing amount in request data"), 400)
                open_request = request.env["smartpay_operations.request"].sudo().search(
                    [('request_type', '=', 'recharge_wallet'),("partner_id", "=", request.env.user.partner_id.id), ("stage_id", "=", 1)],
                    order="id DESC", limit=1)
                if open_request:
                    open_request_in_minute = open_request.filtered(
                        lambda r: r.create_date >= date_time.now() - timedelta(minutes=1))
                    if open_request_in_minute:
                        return invalid_response("request_already_exist",
                                                _("You have a wallet recharge request in progress with REQ Number (%s)")
                                                % (open_request_in_minute.name), 400)
                    else:
                        open_request.update({'stage_id': 3})
                request_data['product_id'] = request.env["product.product"].sudo().search([('name', '=', 'Wallet Recharge')]).id

            if not request_data.get('product_id') and request_data.get('request_type') not in ('general_inquiry', 'wallet_invitation'):
                return invalid_response("service_not_found", _("missing service in request data"), 400)
            elif request_data.get('request_type') not in ('general_inquiry', 'wallet_invitation'):
                service = request.env["product.product"].sudo().search([("id", "=", request_data.get('product_id')), ("type", "=", "service")],
                                                                       order="id DESC", limit=1)
                if not service:
                    return invalid_response("service", _("service invalid"), 400)

            if request_data.get('request_type') == 'wallet_invitation':
                if not request_data.get('mobile_number'):
                    return invalid_response("mobile_number_not_found", _("missing mobile number for invited user in request data"), 400)

                open_request = request.env["smartpay_operations.request"].sudo().search(
                    [('request_type', '=', 'wallet_invitation'), ('mobile_number', '=', request_data.get('mobile_number')),
                     ('partner_id', '=', request.env.user.partner_id.id), ("stage_id", "=", 1)], order="id DESC", limit=1)
                if open_request:
                    return invalid_response("request_already_exist",
                                            _("You have a wallet invitation request in progress for mobile number (%s) with REQ Number (%s)") % (
                                                request_data.get('mobile_number'), open_request.name), 400)

                done_request = request.env["smartpay_operations.request"].sudo().search(
                    [('request_type', '=', 'wallet_invitation'),
                     ('mobile_number', '=', request_data.get('mobile_number')), ("stage_id", "=", 5)],
                    order="id DESC", limit=1)
                if done_request:
                    return invalid_response("request_already_exist",
                                            _("The mobile number (%s) already has a wallet") % (
                                                request_data.get('mobile_number')), 400)

            if request_data.get('request_type') == 'service_bill_inquiry' or request_data.get('request_type') == 'pay_service_bill':
                if not request_data.get('billingAcct'):
                    return invalid_response("billingAcct_not_found", _("missing billing account in request data"), 400)

                provider_provider = request_data.get('provider')
                if request_data.get('request_type') == 'pay_service_bill':
                    if not request_data.get('currency_id'):
                        return invalid_response("curCode_not_found",
                                                _("missing bill currency code in request data"), 400)
                    if not request_data.get('pmtMethod'):
                        return invalid_response("pmtMethod_not_found",
                                                _("missing payment method in request data"), 400)

                    if provider_provider == 'khales':
                        if not request_data.get('pmtType'):
                            return invalid_response("pmtType_not_found", _("missing payment type in request data"), 400)
                        '''
                        if not request_data.get('billerId'):
                            return invalid_response("billerId_not_found", _("missing biller id in request data"), 400)
                        '''
                        if not request_data.get('ePayBillRecID'):
                            return invalid_response("ePayBillRecID_not_found", _("missing ePay Bill Rec ID in request data"), 400)
                        if not request_data.get('pmtId'):
                            return invalid_response("pmtId_not_found", _("missing payment id in request data"), 400)
                        if not request_data.get('feesAmt'):
                            return invalid_response("feesAmt_not_found", _("missing fees amount in request data"), 400)
                        # if not request_data.get('pmtRefInfo'):
                            # return invalid_response("pmtRefInfo_not_found", _("missing payment Ref Info in request data"), 400)
                        payAmtTemp = float(request_data.get('trans_amount'))
                        payAmts = request_data.get('payAmts')
                        if payAmts:
                            payAmts = ast.literal_eval(payAmts)
                            for payAmt in payAmts:
                                payAmtTemp -= float(payAmt.get('AmtDue'))
                            if payAmtTemp != 0:
                                return invalid_response("payAmts_not_match",
                                                        _("The sum of payAmts must be equals trans_amount"), 400)

                        feesAmtTemp = request_data.get('feesAmt') or 0.00
                        feesAmts = request_data.get('feesAmts')
                        if feesAmts:
                            feesAmts = ast.literal_eval(feesAmts)
                            for feeAmt in feesAmts:
                                feesAmtTemp -= float(feeAmt.get('Amt'))
                            if feesAmtTemp != 0:
                                return invalid_response("feesAmts_not_match",
                                                        _("The sum of feesAmts must be equals feesAmt"), 400)

                    if ((provider_provider == 'fawry' and request_data.get('pmtType') == "POST") or provider_provider == 'khales') \
                            and not request_data.get('billRefNumber'):
                        return invalid_response("billRefNumber_not_found", _("missing bill reference number in request data"), 400)

                    # Provider is mandatory because the service fee is different per provider.
                    # So the user must send provider that own the bill inquiry request for prevent pay bill
                    # with total amount different of total amount in bill inquiry
                    if provider_provider:
                        provider = request.env['payment.acquirer'].sudo().search([("provider", "=", provider_provider)])
                        # if provider: # Tamayoz Note: Comment this condition for solving service_providerinfo assign before initilizing
                        service_providerinfo = request.env['product.supplierinfo'].sudo().search([
                            ('product_tmpl_id', '=', service.product_tmpl_id.id),
                            ('name', '=', provider.related_partner.id)
                        ])
                        if not service_providerinfo:
                            return invalid_response(
                                "Incompatible_provider_service", _("%s is not a provider for (%s) service") % (
                                    provider_provider, service.name or '-'), 400)
                        elif provider_provider in ('fawry', 'masary'):
                            inquiryTransactionId = request_data.get('inquiryTransactionId')
                            if (json.loads(service_providerinfo.biller_info, strict=False).get('inquiry_required') # Tamayoz TODO: Rename inquiry_required in standard API
                                # or json.loads(service_providerinfo.biller_info, strict=False).get('SupportPmtReverse')
                            ) \
                                    and not inquiryTransactionId:
                                return invalid_response("inquiryTransactionId_not_found", _("missing inquiry transaction id in request data"), 400)
                    else:
                        return invalid_response("provider_not_found",
                                                _("missing provider in request data"), 400)

                    trans_amount = float(request_data.get('trans_amount'))
                    if not trans_amount:
                        return invalid_response("amount_not_found",
                                                _("missing bill amount in request data"), 400)
                    else:
                        # Calculate Fees
                        provider_fees_calculated_amount = 0.0
                        provider_fees_actual_amount = 0.0
                        merchant_cashback_amount = 0.0
                        customer_cashback_amount = 0.0
                        extra_fees_amount = 0.0
                        commissions = request.env['product.supplierinfo.commission'].sudo().search_read(
                            domain=[('vendor', '=', service_providerinfo.name.id),
                                    ('vendor_product_code', '=', service_providerinfo.product_code)],
                            fields=['Amount_Range_From', 'Amount_Range_To',
                                    'Extra_Fee_Amt', 'Extra_Fee_Prc',
                                    'Mer_Fee_Amt', 'Mer_Fee_Prc', 'Mer_Fee_Prc_MinAmt', 'Mer_Fee_Prc_MaxAmt',
                                    'Mer_Comm_Full_Fix_Amt', 'Cust_Comm_Full_Fix_Amt',
                                    'Bill_Merchant_Comm_Prc', 'Bill_Customer_Comm_Prc']
                        )
                        for commission in commissions:
                            if commission['Amount_Range_From'] <= trans_amount \
                                    and commission['Amount_Range_To'] >= trans_amount:
                                if commission['Mer_Comm_Full_Fix_Amt'] > 0:
                                    merchant_cashback_amount = commission['Mer_Comm_Full_Fix_Amt']
                                    customer_cashback_amount = commission['Cust_Comm_Full_Fix_Amt']
                                elif commission['Bill_Merchant_Comm_Prc'] > 0:
                                    merchant_cashback_amount = trans_amount * commission[
                                        'Bill_Merchant_Comm_Prc'] / 100
                                    customer_cashback_amount = trans_amount * commission[
                                        'Bill_Customer_Comm_Prc'] / 100
                                if commission['Extra_Fee_Amt'] > 0:
                                    extra_fees_amount = commission['Extra_Fee_Amt']
                                elif commission['Extra_Fee_Prc'] > 0:
                                    extra_fees_amount = trans_amount * commission['Extra_Fee_Prc'] / 100
                                if commission['Mer_Fee_Amt'] > 0:
                                    provider_fees_calculated_amount = commission['Mer_Fee_Amt']
                                elif commission['Mer_Fee_Prc'] > 0:
                                    # Fees amount = FA + [Percentage * Payment Amount]
                                    # Fees amount ====================> provider_fees_calculated_amount
                                    # FA =============================> provider_fees_calculated_amount
                                    # [Percentage * Payment Amount] ==> provider_fees_prc_calculated_amount
                                    provider_fees_prc_calculated_amount = trans_amount * commission[
                                        'Mer_Fee_Prc'] / 100
                                    if provider_fees_prc_calculated_amount < commission['Mer_Fee_Prc_MinAmt']:
                                        provider_fees_prc_calculated_amount = commission['Mer_Fee_Prc_MinAmt']
                                    elif provider_fees_prc_calculated_amount > commission['Mer_Fee_Prc_MaxAmt'] \
                                            and commission['Mer_Fee_Prc_MaxAmt'] > 0:
                                        provider_fees_prc_calculated_amount = commission['Mer_Fee_Prc_MaxAmt']
                                    provider_fees_calculated_amount += provider_fees_prc_calculated_amount
                                elif provider_provider == 'khales':
                                    provider_fees_calculated_amount = float(request_data.get('feesAmt'))
                                break
                        calculated_payment_amount = trans_amount + provider_fees_calculated_amount + extra_fees_amount

                        if service.has_sale_limit:
                            limit_fees_amounts = {}
                            for sale_limit_id in service.sale_limit_ids:
                                limit_type = sale_limit_id.limit_type
                                limit_amount = sale_limit_id.limit_amount
                                partner_sale_limit_id = request.env['res.partner.product.sale.limit'].sudo().search(
                                    [('partner_id', '=', request.env.user.partner_id.id),
                                     ('product_tmpl_id', '=', service.product_tmpl_id.id),
                                     ('limit_type', '=', limit_type)], limit=1)
                                if partner_sale_limit_id:
                                    limit_amount = partner_sale_limit_id.limit_amount
                                timetuple = date_time.now().timetuple()
                                sale_limit_domain = [('partner_id', '=', request.env.user.partner_id.id),
                                                     ('product_id', '=', service.id),
                                                     ('limit_type', '=', limit_type),
                                                     ('year', '=', timetuple.tm_year)]
                                if limit_type == 'daily':
                                    sale_limit_domain += [('day', '=', timetuple.tm_yday)]
                                elif limit_type == 'weekly':
                                    sale_limit_domain += [('week', '=', date_time.now().isocalendar()[1])]
                                elif limit_type == 'monthly':
                                    sale_limit_domain += [('month', '=', timetuple.tm_mon)]
                                sale_limit = request.env['res.partner.sale.limit'].sudo().search(sale_limit_domain,
                                                                                                 order="id DESC",
                                                                                                 limit=1)
                                calculated_sold_amount = calculated_payment_amount
                                if sale_limit:
                                    calculated_sold_amount += sale_limit.sold_amount
                                if limit_amount < calculated_sold_amount:
                                    over_limit_fees_ids = []
                                    if partner_sale_limit_id:
                                        if partner_sale_limit_id.over_limit_fees_policy == 'product_over_limit_fees' and partner_sale_limit_id.product_over_limit_fees_ids:
                                            over_limit_fees_ids = partner_sale_limit_id.product_over_limit_fees_ids
                                            limit_amount = over_limit_fees_ids.sorted(lambda l: l.sale_amount_to, reverse=True)[0].sale_amount_to + partner_sale_limit_id.limit_amount
                                        if partner_sale_limit_id.over_limit_fees_policy == 'custom_over_limit_fees' and partner_sale_limit_id.over_limit_fees_ids:
                                            over_limit_fees_ids = partner_sale_limit_id.over_limit_fees_ids
                                            limit_amount = over_limit_fees_ids.sorted(lambda l: l.sale_amount_to, reverse=True)[0].sale_amount_to + partner_sale_limit_id.limit_amount
                                    else:
                                        if sale_limit_id.has_over_limit_fees and sale_limit_id.over_limit_fees_ids:
                                            over_limit_fees_ids = sale_limit_id.over_limit_fees_ids
                                            limit_amount = over_limit_fees_ids.sorted(lambda l: l.sale_amount_to, reverse=True)[0].sale_amount_to + sale_limit_id.limit_amount

                                    if limit_amount < calculated_sold_amount:
                                        return invalid_response("%s_limit_exceeded" % limit_type,
                                                                _("%s limit exceeded for service (%s)") % (
                                                                    limit_type, service.name), 400)

                                    limit_fees_amount = 0
                                    for over_limit_fees_id in over_limit_fees_ids:
                                        if over_limit_fees_id['sale_amount_from'] <= trans_amount and over_limit_fees_id['sale_amount_to'] >= trans_amount:
                                            if over_limit_fees_id['fees_amount'] > 0:
                                                limit_fees_amount = over_limit_fees_id['fees_amount']
                                            elif over_limit_fees_id['fees_amount_percentage'] > 0:
                                                limit_fees_amount = trans_amount * over_limit_fees_id['fees_amount_percentage'] / 100
                                            break
                                    if limit_fees_amount > 0:
                                        limit_fees_amounts.update({limit_type: limit_fees_amount})
                                        calculated_payment_amount += limit_fees_amount

                        if request_data.get("wallet_id"):
                            partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(wallet_id=request_data.get("wallet_id"),
                                                                                                   service=service,
                                                                                                   trans_amount=calculated_payment_amount)
                        else:
                            partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(service=service,
                                                                                                   trans_amount=calculated_payment_amount)
                        if not partner_wallet_id:
                            return invalid_response("wallet_not_found",
                                                    _("No Matched Wallet found for partner [%s] %s") % (
                                                        request.env.user.partner_id.ref,
                                                        request.env.user.partner_id.name), 400)

                        # Check Wallet Transaction limits
                        if partner_wallet_id.type.has_trans_limit:
                            wallet_limit_fees_amounts = {}
                            for trans_limit_id in partner_wallet_id.type.trans_limit_ids:
                                wallet_limit_type = trans_limit_id.limit_type
                                wallet_limit_amount = trans_limit_id.limit_amount
                                wallet_trans_limit_id = request.env['wallet.wallet.type.trans.limit'].sudo().search(
                                    [('wallet_id', '=', partner_wallet_id.id),
                                     # ('wallet_type_id', '=', partner_wallet_id.type.id),
                                     ('limit_type', '=', wallet_limit_type)], limit=1)
                                if wallet_trans_limit_id:
                                    wallet_limit_amount = wallet_trans_limit_id.limit_amount
                                timetuple = date_time.now().timetuple()
                                trans_limit_domain = [('wallet_id', '=', partner_wallet_id.id),
                                                      # ('wallet_type_id', '=', partner_wallet_id.type.id),
                                                      ('limit_type', '=', wallet_limit_type),
                                                      ('year', '=', timetuple.tm_year)]
                                if wallet_limit_type == 'daily':
                                    trans_limit_domain += [('day', '=', timetuple.tm_yday)]
                                elif wallet_limit_type == 'weekly':
                                    trans_limit_domain += [('week', '=', date_time.now().isocalendar()[1])]
                                elif wallet_limit_type == 'monthly':
                                    trans_limit_domain += [('month', '=', timetuple.tm_mon)]
                                trans_limit = request.env['wallet.trans.limit'].sudo().search(trans_limit_domain,
                                                                                              order="id DESC", limit=1)
                                calculated_trans_amount = calculated_payment_amount
                                if trans_limit:
                                    calculated_trans_amount += trans_limit.trans_amount
                                if wallet_limit_amount < calculated_trans_amount:
                                    wallet_over_limit_fees_ids = []
                                    if wallet_trans_limit_id:
                                        if wallet_trans_limit_id.over_limit_fees_policy == 'wallet_type_over_limit_fees' and wallet_trans_limit_id.wallet_type_over_limit_fees_ids:
                                            wallet_over_limit_fees_ids = wallet_trans_limit_id.wallet_type_over_limit_fees_ids
                                            wallet_limit_amount = wallet_over_limit_fees_ids.sorted(lambda l: l.trans_amount_to, reverse=True)[0].trans_amount_to + wallet_trans_limit_id.limit_amount
                                        if wallet_trans_limit_id.over_limit_fees_policy == 'custom_over_limit_fees' and wallet_trans_limit_id.over_limit_fees_ids:
                                            wallet_over_limit_fees_ids = wallet_trans_limit_id.over_limit_fees_ids
                                            wallet_limit_amount = wallet_over_limit_fees_ids.sorted(lambda l: l.trans_amount_to, reverse=True)[0].trans_amount_to + wallet_trans_limit_id.limit_amount
                                    else:
                                        if trans_limit_id.has_over_limit_fees and trans_limit_id.over_limit_fees_ids:
                                            wallet_over_limit_fees_ids = trans_limit_id.over_limit_fees_ids
                                            wallet_limit_amount = wallet_over_limit_fees_ids.sorted(lambda l: l.trans_amount_to, reverse=True)[0].trans_amount_to + trans_limit_id.limit_amount

                                    if wallet_limit_amount < calculated_trans_amount:
                                        return invalid_response("%s_limit_exceeded" % wallet_limit_type,
                                                                _("%s limit exceeded for wallet type (%s)") % (
                                                                    wallet_limit_type, partner_wallet_id.type.name), 400)

                                    wallet_limit_fees_amount = 0
                                    for wallet_over_limit_fees_id in wallet_over_limit_fees_ids:
                                        if wallet_over_limit_fees_id['trans_amount_from'] <= trans_amount and wallet_over_limit_fees_id['trans_amount_to'] >= trans_amount:
                                            if wallet_over_limit_fees_id['fees_amount'] > 0:
                                                wallet_limit_fees_amount = wallet_over_limit_fees_id['fees_amount']
                                            elif wallet_over_limit_fees_id['fees_amount_percentage'] > 0:
                                                wallet_limit_fees_amount = trans_amount * wallet_over_limit_fees_id['fees_amount_percentage'] / 100
                                            break
                                    if wallet_limit_fees_amount > 0:
                                        wallet_limit_fees_amounts.update({wallet_limit_type: wallet_limit_fees_amount})
                                        calculated_payment_amount += wallet_limit_fees_amount
                        
                        unlink_wallet_reservation = False
                        mobile_wallet_reservation_id, mobile_wallet_balance, mobile_wallet_available_amount = \
                            partner_wallet_id.update_wallet_reserved_balance(
                            _('Pay Service Bill for %s service') % (service.name), calculated_payment_amount,
                            request.env.user.company_id.currency_id, 'request'
                        )
                        # # mobile_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                        # mobile_wallet_available_amount = partner_wallet_id.available_amount if partner_wallet_id else 0
                        # if mobile_wallet_available_amount < calculated_payment_amount:
                        if not mobile_wallet_reservation_id:
                            return invalid_response("mobile_balance_not_enough",
                                                    _("Mobile Wallet Available Balance (%s) less than the payment amount (%s)") % (
                                                        mobile_wallet_available_amount, calculated_payment_amount), 400)

            request_data['partner_id'] = request.env.user.partner_id.id
            model_name = 'smartpay_operations.request'
            model_record = request.env['ir.model'].sudo().search([('model', '=', model_name)])

            try:
                data = WebsiteForm().extract_data(model_record, request_data)
            # If we encounter an issue while extracting data
            except ValidationError as e:
                # I couldn't find a cleaner way to pass data to an exception
                return invalid_response("Error", _("Could not submit you request.") + " ==> " + str(e), 500)

            try:
                id_record = WebsiteForm().insert_record(request, model_record, data['record'], data['custom'], data.get('meta'))
                if id_record:
                    WebsiteForm().insert_attachment(model_record, id_record, data['attachments'])
                    request.env.cr.commit()
                    user_request = model_record.env[model_name].sudo().browse(id_record)
                else:
                    return invalid_response("Error", _("Could not submit you request."), 500)

            # Some fields have additional SQL constraints that we can't check generically
            # Ex: crm.lead.probability which is a float between 0 and 1
            # TODO: How to get the name of the erroneous field ?
            except IntegrityError as e:
                return invalid_response("Error", _("Could not submit you request.") + " ==> " + str(e), 500)

            if request_data.get('request_type') == 'recharge_wallet':
                return valid_response({"message": _("Recharge your wallet request was submit successfully."),
                                       "request_number": user_request.name
                                       })
            elif request_data.get('request_type') == 'wallet_invitation':
                return valid_response({"message": _("Wallet inivitation request for mobile number (%s) was submit successfully.") % (
                                                request_data.get('mobile_number')),
                                        "request_number": user_request.name
                                       })

            elif request_data.get('request_type') == 'service_bill_inquiry':
                lang = request_data.get('lang')
                billingAcct = request_data.get('billingAcct')
                extraBillingAcctKeys = request_data.get('extraBillingAcctKeys')
                if extraBillingAcctKeys:
                    extraBillingAcctKeys = ast.literal_eval(extraBillingAcctKeys)
                customProperties = request_data.get('customProperties')
                if customProperties:
                    customProperties = ast.literal_eval(customProperties)

                provider_response = {}
                error = {}
                for provider_info in service.seller_ids:
                    provider = request.env['payment.acquirer'].sudo().search([("related_partner", "=", provider_info.name.id)])
                    if provider:
                        if provider.server_state == 'offline':
                            error.update({provider.provider + "_response": {'error_message': _("Service Not Available")}})
                            break
                        trans_amount = 0.0
                        provider_channel = False
                        machine_channels = request.env['payment.acquirer.channel'].sudo().search([("acquirer_id", "=", provider.id),
                                                                                                  ("type", "in", ("machine", "internet"))], limit=1)
                        if machine_channels:
                            provider_channel = machine_channels[0]

                        if provider.provider == "fawry":
                            provider_response = provider.get_fawry_bill_details(lang, provider_info.product_code,
                                                                                billingAcct, extraBillingAcctKeys,
                                                                                provider_channel, customProperties,
                                                                                user_request.name)
                            if provider_response.get('Success'):
                                billRecType = provider_response.get('Success')
                                provider_response_json = suds_to_json(billRecType)
                                for BillSummAmt in billRecType['BillInfo']['BillSummAmt']:
                                    if BillSummAmt['BillSummAmtCode'] == 'TotalAmtDue':
                                        trans_amount += float(BillSummAmt['CurAmt']['Amt'])
                                        break
                        elif provider.provider == "khales":
                            provider_response = {}
                            biller_info_json_dict = json.loads(provider_info.with_context(lang=request.env.user.lang).biller_info, strict=False)
                            # Handel billingAcct format if exist
                            if biller_info_json_dict.get('BillTypeAcctFormat') and biller_info_json_dict.get('BillTypeAcctFormatSpliter'):
                                formatedBillingAcct = []
                                keysToBeRemoved = []
                                for format in biller_info_json_dict.get('BillTypeAcctFormat').split(biller_info_json_dict.get('BillTypeAcctFormatSpliter')):
                                    if format == 'billingAcct':
                                        formatedBillingAcct.append(billingAcct)
                                    else:
                                        is_extra_key = False
                                        for extraBillingAcctKey in extraBillingAcctKeys:
                                            if extraBillingAcctKey.get("Key") == format:
                                                formatedBillingAcct.append(extraBillingAcctKey.get("Value"))
                                                keysToBeRemoved.append(extraBillingAcctKey)
                                                is_extra_key = True
                                                break
                                        if not is_extra_key:
                                            formatedBillingAcct.append(format)
                                extraBillingAcctKeys = [x for x in extraBillingAcctKeys if x not in keysToBeRemoved]
                                billingAcct = biller_info_json_dict.get('BillTypeAcctFormatSpliter').join(formatedBillingAcct)

                            '''
                            machine_serial = None
                            if len(request.env.user.machine_serial) > 16:  # Ingenico POS
                                machine_serial = request.env.user.machine_serial
                                machine_serial = machine_serial[len(machine_serial) - 16:len(machine_serial)]
                            '''
                            machine_serial = request.env.user.machine_serial
                            if machine_serial and len(machine_serial) > 16:
                                machine_serial = machine_serial[len(machine_serial) - 16:len(machine_serial)]
                            bill_response = provider.get_khales_bill_details(lang, machine_serial or user_request.name,
                                                                             provider_info.product_code, biller_info_json_dict.get('Code'),
                                                                             billingAcct, extraBillingAcctKeys, provider_channel, user_request.name)
                            if bill_response.get('Success'):
                                billRecType = bill_response.get('Success')
                                payAmts = billRecType['BillInfo']['CurAmt']
                                if payAmts and isinstance(payAmts, OrderedDict):
                                    payAmts = [payAmts]
                                    billRecType['BillInfo']['CurAmt'] = payAmts
                                success_response = {"bill_response": suds_to_json(billRecType)}
                                # for payAmt in payAmts:
                                    # trans_amount += float(payAmt.get("AmtDue"))
                                trans_amount += float(payAmts[0].get("AmtDue"))
                                if biller_info_json_dict.get('PmtType') == 'POST':
                                    ePayBillRecID = billRecType['EPayBillRecID']
                                    fees_response = provider.get_khales_fees(lang, machine_serial or user_request.name,
                                                                             ePayBillRecID, payAmts[0], provider_channel, user_request.name)
                                    provider_fees_calculated_amount = 0.0
                                    if fees_response.get('Success'):
                                        feeInqRsType = fees_response.get('Success')
                                        provider_fees_calculated_amount = float(feeInqRsType['FeesAmt']['Amt'])
                                        # success_response.update({"fees_response": suds_to_json(feeInqRsType)})
                                    else:
                                        feeInqRsType = {"EPayBillRecID": ePayBillRecID,
                                                        "FeesAmt": {"Amt": "0.0", "CurCode": "818"}}

                                    if provider_fees_calculated_amount == 0:
                                        service_providerinfo = request.env['product.supplierinfo'].sudo().search([
                                            ('product_tmpl_id', '=', service.product_tmpl_id.id),
                                            ('name', '=', provider.related_partner.id)
                                        ])
                                        commissions = request.env[
                                            'product.supplierinfo.commission'].sudo().search_read(
                                            domain=[('vendor', '=', service_providerinfo.name.id),
                                                    (
                                                        'vendor_product_code', '=', service_providerinfo.product_code)],
                                            fields=['Amount_Range_From', 'Amount_Range_To',
                                                    'Extra_Fee_Amt', 'Extra_Fee_Prc',
                                                    'Mer_Fee_Amt', 'Mer_Fee_Prc', 'Mer_Fee_Prc_MinAmt',
                                                    'Mer_Fee_Prc_MaxAmt']
                                        )
                                        for commission in commissions:
                                            if commission['Amount_Range_From'] <= trans_amount \
                                                    and commission['Amount_Range_To'] >= trans_amount:
                                                if commission['Extra_Fee_Amt'] > 0:
                                                    extra_fees_amount = commission['Extra_Fee_Amt']
                                                elif commission['Extra_Fee_Prc'] > 0:
                                                    extra_fees_amount = trans_amount * commission[
                                                        'Extra_Fee_Prc'] / 100
                                                if commission['Mer_Fee_Amt'] > 0:
                                                    provider_fees_calculated_amount = commission['Mer_Fee_Amt']
                                                elif commission['Mer_Fee_Prc'] > 0:
                                                    # Fees amount = FA + [Percentage * Payment Amount]
                                                    # Fees amount ====================> provider_fees_calculated_amount
                                                    # FA =============================> provider_fees_calculated_amount
                                                    # [Percentage * Payment Amount] ==> provider_fees_prc_calculated_amount
                                                    provider_fees_prc_calculated_amount = trans_amount * commission[
                                                        'Mer_Fee_Prc'] / 100
                                                    if provider_fees_prc_calculated_amount < commission[
                                                        'Mer_Fee_Prc_MinAmt']:
                                                        provider_fees_prc_calculated_amount = commission[
                                                            'Mer_Fee_Prc_MinAmt']
                                                    elif provider_fees_prc_calculated_amount > commission[
                                                        'Mer_Fee_Prc_MaxAmt'] \
                                                            and commission['Mer_Fee_Prc_MaxAmt'] > 0:
                                                        provider_fees_prc_calculated_amount = commission[
                                                            'Mer_Fee_Prc_MaxAmt']
                                                    provider_fees_calculated_amount += provider_fees_prc_calculated_amount
                                                break
                                        feeInqRsType['FeesAmt']['Amt'] = "%s" % ((math.floor(provider_fees_calculated_amount * 100)) / 100.0)

                                    success_response.update({"fees_response": suds_to_json(feeInqRsType)})
                                provider_response = {'Success': success_response}

                                provider_response_json = provider_response.get('Success')
                            else:
                                provider_response = bill_response
                        elif provider.provider == "masary":
                            provider_response = provider.get_masary_bill_details(lang, int(provider_info.product_code),
                                                                                extraBillingAcctKeys, provider_channel, user_request.name)
                            if provider_response.get('Success'):
                                billData = provider_response.get('Success')
                                provider_response_json = billData
                                if billData.get('amount'):
                                    trans_amount += float(billData.get('amount'))
                                # elif billData.get('min_amount'):
                                    # trans_amount += float(billData.get('min_amount'))

                        if provider_response.get('Success'):
                            # if not provider_response_json:
                                # provider_response_json = suds_to_json(provider_response.get('Success'))
                            commissions = request.env['product.supplierinfo.commission'].sudo().search_read(
                                domain=[('vendor', '=', provider_info.name.id), ('vendor_product_code', '=', provider_info.product_code)],
                                fields=['Amount_Range_From', 'Amount_Range_To', 'Extra_Fee_Amt', 'Extra_Fee_Prc']
                            )
                            extra_fees_amount = 0.0
                            for commission in commissions:
                                if commission['Amount_Range_From'] <= trans_amount \
                                        and commission['Amount_Range_To'] >= trans_amount:
                                    if commission['Extra_Fee_Amt'] > 0:
                                        extra_fees_amount = commission['Extra_Fee_Amt']
                                    elif commission['Extra_Fee_Prc'] > 0:
                                        extra_fees_amount = trans_amount * commission['Extra_Fee_Prc'] / 100
                                    break
                            user_request.update(
                                {"provider_id": provider.id, "provider_response": provider_response_json,
                                 "trans_amount": trans_amount, "extra_fees_amount": extra_fees_amount,
                                 "extra_fees": commissions, "stage_id": 5})
                            request.env.cr.commit()
                            return valid_response(
                                {"message": _("Service Bill Inquiry request was submit successfully."),
                                 "request_number": user_request.name,
                                 "provider": provider.provider,
                                 "provider_response": provider_response_json,
                                 "extra_fees_amount": extra_fees_amount,
                                 # "extra_fees": commissions
                                 })
                        else:
                            error.update({provider.provider + "_response": provider_response or ''})
                    else:
                        error.update({provider_info.name.name + "_response": _("%s is not a provider for (%s) service") % (
                            provider_info.name.name, service.name)})

                user_request.update({
                    "provider_response": error or _("(%s) service has not any provider.") % (service.name),
                    "stage_id": 5
                })
                request.env.cr.commit()
                error_key = "user_error"
                error_msg = _("(%s) service has not any provider.") % (service.name)
                if provider:
                    if error.get(provider.provider + "_response").get("error_message"):
                        error_msg = error.get(provider.provider + "_response").get("error_message")
                    elif error.get(provider.provider + "_response").get("error_message_to_be_translated"):
                        error_msg = error.get(provider.provider + "_response").get("error_message_to_be_translated")
                        error_key = "Error"
                elif error.get(provider_info.name.name + "_response"):
                    error_msg = error.get(provider_info.name.name + "_response")
                return invalid_response(error_key, error_msg, 400)

            elif request_data.get('request_type') == 'pay_service_bill':
                if mobile_wallet_reservation_id:
                    mobile_wallet_reservation_id.update({'request_id': user_request.id})
                    request.env.cr.commit()
                lang = request_data.get('lang')
                billingAcct = request_data.get('billingAcct')

                extraBillingAcctKeys = request_data.get('extraBillingAcctKeys')
                if extraBillingAcctKeys:
                    extraBillingAcctKeys = ast.literal_eval(extraBillingAcctKeys)

                notifyMobile = request_data.get('notifyMobile')
                billRefNumber = request_data.get('billRefNumber')
                billerId = request_data.get('billerId')
                pmtType = request_data.get('pmtType')

                trans_amount = request_data.get('trans_amount')
                curCode = request_data.get('currency_id')
                payAmts = request_data.get('payAmts')
                if payAmts:
                    payAmts = ast.literal_eval(payAmts)
                else:
                    payAmts = [{'Sequence':'1', 'AmtDue':trans_amount, 'CurCode':curCode}]
                pmtMethod = request_data.get('pmtMethod')

                ePayBillRecID = request_data.get('ePayBillRecID')
                pmtId = request_data.get('pmtId') or user_request.name
                feesAmt = request_data.get('feesAmt') or 0.00
                feesAmts = request_data.get('feesAmts')
                if feesAmts:
                    feesAmts = ast.literal_eval(feesAmts)
                else:
                    feesAmts = [{'Amt': feesAmt, 'CurCode': curCode}]
                pmtRefInfo = request_data.get('pmtRefInfo')

                providers_info = []
                '''
                provider_provider = request_data.get('provider')
                if provider_provider:
                    provider = request.env['payment.acquirer'].sudo().search([("provider", "=", provider_provider)])
                    if provider:
                        service_providerinfo = request.env['product.supplierinfo'].sudo().search([
                            ('product_tmpl_id', '=', service.product_tmpl_id.id),
                            ('name', '=', provider.related_partner.id)
                        ])
                        if service_providerinfo:
                            providers_info.append(service_providerinfo)
                if not provider_provider or len(providers_info) == 0:
                    providers_info = service.seller_ids
                '''
                providers_info.append(service_providerinfo)

                provider_response = {}
                provider_response_json = {}
                '''
                provider_fees_calculated_amount = 0.0
                provider_fees_actual_amount = 0.0
                merchant_cashback_amount = 0.0
                customer_cashback_amount = 0.0
                extra_fees_amount = 0.0
                '''
                error = {}
                for provider_info in providers_info:
                    biller_info_json_dict = json.loads(provider_info.with_context(lang=request.env.user.lang).biller_info, strict=False)
                    '''
                    # Get Extra Fees
                    commissions = request.env['product.supplierinfo.commission'].sudo().search_read(
                        domain=[('vendor', '=', provider_info.name.id),
                                ('vendor_product_code', '=', provider_info.product_code)],
                        fields=['Amount_Range_From', 'Amount_Range_To',
                                'Extra_Fee_Amt', 'Extra_Fee_Prc',
                                'Mer_Fee_Amt', 'Mer_Fee_Prc', 'Mer_Fee_Prc_MinAmt', 'Mer_Fee_Prc_MaxAmt',
                                'Mer_Comm_Full_Fix_Amt', 'Cust_Comm_Full_Fix_Amt',
                                'Bill_Merchant_Comm_Prc', 'Bill_Customer_Comm_Prc']
                    )
                    for commission in commissions:
                        if commission['Amount_Range_From'] <= machine_request.trans_amount \
                                and commission['Amount_Range_To'] >= machine_request.trans_amount:
                            if commission['Mer_Comm_Full_Fix_Amt'] > 0:
                                merchant_cashback_amount = commission['Mer_Comm_Full_Fix_Amt']
                                customer_cashback_amount = commission['Cust_Comm_Full_Fix_Amt']
                            elif commission['Bill_Merchant_Comm_Prc'] > 0:
                                merchant_cashback_amount = machine_request.trans_amount * commission[
                                    'Bill_Merchant_Comm_Prc'] / 100
                                customer_cashback_amount = machine_request.trans_amount * commission[
                                    'Bill_Customer_Comm_Prc'] / 100
                            if commission['Extra_Fee_Amt'] > 0:
                                extra_fees_amount = commission['Extra_Fee_Amt']
                            elif commission['Extra_Fee_Prc'] > 0:
                                extra_fees_amount = machine_request.trans_amount * commission['Extra_Fee_Prc'] / 100
                            if commission['Mer_Fee_Amt'] > 0:
                                provider_fees_calculated_amount = commission['Mer_Fee_Amt']
                            elif commission['Mer_Fee_Prc'] > 0:
                                # Fees amount = FA + [Percentage * Payment Amount]
                                # Fees amount ====================> provider_fees_calculated_amount
                                # FA =============================> provider_fees_calculated_amount
                                # [Percentage * Payment Amount] ==> provider_fees_prc_calculated_amount
                                provider_fees_prc_calculated_amount = machine_request.trans_amount * commission['Mer_Fee_Prc'] / 100
                                if provider_fees_prc_calculated_amount < commission['Mer_Fee_Prc_MinAmt']:
                                    provider_fees_prc_calculated_amount = commission['Mer_Fee_Prc_MinAmt']
                                elif provider_fees_prc_calculated_amount > commission['Mer_Fee_Prc_MaxAmt'] \
                                        and commission['Mer_Fee_Prc_MaxAmt'] > 0:
                                    provider_fees_prc_calculated_amount = commission['Mer_Fee_Prc_MaxAmt']
                                provider_fees_calculated_amount += provider_fees_prc_calculated_amount
                            elif provider_provider == 'khales':
                                provider_fees_calculated_amount = float(request_data.get('feesAmt'))
                            break
                    calculated_payment_amount = machine_request.trans_amount + provider_fees_calculated_amount + extra_fees_amount
                    if request_data.get("wallet_id"):
                        partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(wallet_id=request_data.get("wallet_id"),
                                                                                               service=service,
                                                                                               trans_amount=calculated_payment_amount)
                    else:
                        partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(service=service,
                                                                                               trans_amount=calculated_payment_amount)
                    unlink_wallet_reservation = False
                    mobile_wallet_reservation_id, mobile_wallet_balance, mobile_wallet_available_amount = partner_wallet_id.update_wallet_reserved_balance(
                            _('Pay Service Bill for %s service') % (service.name), calculated_payment_amount,
                            request.env.user.company_id.currency_id, 'request'
                        )
                    # # mobile_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                    # mobile_wallet_available_amount = partner_wallet_id.available_amount if partner_wallet_id else 0
                    # if mobile_wallet_available_amount < calculated_payment_amount:
                    if not mobile_wallet_reservation_id:
                        error.update({"mobile_balance_not_enough":
                                                _("Mobile Wallet Available Balance (%s) less than the payment amount (%s)") % (mobile_wallet_available_amount,
                                                                                                                      calculated_payment_amount)})
                    '''

                    user_request.update({'provider_fees_calculated_amount': provider_fees_calculated_amount})
                    request.env.cr.commit()
                    provider = request.env['payment.acquirer'].sudo().search([("related_partner", "=", provider_info.name.id)])
                    if provider:
                        try:
                            if provider.server_state == 'offline':
                                error.update({provider.provider + "_response": {'error_message': _("Service Not Available")}})
                                break
                            provider_channel = False
                            machine_channels = request.env['payment.acquirer.channel'].sudo().search([("acquirer_id", "=", provider.id),
                                                                                                      ("type", "in", ("mobile", "internet"))], limit=1)
                            if machine_channels:
                                provider_channel = machine_channels[0]
                            if provider.provider == "fawry":
                                # Tamayoz TODO: Provider Server Timeout Handling
                                user_request.update({'action_status': 'in_progress'})  # ==> current 'payment_status': is 'new'
                                request.env.cr.commit()
                                provider_response = provider.pay_fawry_bill(lang, provider_info.product_code,
                                                                            billingAcct, extraBillingAcctKeys,
                                                                            trans_amount, curCode, pmtMethod,
                                                                            notifyMobile, billRefNumber,
                                                                            billerId, pmtType, provider_channel,
                                                                            inquiryTransactionId, user_request.name,
                                                                            biller_info_json_dict.get('SupportPmtReverse'),
                                                                            biller_info_json_dict.get('AllowRetry'))
                                if provider_response.get('Success'):
                                    if provider_response.get('Success').get('timeout'):
                                        user_request.update({'payment_status': 'timeout'}) # ==> current 'action_status': is 'in_progress'
                                        if biller_info_json_dict.get('PmtType') == 'VOCH':
                                            provider_response = {"error_code": "0", "error_message": None,
                                                                 "error_message_to_be_translated": "FW Server timeout:\n",}
                                            if biller_info_json_dict.get('SupportPmtReverse'):
                                                provider_response.update({"TO_CANCEL": "VOCH"})
                                            else:
                                                provider_response.update({"TO_REVIEW": "VOCH"})
                                    else:
                                        user_request.update({'action_status': 'completed'}) # ==> current 'payment_status': is 'new'
                                    request.env.cr.commit()
                                    if not provider_response.get('error_code'):
                                        provider_response_json = suds_to_json(provider_response.get('Success')['pmtInfoValType'])
                                        msgRqHdr_response_json = suds_to_json(provider_response.get('Success')['msgRqHdrType'])
                                        # Get customProperties
                                        msgRqHdr_response_json_dict = json.loads(msgRqHdr_response_json, strict=False)
                                        customProperties = msgRqHdr_response_json_dict.get('CustomProperties')
                                        cardMetadata = ''
                                        if customProperties:
                                            # Get CardMetadata
                                            for customProperty in customProperties['CustomProperty']:
                                                if customProperty['Key'] == 'CardMetadata':
                                                    cardMetadata = customProperty['Value']
                                                    break
                                        # Get Provider Fees
                                        provider_response_json_dict = json.loads(provider_response_json, strict=False)
                                        # provider_response_json_dict['PmtInfo']['CurAmt']['Amt'] == user_request.trans_amount
                                        provider_fees_actual_amount = provider_response_json_dict['PmtInfo']['FeesAmt']['Amt']
                                        user_request.update({'provider_fees_amount': provider_fees_actual_amount})
                                        request.env.cr.commit()
                                        # Get Provider Payment Trans ID
                                        for payment in provider_response_json_dict['PmtTransId']:
                                            if payment['PmtIdType'] == 'FCRN':
                                                provider_payment_trans_id = payment['PmtId']
                                                break

                            elif provider.provider == "khales":
                                if not billerId:
                                    billerId = biller_info_json_dict.get('Code')
                                # Handel billingAcct format if exist
                                if biller_info_json_dict.get('BillTypeAcctFormat') and biller_info_json_dict.get('BillTypeAcctFormatSpliter'):
                                    formatedBillingAcct = []
                                    keysToBeRemoved = []
                                    for format in biller_info_json_dict.get('BillTypeAcctFormat').split(biller_info_json_dict.get('BillTypeAcctFormatSpliter')):
                                        if format == 'billingAcct':
                                            formatedBillingAcct.append(billingAcct)
                                        else:
                                            is_extra_key = False
                                            for extraBillingAcctKey in extraBillingAcctKeys:
                                                if extraBillingAcctKey.get("Key") == format:
                                                    formatedBillingAcct.append(extraBillingAcctKey.get("Value"))
                                                    keysToBeRemoved.append(extraBillingAcctKey)
                                                    is_extra_key = True
                                                    break
                                            if not is_extra_key:
                                                formatedBillingAcct.append(format)
                                    extraBillingAcctKeys = [x for x in extraBillingAcctKeys if
                                                            x not in keysToBeRemoved]
                                    billingAcct = biller_info_json_dict.get('BillTypeAcctFormatSpliter').join(formatedBillingAcct)
                                # Tamayoz TODO: Provider Server Timeout Handling
                                # Tamayoz TODO: Remove the next temporary line
                                pmtMethod = "CARD"  # TEMP CODE
                                user_request.update({'action_status': 'in_progress'})  # ==> current 'payment_status': is 'new'
                                request.env.cr.commit()
                                '''
                                machine_serial = None
                                if len(request.env.user.machine_serial) > 16:  # Ingenico POS
                                    machine_serial = request.env.user.machine_serial
                                    machine_serial = machine_serial[len(machine_serial) - 16:len(machine_serial)]
                                '''
                                machine_serial = request.env.user.machine_serial
                                if machine_serial and len(machine_serial) > 16:
                                    machine_serial = machine_serial[len(machine_serial) - 16:len(machine_serial)]
                                provider_response = provider.pay_khales_bill(lang, machine_serial or user_request.name,
                                                                             billingAcct, extraBillingAcctKeys, billerId, ePayBillRecID,
                                                                             payAmts, pmtId, pmtType, feesAmts,
                                                                             billRefNumber, pmtMethod, pmtRefInfo,
                                                                             provider_channel, user_request.name,
                                                                             biller_info_json_dict.get('SupportPmtReverse'),
                                                                             biller_info_json_dict.get('AllowRetry'))
                                if provider_response.get('Success'):
                                    if provider_response.get('Success').get('timeout'):
                                        user_request.update({'payment_status': 'timeout'}) # ==> current 'action_status': is 'in_progress'
                                        if biller_info_json_dict.get('PmtType') == 'VOCH':
                                            provider_response = {"error_code": "0", "error_message": None,
                                                                 "error_message_to_be_translated": "KH Server timeout:\n",}
                                            if biller_info_json_dict.get('SupportPmtReverse'):
                                                provider_response.update({"TO_CANCEL": "VOCH"})
                                            else:
                                                provider_response.update({"TO_REVIEW": "VOCH"})
                                    else:
                                        user_request.update({'action_status': 'completed'}) # ==> current 'payment_status': is 'new'
                                    request.env.cr.commit()
                                    if not provider_response.get('error_code'):
                                        provider_response_json = suds_to_json(provider_response.get('Success'))
                                        # Add required parameters for cancel payment scenario
                                        # parsing JSON string:
                                        provider_response_json_dict = json.loads(provider_response_json)
                                        pmtId = provider_response_json_dict['PmtRecAdviceStatus']['PmtTransId']['PmtId']
                                        # appending the data
                                        provider_response_json_dict.update({'billingAcct': billingAcct, 'billRefNumber': billRefNumber,
                                                                            'billerId': billerId, 'pmtType': pmtType, 'trans_amount': trans_amount,
                                                                            'curCode': curCode, 'pmtMethod': pmtMethod, 'ePayBillRecID': ePayBillRecID,
                                                                            'pmtId': pmtId, 'feesAmt': feesAmt, 'pmtRefInfo': pmtRefInfo})
                                        if payAmts:
                                            provider_response_json_dict.update({'payAmts': payAmts})
                                        if feesAmts:
                                            provider_response_json_dict.update({'feesAmts': feesAmts})
                                        # the result is a JSON string:
                                        provider_response_json = json.dumps(provider_response_json_dict)
                                        # Provider Fees
                                        provider_fees_actual_amount = float(feesAmt)
                                        user_request.update({'provider_fees_amount': provider_fees_actual_amount})
                                        request.env.cr.commit()
                                        # Provider Payment Trans ID
                                        provider_payment_trans_id = pmtId
                            elif provider.provider == "masary":
                                user_request.update({'action_status': 'in_progress'}) # ==> current 'payment_status': is 'new'
                                request.env.cr.commit()
                                provider_response = provider.pay_masary_bill(lang, int(provider_info.product_code),
                                                                             float(trans_amount), float(feesAmt),
                                                                             inquiryTransactionId, 1, # quantity
                                                                             extraBillingAcctKeys, provider_channel, user_request.name)
                                if provider_response.get('Success'):
                                    if provider_response.get('Success').get('timeout'):
                                        user_request.update({'payment_status': 'timeout'}) # ==> current 'action_status': is 'in_progress'
                                        if biller_info_json_dict.get('PmtType') == 'VOCH':
                                            provider_response = {"error_code": "0", "error_message": None,
                                                                 "error_message_to_be_translated": "KH Server timeout:\n",}
                                            if biller_info_json_dict.get('SupportPmtReverse'):
                                                provider_response.update({"TO_CANCEL": "VOCH"})
                                            else:
                                                provider_response.update({"TO_REVIEW": "VOCH"})
                                    else:
                                        user_request.update({'action_status': 'completed'}) # ==> current 'payment_status': is 'new'
                                    request.env.cr.commit()
                                    if not provider_response.get('error_code'):
                                        provider_response_json = provider_response.get('Success')
                                        # Get Provider Fees
                                        # provider_response_json_dict = json.loads(provider_response_json, strict=False)
                                        provider_response_json_dict = provider_response_json
                                        transactionId = provider_response_json_dict['transaction_id']
                                        # provider_fees_actual_amount = provider_response_json_dict['details_list']['???']
                                        provider_fees_actual_amount = float(feesAmt)
                                        user_request.update({'provider_fees_amount': provider_fees_actual_amount})
                                        request.env.cr.commit()
                                        # Provider Payment Trans ID
                                        provider_payment_trans_id = transactionId

                            if provider_response.get('Success'):
                                try:
                                    mobile_wallet_create = False
                                    # provider_invoice_id = False
                                    # refund = False
                                    # customer_invoice_id = False
                                    # credit_note = False
                                    user_request_response = {"request_number": user_request.name,
                                                             "request_datetime": str(user_request.create_date + timedelta(hours=2)),
                                                             "provider": provider.provider,
                                                             "provider_response": provider_response_json
                                                             }

                                    if provider.provider == "fawry":
                                        if cardMetadata:
                                            user_request_response.update({"cardMetadata": cardMetadata})

                                    provider_actual_amount = user_request.trans_amount + provider_fees_actual_amount
                                    customer_actual_amount = provider_actual_amount + extra_fees_amount

                                    if not biller_info_json_dict.get('CorrBillTypeCode') or biller_info_json_dict.get('Type') == 'CASHININT':
                                        # Deduct Transaction Amount from Mobile Wallet Balance
                                        '''
                                        wallet_transaction_sudo = request.env['website.wallet.transaction'].sudo()
                                        label = _('Pay Service Bill for %s service') % (service.name)
                                        if request_data.get("wallet_id"):
                                            partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(wallet_id=request_data.get("wallet_id"),
                                                                                                                   service=service,
                                                                                                                   trans_amount=customer_actual_amount)
                                        else:
                                            partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(service=service,
                                                                                                                   trans_amount=customer_actual_amount)
                                        partner_id_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                                        mobile_wallet_create = wallet_transaction_sudo.create(
                                            {'wallet_type': 'debit', 'partner_id': request.env.user.partner_id.id,
                                             'request_id': user_request.id,
                                             'reference': 'request',
                                             'label': label,
                                             'amount': customer_actual_amount, 'currency_id': user_request.currency_id.id,
                                             'wallet_balance_before': partner_id_wallet_balance,
                                             'wallet_balance_after': partner_id_wallet_balance - customer_actual_amount,
                                             'status': 'done'})
                                        request.env.cr.commit()

                                        request.env.user.partner_id.update(
                                            {'wallet_balance': partner_id_wallet_balance - customer_actual_amount})
                                        request.env.cr.commit()
                                        '''
                                        mobile_wallet_create, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                                            'debit', request.env.user.partner_id, 'request',
                                            _('Pay Service Bill for %s service') % (service.name),
                                            customer_actual_amount, user_request.currency_id, user_request,
                                            'smartpay_operations.wallet_pay_service_bill_notify_mode', 'wallet_pay_service',
                                            _('<p>%s %s successfully deducted from your wallet.</p>') % (
                                                customer_actual_amount, _(user_request.currency_id.name))
                                        )

                                        if provider_response.get('Success').get('timeout'):
                                            if not biller_info_json_dict.get('Timeout') and not biller_info_json_dict.get('SupportPmtReverse'):
                                                user_request.update({'payment_status': 'in_queue'})
                                            elif biller_info_json_dict.get('Timeout') == 'PENDING':
                                                user_request.update({'payment_status': 'pending'})
                                            elif biller_info_json_dict.get('SupportPmtReverse'):
                                                # if biller_info_json_dict.get('PmtType') == 'VOCH':
                                                    # user_request.update({'payment_status': 'to_cancel'})
                                                # else:
                                                if biller_info_json_dict.get('PmtType') != 'VOCH':
                                                    user_request.update({'payment_status': 'to_refund'})
                                            # else:
                                                # user_request.update({'payment_status': 'done'}) # Tamayoz: No need to handel "else" case
                                            user_request.update({'action_status': 'new'})
                                        elif provider_response.get('Success').get('pending'):
                                            user_request.update({'payment_status': 'pending', 'action_status': 'new'})
                                        else:
                                            user_request.update({'payment_status': 'done', 'action_status': 'completed'}) # ==> current 'action_status': is 'completed'
                                        request.env.cr.commit()

                                        # Log Sold Limit
                                        if service.has_sale_limit:
                                            for sale_limit_id in service.sale_limit_ids:
                                                limit_type = sale_limit_id.limit_type
                                                timetuple = date_time.now().timetuple()
                                                sale_limit_domain = [
                                                    ('partner_id', '=', request.env.user.partner_id.id),
                                                    ('product_id', '=', service.id),
                                                    ('limit_type', '=', limit_type),
                                                    ('year', '=', timetuple.tm_year)]
                                                if limit_type == 'daily':
                                                    sale_limit_domain += [('day', '=', timetuple.tm_yday)]
                                                elif limit_type == 'weekly':
                                                    sale_limit_domain += [
                                                        ('week', '=', date_time.now().isocalendar()[1])]
                                                elif limit_type == 'monthly':
                                                    sale_limit_domain += [('month', '=', timetuple.tm_mon)]
                                                sale_limit = request.env['res.partner.sale.limit'].sudo().search(
                                                    sale_limit_domain,
                                                    order="id DESC", limit=1)
                                                if sale_limit:
                                                    sale_limit.update({'sold_amount': sale_limit.sold_amount + customer_actual_amount})  # calculated_payment_amount
                                                else:
                                                    sale_limit_values = {
                                                        'partner_id': request.env.user.partner_id.id,
                                                        'product_id': service.id,
                                                        'limit_type': limit_type,
                                                        'year': timetuple.tm_year,
                                                        'sold_amount': customer_actual_amount
                                                    }
                                                    if limit_type == 'daily':
                                                        sale_limit_values.update({'day': timetuple.tm_yday})
                                                    elif limit_type == 'weekly':
                                                        sale_limit_values.update(
                                                            {'week': date_time.now().isocalendar()[1]})
                                                    elif limit_type == 'monthly':
                                                        sale_limit_values.update({'month': timetuple.tm_mon})
                                                    sale_limit = request.env['res.partner.sale.limit'].sudo().create(sale_limit_values)

                                                wallet_transaction_id, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                                                    'debit', request.env.user.partner_id, 'request',
                                                    _('%s over limit fees for %s service') % (limit_type, service.name),
                                                    limit_fees_amounts.get(limit_type), user_request.currency_id, user_request,
                                                    'smartpay_operations.wallet_pay_service_bill_notify_mode', 'wallet_pay_service',
                                                    _('<p>%s %s successfully deducted from your wallet.</p>') % (
                                                        limit_fees_amounts.get(limit_type), _(user_request.currency_id.name))
                                                )
                                                sale_limit_fees = request.env['res.partner.sale.limit.fees'].sudo().create({'user_request_id': user_request.id,
                                                                                                                            'limit_type': limit_type,
                                                                                                                            'fees_amount': limit_fees_amounts.get(limit_type),
                                                                                                                            'wallet_transaction_id': wallet_transaction_id.id})
                                        # Log Wallet Transaction Limit
                                        if partner_wallet_id.type.has_trans_limit:
                                            for trans_limit_id in partner_wallet_id.type.trans_limit_ids:
                                                wallet_limit_type = trans_limit_id.limit_type
                                                timetuple = date_time.now().timetuple()
                                                trans_limit_domain = [
                                                    ('wallet_id', '=', partner_wallet_id.id),
                                                    # ('wallet_type_id', '=', partner_wallet_id.type.id),
                                                    ('limit_type', '=', wallet_limit_type),
                                                    ('year', '=', timetuple.tm_year)]
                                                if wallet_limit_type == 'daily':
                                                    trans_limit_domain += [('day', '=', timetuple.tm_yday)]
                                                elif wallet_limit_type == 'weekly':
                                                    trans_limit_domain += [('week', '=', date_time.now().isocalendar()[1])]
                                                elif wallet_limit_type == 'monthly':
                                                    trans_limit_domain += [('month', '=', timetuple.tm_mon)]
                                                trans_limit = request.env['wallet.trans.limit'].sudo().search(
                                                    trans_limit_domain, order="id DESC", limit=1)
                                                if trans_limit:
                                                    trans_limit.update({'trans_amount': trans_limit.trans_amount + customer_actual_amount})  # calculated_payment_amount
                                                else:
                                                    trans_limit_values = {
                                                        'wallet_id': partner_wallet_id.id,
                                                        # 'wallet_type_id': partner_wallet_id.type.id,
                                                        'limit_type': wallet_limit_type,
                                                        'year': timetuple.tm_year,
                                                        'trans_amount': customer_actual_amount
                                                    }
                                                    if wallet_limit_type == 'daily':
                                                        trans_limit_values.update({'day': timetuple.tm_yday})
                                                    elif wallet_limit_type == 'weekly':
                                                        trans_limit_values.update({'week': date_time.now().isocalendar()[1]})
                                                    elif wallet_limit_type == 'monthly':
                                                        trans_limit_values.update({'month': timetuple.tm_mon})
                                                    trans_limit = request.env['wallet.trans.limit'].sudo().create(
                                                        trans_limit_values)

                                                # Log Transaction Over Limit Fees
                                                if wallet_limit_fees_amounts.get(wallet_limit_type):
                                                    wallet_transaction_id, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                                                        'debit', request.env.user.partner_id, 'request',
                                                        _('%s over limit fees for %s wallet type') % (
                                                            wallet_limit_type, partner_wallet_id.type.name),
                                                        wallet_limit_fees_amounts.get(wallet_limit_type),
                                                        user_request.currency_id, user_request,
                                                        'smartpay_operations.wallet_pay_service_bill_notify_mode',
                                                        'wallet_pay_service',
                                                        _('<p>%s %s successfully deducted from your wallet.</p>') % (
                                                            wallet_limit_fees_amounts.get(wallet_limit_type),
                                                            _(user_request.currency_id.name))
                                                    )
                                                    trans_limit_fees = request.env['wallet.trans.limit.fees'].sudo().create(
                                                        {'user_request_id': user_request.id,
                                                         'limit_type': wallet_limit_type,
                                                         'fees_amount': wallet_limit_fees_amounts.get(
                                                             wallet_limit_type),
                                                         'wallet_transaction_id': wallet_transaction_id.id})

                                        mobile_wallet_reservation_id.sudo().unlink()
                                        request.env.cr.commit()
                                        unlink_wallet_reservation = True

                                        '''
                                        # Notify user
                                        irc_param = request.env['ir.config_parameter'].sudo()
                                        wallet_pay_service_bill_notify_mode = irc_param.get_param("smartpay_operations.wallet_pay_service_bill_notify_mode")
                                        if wallet_pay_service_bill_notify_mode == 'inbox':
                                            request.env['mail.thread'].sudo().message_notify(
                                                subject=label,
                                                body=_('<p>%s %s successfully deducted from your wallet.</p>') % (
                                                    customer_actual_amount, _(user_request.currency_id.name)),
                                                partner_ids=[(4, request.env.user.partner_id.id)],
                                            )
                                        elif wallet_pay_service_bill_notify_mode == 'email':
                                            mobile_wallet_create.wallet_transaction_email_send()
                                        elif wallet_pay_service_bill_notify_mode == 'sms' and request.env.user.partner_id.mobile:
                                            mobile_wallet_create.sms_send_wallet_transaction(wallet_pay_service_bill_notify_mode,
                                                                                             'wallet_pay_service',
                                                                                             request.env.user.partner_id.mobile,
                                                                                             request.env.user.name, label,
                                                                                             '%s %s' % (customer_actual_amount,
                                                                                                        _(user_request.currency_id.name)),
                                                                                             request.env.user.partner_id.country_id.phone_code or '2')
                                        '''

                                        payment_info = {"service": service.with_context(lang=request.env.user.lang).name, "provider": provider.provider,
                                                        "request_number": user_request.name,
                                                        "request_datetime": user_request.create_date + timedelta(hours=2),
                                                        "label": biller_info_json_dict.get("BillTypeAcctLabel"),
                                                        "billing_acct": billingAcct, "ref_number": provider_payment_trans_id,
                                                        "amount": trans_amount,
                                                        "fees": (provider_fees_actual_amount + extra_fees_amount),
                                                        "total": customer_actual_amount}

                                    user_request.update(
                                        {'extra_fees_amount': extra_fees_amount,
                                         'wallet_transaction_id': mobile_wallet_create and mobile_wallet_create.id or False,
                                         'trans_date': date.today(),
                                         'provider_id': provider.id,
                                         'provider_response': provider_response_json, "stage_id": 5})
                                    if biller_info_json_dict.get('CorrBillTypeCode'):
                                        user_request.update(
                                            {'description': _(
                                                 'Initiation Service Payment request (%s) was submit successfully @ %s') % (
                                                                user_request.name,
                                                                str(date_time.now() + timedelta(hours=2)))
                                             })
                                    request.env.cr.commit()
                                    user_request_response.update({'extra_fees_amount': extra_fees_amount})

                                    # VouchPIN Decryption if exist
                                    if provider_response_json_dict.get('VouchInfo'):
                                        decrypted_bytes = bytes(provider_response_json_dict['VouchInfo']['VouchPIN'],
                                                                encoding='utf-8')
                                        # text = base64.decodestring(decrypted_bytes) #
                                        text = base64.b64decode(decrypted_bytes)  #
                                        cipher = DES3.new(SECRET_KEY, DES3.MODE_ECB)
                                        VouchPIN = cipher.decrypt(text)
                                        VouchPIN = UNPAD(VouchPIN)
                                        VouchPIN = VouchPIN.decode('utf-8')  # unpad and decode bytes to str
                                        user_request_response.update({'vouch_pin': VouchPIN})
                                        if not biller_info_json_dict.get('CorrBillTypeCode') or biller_info_json_dict.get('Type') == 'CASHININT':
                                            payment_info.update({"vouch_pin": VouchPIN,
                                                                 "vouch_sn": provider_response_json_dict['VouchInfo']['VouchSN']})
                                            if provider_response_json_dict['VouchInfo'].get('VouchDesc'):
                                                payment_info.update({"vouch_desc": provider_response_json_dict['VouchInfo']['VouchDesc']})

                                    # ExtraBillInfo
                                    # ePayBillRecID : RBINQRQ-220627-619014259490-GT-99959 (Khales)
                                    # billRefNumber : 6bb67311-dde8-47f8-b8f3-3cf8fe5a4be6 (Fawry)
                                    if (provider.provider == 'fawry' and billRefNumber) or (provider.provider == 'khales' and ePayBillRecID):
                                        inquiryTransactionId = request_data.get('inquiryTransactionId')
                                        if inquiryTransactionId:
                                            inquiry_request = request.env["smartpay_operations.request"].sudo().search(
                                                [('name', '=', inquiryTransactionId)], limit=1)
                                        else:
                                            inquiry_request = request.env["smartpay_operations.request"].sudo().search(
                                                [('request_type', '=', 'service_bill_inquiry'),
                                                 ('partner_id', '=', request.env.user.partner_id.id),
                                                 ('product_id', '=', service.id),
                                                 ('create_date', '<=', date_time.now()),
                                                 ('create_date', '>=', date_time.now() - timedelta(minutes=15)),
                                                 ('provider_response', 'ilike',
                                                  '"BillRefNumber": "%s"' % (billRefNumber) if provider.provider == "fawry"
                                                  else '"EPayBillRecID": "%s"' % (ePayBillRecID) # provider.provider == "khales"
                                                  )], limit=1)

                                        if inquiry_request:
                                            inquiry_request_provider_response = inquiry_request.provider_response.replace(
                                                "'bill_response'", '"bill_response"').replace("'fees_response'", '"fees_response"').replace("'", "")
                                            inquiry_request_provider_response_json_dict = json.loads(inquiry_request_provider_response)

                                            # Fawry
                                            if inquiry_request_provider_response_json_dict.get('BillInfo') and \
                                                    inquiry_request_provider_response_json_dict.get('BillInfo').get('ExtraBillInfo'):
                                                payment_info.update({"extra_bill_info": inquiry_request_provider_response_json_dict['BillInfo']['ExtraBillInfo']})

                                            # Khales
                                            if inquiry_request_provider_response_json_dict.get('bill_response') and \
                                                    inquiry_request_provider_response_json_dict.get('bill_response').get('Msg'):
                                                for msg in inquiry_request_provider_response_json_dict.get('bill_response').get('Msg'):
                                                    if msg.get('LanguagePref') == 'ar-eg':  # en-gb
                                                        payment_info.update({"extra_bill_info": msg.get('Text')})
                                                        break

                                    if not biller_info_json_dict.get('CorrBillTypeCode') or biller_info_json_dict.get('Type') == 'CASHININT':
                                        # Wallet Transaction Info with payment info
                                        mobile_wallet_create.update({"wallet_transaction_info": json.dumps({"payment_info": payment_info}, default=default)})
                                        request.env.cr.commit()

                                    '''
                                    # Create Vendor (Provider) Invoices
                                    provider_invoice_ids = ()
                                    # 1- Create Vendor bill
                                    provider_journal_id = request.env['account.journal'].sudo().search([('type', '=', 'purchase'),
                                                                                              ('company_id', '=', request.env.user.company_id.id)], limit=1)
                                    name = provider.provider + ': [' + provider_info.product_code + '] ' + provider_info.product_name
                                    provider_invoice_vals = user_request.with_context(name=name,
                                                                                      provider_payment_trans_id=provider_payment_trans_id,
                                                                                      journal_id=provider_journal_id.id,
                                                                                      invoice_date=date.today(),
                                                                                      invoice_type='in_invoice',
                                                                                      partner_id=provider_info.name.id)._prepare_invoice()
                                    provider_invoice_id = request.env['account.invoice'].sudo().create(provider_invoice_vals)
                                    invoice_line = provider_invoice_id._prepare_invoice_line_from_request(request=user_request,
                                                                                                          name=name,
                                                                                                          qty=1,
                                                                                                          price_unit=provider_actual_amount)
                                    new_line = request.env['account.invoice.line'].sudo().new(invoice_line)
                                    new_line._set_additional_fields(provider_invoice_id)
                                    provider_invoice_id.invoice_line_ids += new_line
                                    provider_invoice_id.action_invoice_open()
                                    provider_invoice_ids += (tuple(provider_invoice_id.ids),)
                                    provider_invoice_id.pay_and_reconcile(request.env['account.journal'].sudo().search(
                                        [('type', '=', 'cash'),
                                         ('company_id', '=', request.env.user.company_id.id),
                                         ('provider_id', '=', provider.id)], limit=1),
                                        provider_actual_amount)
                                    request.env.cr.commit()
                                    # 2- Create Vendor Refund with commision amount
                                    if merchant_cashback_amount > 0:
                                        refund = request.env['account.invoice.refund'].with_context(
                                            active_ids=provider_invoice_id.ids).sudo().create({
                                            'filter_refund': 'refund',
                                            'description': name,
                                            'date': provider_invoice_id.date_invoice,
                                        })
                                        result = refund.invoice_refund()
                                        refund_id = result.get('domain')[1][2]
                                        refund = request.env['account.invoice'].sudo().browse(refund_id)
                                        refund.update({'reference': provider_payment_trans_id, 'request_id': user_request.id})
                                        refund_line = refund.invoice_line_ids[0]
                                        refund_line.update({'price_unit': merchant_cashback_amount, 'request_id': user_request.id})
                                        refund.refresh()
                                        refund.action_invoice_open()
                                        provider_invoice_ids += (tuple(refund.ids),)
                                    user_request.update({'provider_invoice_ids': provider_invoice_ids})
                                    request.env.cr.commit()

                                    # Create Customer Invoices
                                    customer_invoice_ids = ()
                                    # 1- Create Customer Invoice
                                    customer_journal_id = request.env['account.journal'].sudo().search([('type', '=', 'sale'),
                                                                                              ('company_id', '=', request.env.user.company_id.id)], limit=1)
                                    customer_invoice_vals = user_request.with_context(name=provider_payment_trans_id,
                                                                                      journal_id=customer_journal_id.id,
                                                                                      invoice_date=date.today(),
                                                                                      invoice_type='out_invoice',
                                                                                      partner_id=request.env.user.partner_id.id)._prepare_invoice()
                                    customer_invoice_id = request.env['account.invoice'].sudo().create(customer_invoice_vals)
                                    user_request.invoice_line_create(invoice_id=customer_invoice_id.id, name=name,
                                                                        qty=1, price_unit=customer_actual_amount)
                                    customer_invoice_id.action_invoice_open()
                                    customer_invoice_ids += (tuple(customer_invoice_id.ids),)
                                    # Auto Reconcile customer invoice with prepaid wallet recharge payments and previous cashback credit note
                                    domain = [('account_id', '=', customer_invoice_id.account_id.id),
                                              ('partner_id', '=',
                                               customer_invoice_id.env['res.partner']._find_accounting_partner(
                                                   customer_invoice_id.partner_id).id),
                                              ('reconciled', '=', False),
                                              '|',
                                              '&', ('amount_residual_currency', '!=', 0.0), ('currency_id', '!=', None),
                                              '&', ('amount_residual_currency', '=', 0.0), '&', ('currency_id', '=', None),
                                              ('amount_residual', '!=', 0.0)]
                                    domain.extend([('credit', '>', 0), ('debit', '=', 0)])
                                    lines = customer_invoice_id.env['account.move.line'].sudo().search(domain)
                                    for line in lines:
                                        # get the outstanding residual value in invoice currency
                                        if line.currency_id and line.currency_id == customer_invoice_id.currency_id:
                                            amount_residual_currency = abs(line.amount_residual_currency)
                                        else:
                                            currency = line.company_id.currency_id
                                            amount_residual_currency = currency._convert(abs(line.amount_residual),
                                                                                         customer_invoice_id.currency_id,
                                                                                         customer_invoice_id.company_id,
                                                                                         line.date or fields.Date.today())
                                        if float_is_zero(amount_residual_currency,
                                                         precision_rounding=customer_invoice_id.currency_id.rounding):
                                            continue

                                        customer_invoice_id.assign_outstanding_credit(line.id)
                                        if customer_invoice_id.state == 'paid':
                                            break
                                    request.env.cr.commit()

                                    # 2- Create Customer Credit Note with commision amount for only mobile users have commission
                                    if request.env.user.commission and customer_cashback_amount > 0:
                                        credit_note = request.env['account.invoice.refund'].with_context(
                                            active_ids=customer_invoice_id.ids).sudo().create({
                                            'filter_refund': 'refund',
                                            'description': provider_payment_trans_id,
                                            'date': customer_invoice_id.date_invoice,
                                        })
                                        result = credit_note.invoice_refund()
                                        credit_note_id = result.get('domain')[1][2]
                                        credit_note = request.env['account.invoice'].sudo().browse(credit_note_id)
                                        credit_note.update({'request_id': user_request.id})
                                        credit_note_line = credit_note.invoice_line_ids[0]
                                        credit_note_line.update({'price_unit': customer_cashback_amount, 'request_id': user_request.id})
                                        credit_note.refresh()
                                        """  Don't validate the customer credit note until the vendor refund reconciliation
                                        After vendor refund reconciliation, validate the customer credit note with
                                        the net amount of vendor refund sent in provider cashback statement then
                                        increase the customer wallet with the same net amount. """
                                        # credit_note.action_invoice_open()
                                        customer_invoice_ids += (tuple(credit_note.ids),)
                                    user_request.update({'customer_invoice_ids': customer_invoice_ids})
                                    request.env.cr.commit()
                                    '''

                                    if provider.provider == "khales":
                                        # Add required parameters for cancel payment scenario
                                        user_request_response.update({'billingAcct': billingAcct, 'billRefNumber': billRefNumber,
                                                                      'billerId': billerId, 'pmtType': pmtType, 'trans_amount': trans_amount,
                                                                      'curCode': curCode, 'pmtMethod': pmtMethod, 'ePayBillRecID': ePayBillRecID,
                                                                      'pmtId': pmtId, 'feesAmt': feesAmt, 'pmtRefInfo': pmtRefInfo})
                                        if payAmts:
                                            user_request_response.update({'payAmts': payAmts})
                                        if feesAmts:
                                            user_request_response.update({'feesAmts': feesAmts})
                                    if not biller_info_json_dict.get('CorrBillTypeCode') or biller_info_json_dict.get('Type') == 'CASHININT':
                                        user_request_response.update({"message": _("Pay Service Bill request was submit successfully with amount %s %s. Your Machine Wallet Balance is %s %s")
                                                                            % (customer_actual_amount,
                                                                               user_request.currency_id.name,
                                                                               wallet_balance_after,
                                                                               user_request.currency_id.name)})
                                    else:
                                        user_request_response.update({"message": _("Pay Service Bill Initiation request was submit successfully with amount %s %s.")
                                                                                 % (customer_actual_amount,
                                                                                    user_request.currency_id.name)})
                                    if not unlink_wallet_reservation and mobile_wallet_reservation_id:
                                        mobile_wallet_reservation_id.sudo().unlink()
                                        request.env.cr.commit()
                                        unlink_wallet_reservation = True
                                    return valid_response(user_request_response)
                                except Exception as e:
                                    try:
                                        _logger.error("%s", e, exc_info=True)
                                        user_request_update = {'extra_fees_amount': extra_fees_amount,
                                                               'trans_date': date.today(),
                                                               'provider_id': provider.id,
                                                               'provider_response': provider_response_json,"stage_id": 5,
                                                               'description': _("After the Pay Service Request submit successfuly with provider, Error is occur:") + " ==> " + str(e)}
                                        if mobile_wallet_create:
                                            user_request_update.update({'wallet_transaction_id': mobile_wallet_create.id})
                                        '''
                                        provider_invoice_ids = ()
                                        if provider_invoice_id or refund:
                                            if provider_invoice_id:
                                                provider_invoice_ids += (tuple(provider_invoice_id.ids),)
                                            if refund:
                                                provider_invoice_ids += (tuple(refund.ids),)
                                            user_request_update.update({'provider_invoice_ids': provider_invoice_ids})
                                        customer_invoice_ids = ()
                                        if customer_invoice_id or credit_note:
                                            if customer_invoice_id:
                                                customer_invoice_ids += (tuple(customer_invoice_id.ids),)
                                            if credit_note:
                                                customer_invoice_ids += (tuple(credit_note.ids),)
                                            user_request_update.update({'customer_invoice_ids': customer_invoice_ids})
                                        '''
                                        user_request.update(user_request_update)
                                        request.env.cr.commit()
                                    except Exception as e1:
                                        _logger.error("%s", e1, exc_info=True)
                                        if user_request and not user_request.description:
                                            user_request.update({'description': _("After the Pay Service Request submit successfuly with provider, Error is occur:") + " ==> " + str(e)})
                                            request.env.cr.commit()

                                    if not unlink_wallet_reservation and mobile_wallet_reservation_id:
                                        mobile_wallet_reservation_id.sudo().unlink()
                                        request.env.cr.commit()
                                        unlink_wallet_reservation = True
                                    return invalid_response(user_request_response, _("After the Pay Service Request submit successfuly with provider, Error is occur:") + " ==> " + str(e),
                                                            500)
                            else:
                                user_request.update({'payment_status': 'canceled' if provider_response.get('CANCEL_SUCCESS') else ('to_cancel' if provider_response.get('TO_CANCEL') else ('to_review' if provider_response.get('TO_REVIEW') else 'failure')), 'action_status': 'new' if provider_response.get('TO_CANCEL') or provider_response.get('TO_REVIEW') else 'completed'})  # ==> current 'action_status': is 'completed'
                                request.env.cr.commit()
                                error.update({provider.provider + "_response": provider_response or ''})
                        except Exception as e2:
                            _logger.error("%s", e2, exc_info=True)
                            if user_request and not user_request.description:
                                user_request.update({'description': _("Error is occur:") + " ==> " + str(e2)})
                                request.env.cr.commit()
                            if not unlink_wallet_reservation and mobile_wallet_reservation_id:
                                mobile_wallet_reservation_id.sudo().unlink()
                                request.env.cr.commit()
                                unlink_wallet_reservation = True
                            return invalid_response("Error", _("Error is occur:") + " ==> " + str(e2), 500)
                    else:
                        error.update({provider_info.name.name + "_response": _("%s is not a provider for (%s) service") % (
                            provider_info.name.name, service.name)})

                user_request.update({
                    'provider_response': error or _('(%s) service has not any provider.') % (service.name),
                    'stage_id': 5
                })
                request.env.cr.commit()
                error_key = "user_error"
                error_msg = _("(%s) service has not any provider.") % (service.name)
                if provider:
                    if error.get(provider.provider + "_response").get("error_message"):
                        error_msg = error.get(provider.provider + "_response").get("error_message")
                    elif error.get(provider.provider + "_response").get("error_message_to_be_translated"):
                        error_msg = error.get(provider.provider + "_response").get("error_message_to_be_translated")
                        error_key = "Error"
                elif error.get(provider_info.name.name + "_response"):
                    error_msg = error.get(provider_info.name.name + "_response")
                if not unlink_wallet_reservation and mobile_wallet_reservation_id:
                    mobile_wallet_reservation_id.sudo().unlink()
                    request.env.cr.commit()
                    unlink_wallet_reservation = True
                return invalid_response(error_key, error_msg, 400)
            else:
                return valid_response({"message": _("Your request was submit successfully."),
                                       "request_number": user_request.name
                                       })

        @validate_token
        @http.route('/api/cancelRequest', type="http", auth="none", methods=["PUT"], csrf=False)
        def cancelRequest(self, **request_data):
            _logger.info(">>>>>>>>>>>>>>>>>>>> Calling Cancel Mobile Request API")
            user_request = False
            request_number = request_data.get('request_number')
            if request_number:
                user_request = request.env['smartpay_operations.request'].sudo().search([('name', '=', request_number)], limit=1)
            else: # elif request_data.get('provider') == 'khales':
                # if not request_data.get('ePayBillRecID'):
                    # return invalid_response("ePayBillRecID_request_number_not_found", _("missing Request Number or ePay Bill Rec ID in request data"), 400)
                user_request = request.env['smartpay_operations.request'].sudo().search([('request_type', '=', 'pay_service_bill'),
                                                                                         ('create_date', '<=', date_time.now()),
                                                                                         ('create_date', '>=', date_time.now() - timedelta(hours=1)),
                                                                                         ('provider_response', 'like', request_data.get('ePayBillRecID') or request_data.get('billRefNumber'))],
                                                                                        limit=1)
                # _logger.info("@@@@@@@@@@@@@@@@@@@ " + '"EPayBillRecID": "%s"' % (request_data.get('ePayBillRecID')))
            if user_request:
                request_number = user_request.name
                try:
                    service = user_request.product_id
                    provider = user_request.provider_id

                    service_providerinfo = request.env['product.supplierinfo'].sudo().search([
                        ('product_tmpl_id', '=', service.product_tmpl_id.id),
                        ('name', '=', provider.related_partner.id)
                    ])
                    biller_info_json_dict = json.loads(service_providerinfo.with_context(lang=request.env.user.lang).biller_info, strict=False)
                    isAllowCancel = biller_info_json_dict.get('SupportPmtReverse', False)

                    if user_request.request_type == 'pay_service_bill' and user_request.stage_id.id == 5 and isAllowCancel \
                            and (not user_request.description
                                 or ('Cancel Service Payment request (%s) was submit successfully' % user_request.name not in user_request.description
                                     and 'Cancel Service Payment request (%s) In progress' % user_request.name not in user_request.description
                                     and 'Correlation Service Payment request (%s) was submit successfully' % user_request.name not in user_request.description
                                     and 'Correlation Service Payment request (%s) In progress' % user_request.name not in user_request.description
                                 )):

                        user_request.update({
                            'description': _('Cancel Service Payment request (%s) In progress @ %s') % (user_request.name, str(date_time.now() + timedelta(hours=2))),
                            'payment_status': 'canceled', 'action_status': 'new'
                        })
                        request.env.cr.commit()

                        isInternalCancel = biller_info_json_dict.get('IsInternalCancel', False)
                        lang = 'ar-eg'
                        partner = user_request.partner_id
                        # trans_date = user_request.trans_date
                        trans_amount = user_request.trans_amount
                        provider_fees_amount = user_request.provider_fees_amount
                        extra_fees_amount = user_request.extra_fees_amount
                        currency = user_request.currency_id

                        provider_pay_response = user_request.provider_response
                        provider_response_json = {}
                        provider_response_json['provider_pay_response'] = provider_pay_response
                        provider_pay_response_json = json.loads(provider_pay_response)
                        billingAcct = request_data.get('billingAcct') or provider_pay_response_json.get('billingAcct') \
                                      or provider_pay_response_json.get('PmtInfo').get('BillingAcct')

                        extraBillingAcctKeys = request_data.get('extraBillingAcctKeys')
                        if extraBillingAcctKeys:
                            extraBillingAcctKeys = ast.literal_eval(extraBillingAcctKeys)
                        else:
                            extraBillingAcctKeys = provider_pay_response_json.get('extraBillingAcctKeys') or \
                                                   provider_pay_response_json.get('PmtInfo').get('ExtraBillingAcctKeys').get('ExtraBillingAcctKey')
                        notifyMobile = request_data.get('notifyMobile') or provider_pay_response_json.get('notifyMobile') or 'NCName'

                        billRefNumber = request_data.get('billRefNumber') or provider_pay_response_json.get('billRefNumber') \
                                        or provider_pay_response_json.get('PmtInfo').get('BillRefNumber')
                        billerId = request_data.get('billerId') or provider_pay_response_json.get('billerId')
                        pmtType = request_data.get('pmtType') or provider_pay_response_json.get('pmtType')
                        # trans_amount = request_data.get('trans_amount') or provider_pay_response_json.get('trans_amount')
                        curCode = request_data.get('currency_id') or provider_pay_response_json.get('curCode') \
                                  or provider_pay_response_json.get('PmtInfo').get('CurAmt').get('CurCode')
                        payAmts = request_data.get('payAmts')
                        if payAmts:
                            payAmts = ast.literal_eval(payAmts)
                        else:
                            payAmts = [{'Sequence': '1', 'AmtDue': trans_amount, 'CurCode': curCode}]
                        pmtMethod = request_data.get('pmtMethod') or provider_pay_response_json.get('pmtMethod') \
                                    or provider_pay_response_json.get('PmtInfo').get('PmtMethod')
                        ePayBillRecID = request_data.get('ePayBillRecID') or provider_pay_response_json.get('ePayBillRecID')
                        pmtId = request_data.get('pmtId') or provider_pay_response_json.get('pmtId')
                        feesAmt = request_data.get('feesAmt') or provider_pay_response_json.get('feesAmt')
                        feesAmts = request_data.get('feesAmts')
                        if feesAmts:
                            feesAmts = ast.literal_eval(feesAmts)
                        else:
                            feesAmts = [{'Amt': feesAmt, 'CurCode': curCode}]
                        pmtRefInfo = request_data.get('pmtRefInfo') or provider_pay_response_json.get('pmtRefInfo')
                        cancelReason = request_data.get('cancelReason') or '001'
                        inquiryTransactionId = request_data.get('inquiryTransactionId')

                        error = {}

                        provider_channel = False
                        machine_channels = request.env['payment.acquirer.channel'].sudo().search([("acquirer_id", "=", provider.id),
                                                                                                  ("type", "in", ("machine", "internet"))], limit=1)
                        if machine_channels:
                            provider_channel = machine_channels[0]
                        provider_cancel_response = {}
                        if isInternalCancel:
                            provider_cancel_response["Success"] = _("Internal Cancel")
                        else:
                            if provider.provider == "khales":
                                # Handel billingAcct format if exist
                                if biller_info_json_dict.get('BillTypeAcctFormat') and biller_info_json_dict.get('BillTypeAcctFormatSpliter'):
                                    formatedBillingAcct = []
                                    keysToBeRemoved = []
                                    for format in biller_info_json_dict.get('BillTypeAcctFormat').split(biller_info_json_dict.get('BillTypeAcctFormatSpliter')):
                                        if format == 'billingAcct':
                                            formatedBillingAcct.append(billingAcct)
                                        else:
                                            is_extra_key = False
                                            for extraBillingAcctKey in extraBillingAcctKeys:
                                                if extraBillingAcctKey.get("Key") == format:
                                                    formatedBillingAcct.append(extraBillingAcctKey.get("Value"))
                                                    keysToBeRemoved.append(extraBillingAcctKey)
                                                    is_extra_key = True
                                                    break
                                            if not is_extra_key:
                                                formatedBillingAcct.append(format)
                                    extraBillingAcctKeys = [x for x in extraBillingAcctKeys if x not in keysToBeRemoved]
                                    billingAcct = biller_info_json_dict.get('BillTypeAcctFormatSpliter').join(formatedBillingAcct)

                                '''
                                machine_serial = None
                                if len(request.env.user.machine_serial) > 16:  # Ingenico POS
                                    machine_serial = request.env.user.machine_serial
                                    machine_serial = machine_serial[len(machine_serial) - 16:len(machine_serial)]
                                '''
                                machine_serial = request.env.user.machine_serial
                                if machine_serial and len(machine_serial) > 16:
                                    machine_serial = machine_serial[len(machine_serial) - 16:len(machine_serial)]
                                provider_cancel_response = provider.cancel_khales_payment(lang, machine_serial or request_number,
                                                                                          billingAcct, billerId, ePayBillRecID,
                                                                                          payAmts, pmtId, pmtType, feesAmts,
                                                                                          billRefNumber, pmtMethod, pmtRefInfo,
                                                                                          cancelReason,provider_channel, request_number)
                            if provider.provider == "fawry":
                                provider_cancel_response = provider.reverse_fawry_bill(lang, service_providerinfo.product_code,
                                                                                       billingAcct, extraBillingAcctKeys,
                                                                                       trans_amount, curCode, pmtMethod,
                                                                                       notifyMobile, billRefNumber,
                                                                                       billerId, pmtType or "POST",
                                                                                       provider_channel, inquiryTransactionId,
                                                                                       request_number)
                        if provider_cancel_response.get('Success'):
                            try:
                                if isInternalCancel:
                                    provider_response_json['provider_cancel_response'] = _("Internal Cancel")
                                else:
                                    provider_cancel_response_json = suds_to_json(provider_cancel_response.get('Success'))
                                    provider_response_json['provider_cancel_response'] = provider_cancel_response_json

                                provider_actual_amount = trans_amount + provider_fees_amount
                                customer_actual_amount = provider_actual_amount + extra_fees_amount

                                if not biller_info_json_dict.get('CorrBillTypeCode') or biller_info_json_dict.get('Type') == 'CASHININT':
                                    # Refund Payment Amount to Customer Wallet Balance
                                    '''
                                    wallet_transaction_sudo = request.env['website.wallet.transaction'].sudo()
                                    label = _('Cancel Service Payment for %s service') % (service.name)
                                    partner_wallet_id = user_request.wallet_transaction_id.wallet_id or partner.get_transaction_wallet(service=service)
                                    partner_id_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                                    customer_wallet_create = wallet_transaction_sudo.create({'wallet_type': 'credit', 'partner_id': partner.id,
                                                                                             'request_id': user_request.id, 'reference': 'request',
                                                                                             'label': label, 'amount': customer_actual_amount,
                                                                                             'currency_id': currency.id,
                                                                                             'wallet_balance_before': partner_id_wallet_balance,
                                                                                             'wallet_balance_after': partner_id_wallet_balance + customer_actual_amount,
                                                                                             'status': 'done'})
                                    request.env.cr.commit()

                                    partner.update({'wallet_balance': partner_id_wallet_balance + customer_actual_amount})
                                    request.env.cr.commit()
                                    '''
                                    partner_wallet_id = user_request.wallet_transaction_id.wallet_id or partner.get_transaction_wallet(service=service)
                                    if not partner_wallet_id:
                                        return invalid_response("wallet_not_found",
                                                                _("No Matched Wallet found for partner [%s] %s") % (
                                                                    partner.ref,
                                                                    partner.name), 400)
                                    customer_wallet_create, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                                        'credit', partner, 'request',
                                        _('Cancel Service Payment for %s service') % (service.name),
                                        customer_actual_amount, currency,  user_request,
                                        'smartpay_operations.wallet_canel_service_payment_notify_mode',
                                        'wallet_cancel_service_payment',
                                        _('<p>%s %s successfully Added to your wallet.</p>') % (
                                            customer_actual_amount, _(currency.name))
                                    )

                                    # Deduct Sold Limit
                                    if service.has_sale_limit:
                                        for sale_limit_id in service.sale_limit_ids:
                                            limit_type = sale_limit_id.limit_type
                                            timetuple = date_time.now().timetuple()
                                            sale_limit_domain = [
                                                ('partner_id', '=', partner.id),
                                                ('product_id', '=', service.id),
                                                ('limit_type', '=', limit_type),
                                                ('year', '=', timetuple.tm_year)]
                                            if limit_type == 'daily':
                                                sale_limit_domain += [('day', '=', timetuple.tm_yday)]
                                            elif limit_type == 'weekly':
                                                sale_limit_domain += [
                                                    ('week', '=', date_time.now().isocalendar()[1])]
                                            elif limit_type == 'monthly':
                                                sale_limit_domain += [('month', '=', timetuple.tm_mon)]
                                            sale_limit = request.env['res.partner.sale.limit'].sudo().search(
                                                sale_limit_domain,
                                                order="id DESC", limit=1)
                                            if sale_limit:
                                                sale_limit.update({'sold_amount': sale_limit.sold_amount - customer_actual_amount})  # calculated_payment_amount

                                            # Refund Sold Over Limit Fees
                                            sale_limit_fees = request.env['res.partner.sale.limit.fees'].sudo().search([('user_request_id', '=', user_request.id),
                                                                                                                        ('limit_type', '=', limit_type),
                                                                                                                        ('refund_wallet_transaction_id', '=', False)], limit=1)
                                            if sale_limit_fees:
                                                wallet_transaction_id, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                                                    'credit', partner, 'request',
                                                    _('Refund %s over limit fees for %s service') % (limit_type, service.name),
                                                    sale_limit_fees.fees_amount, currency, user_request,
                                                    'smartpay_operations.wallet_canel_service_payment_notify_mode',
                                                    'wallet_cancel_service_payment',
                                                    _('<p>%s %s successfully Added to your wallet.</p>') % (
                                                        sale_limit_fees.fees_amount, _(currency.name))
                                                )
                                                sale_limit_fees.update(
                                                    {'refund_amount': sale_limit_fees.fees_amount, 'refund_wallet_transaction_id': wallet_transaction_id.id})

                                    # Deduct Transaction Limit
                                    if partner_wallet_id.type.has_trans_limit:
                                        for trans_limit_id in partner_wallet_id.type.trans_limit_ids:
                                            wallet_limit_type = trans_limit_id.limit_type
                                            timetuple = date_time.now().timetuple()
                                            trans_limit_domain = [
                                                ('wallet_id', '=', partner_wallet_id.id),
                                                # ('wallet_type_id', '=', partner_wallet_id.type.id),
                                                ('limit_type', '=', wallet_limit_type),
                                                ('year', '=', timetuple.tm_year)]
                                            if wallet_limit_type == 'daily':
                                                trans_limit_domain += [('day', '=', timetuple.tm_yday)]
                                            elif wallet_limit_type == 'weekly':
                                                trans_limit_domain += [('week', '=', date_time.now().isocalendar()[1])]
                                            elif wallet_limit_type == 'monthly':
                                                trans_limit_domain += [('month', '=', timetuple.tm_mon)]
                                            trans_limit = request.env['wallet.trans.limit'].sudo().search(
                                                trans_limit_domain, order="id DESC", limit=1)
                                            if trans_limit:
                                                trans_limit.update({'trans_amount': trans_limit.trans_amount - customer_actual_amount})  # calculated_payment_amount

                                            # Refund Transaction Over Limit Fees
                                            trans_limit_fees = request.env['wallet.trans.limit.fees'].sudo().search(
                                                [('user_request_id', '=', user_request.id),
                                                 ('limit_type', '=', wallet_limit_type),
                                                 ('refund_wallet_transaction_id', '=', False)], limit=1)
                                            if trans_limit_fees:
                                                wallet_transaction_id, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                                                    'credit', partner, 'request',
                                                    _('Refund %s over limit fees for %s wallet type') % (
                                                        wallet_limit_type, partner_wallet_id.type.name),
                                                    trans_limit_fees.fees_amount, currency, user_request,
                                                    'smartpay_operations.wallet_canel_service_payment_notify_mode',
                                                    'wallet_cancel_service_payment',
                                                    _('<p>%s %s successfully Added to your wallet.</p>') % (
                                                        trans_limit_fees.fees_amount, _(currency.name))
                                                )
                                                trans_limit_fees.update({'refund_amount': trans_limit_fees.fees_amount,
                                                                         'refund_wallet_transaction_id': wallet_transaction_id.id})

                                    '''
                                    # Notify customer
                                    irc_param = request.env['ir.config_parameter'].sudo()
                                    wallet_canel_service_payment_notify_mode = irc_param.get_param("smartpay_operations.wallet_canel_service_payment_notify_mode")
                                    if wallet_canel_service_payment_notify_mode == 'inbox':
                                        request.env['mail.thread'].sudo().message_notify(subject=label,
                                                                                      body=_('<p>%s %s successfully Added to your wallet.</p>') % (
                                                                                          customer_actual_amount, _(currency.name)),
                                                                                      partner_ids=[(4, partner.id)],
                                        )
                                    elif wallet_canel_service_payment_notify_mode == 'email':
                                        customer_wallet_create.wallet_transaction_email_send()
                                    elif wallet_canel_service_payment_notify_mode == 'sms' and partner.mobile:
                                        customer_wallet_create.sms_send_wallet_transaction(wallet_canel_service_payment_notify_mode, 'wallet_cancel_service_payment',
                                                                                           partner.mobile, partner.name, # request.env.user.name,
                                                                                           label, '%s %s' % (customer_actual_amount, _(currency.name)),
                                                                                           partner.country_id.phone_code or '2')
                                    '''

                                    # Refund provider bill for reconciliation purpose
                                    # Cancel provider refund (cashback), customer invoice and customer credit note (cashback)
                                    '''
                                    refund = False
                                    provider_invoice_ids = ()
                                    for provider_invoice_id in user_request.provider_invoice_ids:
                                        provider_invoice_ids += (tuple(provider_invoice_id.ids),)
                                        # Refund Provider Bill
                                        if provider_invoice_id.type == 'in_invoice' and len(user_request.provider_invoice_ids) == 2:
                                            refund = request.env['account.invoice.refund'].with_context(
                                                active_ids=provider_invoice_id.ids).sudo().create({
                                                'filter_refund': 'refund',
                                                'description': provider_invoice_id.name,
                                                'date': provider_invoice_id.date_invoice,
                                            })
                                            result = refund.invoice_refund()
                                            refund_id = result.get('domain')[1][2]
                                            refund = request.env['account.invoice'].sudo().browse(refund_id)
                                            refund.update({'reference': pmtId, 'request_id': user_request.id})
                                            refund_line = refund.invoice_line_ids[0]
                                            refund_line.update({'request_id': user_request.id})
                                            refund.refresh()
                                            refund.action_invoice_open()
                                            refund.pay_and_reconcile(request.env['account.journal'].sudo().search(
                                                [('type', '=', 'cash'),
                                                 ('company_id', '=', request.env.user.company_id.id),
                                                 ('provider_id', '=', provider.id)], limit=1),
                                                provider_actual_amount)
                                            provider_invoice_ids += (tuple(refund.ids),)
                                        # Cancel provider refund (cashback)
                                        if provider_invoice_id.type == 'in_refund':
                                            if provider_invoice_id.state in ('in_payment', 'paid'):
                                                provider_invoice_id.action_invoice_re_open()
                                            provider_invoice_id.action_invoice_cancel()

                                    user_request.update({'provider_invoice_ids': provider_invoice_ids})
                                    request.env.cr.commit()

                                    # customer_invoice_ids = ()
                                    for customer_invoice_id in user_request.customer_invoice_ids:
                                        # customer_invoice_ids += (tuple(customer_invoice_id.ids),)
                                        # Cancel Customer Invoice and Customer Credit Note (cashback)
                                        if len(user_request.customer_invoice_ids) == 2:
                                            if customer_invoice_id.state in ('in_payment', 'paid'):
                                                customer_invoice_id.action_invoice_re_open()
                                            customer_invoice_id.action_invoice_cancel()

                                    # user_request.update({'customer_invoice_ids': customer_invoice_ids})
                                    # request.env.cr.commit()
                                    '''

                                    user_request.update({'wallet_transaction_id': customer_wallet_create.id})

                                user_request.update({
                                    'provider_response': provider_response_json , # "stage_id": 4
                                    'description': _('Cancel Service Payment request (%s) was submit successfully @ %s') % (user_request.name, str(date_time.now() + timedelta(hours=2))),
                                    'action_status': 'completed'
                                })
                                request.env.cr.commit()

                                return valid_response({"request_number": user_request.name, "provider": provider.provider,
                                                       "provider_response": provider_response_json,
                                                       "message":
                                                           _("Cancel Service Payment request (%s) was submit successfully. Your Machine Wallet Balance is %s %s")
                                                                  % (user_request.name,
                                                                     wallet_balance_after,
                                                                     currency.name)
                                                       })
                            except Exception as e:
                                try:
                                    _logger.error("%s", e, exc_info=True)
                                    user_request_update = {'provider_response': provider_response_json, # "stage_id": 4,
                                                              'description': _(
                                                                  "After the Cancel Service Payment Request submit successfuly with provider, Error is occur:") + " ==> " + str(
                                                                  e)}
                                    if customer_wallet_create:
                                        user_request_update.update({'wallet_transaction_id': customer_wallet_create.id})
                                    '''
                                    provider_invoice_ids = ()
                                    if provider_invoice_id or refund:
                                        if provider_invoice_id:
                                            provider_invoice_ids += (tuple(provider_invoice_id.ids),)
                                        if refund:
                                            provider_invoice_ids += (tuple(refund.ids),)
                                        user_request_update.update({'provider_invoice_ids': provider_invoice_ids})
                                    '''
                                    '''
                                    customer_invoice_ids = ()
                                    if customer_invoice_id or credit_note:
                                        if customer_invoice_id:
                                            customer_invoice_ids += (tuple(customer_invoice_id.ids),)
                                        if credit_note:
                                            customer_invoice_ids += (tuple(credit_note.ids),)
                                        user_request_update.update({'customer_invoice_ids': customer_invoice_ids})
                                    '''
                                    user_request.update(user_request_update)
                                    request.env.cr.commit()
                                except Exception as e1:
                                    _logger.error("%s", e1, exc_info=True)
                                    if user_request and not user_request.description:
                                        user_request.update({'description': _(
                                                                  "After the Cancel Service Payment Request submit successfuly with provider, Error is occur:") + " ==> " + str(
                                                                  e)})

                                return invalid_response({"request_number": user_request.name, "provider": provider.provider,
                                                         "provider_response": provider_response_json,
                                                         "message":
                                                           _("Cancel Service Payment request (%s) was submit successfully. Your Machine Wallet Balance is %s %s")
                                                                  % (user_request.name,
                                                                     currency.name,
                                                                     wallet_balance_after,
                                                                     currency.name)
                                                         }, _(
                                    "After the Cancel Service Payment Request submit successfuly with provider, Error is occur:") + " ==> " + str(e), 500)
                        else:
                            provider_response_json["provider_cancel_response"] = provider_cancel_response
                            error.update({provider.provider + "_response": provider_response_json or ''})

                        user_request.update({'provider_response': json.dumps(error), 'description': json.dumps(error)}) # 'stage_id': 5
                        request.env.cr.commit()
                        return invalid_response("Error", error, 400)

                    elif (user_request.request_type == 'pay_service_bill' and user_request.stage_id.id == 5 and isAllowCancel
                          and ('Cancel Service Payment request (%s) was submit successfully' % user_request.name in user_request.description
                               # or 'Cancel Service Payment request (%s) In progress' % user_request.name in user_request.description
                               # or 'Correlation Service Payment request (%s) was submit successfully' % user_request.name in user_request.description
                               # or 'Correlation Service Payment request (%s) In progress' % user_request.name in user_request.description
                            )) or user_request.sudo().write({'stage_id': 4}):
                        return valid_response(_("Cancel REQ Number (%s) successfully!") % (request_number))
                except Exception as ex:
                    _logger.error("%s", ex, exc_info=True)
            else:
                return invalid_response("request_not_found", _("Request does not exist!"), 400)

            return invalid_response("request_not_canceled", _("Could not cancel REQ Number (%s)") % (request_number), 400)

        @validate_token
        @http.route('/api/correlationRequest', type="http", auth="none", methods=["PUT"], csrf=False)
        def correlationRequest(self, **request_data):
            _logger.info("@@@@@@@@@@@@@@@@@@@ Calling Correlation Pay Service Request API")
            user_request = False
            request_number = request_data.get('request_number')
            pmtTransIds = request_data.get('pmtTransIds')
            if request_number:
                user_request = request.env['smartpay_operations.request'].sudo().search([('name', '=', request_number)],
                                                                                        limit=1)
            else:  # elif request_data.get('provider') == 'fawry':
                # if not request_data.get('pmtTransIds'):
                # return invalid_response("pmtTransIds_request_number_not_found", _("missing Request Number or Payment Trans Ids in request data"), 400)
                if pmtTransIds:
                    pmtTransIds = ast.literal_eval(pmtTransIds)
                    pmtTransCounts = 0
                    domain = [('request_type', '=', 'pay_service_bill'), ('create_date', '<=', date_time.now()), ('create_date', '>=', date_time.now() - timedelta(hours=1))]
                    for payment in pmtTransIds:
                        if payment['PmtIdType'] == 'FCRN' or payment['PmtIdType'] == 'BNKPTN':
                            domain += [('provider_response', 'like', '<PmtId>%s</PmtId>' % payment['PmtId'])]
                            pmtTransCounts += 1
                    if pmtTransCounts == 2:
                        user_request = request.env['smartpay_operations.request'].sudo().search(domain, limit=1)
                # _logger.info("@@@@@@@@@@@@@@@@@@@ " + '"pmtTransIds": "%s"' % (request_data.get('pmtTransIds')))
            if user_request:
                request_number = user_request.name
                try:
                    service = user_request.product_id
                    provider = user_request.provider_id

                    service_providerinfo = request.env['product.supplierinfo'].sudo().search([
                        ('product_tmpl_id', '=', service.product_tmpl_id.id),
                        ('name', '=', provider.related_partner.id)
                    ])
                    biller_info_json_dict = json.loads(service_providerinfo.with_context(lang=request.env.user.lang).biller_info, strict=False)
                    corrBillTypeCode = biller_info_json_dict.get('CorrBillTypeCode', False)

                    if user_request.request_type == 'pay_service_bill' and user_request.stage_id.id == 5 and corrBillTypeCode \
                            and (not user_request.description
                                 or ('Correlation Service Payment request (%s) was submit successfully' % user_request.name not in user_request.description
                                     and 'Correlation Service Payment request (%s) In progress' % user_request.name not in user_request.description)):

                        user_request.update({'description': _('Correlation Service Payment request (%s) In progress @ %s') % (user_request.name, str(date_time.now() + timedelta(hours=2)))})
                        request.env.cr.commit()

                        lang = 'ar-eg'
                        partner = user_request.partner_id
                        # trans_date = user_request.trans_date
                        trans_amount = user_request.trans_amount
                        provider_fees_amount = user_request.provider_fees_amount
                        extra_fees_amount = user_request.extra_fees_amount
                        currency = user_request.currency_id

                        # Check Customer Wallet Balance Maximum Balance
                        partner_wallet_id = user_request.wallet_transaction_id.wallet_id or partner.get_transaction_wallet(service=service)
                        if not partner_wallet_id:
                            return invalid_response("wallet_not_found",
                                                    _("No Matched Wallet found for partner [%s] %s") % (
                                                        partner.ref,
                                                        partner.name), 400)
                        if biller_info_json_dict.get('Type') == 'CASHOUT':
                            wallet_max_balance = partner_wallet_id.max_balance or partner_wallet_id.type_max_balance or 0.0
                            if wallet_max_balance and (partner_wallet_id.balance_amount + trans_amount) > wallet_max_balance:
                                user_request.update({'description': _(
                                    'Correlation Service Payment request (%s) failed @ (%s) due to the maximum balance of customer wallet will be exceeded')
                                                                    % (user_request.name, str(date_time.now() + timedelta(hours=2)))})
                                request.env.cr.commit()
                                return invalid_response("wallet_max_balance_exceeded", _("Wallet [%s] maximum balance exceeded!") % partner_wallet_id.name, 400)

                        provider_pay_response = user_request.provider_response
                        provider_response_json = {}
                        provider_response_json['provider_pay_response'] = provider_pay_response
                        provider_pay_response_json = json.loads(provider_pay_response)
                        billingAcct = request_data.get('billingAcct') or provider_pay_response_json.get('PmtInfo').get('BillingAcct')
                        # billerId = request_data.get('billerId') or provider_pay_response_json.get('billerId')
                        # pmtType = request_data.get('pmtType') or provider_pay_response_json.get('pmtType')
                        curCode = request_data.get('currency_id') or provider_pay_response_json.get('PmtInfo').get('CurAmt').get('CurCode')
                        # payAmts = request_data.get('payAmts')
                        # if payAmts:
                        # payAmts = ast.literal_eval(payAmts)
                        # else:
                        # payAmts = [{'Sequence': '1', 'AmtDue': trans_amount, 'CurCode': curCode}]
                        pmtMethod = request_data.get('pmtMethod') or provider_pay_response_json.get('PmtInfo').get('PmtMethod')

                        pmtId = request_data.get('pmtId') or user_request.name
                        # feesAmt = request_data.get('feesAmt') or provider_pay_response_json.get('feesAmt')
                        # feesAmts = request_data.get('feesAmts')
                        # if feesAmts:
                        # feesAmts = ast.literal_eval(feesAmts)
                        # else:
                        # feesAmts = [{'Amt': feesAmt, 'CurCode': curCode}]
                        # pmtRefInfo = request_data.get('pmtRefInfo') or provider_pay_response_json.get('pmtRefInfo')

                        if not pmtTransIds:
                            # Get Provider Payment Trans IDs
                            pmtTransIds = []
                            for payment in provider_pay_response_json['PmtTransId']:
                                if payment['PmtIdType'] == 'FCRN' or payment['PmtIdType'] == 'BNKPTN':
                                    pmtTransIds.append({'PmtId': payment['PmtId'], 'PmtIdType': payment['PmtIdType'],
                                                        'CreatedDt': payment['CreatedDt']})

                        error = {}

                        provider_channel = False
                        machine_channels = request.env['payment.acquirer.channel'].sudo().search(
                            [("acquirer_id", "=", provider.id),
                             ("type", "in", ("machine", "internet"))], limit=1)
                        if machine_channels:
                            provider_channel = machine_channels[0]
                        provider_correlation_response = {}
                        if provider.provider == "fawry":
                            # Tamayoz TODO: Provider Server Timeout Handling
                            provider_correlation_response = provider.correlation_fawry_bill(lang,
                                                                                            service_providerinfo.product_code,
                                                                                            provider_channel.fawry_acctId,# billingAcct,
                                                                                            # extraBillingAcctKeys,
                                                                                            0, curCode, pmtMethod,
                                                                                            # notifyMobile, billRefNumber,
                                                                                            # billerId, pmtType,
                                                                                            pmtTransIds, provider_channel,
                                                                                            request_number)
                        if provider_correlation_response.get('Success'):
                            try:
                                provider_correlation_response_json = suds_to_json(
                                    provider_correlation_response.get('Success'))
                                provider_response_json[
                                    'provider_correlation_response'] = provider_correlation_response_json

                                # provider_actual_amount = trans_amount + provider_fees_amount
                                # customer_actual_amount = provider_actual_amount + extra_fees_amount
                                customer_actual_amount = trans_amount

                                wallet_balance_after = partner_wallet_id.balance_amount
                                if biller_info_json_dict.get('Type') == 'CASHOUT':
                                    # Add Payment Amount to Customer Wallet Balance
                                    '''
                                    wallet_transaction_sudo = request.env['website.wallet.transaction'].sudo()
                                    label = _('Correlation Service Payment for %s service') % (service.name)
                                    partner = request.env.user.partner_id
                                    partner_wallet_id = user_request.wallet_transaction_id.wallet_id or partner.get_transaction_wallet(service=service)
                                    partner_id_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                                    customer_wallet_create = wallet_transaction_sudo.create(
                                        {'wallet_type': 'credit', 'partner_id': partner.id,
                                         'request_id': user_request.id, 'reference': 'request',
                                         'label': label, 'amount': customer_actual_amount,
                                         'currency_id': user_request.currency_id.id,
                                         'wallet_balance_before': partner_id_wallet_balance,
                                         'wallet_balance_after': partner_id_wallet_balance + customer_actual_amount,
                                         'status': 'done'})
                                    request.env.cr.commit()

                                    partner.update({'wallet_balance': partner_id_wallet_balance + customer_actual_amount})
                                    request.env.cr.commit()

                                    # Notify customer
                                    irc_param = request.env['ir.config_parameter'].sudo()
                                    wallet_correlation_service_payment_notify_mode = irc_param.get_param(
                                        "smartpay_operations.wallet_pay_service_bill_notify_mode")
                                    if wallet_correlation_service_payment_notify_mode == 'inbox':
                                        request.env['mail.thread'].sudo().message_notify(subject=label,
                                                                                         body=_(
                                                                                             '<p>%s %s successfully Added to your wallet.</p>') % (
                                                                                                  customer_actual_amount,
                                                                                                  _(user_request.currency_id.name)),
                                                                                         partner_ids=[(4, partner.id)],
                                                                                         )
                                    elif wallet_correlation_service_payment_notify_mode == 'email':
                                        customer_wallet_create.wallet_transaction_email_send()
                                    elif wallet_correlation_service_payment_notify_mode == 'sms' and partner.mobile:
                                        customer_wallet_create.sms_send_wallet_transaction(
                                            wallet_correlation_service_payment_notify_mode, 'wallet_correlation_service_payment',
                                            partner.mobile, partner.name,  # request.env.user.name,
                                            label,
                                            '%s %s' % (customer_actual_amount, _(user_request.currency_id.name)),
                                            partner.country_id.phone_code or '2')
                                    '''
                                    customer_wallet_create, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                                        'credit', partner, 'request',
                                        _('Correlation Service Payment for %s service') % (service.name),
                                        customer_actual_amount, currency, user_request,
                                        'smartpay_operations.wallet_correlation_service_payment_notify_mode',
                                        'wallet_correlation_service_payment',
                                        _('<p>%s %s successfully Added to your wallet.</p>') % (
                                            customer_actual_amount, _(currency.name))
                                    )

                                    user_request.update({'wallet_transaction_id': customer_wallet_create.id})

                                user_request.update(
                                    {'provider_response': provider_response_json,  # "stage_id": 4
                                     'description': _(
                                         'Correlation Service Payment request (%s) was submit successfully @ %s') % (
                                                        user_request.name, str(date_time.now() + timedelta(hours=2)))
                                     })
                                request.env.cr.commit()

                                return valid_response(
                                    {"request_number": user_request.name, "provider": provider.provider,
                                     "provider_response": provider_response_json,
                                     "message":
                                         _("Correlation Service Payment request (%s) was submit successfully. Your Machine Wallet Balance is %s %s")
                                         % (user_request.name,
                                            wallet_balance_after,
                                            currency.name)
                                     })
                            except Exception as e:
                                try:
                                    _logger.error("%s", e, exc_info=True)
                                    user_request_update = {'provider_response': provider_response_json,
                                                           # "stage_id": 4,
                                                           'description': _(
                                                               "After the Correlation Service Payment Request submit successfuly with provider, Error is occur:") + " ==> " + str(
                                                               e)}
                                    if customer_wallet_create:
                                        user_request_update.update({'wallet_transaction_id': customer_wallet_create.id})
                                    user_request.update(user_request_update)
                                    request.env.cr.commit()
                                except Exception as e1:
                                    _logger.error("%s", e1, exc_info=True)
                                    if user_request and not user_request.description:
                                        user_request.update({'description': _(
                                            "After the Correlation Service Payment Request submit successfuly with provider, Error is occur:") + " ==> " + str(
                                            e)})
                                        request.env.cr.commit()

                                return invalid_response(
                                    {"request_number": user_request.name, "provider": provider.provider,
                                     "provider_response": provider_response_json,
                                     "message":
                                         _("Correlation Service Payment request (%s) was submit successfully. Your Machine Wallet Balance is %s %s")
                                         % (user_request.name,
                                            currency.name,
                                            wallet_balance_after,
                                            currency.name)
                                     }, _(
                                        "After the Correlation Service Payment Request submit successfuly with provider, Error is occur:") + " ==> " + str(
                                        e), 500)
                        else:
                            provider_response_json["provider_correlation_response"] = provider_correlation_response
                            error.update({provider.provider + "_response": provider_response_json or ''})
                            error_code = provider_correlation_response.get("error_code")
                            if provider.provider == "fawry" and biller_info_json_dict.get('Type') == 'CASHININT' and error_code in ('21092', '21132', '26', '31004'):
                                provider_actual_amount = user_request.trans_amount + provider_fees_amount
                                customer_actual_amount = provider_actual_amount + extra_fees_amount

                                # Refund Payment Amount to Customer Wallet Balance
                                '''
                                wallet_transaction_sudo = request.env['website.wallet.transaction'].sudo()
                                label = _('Correlation Service Payment Failed for %s service') % (service.name)
                                partner_wallet_id = user_request.wallet_transaction_id.wallet_id or partner.get_transaction_wallet(service=service)
                                partner_id_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                                customer_wallet_create = wallet_transaction_sudo.create(
                                    {'wallet_type': 'credit', 'partner_id': partner.id,
                                     'request_id': user_request.id, 'reference': 'request',
                                     'label': label, 'amount': customer_actual_amount,
                                     'currency_id': currency.id,
                                     'wallet_balance_before': partner_id_wallet_balance,
                                     'wallet_balance_after': partner_id_wallet_balance + customer_actual_amount,
                                     'status': 'done'})
                                request.env.cr.commit()

                                partner.update({'wallet_balance': partner_id_wallet_balance + customer_actual_amount})
                                request.env.cr.commit()
                                '''
                                # Tamayoz TODO: Check below TODO: if required to set refunded wallet_transaction_id and update the request when correlation CASHIN is Fail
                                partner_wallet_id = user_request.wallet_transaction_id.wallet_id or partner.get_transaction_wallet(service=service)
                                if not partner_wallet_id:
                                    return invalid_response("wallet_not_found",
                                                            _("No Matched Wallet found for partner [%s] %s") % (
                                                                partner.ref,
                                                                partner.name), 400)
                                customer_wallet_create, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                                    'credit', partner, 'request',
                                    _('Correlation Service Payment Failed for %s service') % (service.name),
                                    customer_actual_amount, currency, user_request,
                                    'smartpay_operations.wallet_canel_service_payment_notify_mode',
                                    'wallet_cancel_service_payment',
                                    _('<p>%s %s successfully Added to your wallet.</p>') % (
                                        customer_actual_amount, _(currency.name))
                                )

                                # Deduct Sold Limit
                                if service.has_sale_limit:
                                    for sale_limit_id in service.sale_limit_ids:
                                        limit_type = sale_limit_id.limit_type
                                        timetuple = date_time.now().timetuple()
                                        sale_limit_domain = [
                                            ('partner_id', '=', partner.id),
                                            ('product_id', '=', service.id),
                                            ('limit_type', '=', limit_type),
                                            ('year', '=', timetuple.tm_year)]
                                        if limit_type == 'daily':
                                            sale_limit_domain += [('day', '=', timetuple.tm_yday)]
                                        elif limit_type == 'weekly':
                                            sale_limit_domain += [
                                                ('week', '=', date_time.now().isocalendar()[1])]
                                        elif limit_type == 'monthly':
                                            sale_limit_domain += [('month', '=', timetuple.tm_mon)]
                                        sale_limit = request.env['res.partner.sale.limit'].sudo().search(
                                            sale_limit_domain,
                                            order="id DESC", limit=1)
                                        if sale_limit:
                                            sale_limit.update({
                                                'sold_amount': sale_limit.sold_amount - customer_actual_amount})  # calculated_payment_amount

                                        # Refund Sold Over Limit Fees
                                        sale_limit_fees = request.env['res.partner.sale.limit.fees'].sudo().search([('user_request_id', '=', user_request.id),
                                                                                                                    ('limit_type', '=', limit_type),
                                                                                                                    ('refund_wallet_transaction_id', '=', False)], limit=1)
                                        if sale_limit_fees:
                                            wallet_transaction_id, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                                                'credit', partner, 'request',
                                                _('Refund %s over limit fees for %s service') % (limit_type, service.name),
                                                sale_limit_fees.fees_amount, currency, user_request,
                                                'smartpay_operations.wallet_canel_service_payment_notify_mode',
                                                'wallet_cancel_service_payment',
                                                _('<p>%s %s successfully Added to your wallet.</p>') % (
                                                    sale_limit_fees.fees_amount, _(currency.name))
                                            )
                                            sale_limit_fees.update({'refund_amount': sale_limit_fees.fees_amount, 'refund_wallet_transaction_id': wallet_transaction_id.id})

                                # Deduct Transaction Limit
                                if partner_wallet_id.type.has_trans_limit:
                                    for trans_limit_id in partner_wallet_id.type.trans_limit_ids:
                                        wallet_limit_type = trans_limit_id.limit_type
                                        timetuple = date_time.now().timetuple()
                                        trans_limit_domain = [
                                            ('wallet_id', '=', partner_wallet_id.id),
                                            # ('wallet_type_id', '=', partner_wallet_id.type.id),
                                            ('limit_type', '=', wallet_limit_type),
                                            ('year', '=', timetuple.tm_year)]
                                        if wallet_limit_type == 'daily':
                                            trans_limit_domain += [('day', '=', timetuple.tm_yday)]
                                        elif wallet_limit_type == 'weekly':
                                            trans_limit_domain += [('week', '=', date_time.now().isocalendar()[1])]
                                        elif wallet_limit_type == 'monthly':
                                            trans_limit_domain += [('month', '=', timetuple.tm_mon)]
                                        trans_limit = request.env['wallet.trans.limit'].sudo().search(
                                            trans_limit_domain, order="id DESC", limit=1)
                                        if trans_limit:
                                            trans_limit.update({'trans_amount': trans_limit.trans_amount - customer_actual_amount})  # calculated_payment_amount

                                        # Refund Transaction Over Limit Fees
                                        trans_limit_fees = request.env['wallet.trans.limit.fees'].sudo().search(
                                            [('user_request_id', '=', user_request.id),
                                             ('limit_type', '=', wallet_limit_type),
                                             ('refund_wallet_transaction_id', '=', False)], limit=1)
                                        if trans_limit_fees:
                                            wallet_transaction_id, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                                                'credit', partner, 'request',
                                                _('Refund %s over limit fees for %s wallet type') % (
                                                    wallet_limit_type, partner_wallet_id.type.name),
                                                trans_limit_fees.fees_amount, currency, user_request,
                                                'smartpay_operations.wallet_canel_service_payment_notify_mode',
                                                'wallet_cancel_service_payment',
                                                _('<p>%s %s successfully Added to your wallet.</p>') % (
                                                    trans_limit_fees.fees_amount, _(currency.name))
                                            )
                                            trans_limit_fees.update({'refund_amount': trans_limit_fees.fees_amount,
                                                                     'refund_wallet_transaction_id': wallet_transaction_id.id})

                                '''
                                # Notify customer
                                irc_param = request.env['ir.config_parameter'].sudo()
                                wallet_canel_service_payment_notify_mode = irc_param.get_param(
                                    "smartpay_operations.wallet_canel_service_payment_notify_mode")
                                if wallet_canel_service_payment_notify_mode == 'inbox':
                                    request.env['mail.thread'].sudo().message_notify(subject=label,
                                                                                     body=_(
                                                                                         '<p>%s %s successfully Added to your wallet.</p>') % (
                                                                                              customer_actual_amount,
                                                                                              _(currency.name)),
                                                                                     partner_ids=[(4, partner.id)],
                                                                                     )
                                elif wallet_canel_service_payment_notify_mode == 'email':
                                    customer_wallet_create.wallet_transaction_email_send()
                                elif wallet_canel_service_payment_notify_mode == 'sms' and partner.mobile:
                                    customer_wallet_create.sms_send_wallet_transaction(
                                        wallet_canel_service_payment_notify_mode, 'wallet_cancel_service_payment',
                                        partner.mobile, partner.name,  # request.env.user.name,
                                        label, '%s %s' % (customer_actual_amount, _(currency.name)),
                                               partner.country_id.phone_code or '2')
                                '''

                                # Tamayoz TODO: Check if required to set refunded wallet_transaction_id and update the request when correlation CASHIN is Fail
                                '''
                                user_request.update({'wallet_transaction_id': customer_wallet_create.id})

                                user_request.update({
                                    'provider_response': provider_response_json , # "stage_id": 4
                                    'description': _('Cancel Service Payment request (%s) was submit successfully @ %s') % (user_request.name, str(date_time.now() + timedelta(hours=2))),
                                    'action_status': 'completed'
                                })
                                request.env.cr.commit()
                                '''

                                # Refund provider bill for reconciliation purpose
                                # Cancel provider refund (cashback), customer invoice and customer credit note (cashback)
                                '''
                                refund = False
                                provider_invoice_ids = ()
                                for provider_invoice_id in user_request.provider_invoice_ids:
                                    provider_invoice_ids += (tuple(provider_invoice_id.ids),)
                                    # Refund Provider Bill
                                    if provider_invoice_id.type == 'in_invoice' and len(
                                            user_request.provider_invoice_ids) == 2:
                                        refund = request.env['account.invoice.refund'].with_context(
                                            active_ids=provider_invoice_id.ids).sudo().create({
                                            'filter_refund': 'refund',
                                            'description': provider_invoice_id.name,
                                            'date': provider_invoice_id.date_invoice,
                                        })
                                        result = refund.invoice_refund()
                                        refund_id = result.get('domain')[1][2]
                                        refund = request.env['account.invoice'].sudo().browse(refund_id)
                                        refund.update({'reference': pmtId, 'request_id': user_request.id})
                                        refund_line = refund.invoice_line_ids[0]
                                        refund_line.update({'request_id': user_request.id})
                                        refund.refresh()
                                        refund.action_invoice_open()
                                        refund.pay_and_reconcile(request.env['account.journal'].sudo().search(
                                            [('type', '=', 'cash'),
                                             ('company_id', '=', request.env.user.company_id.id),
                                             ('provider_id', '=', provider.id)], limit=1),
                                            provider_actual_amount)
                                        provider_invoice_ids += (tuple(refund.ids),)
                                    # Cancel provider refund (cashback)
                                    if provider_invoice_id.type == 'in_refund':
                                        if provider_invoice_id.state in ('in_payment', 'paid'):
                                            provider_invoice_id.action_invoice_re_open()
                                        provider_invoice_id.action_invoice_cancel()

                                user_request.update({'provider_invoice_ids': provider_invoice_ids})
                                request.env.cr.commit()

                                # customer_invoice_ids = ()
                                for customer_invoice_id in user_request.customer_invoice_ids:
                                    # customer_invoice_ids += (tuple(customer_invoice_id.ids),)
                                    # Cancel Customer Invoice and Customer Credit Note (cashback)
                                    if len(user_request.customer_invoice_ids) == 2:
                                        if customer_invoice_id.state in ('in_payment', 'paid'):
                                            customer_invoice_id.action_invoice_re_open()
                                        customer_invoice_id.action_invoice_cancel()

                                # user_request.update({'customer_invoice_ids': customer_invoice_ids})
                                # request.env.cr.commit()
                                '''

                        user_request.update({
                            'provider_response': json.dumps(error),
                            'description': json.dumps(error),
                            # 'stage_id': 5
                        })
                        request.env.cr.commit()
                        return invalid_response("Error", error, 400)

                    elif user_request.sudo().write({'stage_id': 4}):
                        return valid_response(_("Correlation REQ Number (%s) successfully!") % (request_number))
                except Exception as ex:
                    _logger.error("%s", ex, exc_info=True)
            else:
                return invalid_response("request_not_found", _("Request does not exist!"), 400)

            return invalid_response("request_not_correlation",
                                    _("Could not correlation REQ Number (%s)") % (request_number),
                                    400)

        @validate_token
        @http.route('/api/getRequest', type="http", auth="none", methods=["POST"], csrf=False)
        def getRequest(self, **payload):
            _logger.info(">>>>>>>>>>>>>>>>>>>> Calling Get Requests API")
            domain = payload.get("domain")
            if not domain or "name" not in domain:
                return invalid_response("request_number_missing", _("REQ Number is missing. Please Send REQ Number"), 400)
            return restful_main().get('smartpay_operations.request', None, **payload)

        @validate_token
        @http.route('/api/getRequests', type="http", auth="none", methods=["POST"], csrf=False)
        def getRequests(self, **payload):
            _logger.info(">>>>>>>>>>>>>>>>>>>> Calling Get Requests API")
            domain = []
            if payload.get("domain", None):
                domain = ast.literal_eval(payload.get("domain"))
            domain += [("partner_id.id", "=", request.env.user.partner_id.id)]
            if not any(item[0] == 'create_date' for item in domain):
                create_date = (datetime.date.today()+datetime.timedelta(days=-30)).strftime('%Y-%m-%d')
                domain += [("create_date", ">=", create_date)]
            payload.update({
                'domain': str(domain)
            })
            return restful_main().get('smartpay_operations.request', None, **payload)

        @validate_token
        @http.route('/api/getServiceFees', type="http", auth="none", methods=["POST"], csrf=False)
        def getServiceFees(self, **request_data):
            _logger.info(">>>>>>>>>>>>>>>>>>>> Calling Get Service Fees API")

            if not request_data.get('product_id'):
                return invalid_response("service_not_found", _("missing service in request data"), 400)
            else:
                service = request.env["product.product"].sudo().search(
                    [("id", "=", request_data.get('product_id')), ("type", "=", "service")],
                    order="id DESC", limit=1)
                if not service:
                    return invalid_response("service", _("service invalid"), 400)

            # Provider is mandatory because the service fee is different per provider.
            # So the user must send provider that own the bill inquiry request for prevent pay bill
            # with total amount different of total amount in bill inquiry
            provider_provider = request_data.get('provider')
            if provider_provider:
                provider = request.env['payment.acquirer'].sudo().search([("provider", "=", provider_provider)])
                # if provider: # Tamayoz Note: Comment this condition for solving service_providerinfo assign before initilizing
                if provider_provider == 'khales' and provider.server_state == 'offline':
                    return invalid_response("service_fees_not_available",
                                            _("Service Fees Not Available"), 400)
                service_providerinfo = request.env['product.supplierinfo'].sudo().search([
                    ('product_tmpl_id', '=', service.product_tmpl_id.id),
                    ('name', '=', provider.related_partner.id)
                ])
                if not service_providerinfo:
                    return invalid_response(
                        "Incompatible_provider_service", _("%s is not a provider for (%s) service") % (
                            provider_provider, service.name or '-'), 400)
            else:
                return invalid_response("provider_not_found",
                                        _("missing provider in request data"), 400)

            trans_amount = float(request_data.get('trans_amount'))
            if not trans_amount:
                return invalid_response("amount_not_found",
                                        _("missing bill amount in request data"), 400)
            else:
                # Calculate Fees
                provider_fees_calculated_amount = 0.0
                extra_fees_amount = 0.0
                if provider_provider == 'khales':
                    if not request_data.get('ePayBillRecID'):
                        return invalid_response("ePayBillRecID_not_found",
                                                _("missing ePayBillRecID in request data"), 400)
                    if not request_data.get('currency_id'):
                        return invalid_response("currency_not_found", _("missing currency in request data"), 400)

                    provider_channel = False
                    provider_channels = request.env['payment.acquirer.channel'].sudo().search(
                        [("acquirer_id", "=", provider.id)], limit=1)
                    if provider_channels:
                        provider_channel = provider_channels[0]

                    curCode = request_data.get('currency_id')
                    payAmts = request_data.get('payAmts')
                    if payAmts:
                        payAmts = ast.literal_eval(payAmts)
                        payAmtTemp = trans_amount
                        for payAmt in payAmts:
                            payAmtTemp -= float(payAmt.get('AmtDue'))
                        if payAmtTemp != 0:
                            return invalid_response("payAmts_not_match",
                                                    _("The sum of payAmts must be equals trans_amount"), 400)
                    else:
                        payAmts = [{'Sequence': '1', 'AmtDue': trans_amount, 'CurCode': curCode}]

                    '''
                    machine_serial = None
                    if len(request.env.user.machine_serial) > 16:  # Ingenico POS
                        machine_serial = request.env.user.machine_serial
                        machine_serial = machine_serial[len(machine_serial) - 16:len(machine_serial)]
                    '''
                    machine_serial = request.env.user.machine_serial
                    if machine_serial and len(machine_serial) > 16:
                        machine_serial = machine_serial[len(machine_serial) - 16:len(machine_serial)]
                    fees_response = provider.get_khales_fees('', machine_serial or '',
                                                             request_data.get('ePayBillRecID'), payAmts,
                                                             provider_channel)
                    if fees_response.get('Success'):
                        feeInqRsType = fees_response.get('Success')
                        provider_fees_calculated_amount = float(feeInqRsType['FeesAmt']['Amt'])

                if provider_fees_calculated_amount == 0 or provider_provider == 'khales':
                    calculate_provider_fees = True
                    if provider_provider == 'khales' and provider_fees_calculated_amount != 0:
                        calculate_provider_fees = False
                    commissions = request.env['product.supplierinfo.commission'].sudo().search_read(
                        domain=[('vendor', '=', service_providerinfo.name.id),
                                ('vendor_product_code', '=', service_providerinfo.product_code)],
                        fields=['Amount_Range_From', 'Amount_Range_To',
                                'Extra_Fee_Amt', 'Extra_Fee_Prc',
                                'Mer_Fee_Amt', 'Mer_Fee_Prc', 'Mer_Fee_Prc_MinAmt', 'Mer_Fee_Prc_MaxAmt']
                    )
                    for commission in commissions:
                        if commission['Amount_Range_From'] <= trans_amount \
                                and commission['Amount_Range_To'] >= trans_amount:
                            if commission['Extra_Fee_Amt'] > 0:
                                extra_fees_amount = commission['Extra_Fee_Amt']
                            elif commission['Extra_Fee_Prc'] > 0:
                                extra_fees_amount = trans_amount * commission['Extra_Fee_Prc'] / 100
                            if calculate_provider_fees:
                                if commission['Mer_Fee_Amt'] > 0:
                                    provider_fees_calculated_amount = commission['Mer_Fee_Amt']
                                elif commission['Mer_Fee_Prc'] > 0:
                                    # Fees amount = FA + [Percentage * Payment Amount]
                                    # Fees amount ====================> provider_fees_calculated_amount
                                    # FA =============================> provider_fees_calculated_amount
                                    # [Percentage * Payment Amount] ==> provider_fees_prc_calculated_amount
                                    provider_fees_prc_calculated_amount = trans_amount * commission[
                                        'Mer_Fee_Prc'] / 100
                                    if provider_fees_prc_calculated_amount < commission['Mer_Fee_Prc_MinAmt']:
                                        provider_fees_prc_calculated_amount = commission['Mer_Fee_Prc_MinAmt']
                                    elif provider_fees_prc_calculated_amount > commission['Mer_Fee_Prc_MaxAmt'] \
                                            and commission['Mer_Fee_Prc_MaxAmt'] > 0:
                                        provider_fees_prc_calculated_amount = commission['Mer_Fee_Prc_MaxAmt']
                                    provider_fees_calculated_amount += provider_fees_prc_calculated_amount
                            break
                    if calculate_provider_fees and provider_fees_calculated_amount != 0 and provider_provider == 'khales':
                        provider_fees_calculated_amount = ((math.floor(provider_fees_calculated_amount * 100)) / 100.0)

                calculated_payment_amount = trans_amount + provider_fees_calculated_amount + extra_fees_amount
                return valid_response(
                    {"message": _("Get Service Fees request was submit successfully."),
                     "provider": provider.provider,
                     "provider_service_code": service_providerinfo.product_code,
                     "provider_service_name": service_providerinfo.product_name,
                     "trans_amount": trans_amount,
                     "provider_fees_amount": provider_fees_calculated_amount,
                     "extra_fees_amount": extra_fees_amount
                     })

        @validate_token
        @http.route('/api/getWalletBalance', type="http", auth="none", methods=["POST"], csrf=False)
        def getWalletBalance(self, **payload):
            _logger.info(">>>>>>>>>>>>>>>>>>>> Calling Get Main Wallet Balance API")
            # return restful_main().get('res.partner', request.env.user.partner_id.id, **payload)
            wallet_id = None
            if payload.get("wallet_id"):
                wallet_id = request.env['website.wallet'].sudo().search([('id', '=', payload.get("wallet_id")), ('active', '=', True),
                                                                         ('partner_id', '=', request.env.user.partner_id.id)], limit=1)
            partner_wallet_id = wallet_id or request.env.user.partner_id.get_transaction_wallet()
            if not partner_wallet_id:
                return invalid_response("wallet_not_found",
                                        _("No Matched Wallet found for partner [%s] %s") % (
                                            request.env.user.partner_id.ref,
                                            request.env.user.partner_id.name), 400)
            wallets = []  # partner_wallets_balance
            wallet = {
                "id": partner_wallet_id.id,
                "name": partner_wallet_id.name,
                "wallet_balance": partner_wallet_id.balance_amount,
                "available_amount": partner_wallet_id.available_amount,
                "reserved_amount": partner_wallet_id.reserved_amount,
                "currency_id": _(partner_wallet_id.currency_id.name)
            }
            wallets.append(wallet)
            return valid_response(wallets)

        @validate_token
        @http.route('/api/getMyWallets', type="http", auth="none", methods=["POST"], csrf=False)
        def getMyWallets(self, **payload):
            _logger.info("@@@@@@@@@@@@@@@@@@@ Calling Get My Wallets Info API")
            ref = payload.get('reference')
            if ref:
                partner = request.env['res.partner'].sudo().search([('ref', '=', ref)], limit=1)
            else:
                partner = request.env.user.partner_id
            wallets = []  # partner_wallets_balance
            for wallet_id in partner.wallet_ids:
                wallet = {
                    "id": wallet_id.id,
                    "name": wallet_id.name,
                    "wallet_balance": wallet_id.balance_amount,
                    "available_amount": wallet_id.available_amount,
                    "reserved_amount": wallet_id.reserved_amount,
                    "currency_id": _(wallet_id.currency_id.name)
                }

                wallets.append(wallet)
            return valid_response(wallets)

        @validate_token
        @http.route('/api/getMyCustomersWalletBalance', type="http", auth="none", methods=["POST"], csrf=False)
        def getMyCustomersWalletBalance(self, **payload):
            _logger.info(">>>>>>>>>>>>>>>>>>>> Calling Get My Customer Main Wallet Balance API")
            domain, fields, offset, limit, order = extract_arguments(payload)
            user_id = -1
            ref = payload.get('reference')
            if ref:
                partner_id = request.env['res.partner'].sudo().search([('ref', '=', ref)], limit=1)
                if partner_id:
                    user = request.env['res.users'].sudo().search([('partner_id', '=', partner_id.id)])
                    if user:
                        user_id = user.id
            else:
                user_id = request.env.user.id
            domain += [("user_id", "=", user_id)]

            partner_sudo = request.env['res.partner'].sudo()
            my_customers = partner_sudo.search(domain, offset=offset, limit=limit, order=order)
            customers = []
            if my_customers:
                for my_customer in my_customers:
                    partner_wallet_id = my_customer.get_transaction_wallet()
                    partner_id_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                    customer = {
                        "id": my_customer.id,
                        "reference": my_customer.ref,
                        "name": my_customer.name,
                        "wallet_balance": partner_id_wallet_balance
                    }
                    customers.append(customer)
            return valid_response(customers)

        @validate_token
        @http.route('/api/getMyCustomersWallets', type="http", auth="none", methods=["POST"], csrf=False)
        def getMyCustomersWallets(self, **payload):
            _logger.info("@@@@@@@@@@@@@@@@@@@ Calling Get My Customer Wallets Info API")
            domain, fields, offset, limit, order = extract_arguments(payload)
            user_id = -1
            ref = payload.get('reference')
            if ref:
                partner_id = request.env['res.partner'].sudo().search([('ref', '=', ref)], limit=1)
                if partner_id:
                    user = request.env['res.users'].sudo().search([('partner_id', '=', partner_id.id)])
                    if user:
                        user_id = user.id
            else:
                user_id = request.env.user.id
            domain += [("user_id", "=", user_id)]

            partner_sudo = request.env['res.partner'].sudo()
            my_customers = partner_sudo.search(domain, offset=offset, limit=limit, order=order)
            customers = []
            if my_customers:
                for my_customer in my_customers:
                    wallets = []  # partner_wallets_balance
                    for wallet_id in my_customer.wallet_ids:
                        wallet = {
                            "id": wallet_id.id,
                            "name": wallet_id.name,
                            "wallet_balance": wallet_id.balance_amount,
                            "available_amount": wallet_id.available_amount,
                            "reserved_amount": wallet_id.reserved_amount,
                            "currency_id": _(wallet_id.currency_id.name)
                        }
                        wallets.append(wallet)
                    customer = {
                        "id": my_customer.id,
                        "reference": my_customer.ref,
                        "name": my_customer.name,
                        "wallet_balance": wallets
                    }
                    customers.append(customer)
            return valid_response(customers)

        @validate_token
        @http.route('/api/getWalletTransSummary', type="http", auth="none", methods=["POST"], csrf=False)
        def getWalletTransSummary(self, **payload):
            _logger.info(">>>>>>>>>>>>>>>>>>>> Calling Get Wallet Transactions Summary API")
            domain = []
            if payload.get("domain", None):
                domain = ast.literal_eval(payload.get("domain"))
            domain += [("partner_id.id", "=", request.env.user.partner_id.id), ('status', '=', 'done')]
            if not any(item[0] == 'create_date' for item in domain):
                create_date = (datetime.date.today() + datetime.timedelta(days=-30)).strftime('%Y-%m-%d')
                domain += [("create_date", ">=", create_date)]
            if not any(item[0] == 'wallet_id' for item in domain):
                partner_wallet_id = request.env.user.partner_id.get_transaction_wallet()
                if not partner_wallet_id:
                    return invalid_response("wallet_not_found",
                                            _("No Matched Wallet found for partner [%s] %s") % (
                                                request.env.user.partner_id.ref,
                                                request.env.user.partner_id.name), 400)
                domain += [("wallet_id", "=", partner_wallet_id.id)]

            wallet_trans_summary = {}
            wallet_transactions = request.env['website.wallet.transaction'].sudo().search(domain, order='id')

            if len(wallet_transactions) > 0:
                opening_balance = wallet_transactions[0].wallet_balance_before or 0.0
                bonus = sum(
                    float(amount) for amount in wallet_transactions.filtered(lambda wt: wt.wallet_type == 'credit'
                                                                                        and (_('Bonus for inviter user') in wt.label
                                                                                             or _('Bonus for invited user') in wt.label)).mapped('amount'))
                recharge = sum(
                    float(amount) for amount in wallet_transactions.filtered(lambda wt: wt.wallet_type == 'credit'
                                                                                        and (_('Transfer wallet balance from') in wt.label
                                                                                             or wt.label == _('Recharge Wallet'))).mapped('amount'))
                other_wallet_cash_out = sum(
                    float(amount) for amount in wallet_transactions.filtered(lambda wt: wt.wallet_type == 'credit'
                                                                                        and (_('Correlation Service Payment for') in wt.label)).mapped('amount'))
                cashback = sum(
                    float(amount) for amount in wallet_transactions.filtered(lambda wt: wt.wallet_type == 'credit'
                                                                                        and (_('Customer Cashback') in wt.label)).mapped('amount'))  # wt.reference == 'cashback' # Tamayoz TODO: For all Cashback change reference to cashback
                refund = sum(
                    float(amount) for amount in wallet_transactions.filtered(lambda wt: wt.wallet_type == 'credit'
                                                                                        and (_('Correlation Service Payment Failed') in wt.label
                                                                                             or _('Cancel Service Payment for') in wt.label)).mapped('amount'))
                collect_invoice = sum(
                    float(amount) for amount in wallet_transactions.filtered(lambda wt: wt.wallet_type == 'credit'
                                                                                        and (_('Collect invoice payment from') in wt.label)).mapped('amount'))
                add_correction = sum(
                    float(amount) for amount in wallet_transactions.filtered(lambda wt: wt.wallet_type == 'credit'
                                                                                        and wt.reference == 'manual').mapped('amount'))  # Other labels
                trans_payments = sum(
                    float(amount) for amount in wallet_transactions.filtered(lambda wt: wt.wallet_type == 'debit'
                                                                                        and (_('Pay Service Bill for') in wt.label)).mapped('amount'))
                reverse_cashback = sum(
                    float(amount) for amount in wallet_transactions.filtered(lambda wt: wt.wallet_type == 'debit'
                                                                                        and (_('Reverse Customer Cashback') in wt.label)).mapped('amount'))  # wt.reference == 'cashback' # Tamayoz TODO: For all Cashback change reference to cashback
                transfer_balance = sum(
                    float(amount) for amount in wallet_transactions.filtered(lambda wt: wt.wallet_type == 'debit'
                                                                                        and (_('Transfer wallet balance to') in wt.label)).mapped('amount'))
                installments = sum(
                    float(amount) for amount in wallet_transactions.filtered(lambda wt: wt.wallet_type == 'debit'
                                                                                        and wt.reference == 'manual'  # Tamayoz TODO: Collect payment for invoice must be change reference from manual to collection
                                                                                        and (_('Collect payment for invoice') in wt.label)).mapped('amount'))
                pay_invoice = sum(
                    float(amount) for amount in wallet_transactions.filtered(lambda wt: wt.wallet_type == 'debit'
                                                                                        and (_('Pay invoice to') in wt.label)).mapped('amount'))
                deduct_correction = sum(
                    float(amount) for amount in wallet_transactions.filtered(lambda wt: wt.wallet_type == 'debit'
                                                                                        and wt.reference == 'manual'
                                                                                        and (_('Collect payment for invoice') not in wt.label)).mapped('amount'))  # Other label
                ending_balance = wallet_transactions[len(wallet_transactions) - 1].wallet_balance_after or 0.00
                wallet_trans_summary.update({
                    "open": {
                        "opening_balance": {"label": _("Opening Balance"), "value": opening_balance}  # رصيد افتتاحي
                    },
                    "credit": {
                        "bonus": {"label": _("Bonus"), "value": bonus},  # بونص ترحيبى
                        "recharge": {"label": _("Recharge"), "value": recharge},  # اضافة للرصيد
                        "other_wallet_cash_out": {"label": _("Other Wallet Cash Out"), "value": other_wallet_cash_out}, # سحب من محفظة اخرى
                        "cashback": {"label": _("Cashback"), "value": cashback},  # اضافة عمولات
                        "refund": {"label": _("Refund"), "value": refund},  # استرجاع عمليات فاشلة
                        "collect_invoice": {"label": _("Collect Invoice"), "value": collect_invoice},  # فواتير التاجر
                        "add_correction": {"label": _("Addition Correction"), "value": add_correction}  # تصحيح اضافة
                    },
                    "debit": {
                        "trans_payments": {"label": _("Transaction Payments"), "value": trans_payments}, # مدفوعات العملاء
                        "reverse_cashback": {"label": _("Reverse Cashback"), "value": reverse_cashback},  # خصم عمولات
                        "transfer_balance": {"label": _("Transfer Balance"), "value": transfer_balance},  # تحويل رصيد
                        "installments": {"label": _("Installments"), "value": installments},  # اقساط
                        "pay_invoice": {"label": _("Pay Invoice"), "value": pay_invoice},  # فواتير التاجر
                        "deduct_correction": {"label": _("Deduction Correction"), "value": deduct_correction} # تصحيح خصم
                    },
                    "end": {
                        "ending_balance": {"label": _("Ending Balance"), "value": ending_balance}  # الرصيد الختامي
                    }
                })

            return valid_response(wallet_trans_summary)

        @validate_token
        @http.route('/api/getWalletTrans', type="http", auth="none", methods=["POST"], csrf=False)
        def getWalletTrans(self, **payload):
            _logger.info(">>>>>>>>>>>>>>>>>>>> Calling Get Wallet Transactions API")
            domain = []
            if payload.get("domain", None):
                domain = ast.literal_eval(payload.get("domain"))
            domain += [("partner_id.id", "=", request.env.user.partner_id.id), ('status', '=', 'done')]
            if not any(item[0] == 'create_date' for item in domain):
                create_date = (datetime.date.today()+datetime.timedelta(days=-30)).strftime('%Y-%m-%d')
                domain += [("create_date", ">=", create_date)]
            if not any(item[0] == 'wallet_id' for item in domain):
                partner_wallet_id = request.env.user.partner_id.get_transaction_wallet()
                if not partner_wallet_id:
                    return invalid_response("wallet_not_found",
                                            _("No Matched Wallet found for partner [%s] %s") % (
                                                request.env.user.partner_id.ref,
                                                request.env.user.partner_id.name), 400)
                domain += [("wallet_id", "=", partner_wallet_id.id)]
            payload.update({
                'domain': str(domain)
            })
            return restful_main().get('website.wallet.transaction', None, **payload)

        @validate_token
        @validate_machine
        @http.route('/api/rechargeMobileWallet', type="http", auth="none", methods=["POST"], csrf=False)
        def rechargeMobileWallet(self, **request_data):
            _logger.info(">>>>>>>>>>>>>>>>>>>> Calling Recharge Mobile Wallet Request API")
            if not request_data.get('request_number'):
                if request_data.get('transfer_to') and request_data.get('trans_amount'):
                    # current_user = request.env.user
                    # current_user_access_token = request.httprequest.headers.get("access_token")
                    # current_user_machine_serial = request.httprequest.headers.get("machine_serial")
                    # Create Recharge Mobile Wallet Request
                    transfer_to_user = request.env['res.users'].sudo().search(['|',
                                                                               ('login', '=', request_data.get('transfer_to')),
                                                                               ('ref', '=', request_data.get('transfer_to'))], limit=1)[0]
                    if not transfer_to_user:
                        return invalid_response("request_code_invalid", _("invalid transfer user in request data"), 400)

                    _token = request.env["api.access_token"]
                    token = ''
                    access_token = (
                        _token
                            .sudo()
                            .search([("user_id", "=", transfer_to_user.id)], order="id DESC", limit=1)
                    )
                    if access_token:
                        access_token = access_token[0]
                        if access_token.has_expired():
                            # return invalid_response("token_expired", _("transfer to user token expired"), 400)
                            access_token.update({'expires': date_time.now() + timedelta(minutes=15)})
                            request.env.cr.commit()
                        token = access_token.token
                    else:
                        # return invalid_response("account_deactivate", _("transfer to user account is deactivated"), 400)
                        token = _token.find_one_or_create_token(user_id=transfer_to_user.id, create=True)
                        request.env.cr.commit()

                    base_url = request.env['ir.config_parameter'].sudo().get_param('smartpay.base.url', default='web.base.url')
                    headers = {
                        'content-type': 'application/x-www-form-urlencoded',
                        'charset': 'utf-8',
                        'access_token': token
                    }
                    data = {
                        'request_type': 'recharge_wallet',
                        'trans_amount': request_data.get('trans_amount')
                    }

                    res = requests.post('{}/api/create_mobile_request'.format(base_url), headers=headers, data=data)
                    content = json.loads(res.content.decode('utf-8'))
                    # res = self.create_mobile_request(**data)
                    _logger.info("@@@@@@@@@@@@@@@@@@@ Recharge Mobile Wallet Response: " + str(content))
                    if content.get('data'):
                        request_number = content.get('data').get('request_number')  # json.loads(res.response[0].decode('utf-8')).get('request_number')
                        if not request_number:
                            return invalid_response("recharge_request_not created", _("wallet recharge request not cteated"), 400)
                        request_data.update({'request_number': request_number})
                        request.env.cr.commit()
                    else:
                        return invalid_response('Error: %s' % content.get('response'), _(content.get('message')), 400)
                    '''
                    request.httprequest.headers = {
                        'content-type': 'application/x-www-form-urlencoded',
                        'charset': 'utf-8',
                        'access_token': current_user_access_token,
                        'access_token': current_user_machine_serial
                    }
                    request.session.uid = current_user.id
                    request.uid = current_user.id
                    '''
                else:
                    return invalid_response("request_code_missing", _("missing request number in request data"), 400)
            user_request = request.env['smartpay_operations.request'].sudo().search(
                [('name', '=', request_data.get('request_number')), ('request_type', '=', "recharge_wallet")], limit=1)
            if user_request:
                if user_request.stage_id.id != 1:
                    return invalid_response("request_not_found",
                                            _("REQ Number (%s) invalid!") % (request_data.get('request_number')), 400)
                if request_data.get("wallet_id"):
                    partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(wallet_id=request_data.get("wallet_id"),
                                                                                           # service=user_request.product_id,
                                                                                           trans_amount=user_request.trans_amount)
                else:
                    partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(# service=user_request.product_id,
                                                                                           trans_amount=user_request.trans_amount)
                if not partner_wallet_id:
                    return invalid_response("wallet_not_found",
                                            _("No Matched Wallet found for partner [%s] %s") % (
                                                request.env.user.partner_id.ref,
                                                request.env.user.partner_id.name), 400)
                # Check minimum and maximum transfer amount
                min_transfer_amount = partner_wallet_id.type.min_transfer_amount
                max_transfer_amount = partner_wallet_id.type.max_transfer_amount
                if min_transfer_amount and user_request.trans_amount < min_transfer_amount:
                    return invalid_response("min_transfer_amount_exceeded",
                                            _("Minimum transfer amount (%s) exceeded!") % min_transfer_amount, 400)
                if max_transfer_amount and user_request.trans_amount > max_transfer_amount:
                    return invalid_response("max_transfer_amount_exceeded",
                                            _("Maximum transfer amount (%s) exceeded!") % max_transfer_amount, 400)
                if partner_wallet_id.type.allowed_transfer_ids:
                    allowed_type_ids = partner_wallet_id.type.allowed_transfer_ids.mapped('wallet_type_dest_id')
                    if all(wallet.type.id not in allowed_type_ids.ids for wallet in user_request.partner_id.wallet_ids):
                        return invalid_response("machine_allowed_transfer_not_matched",
                                                _("Machine Wallet does not allowed for transfer to Customer Wallet Types"), 400)
                unlink_wallet_reservation = False
                machine_wallet_reservation_id, machine_wallet_balance, machine_wallet_available_amount = \
                    partner_wallet_id.update_wallet_reserved_balance(
                        _('Transfer wallet balance to %s') % (user_request.partner_id.name), user_request.trans_amount,
                        user_request.currency_id, 'request', user_request
                    )
                # # machine_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                # machine_wallet_available_amount = partner_wallet_id.available_amount if partner_wallet_id else 0
                # if machine_wallet_available_amount < user_request.trans_amount:
                if not machine_wallet_reservation_id:
                    user_request.update({'stage_id': 3})
                    return invalid_response("machine_balance_not_enough",
                                            _("Machine Wallet Available Balance less than the request amount"), 400)

                # Transfer Balance from Machine Wallet to Mobile Wallet
                '''
                wallet_transaction_sudo = request.env['website.wallet.transaction'].sudo()
                label = _('Transfer wallet balance from %s') % (request.env.user.partner_id.name)
                partner_wallet_id = user_request.partner_id.get_transaction_wallet()
                partner_id_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                mobile_wallet_create = wallet_transaction_sudo.create(
                    {'wallet_type': 'credit', 'partner_id': user_request.partner_id.id, 'request_id': user_request.id,
                     'reference': 'request', 'label': label,
                     'amount': user_request.trans_amount, 'currency_id': user_request.currency_id.id,
                     'wallet_balance_before': partner_id_wallet_balance,
                     'wallet_balance_after': partner_id_wallet_balance + user_request.trans_amount,
                     'status': 'done'})
                request.env.cr.commit()

                user_request.partner_id.update(
                    {'wallet_balance': partner_id_wallet_balance + user_request.trans_amount})
                request.env.cr.commit()

                # Notify Mobile User
                irc_param = request.env['ir.config_parameter'].sudo()
                wallet_transfer_balance_notify_mode = irc_param.get_param("smartpay_operations.wallet_transfer_balance_notify_mode")
                if wallet_transfer_balance_notify_mode == 'inbox':
                    request.env['mail.thread'].sudo().message_notify(
                        subject=label,
                        body=_('<p>%s %s successfully added to your wallet.</p>') % (
                            user_request.trans_amount, _(user_request.currency_id.name)),
                        partner_ids=[(4, user_request.partner_id.id)],
                    )
                elif wallet_transfer_balance_notify_mode == 'email':
                    mobile_wallet_create.wallet_transaction_email_send()
                elif wallet_transfer_balance_notify_mode == 'sms' and user_request.partner_id.mobile:
                    mobile_wallet_create.sms_send_wallet_transaction(wallet_transfer_balance_notify_mode,
                                                                     'wallet_transfer_balance',
                                                                     user_request.partner_id.mobile,
                                                                     user_request.partner_id.name, label,
                                                                     '%s %s' % (user_request.trans_amount,
                                                                                _(user_request.currency_id.name)),
                                                                     user_request.partner_id.country_id.phone_code or '2')
                '''
                machine_customer_receivable_account = request.env.user.partner_id.property_account_receivable_id
                user_wallet_id = None
                if request_data.get("wallet_dest_id"):
                    user_wallet_id = request.env['website.wallet'].sudo().search(
                        [('id', '=', request_data.get("wallet_dest_id")), ('active', '=', True),
                         ('partner_id', '=', user_request.partner_id.id)], limit=1)
                if partner_wallet_id.type.allowed_transfer_ids:
                    allowed_type_ids = partner_wallet_id.type.allowed_transfer_ids.mapped('wallet_type_dest_id')
                    mobile_wallet_id = user_wallet_id.filtered(
                        lambda w: w.type.id in allowed_type_ids.ids) if user_wallet_id else \
                    user_request.partner_id.wallet_ids.filtered(lambda w: w.type.id in allowed_type_ids.ids)[0]
                else:
                    mobile_wallet_id = user_wallet_id or user_request.partner_id.get_transaction_wallet()
                if not mobile_wallet_id:
                    machine_wallet_reservation_id.sudo().unlink()
                    request.env.cr.commit()
                    return invalid_response("wallet_not_found",
                                            _("No Matched Wallet found for partner [%s] %s") % (
                                                user_request.partner_id.ref,
                                                user_request.partner_id.name), 400)
                mobile_wallet_create, wallet_balance_after = mobile_wallet_id.create_wallet_transaction(
                    'credit', user_request.partner_id, 'request',
                    _('Transfer wallet balance from %s') % (request.env.user.partner_id.name),
                    user_request.trans_amount, user_request.currency_id, user_request,
                    'smartpay_operations.wallet_transfer_balance_notify_mode', 'wallet_transfer_balance',
                    _('<p>%s %s successfully added to your wallet.</p>') % (
                        user_request.trans_amount, _(user_request.currency_id.name)),
                    machine_customer_receivable_account, 'Transfer Wallet Balance', request.env.user.partner_id
                )
                # Check Customer Wallet Balance Maximum Balance
                if not mobile_wallet_create:
                    # user_request.sudo().write({'stage_id': 5})
                    machine_wallet_reservation_id.sudo().unlink()
                    request.env.cr.commit()
                    return invalid_response("wallet_max_balance_exceeded", _("Wallet [%s] maximum balance exceeded!") % partner_wallet_id.name, 400)

                '''
                label = _('Transfer wallet balance to %s') % (user_request.partner_id.name)
                if request_data.get("wallet_id"):
                    partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(wallet_id=request_data.get("wallet_id"),
                                                                                           service=service,
                                                                                           trans_amount=customer_actual_amount)
                else:
                    partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(service=service,
                                                                                           trans_amount=customer_actual_amount)
                partner_id_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                machine_wallet_create = wallet_transaction_sudo.create(
                    {'wallet_type': 'debit', 'partner_id': request.env.user.partner_id.id, 'request_id': user_request.id,
                     'reference': 'request', 'label': label,
                     'amount': user_request.trans_amount, 'currency_id': user_request.currency_id.id,
                     'wallet_balance_before': partner_id_wallet_balance,
                     'wallet_balance_after': partner_id_wallet_balance - user_request.trans_amount,
                     'status': 'done'})
                request.env.cr.commit()

                request.env.user.partner_id.update(
                    {'wallet_balance': partner_id_wallet_balance - user_request.trans_amount})
                request.env.cr.commit()
                user_request.sudo().write({'wallet_transaction_id': machine_wallet_create.id, 'stage_id': 5})
                request.env.cr.commit()

                # Notify customer
                if wallet_transfer_balance_notify_mode == 'inbox':
                    request.env['mail.thread'].sudo().message_notify(
                        subject=label,
                        body=_('<p>%s %s successfully deducted from your wallet.</p>') % (
                            user_request.trans_amount, _(user_request.currency_id.name)),
                        partner_ids=[(4, request.env.user.partner_id.id)],
                    )
                elif wallet_transfer_balance_notify_mode == 'email':
                    machine_wallet_create.wallet_transaction_email_send()
                elif wallet_transfer_balance_notify_mode == 'sms' and request.env.user.partner_id.mobile:
                    machine_wallet_create.sms_send_wallet_transaction(wallet_transfer_balance_notify_mode,
                                                                      'wallet_transfer_balance',
                                                                      request.env.user.partner_id.mobile,
                                                                      request.env.user.name, label,
                                                                      '%s %s' % (user_request.trans_amount,
                                                                                 _(user_request.currency_id.name)),
                                                                      request.env.user.partner_id.country_id.phone_code or '2')
                '''
                machine_wallet_create, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                    'debit', request.env.user.partner_id, 'request',
                    _('Transfer wallet balance to %s') % (user_request.partner_id.name),
                    user_request.trans_amount, user_request.currency_id, user_request,
                    'smartpay_operations.wallet_transfer_balance_notify_mode', 'wallet_transfer_balance',
                    _('<p>%s %s successfully deducted from your wallet.</p>') % (
                        user_request.trans_amount, _(user_request.currency_id.name))
                )
                user_request.sudo().write({'wallet_transaction_id': machine_wallet_create.id, 'stage_id': 5})
                machine_wallet_reservation_id.sudo().unlink()
                request.env.cr.commit()
                unlink_wallet_reservation = True

                '''
                # Create journal entry for transfer AR balance from machine customer to mobile user.
                machine_customer_receivable_account = request.env.user.partner_id.property_account_receivable_id
                mobile_user_receivable_account = user_request.partner_id.property_account_receivable_id
                account_move = request.env['account.move'].sudo().create({
                    'journal_id': request.env['account.journal'].sudo().search([('type', '=', 'general')], limit=1).id,
                })
                request.env['account.move.line'].with_context(check_move_validity=False).sudo().create({
                    'name': user_request.name + ': Transfer Wallet Balance',
                    'move_id': account_move.id,
                    'account_id': machine_customer_receivable_account.id,
                    'partner_id': request.env.user.partner_id.id,
                    'debit': user_request.trans_amount,
                })
                request.env['account.move.line'].with_context(check_move_validity=False).sudo().create({
                    'name': user_request.name + ': Transfer Wallet Balance',
                    'move_id': account_move.id,
                    'account_id': mobile_user_receivable_account.id,
                    'partner_id': user_request.partner_id.id,
                    'credit': user_request.trans_amount,
                })
                account_move.post()
                '''

                return valid_response(_(
                    "Wallet for User (%s) recharged successfully with amount %s %s. Your Machine Wallet Balance is %s %s") %
                                      (user_request.partner_id.name, user_request.trans_amount,
                                       user_request.currency_id.name,
                                       wallet_balance_after, user_request.currency_id.name))
            else:
                return invalid_response("request_not_found", _("REQ Number (%s) does not exist!") % (
                request_data.get('request_number')), 400)

        @validate_token
        @http.route('/api/payInvoice', type="http", auth="none", methods=["POST"], csrf=False)
        def payInvoice(self, **request_data):
            _logger.info(">>>>>>>>>>>>>>>>>>>> Calling Pay Invoice Request API")
            if not request_data.get('request_number'):
                return invalid_response("request_code_missing", _("missing request number in request data"), 400)
            customer_request = request.env['smartpay_operations.request'].sudo().search(
                [('name', '=', request_data.get('request_number')), ('request_type', '=', "pay_invoice")], limit=1)
            if customer_request:
                if customer_request.stage_id.id != 1:
                    return invalid_response("request_not_found",
                                            _("REQ Number (%s) invalid!") % (request_data.get('request_number')), 400)
                if request_data.get("wallet_id"):
                    partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(wallet_id=request_data.get("wallet_id"),
                                                                                           service=customer_request.product_id,
                                                                                           trans_amount=customer_request.trans_amount)
                else:
                    partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(service=customer_request.product_id,
                                                                                           trans_amount=customer_request.trans_amount)
                if not partner_wallet_id:
                    return invalid_response("wallet_not_found",
                                            _("No Matched Wallet found for partner [%s] %s") % (
                                                request.env.user.partner_id.ref,
                                                request.env.user.partner_id.name), 400)
                # Check minimum and maximum transfer amount
                min_transfer_amount = partner_wallet_id.type.min_transfer_amount
                max_transfer_amount = partner_wallet_id.type.max_transfer_amount
                if min_transfer_amount and customer_request.trans_amount < min_transfer_amount:
                    return invalid_response("min_transfer_amount_exceeded",
                                            _("Minimum transfer amount (%s) exceeded!") % min_transfer_amount, 400)
                if max_transfer_amount and customer_request.trans_amount > max_transfer_amount:
                    return invalid_response("max_transfer_amount_exceeded",
                                            _("Maximum transfer amount (%s) exceeded!") % max_transfer_amount, 400)
                unlink_wallet_reservation = False
                mobile_wallet_reservation_id, mobile_wallet_balance, mobile_wallet_available_amount = \
                    partner_wallet_id.update_wallet_reserved_balance(
                        _('Pay invoice to %s') % (customer_request.partner_id.name), customer_request.trans_amount,
                        customer_request.currency_id, 'request', customer_request
                    )
                # # mobile_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                # mobile_wallet_available_amount = partner_wallet_id.available_amount if partner_wallet_id else 0
                # if mobile_wallet_available_amount < customer_request.trans_amount:
                if not mobile_wallet_reservation_id:
                    return invalid_response("mobile_balance_not_enough",
                                            _("Mobile Wallet Available Balance less than the request amount"), 400)

                # Transfer Balance from Mobile Wallet to Machine Wallet
                '''
                wallet_transaction_sudo = request.env['website.wallet.transaction'].sudo()
                label = _('Collect invoice payment from %s') % (request.env.user.partner_id.name)
                partner_wallet_id = customer_request.partner_id.get_transaction_wallet()
                partner_id_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                machine_wallet_create = wallet_transaction_sudo.create(
                    {'wallet_type': 'credit', 'partner_id': customer_request.partner_id.id, 'request_id': customer_request.id,
                     'reference': 'request', 'label': label,
                     'amount': customer_request.trans_amount, 'currency_id': customer_request.currency_id.id,
                     'wallet_balance_before': partner_id_wallet_balance,
                     'wallet_balance_after': partner_id_wallet_balance + customer_request.trans_amount,
                     'status': 'done'})
                request.env.cr.commit()

                customer_request.partner_id.update(
                    {'wallet_balance': partner_id_wallet_balance + customer_request.trans_amount})
                request.env.cr.commit()

                # Notify Customer
                irc_param = request.env['ir.config_parameter'].sudo()
                wallet_pay_invoice_notify_mode = irc_param.get_param("smartpay_operations.wallet_pay_invoice_notify_mode")
                if wallet_pay_invoice_notify_mode == 'inbox':
                    request.env['mail.thread'].sudo().message_notify(
                        subject=label,
                        body=_('<p>%s %s successfully added to your wallet.</p>') % (
                            customer_request.trans_amount, _(customer_request.currency_id.name)),
                        partner_ids=[(4, customer_request.partner_id.id)],
                    )
                elif wallet_pay_invoice_notify_mode == 'email':
                    machine_wallet_create.wallet_transaction_email_send()
                elif wallet_pay_invoice_notify_mode == 'sms' and customer_request.partner_id.mobile:
                    machine_wallet_create.sms_send_wallet_transaction(wallet_pay_invoice_notify_mode,
                                                                      'wallet_pay_invoice',
                                                                      customer_request.partner_id.mobile,
                                                                      customer_request.partner_id.name, label,
                                                                      '%s %s' % (customer_request.trans_amount,
                                                                                 _(customer_request.currency_id.name)),
                                                                      customer_request.partner_id.country_id.phone_code or '2')
                '''
                mobile_user_receivable_account = request.env.user.partner_id.property_account_receivable_id
                customer_wallet_id = None
                if request_data.get("wallet_dest_id"):
                    customer_wallet_id = request.env['website.wallet'].sudo().search(
                        [('id', '=', request_data.get("wallet_dest_id")), ('active', '=', True),
                         ('partner_id', '=', customer_request.partner_id.id)], limit=1)
                '''
                if partner_wallet_id.type.allowed_transfer_ids:
                    allowed_type_ids = partner_wallet_id.type.allowed_transfer_ids.mapped('wallet_type_dest_id')
                    machine_wallet_id = customer_wallet_id.filtered(
                        lambda w: w.type.id in allowed_type_ids.ids) if customer_wallet_id else \
                        customer_request.partner_id.wallet_ids.filtered(lambda w: w.type.id in allowed_type_ids.ids)[0]
                else:
                    machine_wallet_id = customer_wallet_id or customer_request.partner_id.get_transaction_wallet()
                '''
                machine_wallet_id = customer_wallet_id or customer_request.partner_id.get_transaction_wallet()
                if not machine_wallet_id:
                    return invalid_response("wallet_not_found",
                                            _("No Matched Wallet found for partner [%s] %s") % (
                                                customer_request.partner_id.ref,
                                                customer_request.partner_id.name), 400)
                machine_wallet_create, wallet_balance_after = machine_wallet_id.create_wallet_transaction(
                    'credit', customer_request.partner_id.id, 'request',
                    _('Collect invoice payment from %s') % (request.env.user.partner_id.name),
                    customer_request.trans_amount, customer_request.currency_id, customer_request,
                    'smartpay_operations.wallet_pay_invoice_notify_mode', 'wallet_pay_invoice',
                    _('<p>%s %s successfully added to your wallet.</p>') % (
                        customer_request.trans_amount, _(customer_request.currency_id.name)),
                    mobile_user_receivable_account, 'Pay Invoice', request.env.user.partner_id
                )
                # Check Customer Wallet Balance Maximum Balance
                if not machine_wallet_create:
                    # user_request.sudo().write({'stage_id': 5})
                    mobile_wallet_reservation_id.sudo().unlink()
                    request.env.cr.commit()
                    return invalid_response("wallet_max_balance_exceeded", _("Wallet [%s] maximum balance exceeded!") % partner_wallet_id.name, 400)

                '''
                label = _('Pay invoice to %s') % (customer_request.partner_id.name)
                if request_data.get("wallet_id"):
                    partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(wallet_id=request_data.get("wallet_id"),
                                                                                           service=service,
                                                                                           trans_amount=customer_actual_amount)
                else:
                    partner_wallet_id = request.env.user.partner_id.get_transaction_wallet(service=service,
                                                                                           trans_amount=customer_actual_amount)
                partner_id_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                mobile_wallet_create = wallet_transaction_sudo.create(
                    {'wallet_type': 'debit', 'partner_id': request.env.user.partner_id.id, 'request_id': customer_request.id,
                     'reference': 'request', 'label': label,
                     'amount': customer_request.trans_amount, 'currency_id': customer_request.currency_id.id,
                     'wallet_balance_before': partner_id_wallet_balance,
                     'wallet_balance_after': partner_id_wallet_balance - customer_request.trans_amount,
                     'status': 'done'})
                request.env.cr.commit()

                request.env.user.partner_id.update(
                    {'wallet_balance': partner_id_wallet_balance - customer_request.trans_amount})
                request.env.cr.commit()
                customer_request.sudo().write({'wallet_transaction_id': mobile_wallet_create.id, 'stage_id': 5})
                request.env.cr.commit()

                # Notify User
                if wallet_pay_invoice_notify_mode == 'inbox':
                    request.env['mail.thread'].sudo().message_notify(
                        subject=label,
                        body=_('<p>%s %s successfully deducted from your wallet.</p>') % (
                            customer_request.trans_amount, _(customer_request.currency_id.name)),
                        partner_ids=[(4, request.env.user.partner_id.id)],
                    )
                elif wallet_pay_invoice_notify_mode == 'email':
                    mobile_wallet_create.wallet_transaction_email_send()
                elif wallet_pay_invoice_notify_mode == 'sms' and request.env.user.partner_id.mobile:
                    mobile_wallet_create.sms_send_wallet_transaction(wallet_pay_invoice_notify_mode,
                                                                      'wallet_pay_invoice',
                                                                      request.env.user.partner_id.mobile,
                                                                      request.env.user.name, label,
                                                                      '%s %s' % (customer_request.trans_amount,
                                                                                 _(customer_request.currency_id.name)),
                                                                      request.env.user.partner_id.country_id.phone_code or '2')
                '''
                mobile_wallet_create, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                    'debit', request.env.user.partner_id, 'request',
                    _('Pay invoice to %s') % (customer_request.partner_id.name),
                    customer_request.trans_amount, customer_request.currency_id, customer_request,
                    'smartpay_operations.wallet_pay_invoice_notify_mode', 'wallet_pay_invoice',
                    _('<p>%s %s successfully deducted from your wallet.</p>') % (
                        customer_request.trans_amount, _(customer_request.currency_id.name))
                )
                customer_request.sudo().write({'wallet_transaction_id': mobile_wallet_create.id, 'stage_id': 5})
                mobile_wallet_reservation_id.sudo().unlink()
                request.env.cr.commit()
                unlink_wallet_reservation = True

                '''
                # Create journal entry for transfer AR balance from mobile user to machine customer.
                mobile_user_receivable_account = request.env.user.partner_id.property_account_receivable_id
                machine_customer_receivable_account = customer_request.partner_id.property_account_receivable_id
                account_move = request.env['account.move'].sudo().create({
                    'journal_id': request.env['account.journal'].sudo().search([('type', '=', 'general')], limit=1).id,
                })
                request.env['account.move.line'].with_context(check_move_validity=False).sudo().create({
                    'name': customer_request.name + ': Pay Invoice',
                    'move_id': account_move.id,
                    'account_id': mobile_user_receivable_account.id,
                    'partner_id': request.env.user.partner_id.id,
                    'debit': customer_request.trans_amount,
                })
                request.env['account.move.line'].with_context(check_move_validity=False).sudo().create({
                    'name': customer_request.name + ': Pay Invoice',
                    'move_id': account_move.id,
                    'account_id': machine_customer_receivable_account.id,
                    'partner_id': customer_request.partner_id.id,
                    'credit': customer_request.trans_amount,
                })
                account_move.post()
                '''

                return valid_response(_(
                    "Invoice request (%s) paid successfully with amount %s %s. Your Mobile Wallet Balance is %s %s") %
                                      (customer_request.name, customer_request.trans_amount,
                                       customer_request.currency_id.name,
                                       wallet_balance_after, customer_request.currency_id.name))
            else:
                return invalid_response("request_not_found", _("REQ Number (%s) does not exist!") % (
                    request_data.get('request_number')), 400)

        ###############################################
        ######### Fawry Integration Requests ##########
        ###############################################
        @validate_token
        @http.route('/api/getServiceCategories', type="http", auth="none", methods=["POST"], csrf=False)
        def getServiceCategories(self, **payload):
            _logger.info(">>>>>>>>>>>>>>>>>>>> Calling Get Sevice Category API")
            domain, fields, offset, limit, order = extract_arguments(payload)
            domain += [("parent_id", "=", request.env.ref("tm_base_gateway.product_category_services").id), ("product_count", "!=", 0)]
            # if not any(item[0] == 'tag_ids' for item in domain):
            for item in domain:
                if item[0] == 'tag_ids':
                    domain.pop(domain.index(item))
                    break
            user = request.env['res.users'].sudo().search([('id', '=', request.env.user.id)], limit=1)
            if user.allowed_product_tag_ids:
                domain += [('tag_ids', 'in', user.allowed_product_tag_ids.ids)]
            else:
                domain += [('tag_ids', 'in', (0))]

            lang = payload.get("lang", "en_US")
            ir_translation_sudo = request.env['ir.translation'].sudo()
            product_category_sudo = request.env['product.category'].sudo()
            '''
            service_categories = product_category_sudo.search_read(domain=domain,
                                                                     fields=fields,
                                                                     offset=offset,
                                                                     limit=limit,
                                                                     order=order,
                                                                     )
            '''
            service_categories = product_category_sudo.search(domain, offset=offset, limit=limit, order=order)
            categories = []
            if service_categories:
                for service_category in service_categories:
                    category = {
                        "id": service_category.id,
                        # "image": service_category.image_medium and service_category.image_medium.decode('ascii') or False,
                        # "name": service_category.name
                    }

                    if service_category.image_medium:
                        category.update({"image": "/web/image?model=%s&field=image_medium&id=%s" % ("product.category", service_category.id)})

                    '''
                    ir_translation_ids = ir_translation_sudo.search_read(
                        domain=[("name", "=", "product.category,name"), ("res_id", "=", service_category.id)],
                        fields=["lang", "source", "value"], order="res_id")
                    if ir_translation_ids:
                        category_trans = []
                        for ir_translation in ir_translation_ids:
                            category_trans.append({
                                "lang": ir_translation["lang"],
                                "name": ir_translation["value"]
                            })
                        category.update({"name_translate": category_trans})
                    '''

                    if lang == "en_US":
                        category.update({"name": service_category.name})
                    else:
                        ir_translation_id = ir_translation_sudo.search(
                            [("name", "=", "product.category,name"), ("res_id", "=", service_category.id), ("lang", "=", lang)],
                            limit=1)
                        if ir_translation_id:
                            category.update({"name": ir_translation_id.value})

                    categories.append(category)

            return valid_response(categories)
            # return invalid_response("service_categories_not_found",  _("Could not get Service Categories"), 400)

        @validate_token
        @http.route('/api/getServiceBillers', type="http", auth="none", methods=["POST"], csrf=False)
        def getServiceBillers(self, **payload):
            _logger.info(">>>>>>>>>>>>>>>>>>>> Calling Get Sevice Biller API")
            domain, fields, offset, limit, order = extract_arguments(payload)
            domain += [("product_count", "!=", 0)]
            # if not any(item[0] == 'tag_ids' for item in domain):
            for item in domain:
                if item[0] == 'tag_ids':
                    domain.pop(domain.index(item))
                    break
            user = request.env['res.users'].sudo().search([('id', '=', request.env.user.id)], limit=1)
            if user.allowed_product_tag_ids:
                domain += [('tag_ids', 'in', user.allowed_product_tag_ids.ids)]
            else:
                domain += [('tag_ids', 'in', (0))]

            lang = payload.get("lang", "en_US")
            ir_translation_sudo = request.env['ir.translation'].sudo()
            product_category_sudo = request.env['product.category'].sudo()
            '''
            service_billers = product_category_sudo.search_read(domain=domain,
                                                                     fields=fields,
                                                                     offset=offset,
                                                                     limit=limit,
                                                                     order=order,
                                                                     )
            '''
            service_billers = product_category_sudo.search(domain, offset=offset, limit=limit, order=order)
            billers = []
            if service_billers:
                for service_biller in service_billers:
                    biller = {
                        "id": service_biller.id,
                        "categ_id": service_biller.parent_id.id,
                        "categ_name": service_biller.parent_id.name,
                        # "image": service_biller.image_medium and service_biller.image_medium.decode('ascii') or False,
                        # "name": service_biller.name
                    }

                    if service_biller.image_medium:
                        biller.update({"image": "/web/image?model=%s&field=image_medium&id=%s" % ("product.category", service_biller.id)})

                    '''
                    ir_translation_ids = ir_translation_sudo.search_read(
                        domain=[("name", "=", "product.category,name"), ("res_id", "=", service_biller.id)],
                        fields=["lang", "source", "value"], order="res_id")
                    if ir_translation_ids:
                        biller_trans = []
                        for ir_translation in ir_translation_ids:
                            biller_trans.append({
                                "lang": ir_translation["lang"],
                                "name": ir_translation["value"]
                            })
                        biller.update({"name_translate": biller_trans})
                    '''

                    if lang == "en_US":
                        biller.update({"name": service_biller.name})
                    else:
                        ir_translation_id = ir_translation_sudo.search(
                            [("name", "=", "product.category,name"), ("res_id", "=", service_biller.id), ("lang", "=", lang)],
                            limit=1)
                        if ir_translation_id:
                            biller.update({"name": ir_translation_id.value})

                    billers.append(biller)

            return valid_response(billers)
            # return invalid_response("service_billers_not_found", _("Could not get Service Billers"), 400)

        @validate_token
        @http.route('/api/getServices', type="http", auth="none", methods=["POST"], csrf=False)
        def getServices(self, **payload):
            _logger.info(">>>>>>>>>>>>>>>>>>>> Calling Get Sevices API")
            domain, fields, offset, limit, order = extract_arguments(payload)
            # if not any(item[0] == 'tag_ids' for item in domain):
            for item in domain:
                if item[0] == 'tag_ids':
                    domain.pop(domain.index(item))
                    break
            user = request.env['res.users'].sudo().search([('id', '=', request.env.user.id)], limit=1)
            if user.allowed_product_tag_ids:
                domain += [('tag_ids', 'in', user.allowed_product_tag_ids.ids)]
            else:
                domain += [('tag_ids', 'in', (0))]

            lang = payload.get("lang", "en_US")
            biller_info_sudo = request.env['product.supplierinfo'].sudo()
            ir_translation_sudo = request.env['ir.translation'].sudo()
            product_template_sudo = request.env['product.template'].sudo()
            '''
            service_ids = product_template_sudo.search_read(domain=domain,
                                                                     fields=fields,
                                                                     offset=offset,
                                                                     limit=limit,
                                                                     order=order,
                                                                     )
            '''
            service_ids = product_template_sudo.search(domain, offset=offset, limit=limit, order=order)
            services = []
            if service_ids:
                for service_id in service_ids:
                    service = {
                        "id": service_id.product_variant_id.id,
                        "categ_id": service_id.categ_id.id,
                        "categ_name": service_id.categ_id.name,
                        # "image": service_id.image_medium and service_id.image_medium.decode('ascii') or False,
                        # "name": service_id.name
                    }

                    if service_id.image_medium:
                        service.update({"image": "/web/image?model=%s&field=image_medium&id=%s" % ("product.template", service_id.id)})

                    '''
                    ir_translation_ids = ir_translation_sudo.search_read(
                        domain=[("name", "=", "product.template,name"), ("res_id", "=", service_id.id)],
                        fields=["lang", "source", "value"], order="res_id")
                    if ir_translation_ids:
                        service_trans = []
                        for ir_translation in ir_translation_ids:
                            service_trans.append({
                                "lang": ir_translation["lang"],
                                "name": ir_translation["value"]
                            })
                        service.update({"name_translate": service_trans})
                    '''

                    biller_info_id = biller_info_sudo.search(
                        [("product_tmpl_id.type", "=", "service"),
                                ("product_tmpl_id.id", "=", service_id.id)],
                        limit=1)

                    if lang == "en_US":
                        service.update({"name": service_id.name})

                        if biller_info_id:
                            biller_info_dict = json.loads(biller_info_id.biller_info.replace("'", '"').replace('True', 'true').replace('False', 'false'), strict=False)
                            if biller_info_dict.get('ServiceTypeLogo'):
                                biller_info_dict.pop('ServiceTypeLogo')
                            if biller_info_dict.get('BillTypeLogo'):
                                biller_info_dict.pop('BillTypeLogo')
                            service.update({"biller_info": json.dumps(biller_info_dict, default=default)})
                    else:
                        ir_translation_id = ir_translation_sudo.search(
                            [("name", "=", "product.template,name"), ("res_id", "=", service_id.id),
                                    ("lang", "=", lang)],
                            limit=1)
                        if ir_translation_id:
                            service.update({"name": ir_translation_id.value})

                        ir_translation_id = ir_translation_sudo.search(
                            [("name", "=", "product.supplierinfo,biller_info"), ("res_id", "=", biller_info_id.id),
                                    ("lang", "=", lang)],
                            limit=1)
                        if ir_translation_id:
                            biller_info_dict = json.loads(ir_translation_id.value.replace("'", '"').replace('True', 'true').replace('False', 'false'), strict=False)
                            if biller_info_dict.get('ServiceTypeLogo'):
                                biller_info_dict.pop('ServiceTypeLogo')
                            if biller_info_dict.get('BillTypeLogo'):
                                biller_info_dict.pop('BillTypeLogo')
                            service.update({"biller_info": json.dumps(biller_info_dict, default=default)})

                    services.append(service)

            return valid_response(services)
            # return invalid_response("services_not_found", _("Could not get Services"), 400)

        @validate_token
        @http.route('/api/getAllServices', type="http", auth="none", methods=["POST"], csrf=False)
        def getAllServices(self, **payload):
            _logger.info(">>>>>>>>>>>>>>>>>>>> Calling Get All Services API")
            domain, fields, offset, limit, order = extract_arguments(payload)
            domain += [("parent_id", "=", request.env.ref("tm_base_gateway.product_category_services").id),
                       ("product_count", "!=", 0)]
            # if not any(item[0] == 'tag_ids' for item in domain):
            for item in domain:
                if item[0] == 'tag_ids':
                    domain.pop(domain.index(item))
                    break
            user = request.env['res.users'].sudo().search([('id', '=', request.env.user.id)], limit=1)
            if user.allowed_product_tag_ids:
                domain += [('tag_ids', 'in', user.allowed_product_tag_ids.ids)]
            else:
                domain += [('tag_ids', 'in', (0))]

            lang = payload.get("lang", "en_US")
            ir_translation_sudo = request.env['ir.translation'].sudo()
            product_category_sudo = request.env['product.category'].sudo()

            service_categories = product_category_sudo.search(domain, offset=offset, limit=limit, order=order)
            categories = []
            for service_category in service_categories:
                category = {
                    "id": service_category.id
                }

                if service_category.image_medium:
                    category.update({"image": "/web/image?model=%s&field=image_medium&id=%s" % (
                    "product.category", service_category.id)})

                if lang == "en_US":
                    category.update({"name": service_category.name})
                else:
                    ir_translation_id = ir_translation_sudo.search(
                        [("name", "=", "product.category,name"), ("res_id", "=", service_category.id),
                         ("lang", "=", lang)],
                        limit=1)
                    if ir_translation_id:
                        category.update({"name": ir_translation_id.value})

                # Get billers
                _logger.info("@@@@@@@@@@@@@@@@@@@ Get Billers")
                domain, fields, offset, limit, order = extract_arguments(payload)
                domain += [("parent_id.id", "=", service_category.id), ("product_count", "!=", 0)]

                service_billers = product_category_sudo.search(domain, offset=offset, limit=limit, order=order)
                billers = []
                for service_biller in service_billers:
                    biller = {
                        "id": service_biller.id,
                        "categ_id": service_biller.parent_id.id,
                        "categ_name": service_biller.parent_id.name
                    }

                    if service_biller.image_medium:
                        biller.update({"image": "/web/image?model=%s&field=image_medium&id=%s" % (
                        "product.category", service_biller.id)})

                    if lang == "en_US":
                        biller.update({"name": service_biller.name})
                    else:
                        ir_translation_id = ir_translation_sudo.search(
                            [("name", "=", "product.category,name"), ("res_id", "=", service_biller.id),
                             ("lang", "=", lang)],
                            limit=1)
                        if ir_translation_id:
                            biller.update({"name": ir_translation_id.value})

                    # Get Services
                    _logger.info("@@@@@@@@@@@@@@@@@@@ Get Services")
                    domain, fields, offset, limit, order = extract_arguments(payload)
                    domain += [("type", "=", "service"), ("categ_id.id", "=", service_biller.id)]

                    biller_info_sudo = request.env['product.supplierinfo'].sudo()
                    product_template_sudo = request.env['product.template'].sudo()

                    service_ids = product_template_sudo.search(domain, offset=offset, limit=limit, order=order)
                    services = []
                    for service_id in service_ids:
                        service = {
                            "id": service_id.product_variant_id.id,
                            "categ_id": service_id.categ_id.id,
                            "categ_name": service_id.categ_id.name
                        }

                        if service_id.image_medium:
                            service.update({"image": "/web/image?model=%s&field=image_medium&id=%s" % (
                                "product.template", service_id.id)})

                        biller_info_id = biller_info_sudo.search(
                            [("product_tmpl_id.type", "=", "service"),
                             ("product_tmpl_id.id", "=", service_id.id)],
                            limit=1)

                        if lang == "en_US":
                            service.update({"name": service_id.name})

                            if biller_info_id:
                                biller_info_dict = json.loads(biller_info_id.biller_info.replace("'", '"').replace('True', 'true').replace('False', 'false'), strict=False)
                                if biller_info_dict.get('ServiceTypeLogo'):
                                    biller_info_dict.pop('ServiceTypeLogo')
                                if biller_info_dict.get('BillTypeLogo'):
                                    biller_info_dict.pop('BillTypeLogo')
                                service.update({"biller_info": json.dumps(biller_info_dict, default=default)})
                        else:
                            ir_translation_id = ir_translation_sudo.search(
                                [("name", "=", "product.template,name"), ("res_id", "=", service_id.id),
                                 ("lang", "=", lang)],
                                limit=1)
                            if ir_translation_id:
                                service.update({"name": ir_translation_id.value})

                            ir_translation_id = ir_translation_sudo.search(
                                [("name", "=", "product.supplierinfo,biller_info"),
                                 ("res_id", "=", biller_info_id.id),
                                 ("lang", "=", lang)],
                                limit=1)
                            if ir_translation_id:
                                biller_info_dict = json.loads(ir_translation_id.value.replace("'", '"').replace('True', 'true').replace('False', 'false'), strict=False)
                                if biller_info_dict.get('ServiceTypeLogo'):
                                    biller_info_dict.pop('ServiceTypeLogo')
                                if biller_info_dict.get('BillTypeLogo'):
                                    biller_info_dict.pop('BillTypeLogo')
                                service.update({"biller_info": json.dumps(biller_info_dict, default=default)})

                        services.append(service)

                    biller.update({"services": services})
                    billers.append(biller)

                category.update({"billers": billers})
                categories.append(category)

            return valid_response(categories)
            # return invalid_response("service_categories_not_found",  _("Could not get Service Categories"), 400)

    class AccessToken(http.Controller):
        """."""

        def __init__(self):

            self._token = request.env["api.access_token"]
            self._expires_in = request.env.ref("restful.access_token_expires_in").sudo().value

        @http.route("/api/auth/machine_token", methods=["POST"], type="http", auth="none", csrf=False)
        def machine_token(self, **post):
            """The token URL to be used for getting the access_token:

            Args:
                **post must contain login and password.
            Returns:

                returns https response code 404 if failed error message in the body in json format
                and status code 202 if successful with the access_token.
            Example:
               import requests

               headers = {'content-type': 'text/plain', 'charset':'utf-8', 'machine_serial': '123456ABCDEF'}

               data = {
                   'login': 'admin',
                   'password': 'admin',
                   'db': 'galago.ng'
                   'Machine_serial': '123456ABCDEF',
                }
               base_url = 'http://odoo.ng'
               eq = requests.post(
                   '{}/api/auth/token'.format(base_url), data=data, headers=headers)
               content = json.loads(req.content.decode('utf-8'))
               headers.update(access-token=content.get('access_token'))
            """
            _token = request.env["api.access_token"]
            params = ["db", "login", "password"]
            params = {key: post.get(key) for key in params if post.get(key)}
            db, username, password, machine_serial = (
                params.get("db"),
                params.get("login"),
                params.get("password"),
                params.get("machine_serial"),
            )
            _credentials_includes_in_body = all([db, username, password, machine_serial])
            if not _credentials_includes_in_body:
                # The request post body is empty the credetials maybe passed via the headers.
                headers = request.httprequest.headers
                db = headers.get("db")
                username = headers.get("login")
                password = headers.get("password")
                machine_serial = headers.get("machine_serial")
                _credentials_includes_in_headers = all([db, username, password, machine_serial])
                if not _credentials_includes_in_headers:
                    # Empty 'db' or 'username' or 'password' or 'machine_serial':
                    return invalid_response(
                        "missing error",
                        _("either of the following are missing [db, username, password, machine_serial]"),
                        403,
                    )
            # Login in odoo database:
            try:
                request.session.authenticate(db, username, password)
            except Exception as e:
                # Invalid database:
                info = "The database name is not valid {}".format((e))
                error = "invalid_database"
                _logger.error(info)
                return invalid_response(_("wrong database name", error, 403))

            uid = request.session.uid
            # odoo login failed:
            if not uid:
                info = _("authentication failed")
                error = "authentication failed"
                _logger.error(info)
                return invalid_response(401, error, info)

            # Validate machine serial
            machine_serial_data = (
                request.env["res.users"]
                    .sudo()
                    .search([("machine_serial", "=", machine_serial), ("id", "=", uid)], order="id DESC", limit=1)
            )
            if not machine_serial_data:
                info = _("machine serial invalid")
                error = "machine_serial"
                _logger.error(info)
                return invalid_response(401, error, info)

            # Change the current password
            prefix = "TP_"
            password_characters = string.ascii_letters + string.digits + string.punctuation
            new_password = ''.join(random.choice(password_characters) for i in range(10))
            user = request.env['res.users'].sudo().search([('id', '=', request.env.user.id)], limit=1)
            user.sudo().write({'password': prefix + new_password})

            # Delete existing token
            access_token = (
                self.env["api.access_token"]
                    .sudo()
                    .search([("user_id", "=", uid)], order="id DESC", limit=1)
            )
            if access_token:
                access_token.unlink()
            # Generate tokens
            access_token = _token.find_one_or_create_token(user_id=uid, create=True)
            # Successful response:
            return werkzeug.wrappers.Response(
                status=200,
                content_type="application/json; charset=utf-8",
                headers=[("Cache-Control", "no-store"), ("Pragma", "no-cache")],
                response=json.dumps(
                    {
                        "uid": uid,
                        "user_context": request.session.get_context() if uid else {},
                        "company_id": request.env.user.company_id.id if uid else None,
                        "access_token": access_token,
                        "expires_in": self._expires_in,
                    }
                ),
            )

        @validate_token
        @validate_machine
        @http.route("/api/auth/refresh_machine_token", methods=["PUT"], type="http", auth="none", csrf=False)
        def refresh_machine_token(self, **post):
            """."""
            _token = request.env["api.access_token"].sudo()
            access_token = request.httprequest.headers.get("access_token")
            access_token = _token.search([("token", "=", access_token)])
            user_id = access_token.user_id.id
            if not access_token:
                info = _("No access token was provided in request!")
                error = "no_access_token"
                _logger.error(info)
                return invalid_response(400, error, info)
            # Delete current token
            for token in access_token:
                token.unlink()

            # Generate new token
            access_token = _token.find_one_or_create_token(user_id=user_id, create=True)
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
                        "access_token": access_token,
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
            access_token = _token.search([("token", "=", access_token)])
            user_id = access_token.user_id.id
            if not access_token:
                info = _("No access token was provided in request!")
                error = "no_access_token"
                _logger.error(info)
                return invalid_response(400, error, info)
            # Delete current tokens
            for token in access_token:
                token.unlink()

            # Generate new token
            access_token = _token.find_one_or_create_token(user_id=user_id, create=True)
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
                        "access_token": access_token,
                        "expires_in": self._expires_in,
                    }
                ),
            )

    class FawaterApi(http.Controller):

        @validate_token
        @http.route("/api/product_create", methods=["POST"], type="http", auth="none", csrf=False)
        def create_product(self, **post):
            user_id = request.uid
            user_obj = request.env['res.users'].browse(user_id)
            prod_name_ar = post.get("prod_name_ar")
            prod_name_en = post.get("prod_name_en")
            prod_company_id = post.get("prod_company_id")
            prod_price = post.get("prod_price")
            prod_type = post.get("prod_type")
            prod_categ_id = post.get("prod_categ_id")
            prod_can_sold = post.get("prod_can_sold")
            prod_can_purchased = post.get("prod_can_purchased")
            prod_obj = request.env['product.product']
            new_prod = prod_obj.create({
                'name': prod_name_en,
                'company_id': prod_company_id,
                'lst_price': prod_price,
                'type': prod_type,
                'categ_id': prod_categ_id,
                'sale_of': prod_can_sold,
                'purchase_ok': prod_can_purchased,
            })
            new_prod.with_context(lang='ar_AA').write({'name': prod_name_ar})
            if new_prod:
                return valid_response([{"prod_id": new_prod.id,
                                        "user_obj": user_obj.name,
                                        "message": "Product created successfully"}], status=201)

        @validate_token
        @http.route("/api/product_write", methods=["POST"], type="http", auth="none", csrf=False)
        def update_product(self, **post):
            user_id = request.uid
            user_obj = request.env['res.users'].browse(user_id)
            prod_id = post.get("prod_id")
            prod_write_name_ar = post.get("prod_name_ar")
            prod_write_name_en = post.get("prod_name_en")
            prod_write_price = post.get("prod_price")
            prod_type = post.get("prod_type")
            prod_categ_id = post.get("prod_categ_id")
            prod_can_sold = post.get("prod_can_sold")
            prod_can_purchased = post.get("prod_can_purchased")
            prod_obj = request.env['product.product']
            updated_prod = prod_obj.browse(int(prod_id))
            if user_obj.company_id.id == updated_prod.company_id.id:
                is_updated = updated_prod.write({
                    'name': prod_write_name_en,
                    'lst_price': prod_write_price,
                    'type': prod_type,
                    'categ_id': prod_categ_id,
                    'sale_ok': prod_can_sold,
                    'purchase_ok': prod_can_purchased,
                })
                is_updated.with_context(lang='ar_AA').write({'name': prod_write_name_ar})
            else:
                return invalid_response("UNAUTHORIZED", message="You Trying to Update on Product on another company.")
            if is_updated:
                return valid_response([{"prod_id": prod_id, "message": "Product updated successfully"}], status=200)

        @validate_token
        @http.route("/api/all_products_read", methods=["POST"], type="http", auth="none", csrf=False)
        def all_product_read(self, **post):
            user_id = request.uid
            user_obj = request.env['res.users'].browse(user_id)
            prod_lang = post.get("prod_lang")
            stages_obj = request.env['product.product']
            read_stages = stages_obj.with_context(lang=prod_lang).search(
                ['|', '|', ('company_id', '=', user_obj.company_id.id), ('company_id', '=', False),
                 ('company_id', 'child_of', [user_obj.company_id.id])])
            stages_list = []
            for prd in read_stages:
                value_dict = {}
                for f in prd._fields:
                    try:
                        value_dict[f] = str(getattr(prd, f))
                    except AccessError as aee:
                        print(aee)
                stages_list.append(value_dict)

            return werkzeug.wrappers.Response(
                status=200,
                content_type="application/json; charset=utf-8",
                headers=[("Cache-Control", "no-store"), ("Pragma", "no-cache")],
                response=json.dumps(
                    stages_list
                ),
            )

        @validate_token
        @http.route("/api/product_read", methods=["POST"], type="http", auth="none", csrf=False)
        def read_product(self, **post):
            user_id = request.uid
            user_obj = request.env['res.users'].browse(user_id)
            # payload = request.httprequest.data.decode()
            # payload = json.loads(payload)
            product_id = post.get("prod_id")
            prod_lang = post.get("prod_lang")
            stages_obj = request.env['product.product']
            read_stages = stages_obj.with_context(lang=prod_lang).search(
                [('id', '=', int(product_id)), ('company_id', '=', user_obj.company_id.id), '|',
                 ('company_id', '=', False), '|', ('company_id', 'child_of', [user_obj.company_id.id])])
            if read_stages:
                status = 200
                stages_list = []
                for prd in read_stages:
                    value_dict = {}
                    for f in prd._fields:
                        try:
                            value_dict[f] = str(getattr(prd, f))
                        except AccessError as aee:
                            print(aee)
                    stages_list.append(value_dict)
            else:
                stages_list = []
                status = 204
                value_dict = {
                    "message": "no data found"
                }
                stages_list.append(value_dict)

            return werkzeug.wrappers.Response(
                status=status,
                content_type="application/json; charset=utf-8",
                headers=[("Cache-Control", "no-store"), ("Pragma", "no-cache")],
                response=json.dumps(
                    stages_list
                ),
            )

        @validate_token
        @http.route(["/api/product_unlink"], methods=["POST"], type="http", auth="none", csrf=False)
        def unlink_product(self, **post):
            user_id = request.uid
            user_obj = request.env['res.users'].browse(user_id)
            prod_id = post.get("prod_id")
            prod_obj = request.env['product.product']
            delete_product = prod_obj.search([('id', '=', prod_id)])
            if user_obj.company_id.id == delete_product.company_id.id:
                if delete_product:
                    # try:
                    #     delete_product.unlink()
                    #     return valid_response(
                    #         [{"message": "Product Id %s successfully deleted" % (prod_id,), "delete": True}])
                    # except DatabaseError:
                    #     transaction.rollback()
                    # finally:
                    delete_product.write({'active': 0})
                    return valid_response(
                        [{"message": "Product Id %s successfully archived" % (prod_id,), "archive": True}])

            else:
                return invalid_response("UNAUTHORIZED", message="You Trying to Delete Product on another company.")

        """ Unit of measure API """

        @validate_token
        @http.route("/api/all_units_read", methods=["POST"], type="http", auth="none", csrf=False)
        def all_units_read(self, **post):
            user_id = request.uid
            user_obj = request.env['res.users'].browse(user_id)

            stages_obj = request.env['uom.uom']
            read_stages = stages_obj.search([])
            stages_list = []
            for unit in read_stages:
                value_dict = {}
                for f in unit._fields:
                    try:
                        value_dict[f] = str(getattr(unit, f))
                    except AccessError as aee:
                        print(aee)
                stages_list.append(value_dict)

            return werkzeug.wrappers.Response(
                status=200,
                content_type="application/json; charset=utf-8",
                headers=[("Cache-Control", "no-store"), ("Pragma", "no-cache")],
                response=json.dumps(
                    stages_list
                ),
            )

        """ Product Category APIs """

        @validate_token
        @http.route("/api/product_category_create", methods=["POST"], type="http", auth="none", csrf=False)
        def create_product_category(self, **post):
            user_id = request.uid
            user_obj = request.env['res.users'].browse(user_id)
            categ_name = post.get("categ_name")
            prod_company_id = post.get("prod_company_id")
            categ_parent_id = post.get("categ_parent_id")
            categ_obj = request.env['product.category']
            new_categ = categ_obj.create({
                'name': categ_name,
                'company_id': prod_company_id,
                'parent_id': categ_parent_id,
            })
            if new_categ:
                return valid_response([{"categ_id": new_categ.id, "message": "Product Category created successfully"}],
                                      status=201)

        @validate_token
        @http.route("/api/product_category_write", methods=["POST"], type="http", auth="none", csrf=False)
        def update_product_category(self, **post):
            user_id = request.uid
            user_obj = request.env['res.users'].browse(user_id)
            # payload = request.httprequest.data.decode()
            # payload = json.loads(payload)
            categ_id = post.get("categ_id")
            categ_write_name = post.get("categ_name")
            categ_write_parent = post.get("categ_parent")
            categ_obj = request.env['product.category']
            updated_categ = categ_obj.browse(int(categ_id))
            if user_obj.company_id.id == updated_categ.company_id.id:
                is_updated = updated_categ.write({
                    'name': categ_write_name,
                    'parent_id': categ_write_parent,
                })
            else:
                return invalid_response("UNAUTHORIZED",
                                        message="You Trying to Update on Product Category on another company.")
            if is_updated:
                return valid_response([{"categ_id": categ_id, "message": "Product Category updated successfully"}],
                                      status=200)

        @validate_token
        @http.route("/api/all_product_categories_read", methods=["POST"], type="http", auth="none", csrf=False)
        def all_product_category_read(self, **post):
            user_id = request.uid
            user_obj = request.env['res.users'].browse(user_id)

            stages_obj = request.env['product.category']
            read_stages = stages_obj.search([
                ('company_id', '=', user_obj.company_id.id), '|', ('company_id', '=', False),
                ('company_id', 'child_of', [user_obj.company_id.id])
            ])
            stages_list = []
            for categ in read_stages:
                value_dict = {}
                for f in categ._fields:
                    try:
                        value_dict[f] = str(getattr(categ, f))
                    except AccessError as aee:
                        print(aee)
                stages_list.append(value_dict)

            return werkzeug.wrappers.Response(
                status=200,
                content_type="application/json; charset=utf-8",
                headers=[("Cache-Control", "no-store"), ("Pragma", "no-cache")],
                response=json.dumps(
                    stages_list
                ),
            )

        @validate_token
        @http.route("/api/product_category_read", methods=["POST"], type="http", auth="none", csrf=False)
        def read_product_category(self, **post):
            user_id = request.uid
            user_obj = request.env['res.users'].browse(user_id)
            categ_id = post.get("categ_id")
            stages_obj = request.env['product.category']
            read_stages = stages_obj.search(
                [('id', '=', int(categ_id)), ('company_id', '=', user_obj.company_id.id), '|',
                 ('company_id', '=', False), '|', ('company_id', 'child_of', [user_obj.company_id.id])])
            if read_stages:
                status = 200
                stages_list = []
                for categ in read_stages:
                    value_dict = {}
                    for f in categ._fields:
                        try:
                            value_dict[f] = str(getattr(categ, f))
                        except AccessError as aee:
                            print(aee)
                    stages_list.append(value_dict)
            else:
                stages_list = []
                status = 204
                value_dict = {
                    "message": "no data found"
                }
                stages_list.append(value_dict)

            return werkzeug.wrappers.Response(
                status=status,
                content_type="application/json; charset=utf-8",
                headers=[("Cache-Control", "no-store"), ("Pragma", "no-cache")],
                response=json.dumps(
                    stages_list
                ),
            )

        """ Vendor APIs """

        @validate_token
        @http.route("/api/vendor_create", methods=["POST"], type="http", auth="none", csrf=False)
        def create_vendor(self, **post):
            user_id = request.uid
            user_obj = request.env['res.users'].browse(user_id)
            # payload = request.httprequest.data.decode()
            # payload = json.loads(payload)
            vendor_name = post.get("vend_name")
            vendor_obj = request.env['res.partner']
            new_vendor = vendor_obj.create({
                'name': vendor_name,
            })
            if new_vendor:
                return valid_response([{"vendor_id": new_vendor.id, "message": "Vendor created successfully"}],
                                      status=201)

        @validate_token
        @http.route("/api/all_vendors_read", methods=["POST"], type="http", auth="none", csrf=False)
        def all_vendors_read(self, **post):
            user_id = request.uid
            user_obj = request.env['res.users'].browse(user_id)

            stages_obj = request.env['res.partner']
            read_stages = stages_obj.search([('company_id', '=', user_obj.company_id.id), '|',
                                             ('company_id', '=', False),
                                             ('company_id', 'child_of', [user_obj.company_id.id])])
            stages_list = []
            for vendor in read_stages:
                value_dict = {}
                for f in vendor._fields:
                    try:
                        value_dict[f] = str(getattr(vendor, f))
                    except AccessError as aee:
                        print(aee)
                stages_list.append(value_dict)

            return werkzeug.wrappers.Response(
                status=200,
                content_type="application/json; charset=utf-8",
                headers=[("Cache-Control", "no-store"), ("Pragma", "no-cache")],
                response=json.dumps(
                    stages_list
                ),
            )

        @validate_token
        @http.route("/api/vendor_read", methods=["POST"], type="http", auth="none", csrf=False)
        def read_vendor(self, **post):
            user_id = request.uid
            user_obj = request.env['res.users'].browse(user_id)
            vendor_id = post.get("vendor_id")
            stages_obj = request.env['res.partner']
            read_stages = stages_obj.search(
                [('id', '=', int(vendor_id)), ('company_id', '=', user_obj.company_id.id), '|',
                 ('company_id', '=', False), '|', ('company_id', 'child_of', [user_obj.company_id.id])])
            if read_stages:
                status = 200
                stages_list = []
                for vendor in read_stages:
                    value_dict = {}
                    for f in vendor._fields:
                        try:
                            value_dict[f] = str(getattr(vendor, f))
                        except AccessError as aee:
                            print(aee)
                    stages_list.append(value_dict)
            else:
                stages_list = []
                status = 204
                value_dict = {
                    "message": "no data found"
                }
                stages_list.append(value_dict)

            return werkzeug.wrappers.Response(
                status=status,
                content_type="application/json; charset=utf-8",
                headers=[("Cache-Control", "no-store"), ("Pragma", "no-cache")],
                response=json.dumps(
                    stages_list
                ),
            )
