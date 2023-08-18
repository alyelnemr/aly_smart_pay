# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

import re
import json
import datetime
from datetime import datetime, timedelta, date
import logging
from odoo import api, fields, models, tools, SUPERUSER_ID, _
from odoo.exceptions import AccessError, UserError
from odoo.tools import float_is_zero

AVAILABLE_PRIORITIES = [
    ('0', 'Low'),
    ('1', 'Normal'),
    ('2', 'High'),
    ('3', 'Urgent'),
]

REQUEST_TYPES = [
    ('general_inquiry', 'General Inquiry'),
    ('recharge_wallet', 'Recharge Wallet'),
    ('service_bill_inquiry', 'Service Bill Inquiry'),
    ('pay_service_bill', 'Pay Service Bill'),
    ('pay_invoice', 'Pay Invoice'),
    ('wallet_invitation', 'Wallet Invitation')
]

_logger = logging.getLogger(__name__)

class HelpdeskRequest(models.Model):
    _name = "smartpay_operations.request"
    _description = "Helpdesk Requests"
    _inherit = ['mail.thread', 'mail.activity.mixin', 'portal.mixin']
    _order = "priority desc, create_date desc"
    _mail_post_access = 'read'

    @api.model
    def _get_default_stage_id(self):
        return self.env['smartpay_operations.stage'].search([], order='sequence', limit=1)

    name = fields.Char(string='Request', required=True, index=True, copy=False, default='New')
    description = fields.Text('Private Note')
    partner_id = fields.Many2one('res.partner', string='Customer', track_visibility='onchange', index=True)
    commercial_partner_id = fields.Many2one(
        related='partner_id.commercial_partner_id', string='Customer Company', store=True, index=True)
    contact_name = fields.Char('Contact Name')
    email_from = fields.Char('Email', help="Email address of the contact", index=True)
    user_id = fields.Many2one('res.users', string='Assigned to', track_visibility='onchange', index=True, default=False)
    team_id = fields.Many2one('smartpay_operations.team', string='Support Team', track_visibility='onchange',
        default=lambda self: self.env['smartpay_operations.team'].sudo()._get_default_team_id(user_id=self.env.uid),
        index=True, help='When sending mails, the default email address is taken from the support team.')
    date_deadline = fields.Datetime(string='Deadline', track_visibility='onchange')
    date_done = fields.Datetime(string='Done', track_visibility='onchange')

    request_type = fields.Selection(REQUEST_TYPES, string='Request type', default='general_inquiry', required=True, track_visibility='onchange')
    payment_status = fields.Selection([('new', 'New'),
                                       # ('in_progress', 'In Progress'),           # Sent to Provider
                                       ('failure', 'Failure'),                     # Failure from Provider
                                       ('dispute', 'Dispute'),                     # TODO: Handel Failure status to be in dispute Status when provider transaction status is pending (To be deducted from customer)
                                       # ('success', 'Success'),                     # Success from Provider
                                       ('timeout', 'Timeout'),
                                       ('in_queue', 'In Queue'),                   # Transaction Timeout and service hasn't both Timeout and SupportPmtReverse attributes in biller_info
                                       ('pending', 'Pending Timeout'),             # Transaction Timeout and service has Timeout attribute in biller_info or pending from provider. (May be refunded to customer)
                                       ('canceled', 'Canceled'),                   # Transaction Timeout and service has only SupportPmtReverse and cancel request from provider was successfully
                                       ('to_cancel', 'To Cancel'),                 # Service "PmtType" is "VOCH" and Transaction Timeout and service has only SupportPmtReverse and cancel request
                                                                                   # from provider was failure, So we will send cancel request to provider
                                       ('to_review', 'To Review'),                 # Service "PmtType" is "VOCH" and Transaction Timeout and service hasn't SupportPmtReverse, So we will rview with provider
                                       ('to_refund', 'To Refund'),                 # Service "PmtType" is not "VOCH" and Transaction Timeout and service has only SupportPmtReverse and cancel request
                                                                                   # from provider was failure, So we will send cancel request to provider and may be refunded to customer
                                       ('done', 'Done'),], string='Payment Status', default='new', track_visibility='onchange', index=True)
                                       # requests have "pending" and "to_refund" status must be reconciled with provider, then only requests not successfully will be allowed to refund to customer
    action_status = fields.Selection([('new', 'New'),
                                      ('in_progress', 'In Progress'),              # Payment_status equal "new": thats means the request sent to Provider
                                      ('completed', 'Completed')],                 # Payment_status equal "new": thats means the request success from Provider
                                     string='Action Status', default='new',
                                     track_visibility='onchange', index=True)
    product_id = fields.Many2one('product.product', string='Service', domain=[('type','=','service')], track_visibility='onchange', index=True)
    stage_id = fields.Many2one('smartpay_operations.stage', string='Stage', index=True, track_visibility='onchange',
                               domain="[]",
                               copy=False,
                               group_expand='_read_group_stage_ids',
                               default=_get_default_stage_id)
    priority = fields.Selection(AVAILABLE_PRIORITIES, 'Priority', index=True, default='1', track_visibility='onchange')
    kanban_state = fields.Selection([('normal', 'Normal'), ('blocked', 'Blocked'), ('done', 'Ready for next stage')],
                                    string='Kanban State', track_visibility='onchange',
                                    required=True, default='normal',
                                    help="""A Request's kanban state indicates special situations affecting it:\n
                                           * Normal is the default situation\n
                                           * Blocked indicates something is preventing the progress of this request\n
                                           * Ready for next stage indicates the request is ready to go to next stage""")

    color = fields.Integer('Color Index')
    legend_blocked = fields.Char(related="stage_id.legend_blocked", readonly=True)
    legend_done = fields.Char(related="stage_id.legend_done", readonly=True)
    legend_normal = fields.Char(related="stage_id.legend_normal", readonly=True)

    active = fields.Boolean(default=True)
    company_id = fields.Many2one('res.company', string='Company', default=lambda self: self.env.user.company_id)

    # Recharge Wallet Extra Info
    trans_number = fields.Char(string='Transaction Receipt No.', copy=False)
    payment_id = fields.Many2one('account.payment', string='Payment', help='Payment for recharge wallet',
                                 copy=False, domain="[('company_id', '=', company_id), "
                                                    "('partner_id', '=', partner_id), "
                                                    "('request_id', '=', False), "
                                                    "('payment_type', '=', 'inbound'), "
                                                    "('state', '=', 'posted'), "
                                                    # " ('amount', '=', 'trans_amount'), "
                                                    # "('currency_id', '=', currency_id)"
                                                    "]")
    # Recharge Wallet & Pay Service Bill Extra Info
    trans_date = fields.Date(string='Transaction Date', copy=False, default=fields.Date.today)
    # Recharge Wallet & Pay Invoice & Pay Service Bill Extra Info
    trans_amount = fields.Float(string='Transaction Amount', copy=False)
    currency_id = fields.Many2one('res.currency', string='Currency',
                                  required=True, readonly=True, states={'draft': [('readonly', False)]},
                                  default=lambda self: self.env.user.company_id.currency_id, track_visibility='always')
    wallet_transaction_id = fields.Many2one('website.wallet.transaction', 'Wallet Transaction', copy=False)

    # Wallet Invitation Extra Info
    mobile_number = fields.Char(string='Mobile Number.', copy=False)

    # Service Bill Inquiry & Pay Service Bill Extra Info
    provider_id = fields.Many2one('payment.acquirer', string='Provider', copy=False)
    provider_response = fields.Text(string='Provider Response', copy=False)
    extra_fees = fields.Text(string='Extra Fees', copy=False)
    provider_fees_amount = fields.Float(string='Provider Fees Amount', copy=False)
    provider_fees_calculated_amount = fields.Float(string='Provider Fees Caluulated Amount',
                                                   help='Technicl Field for calulate provider fee to check wallet balance before payment', copy=False)
    extra_fees_amount = fields.Float(string='Extra Fees Amount', copy=False)
    provider_invoice_ids = fields.One2many('account.invoice', 'request_id', string='Provider Invoices', readonly=True, copy=False,
                                           domain=[('type','in',('in_invoice', 'in_refund'))])
    provider_invoice_ids_count = fields.Integer(string='Provider Invoices  Count', compute='_get_len_provider_invoice_ids', store=True)
    aggregated_provider_invoice_ids = fields.Many2many('account.invoice', 'smartpay_operations_request_bill_rel',
                                                       'request_id', 'bill_id',
                                                       string='Aggregated Vendor Bills', readonly=True, copy=False)
    aggregated_provider_invoice_ids_count = fields.Integer(string='Aggregated Vendor Bills Count',
                                                           compute='_get_len_provider_invoice_ids', store=True)
    customer_invoice_ids = fields.One2many('account.invoice', 'request_id', string='Customer Invoices', readonly=True, copy=False,
                                           domain=[('type', 'in', ('out_invoice', 'out_refund'))])
    customer_invoice_ids_count = fields.Integer(string='Customer Invoices Count', compute='_get_len_customer_invoice_ids', store=True)
    aggregated_customer_invoice_ids = fields.Many2many('account.invoice', 'smartpay_operations_request_invoice_rel',
                                                       'request_id', 'invoice_id',
                                                       string='Aggregated Customer Invoices', readonly=True, copy=False)
    aggregated_customer_invoice_ids_count = fields.Integer(string='Aggregated Customer Invoices Count',
                                                           compute='_get_len_customer_invoice_ids', store=True)

    @api.multi
    @api.depends('provider_invoice_ids', 'aggregated_provider_invoice_ids')
    def _get_len_provider_invoice_ids(self):
        for request in self:
            request.provider_invoice_ids_count = len(request.provider_invoice_ids)
            request.aggregated_provider_invoice_ids_count = len(request.aggregated_provider_invoice_ids)

    @api.multi
    @api.depends('customer_invoice_ids', 'aggregated_customer_invoice_ids')
    def _get_len_customer_invoice_ids(self):
        for request in self:
            request.customer_invoice_ids_count = len(request.customer_invoice_ids)
            request.aggregated_customer_invoice_ids_count = len(request.aggregated_customer_invoice_ids)

    @api.multi
    def view_provider_invoices(self):
        provider_invoice_ids = self.provider_invoice_ids
        if provider_invoice_ids:
            action = self.env.ref('account.action_vendor_bill_template').read()[0]
            action['domain'] = [('id', 'in', provider_invoice_ids.ids)]
            return action

    @api.multi
    def view_customer_invoices(self):
        customer_invoice_ids = self.customer_invoice_ids
        if customer_invoice_ids:
            action = self.env.ref('account.action_invoice_tree1').read()[0]
            action['domain'] = [('id', 'in', customer_invoice_ids.ids)]
            return action

    @api.multi
    def view_aggregated_provider_invoices(self):
        provider_invoice_ids = self.aggregated_provider_invoice_ids
        if provider_invoice_ids:
            action = self.env.ref('account.action_vendor_bill_template').read()[0]
            action['domain'] = [('id', 'in', provider_invoice_ids.ids)]
            return action

    @api.multi
    def view_aggregated_customer_invoices(self):
        customer_invoice_ids = self.aggregated_customer_invoice_ids
        if customer_invoice_ids:
            action = self.env.ref('account.action_invoice_tree1').read()[0]
            action['domain'] = [('id', 'in', customer_invoice_ids.ids)]
            return action

    @api.onchange('partner_id')
    def _onchange_partner_id(self):
        """ This function sets partner email address based on partner
        """
        self.email_from = self.partner_id.email
        if self.request_type == 'recharge_wallet':
            return {'domain': {'payment_id': [('company_id', '=', self.company_id.id),
                                              ('partner_id', '=', self.partner_id.id),
                                              ('request_id', '=', False),
                                              ('payment_type', '=', 'inbound'),
                                              ('state', '=', 'posted'),
                                              # ('amount', '=', self.trans_amount),
                                              ('currency_id', '=', self.currency_id.id)
                                              ]}}

    @api.onchange('request_type')
    def _onchange_request_type(self):
        if self.request_type == 'recharge_wallet':
            return {'domain': {'product_id': [('name', '=', 'Wallet Recharge')],
                               'payment_id': [('company_id', '=', self.company_id.id),
                                              ('partner_id', '=', self.partner_id.id),
                                              ('request_id', '=', False),
                                              ('payment_type', '=', 'inbound'),
                                              ('state', '=', 'posted'),
                                              # ('amount', '=', self.trans_amount),
                                              ('currency_id', '=', self.currency_id.id)
                                              ]}}
        else:
            return {'domain': {'product_id': [('type', '=', 'service')]}}

    '''
    @api.onchange('trans_amount')
    def _onchange_trans_amount(self):
        if self.request_type == 'recharge_wallet':
            return {'domain': {'payment_id': [('company_id', '=', self.company_id.id),
                                              ('partner_id', '=', self.partner_id.id),
                                              ('request_id', '=', False),
                                              ('payment_type', '=', 'inbound'),
                                              ('state', '=', 'posted'),
                                              # ('amount', '=', self.trans_amount),
                                              ('currency_id', '=', self.currency_id.id)
                                              ]}}
    '''

    @api.onchange('payment_id')
    def _onchange_payment_id(self):
        if self.request_type == 'recharge_wallet':
            if not self.trans_number:
                if self.payment_id:
                    self.trans_amount = self.payment_id.amount
                    self.trans_date = self.payment_id.payment_date
                # else:
                    # self.trans_amount = 0
            elif self.trans_amount != self.payment_id.amount:
                raise UserError(_('The selected customer payment amount must be equals the request trans amount'))

    @api.multi
    def copy(self, default=None):
        if default is None:
            default = {}
        default.update(name=_('%s (copy)') % (self.name))
        return super(HelpdeskRequest, self).copy(default=default)

    def _can_add__recipient(self, partner_id):
        if not self.partner_id.email:
            return False
        if self.partner_id in self.message_follower_ids.mapped('partner_id'):
            return False
        return True

    @api.multi
    def message_get_suggested_recipients(self):
        recipients = super(HelpdeskRequest, self).message_get_suggested_recipients()
        try:
            for tic in self:
                if tic.partner_id:
                    if tic._can_add__recipient(tic.partner_id):
                        tic._message_add_suggested_recipient(recipients, partner=tic.partner_id,
                                                             reason=_('Customer'))
                elif tic.email_from:
                    tic._message_add_suggested_recipient(recipients, email=tic.email_from,
                                                         reason=_('Customer Email'))
        except AccessError:  # no read access rights -> just ignore suggested recipients because this imply modifying followers
            pass
        return recipients

    def _email_parse(self, email):
        match = re.match(r"(.*) *<(.*)>", email)
        if match:
            contact_name, email_from =  match.group(1,2)
        else:
            match = re.match(r"(.*)@.*", email)
            contact_name =  match.group(1)
            email_from = email
        return contact_name, email_from

    @api.model
    def message_new(self, msg, custom_values=None):
        match = re.match(r"(.*) *<(.*)>", msg.get('from'))
        if match:
            contact_name, email_from =  match.group(1,2)
        else:
            match = re.match(r"(.*)@.*", msg.get('from'))
            contact_name =  match.group(1)
            email_from = msg.get('from')

        body = tools.html2plaintext(msg.get('body'))
        bre = re.match(r"(.*)^-- *$", body, re.MULTILINE|re.DOTALL|re.UNICODE)
        desc = bre.group(1) if bre else None

        defaults = {
            'name':  msg.get('subject') or _("No Subject"),
            'email_from': email_from,
            'description':  desc or body,
        }

        partner = self.env['res.partner'].sudo().search([('email', '=ilike', email_from)], limit=1)
        if partner:
            defaults.update({
                'partner_id': partner.id,
            })
        else:
            defaults.update({
                'contact_name': contact_name,
            })

        create_context = dict(self.env.context or {})
        # create_context['default_user_id'] = False
        # create_context.update({
        #     'mail_create_nolog': True,
        # })

        company_id = False
        if custom_values:
            defaults.update(custom_values)
            team_id = custom_values.get('team_id')
            if team_id:
                team = self.env['smartpay_operations.team'].sudo().browse(team_id)
                if team.company_id:
                    company_id = team.company_id.id
        if not company_id and partner.company_id:
            company_id = partner.company_id.id
        defaults.update({'company_id': company_id})

        return super(HelpdeskRequest, self.with_context(create_context)).message_new(msg, custom_values=defaults)

    @api.model_create_single
    def create(self, vals):
        if vals.get('name', 'New') == 'New':
            vals['name'] = self.env['ir.sequence'].next_by_code('helpdesk.request') or '/'
        if vals.get('payment_id'):
            payment_id = self.env['account.payment'].search([('id', '=', vals.get('payment_id'))])
            if payment_id:
                vals.update({'trans_amount': payment_id.amount})
        context = dict(self.env.context)
        context.update({
            'mail_create_nosubscribe': False,
        })
        res = super(HelpdeskRequest, self.with_context(context)).create(vals)
        # res = super().create(vals)
        if res.partner_id:
            res.message_subscribe([res.partner_id.id])
        return res


    @api.multi
    def write(self, vals):
        if self.request_type == 'recharge_wallet' and not self.trans_number:
            if vals.get('payment_id'):
                payment_id = self.env['account.payment'].search([('id','=',vals.get('payment_id'))])
                if payment_id:
                    vals.update({'trans_amount': payment_id.amount})
                # else:
                    # vals.update({'trans_amount': 0})
            # else:
                # vals.update({'trans_amount': 0}) # Don't update trans_amount to zero because payment_id doesn't exist when approve request
            # stage change: update date_last_stage_update
        if 'stage_id' in vals:
            current_stage = self.stage_id
            new_stage = vals.get('stage_id')
            # if (new_stage in ['approved', 'rejected']) and (
            # not self.env.user.has_group('your_module.your_group_xml_id')):
            #     raise ValidationError(_("Only Managers can perform that move !"))
            # elif some other_conditions:
            # some other logics

            # if current_stage.id == self.env.ref('your_module.xml_id_of_your_stage').id:
            if current_stage.id != self.env.ref('smartpay_operations.stage_new').id:
                raise UserError(_('You can not change stage from (%s) to another stage') % (self.stage_id.name))

            if self.request_type == 'recharge_wallet' and new_stage == self.env.ref('smartpay_operations.stage_approved').id:
                # The recharge wallet request must have a customer payment for approve it
                if self.payment_id:
                    self.payment_id.update({'request_id': self.id})
                    # if self.partner_id.user_id.machine_serial:
                    '''
                    wallet_transaction_sudo = self.env['website.wallet.transaction'].sudo()
                    label = _('Recharge Wallet')
                    partner_wallet_id = self.partner_id.get_transaction_wallet()
                    customer_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                    customer_wallet_create = wallet_transaction_sudo.create(
                        {'wallet_type': 'credit', 'partner_id': self.partner_id.id, 'request_id': self.id,
                         'reference': 'request', 'label': label, 'amount': self.trans_amount,
                         'currency_id': self.currency_id.id,
                         'wallet_balance_before': customer_wallet_balance,
                         'wallet_balance_after': customer_wallet_balance + self.trans_amount,
                         'status': 'done'})
                    self.env.cr.commit()

                    self.partner_id.update({'wallet_balance': customer_wallet_balance + self.trans_amount})
                    self.env.cr.commit()

                    # Notify Customer
                    irc_param = self.env['ir.config_parameter'].sudo()
                    wallet_recharge_notify_mode = irc_param.get_param("smartpay_operations.wallet_recharge_notify_mode")
                    if wallet_recharge_notify_mode == 'inbox':
                        self.env['mail.thread'].sudo().message_notify(
                            subject=label,
                            body=_('<p>%s %s successfully added to your wallet.</p>') % (
                                self.trans_amount, _(self.currency_id.name)),
                            partner_ids=[(4, self.partner_id.id)],
                        )
                    elif wallet_recharge_notify_mode == 'email':
                        customer_wallet_create.wallet_transaction_email_send()
                    elif wallet_recharge_notify_mode == 'sms' and self.partner_id.mobile:
                        customer_wallet_create.sms_send_wallet_transaction(wallet_recharge_notify_mode,
                                                                           'wallet_recharge',
                                                                           self.partner_id.mobile,
                                                                           self.partner_id.name, label,
                                                                           '%s %s' % (self.trans_amount,
                                                                                      _(self.currency_id.name)),
                                                                           self.partner_id.country_id.phone_code or '2')
                    '''
                    partner_wallet_id = self.partner_id.get_transaction_wallet()
                    if not partner_wallet_id:
                        raise UserError(_("No Matched Wallet found for partner [%s] %s") % (
                                                self.partner_id.ref,
                                                self.partner_id.name))
                    customer_wallet_create, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                        'credit', self.partner_id, 'request', _('Recharge Wallet'),
                        self.trans_amount, self.env.user.company_id.currency_id, self,
                        'smartpay_operations.wallet_recharge_notify_mode', 'wallet_recharge',
                        _('<p>%s %s successfully added to your wallet.</p>') % (
                            self.trans_amount, _(self.currency_id.name))
                    )
                    # Check Customer Wallet Balance Maximum Balance
                    if not customer_wallet_create:
                        raise UserError(_("Wallet [%s] maximum balance exceeded!") % partner_wallet_id.name)
                else:
                    raise UserError(_('You must select a customer payment for recharge wallet'))

            if 'kanban_state' not in vals:
                vals['kanban_state'] = 'normal'
            stage = self.env['smartpay_operations.stage'].browse(vals['stage_id'])
            if stage.last:
                vals.update({'date_done': fields.Datetime.now()})
            else:
                vals.update({'date_done': False})

        return super(HelpdeskRequest, self).write(vals)

    @api.model
    def _read_group_stage_ids(self, stages, domain, order):

        search_domain = []

        # perform search
        stage_ids = stages._search(search_domain, order=order, access_rights_uid=SUPERUSER_ID)
        return stages.browse(stage_ids)

    @api.multi
    def takeit(self):
        self.ensure_one()
        vals = {
            'user_id' : self.env.uid,
            # 'team_id': self.env['smartpay_operations.team'].sudo()._get_default_team_id(user_id=self.env.uid).id
        }
        return super(HelpdeskRequest, self).write(vals)

    '''
    @api.model_cr
    def _register_hook(self):
        HelpdeskRequest.website_form = bool(self.env['ir.module.module'].
                                           search([('name', '=', 'website_form'), ('state', '=', 'installed')]))
        if HelpdeskRequest.website_form:
            self.env['ir.model'].search([('model', '=', self._name)]).write({'website_form_access': True})
            self.env['ir.model.fields'].formbuilder_whitelist(
                self._name, ['name', 'request_type', 'product_id', 'description', 'date_deadline', 'priority', 'partner_id',
                             'user_id', 'trans_number', 'trans_date', 'trans_amount', 'currency_id', 'mobile_number'])
        pass
    '''

    def auto_expire_request(self):
        try:
            request_pool = self.env['smartpay_operations.request']
            request_hours = int(self.env['ir.config_parameter'].sudo().get_param("smartpay_operations.request_hours"))

            timeout_request_ids=request_pool.search([('stage_id','=',self.env.ref('smartpay_operations.stage_new').id),('create_date','<=',str(datetime.now() - timedelta(hours=request_hours)))])
            for request in timeout_request_ids:
                request.write({'stage_id': self.env.ref('smartpay_operations.stage_expired').id})
        except Exception as e:
            _logger.error("%s", e)
            return "internal error"

    def auto_create_invoices_for_pay_request(self, date_from=None, date_to=None):
        try:
            request_pool = self.env['smartpay_operations.request']
            # request_hours = int(self.env['ir.config_parameter'].sudo().get_param("smartpay_operations.request_hours"))

            domain = [('stage_id','=',self.env.ref('smartpay_operations.stage_done').id),
                      ('request_type', '=', 'pay_service_bill'),
                      ('provider_response', 'not ilike', 'error_message'),
                      ('provider_response', 'not ilike', 'provider_cancel_response'),
                      '|',
                      ('description', '=', False),
                      '&',
                      ('description', 'not ilike', 'Cancel Service Payment request'),
                      ('description', 'not ilike', 'Initiation Service Payment request'),
                      ## ('create_date','<=',str(datetime.now() - timedelta(hours=request_hours))),
                      # '|',
                      # ('customer_invoice_ids_count', '<', 2),
                      # ('provider_invoice_ids_count', '<', 2)
            ]
            if date_from:
                domain += [('create_date','>=','%s' % (date_from))]
            if date_to:
                domain += [('create_date', '<=','%s' % (date_to))]
            domain += ['|',
                      ('customer_invoice_ids_count', '=', 0),
                      ('provider_invoice_ids_count', '=', 0)]
            requests = request_pool.search(domain, order='id'
                                          )#.filtered(lambda x: len(x.customer_invoice_ids) < 2 or len(x.provider_invoice_ids) < 2)
            _logger.info("@@@@@@@@@@@@@@@@@@@ Start Create auto invoices for [%s] requests" % (len(requests)))
            for request in requests:
                _logger.info("@@@@@@@@@@@@@@@@@@@ Create auto invoices for request [%s]" % (request.name))

                provider_response = request.provider_response
                if "provider_correlation_response" in provider_response:
                    provider_response = json.dumps(json.loads(provider_response.replace("\'{", "{").replace("}\'", "}").replace("\'", "\""))['provider_correlation_response'])
                provider_response_json = json.loads(provider_response)
                # Get Provider Payment Trans ID
                if request.provider_id.provider == "fawry":
                    for payment in provider_response_json['PmtTransId']:
                        if payment['PmtIdType'] == 'FCRN':
                            provider_payment_trans_id = payment['PmtId']
                            break
                if request.provider_id.provider == "khales":
                    provider_payment_trans_id = provider_response_json['PmtRecAdviceStatus']['PmtTransId']['PmtId']

                provider_actual_amount = request.trans_amount + request.provider_fees_amount
                customer_actual_amount = provider_actual_amount + request.extra_fees_amount

                merchant_cashback_amount = 0.0
                customer_cashback_amount = 0.0
                provider_info = request.env['product.supplierinfo'].sudo().search([
                    ('product_tmpl_id', '=', request.product_id.product_tmpl_id.id),
                    ('name', '=', request.provider_id.related_partner.id)
                ])
                commissions = request.env['product.supplierinfo.commission'].sudo().search_read(
                    domain=[('vendor', '=', provider_info.name.id),
                            ('vendor_product_code', '=', provider_info.product_code)],
                    fields=['Amount_Range_From', 'Amount_Range_To',
                            'Mer_Comm_Full_Fix_Amt', 'Cust_Comm_Full_Fix_Amt',
                            'Bill_Merchant_Comm_Prc', 'Bill_Customer_Comm_Prc']
                )
                for commission in commissions:
                    if commission['Amount_Range_From'] <= request.trans_amount \
                            and commission['Amount_Range_To'] >= request.trans_amount:
                        if commission['Mer_Comm_Full_Fix_Amt'] > 0:
                            merchant_cashback_amount = commission['Mer_Comm_Full_Fix_Amt']
                            customer_cashback_amount = commission['Cust_Comm_Full_Fix_Amt']
                        elif commission['Bill_Merchant_Comm_Prc'] > 0:
                            merchant_cashback_amount = request.trans_amount * commission[
                                'Bill_Merchant_Comm_Prc'] / 100
                            customer_cashback_amount = request.trans_amount * commission[
                                'Bill_Customer_Comm_Prc'] / 100
                        break

                name = request.provider_id.provider + ': [' + provider_info.product_code + '] ' + provider_info.product_name
                # Create Vendor (Provider) Invoices
                provider_invoice_ids = ()
                request_provider_bills = request.provider_invoice_ids.filtered(lambda x: x.type == 'in_invoice')
                if len(request_provider_bills) == 0:
                    # 1- Create Vendor bill
                    provider_journal_id = request.env['account.journal'].sudo().search([('type', '=', 'purchase'),
                                                                                        ('company_id', '=',
                                                                                         request.company_id.id)], limit=1)
                    provider_invoice_vals = request.with_context(name=name,
                                                                         provider_payment_trans_id=provider_payment_trans_id,
                                                                         journal_id=provider_journal_id.id,
                                                                         invoice_date=date.today(),
                                                                         invoice_type='in_invoice',
                                                                         partner_id=provider_info.name.id)._prepare_invoice()
                    provider_invoice_id = request.env['account.invoice'].sudo().create(provider_invoice_vals)
                    invoice_line = provider_invoice_id._prepare_invoice_line_from_request(request=request,
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
                         ('company_id', '=', request.company_id.id),
                         ('provider_id', '=', request.provider_id.id)], limit=1),
                        provider_actual_amount)
                    request.env.cr.commit()
                else:
                    provider_invoice_id = request_provider_bills[0]
                    provider_invoice_ids += (tuple(provider_invoice_id.ids),)

                request_provider_refunds = request.provider_invoice_ids.filtered(lambda x: x.type == 'in_refund')
                if len(request_provider_refunds) == 0:
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
                        refund.update({'reference': provider_payment_trans_id, 'request_id': request.id})
                        refund_line = refund.invoice_line_ids[0]
                        refund_line.update({'price_unit': merchant_cashback_amount, 'request_id': request.id})
                        refund.refresh()
                        refund.action_invoice_open()
                        provider_invoice_ids += (tuple(refund.ids),)
                        request.env.cr.commit()
                else:
                    refund = request_provider_refunds[0]
                    provider_invoice_ids += (tuple(refund.ids),)

                request.update({'provider_invoice_ids': provider_invoice_ids})
                request.env.cr.commit()

                # Create Customer Invoices
                customer_invoice_ids = ()
                request_customer_invoices = request.customer_invoice_ids.filtered(lambda x: x.type == 'out_invoice')
                if len(request_customer_invoices) == 0:
                    # 1- Create Customer Invoice
                    customer_journal_id = request.env['account.journal'].sudo().search([('type', '=', 'sale'),
                                                                                        ('company_id', '=',
                                                                                         request.company_id.id)],
                                                                                       limit=1)
                    customer_invoice_vals = request.with_context(name=provider_payment_trans_id,
                                                                         journal_id=customer_journal_id.id,
                                                                         invoice_date=date.today(),
                                                                         invoice_type='out_invoice',
                                                                         partner_id=request.partner_id.id)._prepare_invoice()
                    customer_invoice_id = request.env['account.invoice'].sudo().create(customer_invoice_vals)
                    request.invoice_line_create(invoice_id=customer_invoice_id.id, name=name,
                                                        qty=1, price_unit=customer_actual_amount)
                    customer_invoice_id.action_invoice_open()
                    customer_invoice_ids += (tuple(customer_invoice_id.ids),)
                    # Tamayoz TODO: Auto Reconcile customer invoice with prepaid wallet recharge payments and previous cashback credit note
                    """
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
                    """
                    request.env.cr.commit()
                else:
                    customer_invoice_id = request_customer_invoices[0]
                    customer_invoice_ids += (tuple(customer_invoice_id.ids),)

                request_customer_credit_notes = request.customer_invoice_ids.filtered(lambda x: x.type == 'out_refund')
                if len(request_customer_credit_notes) == 0:
                    # 2- Create Customer Credit Note with commision amount for only customers have commission
                    customer_user = request.env['res.users'].sudo().search([('partner_id', '=', request.partner_id.id)], limit=1)
                    if customer_user and customer_user.commission and customer_cashback_amount > 0:
                        credit_note = request.env['account.invoice.refund'].with_context(
                            active_ids=customer_invoice_id.ids).sudo().create({
                            'filter_refund': 'refund',
                            'description': provider_payment_trans_id,
                            'date': customer_invoice_id.date_invoice,
                        })
                        result = credit_note.invoice_refund()
                        credit_note_id = result.get('domain')[1][2]
                        credit_note = request.env['account.invoice'].sudo().browse(credit_note_id)
                        credit_note.update({'request_id': request.id})
                        credit_note_line = credit_note.invoice_line_ids[0]
                        credit_note_line.update({'price_unit': customer_cashback_amount, 'request_id': request.id})
                        credit_note.refresh()
                        """  Don't validate the customer credit note until the vendor refund reconciliation
                        After vendor refund reconciliation, validate the customer credit note with
                        the net amount of vendor refund sent in provider cashback statement then
                        increase the customer wallet with the same net amount. """
                        # credit_note.action_invoice_open()
                        customer_invoice_ids += (tuple(credit_note.ids),)
                        request.env.cr.commit()
                else:
                    credit_note = request_customer_credit_notes[0]
                    customer_invoice_ids += (tuple(credit_note.ids),)

                request.update({'customer_invoice_ids': customer_invoice_ids})
                request.env.cr.commit()
        except Exception as e:
            _logger.error("%s", e)
            return "internal error"

    @api.multi
    def _prepare_invoice(self):
        """
        Prepare the dict of values to create the new invoice for a helpdesk request. This method may be
        overridden to implement custom invoice generation (making sure to call super() to establish
        a clean extension chain).
        """
        self.ensure_one()
        context = self.env.context
        invoice_type = context.get('invoice_type')
        name = context.get('name')
        provider_payment_trans_id = context.get('provider_payment_trans_id')
        vinvoice = self.env['account.invoice'].new({'partner_id': context.get('partner_id'), 'type': invoice_type})
        # Get partner extra fields
        vinvoice._onchange_partner_id()
        invoice_vals = vinvoice._convert_to_write(vinvoice._cache)
        invoice_vals.update({
            'name': name or self.name,
            'origin': self.name,
            'journal_id': context.get('journal_id'),
            'currency_id': self.company_id.currency_id.id,
            'company_id': self.company_id.id,
            'user_id': self.user_id and self.user_id.id,
            'date_invoice': context.get('invoice_date'),
            'comment': self.description,
            'request_id': self.id,
        })
        if invoice_type in ('in_invoice', 'in_refund') and provider_payment_trans_id:
            invoice_vals.update({'reference': provider_payment_trans_id})
        return invoice_vals

    @api.multi
    def _prepare_invoice_line(self, name, qty, price_unit):
        """
        Prepare the dict of values to create the new invoice line for a request.

        :param qty: float quantity to invoice
        """
        self.ensure_one()
        res = {}
        product = self.product_id.with_context(force_company=self.company_id.id)
        account = product.property_account_income_id or product.categ_id.property_account_income_categ_id

        if not account and self.product_id:
            raise UserError(
                _('Please define income account for this product: "%s" (id:%d) - or for its category: "%s".') %
                (self.product_id.name, self.product_id.id, self.product_id.categ_id.name))

        fpos = self.partner_id.property_account_position_id
        if fpos and account:
            account = fpos.map_account(account)

        res = {
            'name': name,
            'origin': self.name,
            'account_id': account.id,
            'price_unit': price_unit,
            'quantity': qty,
            'uom_id': self.product_id.uom_id.id,
            'product_id': self.product_id.id or False,
            # 'invoice_line_tax_ids': [(6, 0, self.tax_id.ids)],
            # 'account_analytic_id': self.order_id.analytic_account_id.id,
            # 'analytic_tag_ids': [(6, 0, self.analytic_tag_ids.ids)],
        }
        return res

    @api.multi
    def invoice_line_create(self, invoice_id, name, qty, price_unit):
        """ Create an invoice line. The quantity to invoice can be positive (invoice) or negative (refund).

            .. deprecated:: 12.0
                Replaced by :func:`invoice_line_create_vals` which can be used for creating
                `account.invoice.line` records in batch

            :param invoice_id: integer
            :param qty: float quantity to invoice
            :returns recordset of account.invoice.line created
        """
        return self.env['account.invoice.line'].create(
            self.invoice_line_create_vals(invoice_id, name, qty, price_unit))

    def invoice_line_create_vals(self, invoice_id, name, qty, price_unit):
        """ Create an invoice line. The quantity to invoice can be positive (invoice) or negative
            (refund).

            :param invoice_id: integer
            :param qty: float quantity to invoice
            :returns list of dict containing creation values for account.invoice.line records
        """
        vals_list = []
        precision = self.env['decimal.precision'].precision_get('Product Unit of Measure')
        for request in self:
            if not float_is_zero(qty, precision_digits=precision) or not request.product_id:
                vals = request._prepare_invoice_line(name=name, qty=qty, price_unit=price_unit)
                vals.update({'invoice_id': invoice_id, 'request_id': request.id})
                vals_list.append(vals)
        return vals_list
