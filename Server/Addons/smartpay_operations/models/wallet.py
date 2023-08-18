# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

import logging

from odoo import fields, models, api, _
from odoo.exceptions import UserError
from odoo.addons import decimal_precision as dp

_logger = logging.getLogger(__name__)


class website_wallet_type(models.Model):
    _name = 'website.wallet.type'
    _description = 'Customer Wallet Type'
    _order = 'sequence, id'

    name = fields.Char('Name', required=True)
    sequence = fields.Integer(default=10)
    '''
    collection_terms = fields.Integer('Collection Period', default="1",
                                      help="Collection Term, in days. It's the number of days for the collection "
                                           "period. 1 means the collection is daily bases.")
    '''
    allow_payment = fields.Boolean('Allow Payment Bills', default=True)
    allowed_service_ids = fields.Many2many('product.product',
                                           'wallet_type_allowed_services',
                                           'wallet_type_id',
                                           'product_id',
                                           string='Allowed Services', domain=[('type','=','service')],
                                           help='Only Services available for pay with this type. '
                                                'Keep empty for every service available to pay with this type.')
    ignored_service_ids = fields.Many2many('product.product',
                                           'wallet_type_ignored_services',
                                           'wallet_type_id',
                                           'product_id',
                                           string='Ignored Services',
                                           domain=[('type', '=', 'service')],
                                           help='Only Services ignored for pay with this type. '
                                                'Keep empty for every service available to pay with this type.')
    allow_transfer_to = fields.Boolean('Allow Transfer to other types')
    allowed_transfer_ids = fields.One2many('website.wallet.type.transfer', 'wallet_type_id',
                                           string='Allowed Types for Transfer', copy=True, auto_join=True)
    min_transfer_amount = fields.Float('Minimum Transfer Amount', digits=(16, 2), help="Minimum Transfer Amount per transaction")
    max_transfer_amount = fields.Float('Maximum Transfer Amount', digits=(16, 2), help="Maximum Transfer Amount per transaction")

    credit_limit = fields.Float('Credit Limit', digits=(16, 2), help="Zero indicates no credit limit")
    max_balance = fields.Float('Maximum Balance', digits=(16, 2), help="Zero indicates no limit")

    has_trans_limit = fields.Boolean('Has Transaction Limit')
    trans_limit_ids = fields.One2many('wallet.type.trans.limit', 'wallet_type_id', 'Transaction limits', help="Define transaction limits.")

    active = fields.Boolean('Active', default=True,
                            help="If unchecked, it will allow you to hide the wallet type without removing it.")

    _sql_constraints = [
        ('check_wallet_type_credit_limit', 'CHECK(credit_limit>=0)', 'Credit limit must be a positive value'),
    ]


class website_wallet_type_transfer(models.Model):
    _name = 'website.wallet.type.transfer'
    _description = 'Allowed Wallet Types to transfer'
    _order = 'sequence, id'

    sequence = fields.Integer(default=10)
    wallet_type_dest_id = fields.Many2one('website.wallet.type', string='Transfer To')
    wallet_type_id = fields.Many2one('website.wallet.type', string='Wallet Type', required=True, ondelete='cascade',
                                     index=True, copy=False)

    _sql_constraints = [
        ('wallet_type_dest_id_uniq', 'unique(wallet_type_id, wallet_type_dest_id)', 'Transfer To must be unique !'),
    ]


class WalletTypeTransLimit(models.Model):
    _name = 'wallet.type.trans.limit'
    _description = "Wallet Type Transactions Limit"
    _order = 'sequence, limit_type'

    sequence = fields.Integer(
        'Sequence', default=1, help="Assigns the priority to the list of transaction limit.")
    limit_type = fields.Selection([('daily', 'Daily'), ('weekly', 'Weekly'), ('monthly', 'Monthly')], 'Limit Type',
                                  default='daily', required=True)
    limit_amount = fields.Float(
        'Limit Amount', default=1.0, required=True,
        digits=dp.get_precision('Product Price'),
        help="Wallet Transaction Limit.")

    has_over_limit_fees = fields.Boolean('Has Over Limit Fees')
    over_limit_fees_ids = fields.One2many('wallet.type.trans.limit.fees', 'wallet_type_trans_limit_id', 'Transaction Over Limit Fees', help="Define transaction over limit fees.")

    company_id = fields.Many2one(
        'res.company', 'Company',
        default=lambda self: self.env.user.company_id.id, index=1)
    currency_id = fields.Many2one(
        'res.currency', 'Currency',
        default=lambda self: self.env.user.company_id.currency_id.id, required=True)
    date_start = fields.Date('Start Date', help="Start date for this transaction limit")
    date_end = fields.Date('End Date', help="End date for this transaction limit")
    wallet_type_id = fields.Many2one('website.wallet.type', 'Wallet Type', index=True, ondelete='cascade')


class WalletTypeTransLimitFees(models.Model):
    _name = 'wallet.type.trans.limit.fees'
    _description = "Wallet Type Transactions Limit Fees"
    _order = 'sequence, trans_amount_from, trans_amount_to'

    sequence = fields.Integer(
        'Sequence', default=1, help="Assigns the priority to the list of transaction over limit fees.")
    trans_amount_from = fields.Float('From Amount', required=True, digits=dp.get_precision('Product Price'),
                                     help="Transaction Amount From.")
    trans_amount_to = fields.Float('To Amount', required=True, digits=dp.get_precision('Product Price'),
                                   help="Transaction Amount To.")
    fees_amount = fields.Float('Fees Amount', required=True, digits=dp.get_precision('Product Price'),
                               help="Fees Amount.")
    fees_amount_percentage = fields.Float('Fees Amount %', required=True, digits=dp.get_precision('Product Price'),
                                          help="Fees Amount %")

    wallet_type_trans_limit_id = fields.Many2one('wallet.type.trans.limit', 'Wallet Type Transactions Limit', index=True, ondelete='cascade')
    wallet_type_id = fields.Many2one('website.wallet.type', 'Wallet Type', related='wallet_type_trans_limit_id.wallet_type_id')

    company_id = fields.Many2one(
        'res.company', 'Company',
        default=lambda self: self.env.user.company_id.id, index=1)
    currency_id = fields.Many2one(
        'res.currency', 'Currency',
        default=lambda self: self.env.user.company_id.currency_id.id,
        required=True)


class WalletTransLimit(models.Model):
    _name = 'wallet.trans.limit'
    _description = "Wallet Transactions Limit"

    wallet_id = fields.Many2one('website.wallet', 'Wallet', readonly=True)
    # wallet_type_id = fields.Many2one('website.wallet.type', 'Wallet Type', readonly=True)
    limit_type = fields.Selection([('daily', 'Daily'), ('weekly', 'Weekly'), ('monthly', 'Monthly')], 'Limit Type',
                                  default='daily', readonly=True)
    day = fields.Integer('Day of Year', readonly=True)
    week = fields.Integer('Week of Year', readonly=True)
    month = fields.Integer('Month of Year', readonly=True)
    year = fields.Integer('Year', readonly=True)

    trans_amount = fields.Float(
        'Transaction Amount',
        digits=dp.get_precision('Product Price'),
        help="Total Transaction Amount made by customer wallet.", readonly=True)


class WalletTransLimitFees(models.Model):
    _name = 'wallet.trans.limit.fees'
    _description = "Wallet Transactions Limit Feees"

    # wallet_id = fields.Many2one('website.wallet', 'Wallet', readonly=True)
    # # wallet_type_id = fields.Many2one('website.wallet.type', 'Wallet Type', readonly=True)
    user_request_id = fields.Many2one('smartpay_operations.request', 'Request', readonly=True)
    limit_type = fields.Selection([('daily', 'Daily'), ('weekly', 'Weekly'), ('monthly', 'Monthly')], 'Limit Type',
                                  default='daily', readonly=True)
    fees_amount = fields.Float(
        'Fees Amount',
        digits=dp.get_precision('Product Price'),
        help="Over Limit Fees Amount at wallet transaction.", readonly=True)
    wallet_transaction_id = fields.Many2one('website.wallet.transaction', 'Wallet Transaction', copy=False)

    refund_amount = fields.Float(
        'Fees Amount',
        digits=dp.get_precision('Product Price'),
        help="Refunded Over Limit Fees Amount at wallet transaction.", readonly=True)
    refund_wallet_transaction_id = fields.Many2one('website.wallet.transaction', 'Wallet Transaction', copy=False)


class WalletWalletTypeTransLimitFees(models.Model):
    _name = 'wallet.wallet.type.trans.limit.fees'
    _description = "Wallet Transaction Over Limit Fees per Wallet Type"
    _order = 'sequence, trans_amount_from, trans_amount_to'

    sequence = fields.Integer(
        'Sequence', default=1, help="Assigns the priority to the list of transaction over limit fees.")
    trans_amount_from = fields.Float('From Amount', required=True, digits=dp.get_precision('Product Price'),
                                     help="Transaction Amount From.")
    trans_amount_to = fields.Float('To Amount', required=True, digits=dp.get_precision('Product Price'),
                                   help="Transaction Amount To.")
    fees_amount = fields.Float('Fees Amount', required=True, digits=dp.get_precision('Product Price'),
                               help="Fees Amount.")
    fees_amount_percentage = fields.Float('Fees Amount %', required=True, digits=dp.get_precision('Product Price'),
                                          help="Fees Amount %")

    wallet_wallet_type_trans_limit_id = fields.Many2one('wallet.wallet.type.trans.limit', 'Wallet Type Transaction Limit', index=True, ondelete='cascade')
    wallet_type_id = fields.Many2one('website.wallet.type', 'Wallet Type', related='wallet_wallet_type_trans_limit_id.wallet_type_id')

    company_id = fields.Many2one(
        'res.company', 'Company',
        default=lambda self: self.env.user.company_id.id, index=1)
    currency_id = fields.Many2one(
        'res.currency', 'Currency',
        default=lambda self: self.env.user.company_id.currency_id.id,
        required=True)


class WalletWalletTypeTransLimit(models.Model):
    _name = 'wallet.wallet.type.trans.limit'
    _description = "Wallet Transaction Over Limit per Wallet Type"
    _order = 'sequence, limit_type'

    sequence = fields.Integer(
        'Sequence', default=1, help="Assigns the priority to the list of transaction limit.")
    """
    wallet_type_id = fields.Many2one(
        'website.wallet.type', 'Wallet Type', domain=[('has_trans_limit', '=', True)],
        index=True, ondelete='cascade', required=True)
    """
    limit_type = fields.Selection([('daily', 'Daily'), ('weekly', 'Weekly'), ('monthly', 'Monthly')], 'Limit Type',
                                  default='daily', required=True)
    limit_amount = fields.Float(
        'Limit Amount', default=1.0,
        digits=dp.get_precision('Product Price'),
        help="Transaction Limit at wallet type.", required=True)

    # has_over_limit_fees = fields.Boolean('Has Over Limit Fees')
    over_limit_fees_policy = fields.Selection([('no_over_limit_fees', 'No Over Limit Fees'),
                                               ('wallet_type_over_limit_fees', 'Wallet Type Over Limit Fees'),
                                               ('custom_over_limit_fees', 'Custom Over Limit Fees')], 'Over Limit Fees Poloicy',
                                              default='no_over_limit_fees', required=True)
    wallet_type_over_limit_fees_ids = fields.One2many('wallet.type.trans.limit.fees', string='Wallet Type Transaction Over Limit Fees',
                                                       related='wallet_type_id.trans_limit_ids.over_limit_fees_ids')
    over_limit_fees_ids = fields.One2many('wallet.wallet.type.trans.limit.fees', 'wallet_wallet_type_trans_limit_id', 'Custom Transaction Over Limit Fees',
                                          help="Define transaction over limit fees.")

    company_id = fields.Many2one(
        'res.company', 'Company',
        default=lambda self: self.env.user.company_id.id, index=1)
    currency_id = fields.Many2one(
        'res.currency', 'Currency',
        default=lambda self: self.env.user.company_id.currency_id.id,
        required=True)
    date_start = fields.Date('Start Date', help="Start date for this transaction limit")
    date_end = fields.Date('End Date', help="End date for this transaction limit")
    wallet_id = fields.Many2one('website.wallet', 'Wallet')
    wallet_type_id = fields.Many2one(
        'website.wallet.type', 'Wallet Type', related="wallet_id.type")


class website_wallet(models.Model):
    _name = 'website.wallet'
    _description = 'Customer Wallet'
    _order = 'type_sequence, type_id, id'
    _rec_name = 'complete_name'

    name = fields.Char('Name', required=True)
    # sequence = fields.Integer(default=10)
    partner_id = fields.Many2one('res.partner', string='Customer',
                                 ondelete='restrict', index=True, copy=False, required=True)
    complete_name = fields.Char('Complete Name', compute='_compute_complete_name', recursive=True, store=True)
    type = fields.Many2one('website.wallet.type', string='Type', ondelete='restrict', index=True, copy=False,
                           required=True)
    type_sequence = fields.Integer(related='type.sequence', store=True)
    type_id = fields.Integer('Type ID', related='type.id', store=True)
    type_credit_limit = fields.Float('Type Credit Limit', related='type.credit_limit', store=True)
    credit_limit = fields.Float('Credit Limit', digits=(16, 2), help="Set value greater than zero if you want to "
                                                                     "override the credit limit of wallet type. "
                                                                     "zero value indicates the credit limit of wallet "
                                                                     "is equal the credit limit of wallet type")
    type_max_balance = fields.Float('Type Maximum Balance', related='type.max_balance', store=True)
    max_balance = fields.Float('Maximum Balance', digits=(16, 2), help="Set value greater than zero if you want "
                                                                              "to override the maximum balance of "
                                                                              "wallet type. zero value indicates the "
                                                                              "maximum balance of wallet is equal the "
                                                                              "maximum balance of wallet type")
    type_has_trans_limit = fields.Boolean('Has Transaction Limit', related='type.has_trans_limit')
    trans_limit_ids = fields.One2many('wallet.wallet.type.trans.limit', 'wallet_id', 'Transaction limits',
                                     help="Define transaction limits.")
    balance_amount = fields.Float('Balance', digits=(16, 2), readonly=True, store=True)
    reserved_amount = fields.Float('Reserved', compute='_compute_reserved_amount', store=True, digits=(16, 2))
    available_amount = fields.Float('Available', compute='_compute_available_amount', store=True, digits=(16, 2))
    currency_id = fields.Many2one('res.currency', 'Currency', default=lambda self: self.env.user.company_id.currency_id.id)

    wallet_transactions = fields.One2many('website.wallet.transaction', 'wallet_id', string='Wallet Transactions',
                                          readonly=True, copy=False, auto_join=True)
    wallet_reservations = fields.One2many('website.wallet.reservation', 'wallet_id', string='Wallet Reservation Amounts',
                                          readonly=True, copy=False, auto_join=True)

    # Technical Fields for unlock the record when no reservation case
    no_available_balance_count = fields.Integer('No Available Balance Count', readonly=True, store=True)
    no_available_balance_total_amount = fields.Float('No Available Balance Total Amount', digits=(16, 2), readonly=True, store=True)

    active = fields.Boolean('Active', default=True,
                            help="If unchecked, it will allow you to hide the wallet without removing it.")

    _sql_constraints = [
        ('type_partner_uniq', 'unique(type, partner_id)', 'This partner has wallet with the same type!'),
        ('check_wallet_credit_limit', 'CHECK(credit_limit>=0)', 'Credit limit must be a positive value'),
    ]

    @api.depends('name', 'partner_id.name')
    def _compute_complete_name(self):
        for wallet in self:
            wallet.complete_name = '%s - %s' % (wallet.name, wallet.partner_id.name)

    @api.depends('wallet_reservations')
    def _compute_reserved_amount(self):
        for wallet in self:
            wallet.reserved_amount = sum(wallet.wallet_reservations.mapped('reserved_amount'))

    @api.depends('balance_amount', 'reserved_amount', 'credit_limit', 'type', 'type.credit_limit')
    def _compute_available_amount(self):
        for wallet in self:
            wallet.available_amount = wallet.balance_amount - wallet.reserved_amount + (wallet.credit_limit if wallet.credit_limit else wallet.type.credit_limit)

    @api.multi
    def unlink(self):
        for wallet in self:
            if wallet.wallet_transactions: # or wallet.balance_amount or wallet.reserved_amount or wallet.available_amount:
                raise UserError(
                    _('You can not delete a wallet have any transactions.'))
        return super(website_wallet, self).unlink()

    def update_wallet_reserved_balance(self, label, transaction_amount, currency_id, reference, origin=False):
        wallet = None
        website_wallet_reservation_id = None
        reserved_amount = 0.0
        balance_amount = 0.0
        available_amount = 0.0
        no_available_balance_count = 0
        no_available_balance_total_amount = 0.0
        # FOR UPDATE mode assumes a total change (or delete) of a row.
        # FOR NO KEY UPDATE mode assumes a change only to the fields that are not involved in unique indexes (in other words, this change does not affect foreign keys).
        # see _acquire_one_job for explanations
        # self._cr.execute("SELECT id, reserved_amount, balance_amount, available_amount, no_available_balance_count, no_available_balance_total_amount FROM website_wallet WHERE id = %s FOR NO KEY UPDATE SKIP LOCKED", [self.id])
        self._cr.execute("SELECT id, reserved_amount, balance_amount, available_amount, "
                         "no_available_balance_count, no_available_balance_total_amount"
                         " FROM website_wallet WHERE id = %s FOR NO KEY UPDATE", [self.id])
        res_wallet_result = self._cr.fetchone()
        if res_wallet_result:
            wallet = self.browse(res_wallet_result[0])
            reserved_amount = res_wallet_result[1]
            # reserved_amount_after = reserved_amount + transaction_amount
            balance_amount = res_wallet_result[2]
            available_amount = res_wallet_result[3]
            no_available_balance_count = res_wallet_result[4] or 0
            no_available_balance_total_amount = res_wallet_result[5] or 0

        if wallet:
            if available_amount >= transaction_amount:
                wallet_reservationtion_values = {
                    'label': label,
                    'reference': reference,
                    'reserved_amount': transaction_amount,
                    'currency_id': currency_id.id,
                    'wallet_id': self.id
                }
                if reference == 'request' and origin:
                    wallet_reservationtion_values.update({'request_id': origin.id})
                website_wallet_reservation_id = self.env['website.wallet.reservation'].create(wallet_reservationtion_values)
                wallet.wallet_reservations += website_wallet_reservation_id
                available_amount = available_amount - transaction_amount # instead of ==> self.env.cr.commit() wallet.available_amount
            else:
                wallet.write({
                    'no_available_balance_count': no_available_balance_count + 1,
                    'no_available_balance_total_amount': no_available_balance_total_amount + transaction_amount,
                })
            self.env.cr.commit()

        return website_wallet_reservation_id, balance_amount, available_amount

    def update_wallet_balance(self, transaction_type, amount, force_update=True):
        wallet = None
        wallet_balance_before = 0.0
        wallet_balance_after = 0.0
        wallet_max_balance = 0.0
        # FOR UPDATE mode assumes a total change (or delete) of a row.
        # FOR NO KEY UPDATE mode assumes a change only to the fields that are not involved in unique indexes (in other words, this change does not affect foreign keys).
        # see _acquire_one_job for explanations
        # self._cr.execute("SELECT id, balance_amount FROM website_wallet WHERE id = %s FOR NO KEY UPDATE SKIP LOCKED", [wallet_id.id])
        self._cr.execute("SELECT id, balance_amount, max_balance, type_max_balance FROM website_wallet WHERE id = %s FOR NO KEY UPDATE", [self.id])
        res_wallet_result = self._cr.fetchone()
        if res_wallet_result:
            wallet = self.browse(res_wallet_result[0])
            wallet_balance_before = res_wallet_result[1] or 0.0
            wallet_balance_after = wallet_balance_before + (amount if transaction_type == 'credit' else -amount)
            wallet_max_balance = res_wallet_result[2] or res_wallet_result[3] or 0.0

        if not force_update:
            force_update = transaction_type == 'debit' or not wallet_max_balance or wallet_balance_after <= wallet_max_balance
        if wallet:
            wallet.write({
                'balance_amount': wallet_balance_after if force_update else wallet_balance_before
            })
            self.env.cr.commit()

        return wallet_balance_before, wallet_balance_after, force_update

    def create_wallet_transaction(self, wallet_type, partner_id, reference, label, amount, currency_id,
                                  origin=False, notify_mode=False, notify_sms_template=False, notify_msg=False,
                                  counter_account=False, journal_entry_label=False, counter_partner_id=False):
        wallet_transaction_sudo = self.env['website.wallet.transaction'].sudo()

        wallet_id = self
        if not wallet_id:
            if len(partner_id.wallet_ids) > 0:
                wallet_id = partner_id.wallet_ids[0]
            else:
                return None, 0

        wallet_balance_before, wallet_balance_after, force_update = wallet_id.update_wallet_balance(
            wallet_type, amount, force_update=(False if (wallet_type == 'credit' and notify_sms_template in (
                'wallet_bouns',
                # 'wallet_correlation_service_payment', # Ignore this type because the check of wallet maximum balance
                                                        # already happened before calling the provider for correlation
                'wallet_transfer_balance',
                'wallet_pay_invoice',
                'wallet_recharge')) else True)
        )
        if not force_update:
            return None, 0

        wallet_transaction_values = {
            'wallet_id': wallet_id.id, 'wallet_type': wallet_type, 'partner_id': partner_id.id, 'reference': reference,
            'label': label, 'amount': amount, 'currency_id': currency_id.id, 'wallet_balance_before': wallet_balance_before,
            'wallet_balance_after': wallet_balance_after, 'status': 'done'
        }
        if reference == 'request' and origin:
            wallet_transaction_values.update({'request_id': origin.id})

        wallet_transaction_id = wallet_transaction_sudo.create(wallet_transaction_values)
        self.env.cr.commit()

        # Create journal entry for increase AR balance for user.
        if counter_account:
            partner_receivable_account = partner_id.property_account_receivable_id
            account_move = self.env['account.move'].sudo().create({
                'journal_id': self.env['account.journal'].sudo().search([('type', '=', 'general')], limit=1).id,
                'ref': '%s: %s' % (origin.name if origin else label, journal_entry_label)
            })

            credit_account_move_line = self.env['account.move.line'].with_context(check_move_validity=False).sudo().create({
                'name': '%s: %s' % (origin.name if origin else label, journal_entry_label),
                'move_id': account_move.id,
                'wallet_transaction_id': wallet_transaction_id.id,
                'account_id': partner_receivable_account.id if wallet_type == 'credit' else counter_account.id,
                'credit': amount,
            })
            if wallet_type == 'credit':
                credit_account_move_line.update({'partner_id': partner_id.id})

            debit_account_move_line = self.env['account.move.line'].with_context(check_move_validity=False).sudo().create({
                'name': '%s: %s' % (origin.name if origin else label, journal_entry_label),
                'move_id': account_move.id,
                'wallet_transaction_id': wallet_transaction_id.id,
                'account_id': counter_account.id if wallet_type == 'credit' else partner_receivable_account.id,
                'debit': amount,
            })
            if counter_partner_id:
                debit_account_move_line.update({'partner_id': counter_partner_id.id})
            # Tamayoz: Post Journal Entry in Schedule Action for prevent
            # ERROR: "could not serialize access due to concurrent update" that occur when try to execute
            # SELECT number_next FROM ir_sequence_date_range WHERE id=? FOR UPDATE NOWAIT
            # account_move.post()

        # Tamayoz TODO: Create Schedule Action for Notify Partner
        '''
        self.notify_customer_with_wallet_transaction(notify_mode, label, notify_msg, notify_sms_template, 
                                                     partner_id, wallet_transaction_id, amount, currency_id)
        '''
        return wallet_transaction_id, wallet_balance_after

    def auto_post_journal_entries_for_wallet_trans(self):
        account_move_line_sudo = self.env['account.move.line'].sudo()
        account_move_lines = account_move_line_sudo.search([('wallet_transaction_id', '!=', False),
                                                            ('move_id.state', '=', 'draft')]).mapped('move_id').post()

    def notify_customer_with_wallet_transaction(self, notify_mode, label, notify_msg, notify_sms_template,
                                                partner_id, wallet_transaction_id, amount, currency_id):
        if notify_mode:
            # Notify partner
            irc_param = self.env['ir.config_parameter'].sudo()
            wallet_notify_mode = irc_param.get_param(notify_mode)
            if wallet_notify_mode == 'inbox':
                self.env['mail.thread'].sudo().message_notify(subject=label, body=notify_msg if notify_msg else '',
                                                              partner_ids=[(4, partner_id.id)])
            elif wallet_notify_mode == 'email':
                wallet_transaction_id.wallet_transaction_email_send()
            elif wallet_notify_mode == 'sms' and self.env.user.partner_id.mobile:
                wallet_transaction_id.sms_send_wallet_transaction(wallet_notify_mode, notify_sms_template, # notify_mode.split('.')[1].split('_notify_mode')[0] if notify_mode else '',
                                                                                                           # Tamayoz TODO: wallet_pay_service_bill_notify_mode ==> wallet_pay_service_bill_notify_mode,
                                                                                                           #  wallet_canel_service_payment_notify_mode ==> c in cancel not found
                                                                  partner_id.mobile, self.env.user.name, label,
                                                                  '%s %s' % (amount, _(currency_id.name)),
                                                                  partner_id.country_id.phone_code or '2')

    def auto_deduct_installment_from_customer_wallet(self, max_deduction_count=1, raise_error=None):
        try:
            '''
            request_pool = self.env['smartpay_operations.request']
            request_hours = int(self.env['ir.config_parameter'].sudo().get_param("smartpay_operations.request_hours"))

            timeout_request_ids=request_pool.search([('stage_id','=',self.env.ref('smartpay_operations.stage_new').id),('create_date','<=',str(datetime.now() - timedelta(hours=request_hours)))])
            for request in timeout_request_ids:
                request.write({'stage_id': self.env.ref('smartpay_operations.stage_expired').id})
            '''
            receivable_account_ids = self.env['account.account'].sudo().search([('user_type_id', '=', self.env.ref('account.data_account_type_receivable').id)])
            installment_move_line_ids = self.env['account.move.line'].sudo().search([('account_id', 'in', receivable_account_ids.ids),
                                                                                     ('invoice_id', '!=', None),
                                                                                     ('invoice_id.origin', 'ilike', 'SO'),
                                                                                     # ('invoice_id.name', '=', None),
                                                                                     # ('name', '=', None),
                                                                                     ('amount_residual', '>', 0),
                                                                                     # Next line is temp code for >> Tamayoz TODO: Reconcile installment_move_line_id with prepaid wallet recharge payments and previous cashback credit note by installment_amount only
                                                                                     ('deducted_from_wallet', '=', False),
                                                                                     ('date_maturity', '<=', fields.Date.today())])
            _logger.info("@@@@@@@@@@@@@@@@@@@ Start Auto deduction from wallet for [%s] installments" % (len(installment_move_line_ids)))
            deduction_counts = {}
            for installment_move_line_id in installment_move_line_ids:
                deduction_count = deduction_counts.get(installment_move_line_id.invoice_id.id) or 0
                if deduction_count >= max_deduction_count:  # Deduct only installments count less than max_deduction_count for each customer
                    continue
                deduction_counts.update({installment_move_line_id.invoice_id.id: deduction_count + 1})
                _logger.info("@@@@@@@@@@@@@@@@@@@ Auto deduction from wallet for installment [%s]" % (installment_move_line_id.display_name))
                installment_invoice_id = installment_move_line_id.invoice_id
                installment_amount = installment_move_line_id.amount_residual
                installment_partner_id = installment_move_line_id.partner_id
                # Tamayoz TODO: VERY IMPORTANT: Reconcile installment_move_line_id with prepaid wallet recharge payments and previous cashback credit note by installment_amount only
                '''
                # Auto Reconcile installment invoice with prepaid wallet recharge payments and previous cashback credit note by installment_amount only
                domain = [('account_id', '=', installment_invoice_id.account_id.id),
                          ('partner_id', '=',
                           self.env['res.partner']._find_accounting_partner(installment_invoice_id.partner_id).id),
                          ('reconciled', '=', False),
                          '|',
                          '&', ('amount_residual_currency', '!=', 0.0), ('currency_id', '!=', None),
                          '&', ('amount_residual_currency', '=', 0.0), '&', ('currency_id', '=', None),
                          ('amount_residual', '!=', 0.0)]
                domain.extend([('credit', '>', 0), ('debit', '=', 0)])
                lines = self.env['account.move.line'].sudo().search(domain)
                for line in lines:
                    # get the outstanding residual value in invoice currency
                    if line.currency_id and line.currency_id == installment_invoice_id.currency_id:
                        amount_residual_currency = abs(line.amount_residual_currency)
                    else:
                        currency = line.company_id.currency_id
                        amount_residual_currency = currency._convert(abs(line.amount_residual),
                                                                     installment_invoice_id.currency_id,
                                                                     installment_invoice_id.company_id,
                                                                     line.date or fields.Date.today())
                    if float_is_zero(amount_residual_currency,
                                     precision_rounding=installment_invoice_id.currency_id.rounding):
                        continue

                    installment_invoice_id.assign_outstanding_credit(line.id)
                    if installment_invoice_id.state == 'paid':
                        break
                wallet_transaction_sudo = self.env['website.wallet.transaction'].sudo()
                label = _('Collect payment for invoice [%s]') % (installment_invoice_id.number)
                partner_wallet_id = installment_partner_id.get_transaction_wallet()
                partner_id_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                machine_wallet_create = wallet_transaction_sudo.create(
                    {'wallet_type': 'debit', 'partner_id': installment_partner_id.id, 'reference': 'manual',
                     'label': label, 'amount': installment_amount, 'currency_id': installment_invoice_id.currency_id.id,
                     'wallet_balance_before': partner_id_wallet_balance,
                     'wallet_balance_after': partner_id_wallet_balance - installment_amount,
                     'status': 'done'})
                # self.env.cr.commit()

                installment_partner_id.update(
                    {'wallet_balance': partner_id_wallet_balance - installment_amount})
                '''
                partner_wallet_id = installment_partner_id.get_transaction_wallet()
                machine_wallet_create, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
                    'debit', installment_partner_id, 'manual',
                    _('Collect payment for invoice [%s]') % (installment_invoice_id.number),
                    installment_amount, installment_invoice_id.currency_id, False,
                    'smartpay_operations.wallet_pay_invoice_notify_mode', 'wallet_pay_invoice',
                    _('<p>%s %s successfully deducted from your wallet.</p>') % (
                        installment_amount, _(installment_invoice_id.currency_id.name))
                )

                # Next line is temp code for >> Tamayoz TODO: Reconcile installment_move_line_id with prepaid wallet recharge payments and previous cashback credit note by installment_amount only
                installment_move_line_id.update({'deducted_from_wallet': True})
                self.env.cr.commit()

                '''
                # Notify customer
                irc_param = self.env['ir.config_parameter'].sudo()
                wallet_pay_invoice_notify_mode = irc_param.get_param(
                    "smartpay_operations.wallet_pay_invoice_notify_mode")
                if wallet_pay_invoice_notify_mode == 'inbox':
                    self.env['mail.thread'].sudo().message_notify(
                        subject=label,
                        body=_('<p>%s %s successfully deducted from your wallet.</p>') % (
                            installment_amount, _(installment_invoice_id.currency_id.name)),
                        partner_ids=[(4, installment_partner_id.id)],
                    )
                elif wallet_pay_invoice_notify_mode == 'email':
                    machine_wallet_create.wallet_transaction_email_send()
                elif wallet_pay_invoice_notify_mode == 'sms' and installment_partner_id.mobile:
                    machine_wallet_create.sms_send_wallet_transaction(wallet_pay_invoice_notify_mode,
                                                                      'wallet_pay_invoice',
                                                                      # Tamayoz TODO: Add 'wallet_deduction' sms template
                                                                      installment_partner_id.mobile,
                                                                      installment_partner_id.name, label,
                                                                      '%s %s' % (installment_amount,
                                                                                 _(
                                                                                     installment_invoice_id.currency_id.name)),
                                                                      installment_partner_id.country_id.phone_code or '2')
                '''
        except Exception as e:
            _logger.error("%s", e)
            if raise_error:
                raise e
            return "internal error"

    def action_wallet_in(self):
        self.ensure_one()
        '''
        ctx = dict(self.env.context or {})
        ctx.update({
            'default_model': 'website.wallet',
            'default_res_id': self.ids[0]
        })

        return {
            'name': _('Put Credit In Wallet'),
            'type': 'ir.actions.act_window',
            'view_mode': 'form',
            'res_model': 'wallet.in',
            'target': 'new',
            # 'key2': 'client_action_multi',
            # 'id': 'action_wallet_in',
            # 'groups': 'base.group_erp_manager,account.group_account_manager',
            'context': ctx,
        }
        '''
        action = self.env.ref('smartpay_operations.action_wallet_in').read()[0]
        action['context'] = {
            'default_model': 'website.wallet',
            'default_res_id': self.ids[0]
        }
        return action

    def action_wallet_out(self):
        self.ensure_one()
        '''
        ctx = dict(self.env.context or {})
        ctx.update({
            'default_model': 'website.wallet',
            'default_res_id': self.ids[0]
        })
        
        return {
            'name': _('Take Credit From Wallet'),
            'type': 'ir.actions.act_window',
            'view_mode': 'form',
            'res_model': 'wallet.out',
            'target': 'new',
            # 'key2': 'client_action_multi',
            # 'id': 'action_wallet_out',
            # 'groups': 'base.group_erp_manager,account.group_account_manager',
            'context': ctx,
        }
        '''
        action = self.env.ref('smartpay_operations.action_wallet_out').read()[0]
        action['context'] = {
            'default_model': 'website.wallet',
            'default_res_id': self.ids[0]
        }
        return action


class res_partner(models.Model):
    _inherit = 'res.partner'

    partner_wallets_balance = fields.Float('All Wallets Balance', compute='_compute_wallets_balance', store=True, digits=(16, 2))
    wallet_ids = fields.One2many('website.wallet', 'partner_id', string='Customer Wallets',
                                 copy=False, auto_join=True, context={'active_test': False}) # domain=['|',('active','=',False),('active','=',True)]

    @api.depends('wallet_ids')
    def _compute_wallets_balance(self):
        for partner in self:
            partner.partner_wallets_balance = sum(partner.wallet_ids.mapped('balance_amount'))

    def get_transaction_wallet(self, wallet_id=None, type=False, service=False, trans_amount=0.0, allow_payment=False, allow_transfer_to=False):
        partner_wallet_id = None
        wallet_ids = self.wallet_ids.filtered(lambda w: w.active == True)
        if wallet_id:
            if isinstance(wallet_id, str):
                try:
                    wallet_id = int(wallet_id)
                except:
                    wallet_id = 0
            wallet_ids = wallet_ids.filtered(lambda w: w.id == wallet_id)
        if type:
            wallet_ids = wallet_ids.filtered(lambda w: w.type == type)
        if service:
            wallet_ids = wallet_ids.filtered(lambda w: w.type.allow_payment and ((w.type.allowed_service_ids and service.id in w.type.allowed_service_ids.ids)
                                                                                 or (not w.type.allowed_service_ids and ((w.type.ignored_service_ids and service.id not in w.type.ignored_service_ids.ids) or not w.type.ignored_service_ids))
                                                                                 ))
        if trans_amount:
            wallet_ids_has_enough_balance = wallet_ids.filtered(lambda w: trans_amount <= w.available_amount)
            if len(wallet_ids_has_enough_balance) > 0:
                wallet_ids = wallet_ids_has_enough_balance
        if allow_payment:
            wallet_ids = wallet_ids.filtered(lambda w: w.type.allow_payment)
        if allow_transfer_to:
            wallet_ids = wallet_ids.filtered(lambda w: w.type.allow_transfer_to)
        if len(wallet_ids) > 0:
            partner_wallet_id = wallet_ids[0]
        elif len(self.wallet_ids) > 0:
            active_wallet_ids = self.wallet_ids.filtered(lambda w: w.active == True)
            if len(active_wallet_ids) > 0 and not wallet_id and not type and not service and not trans_amount and not allow_payment and not allow_transfer_to:
                partner_wallet_id = active_wallet_ids[0]
        else:
            default_wallet_type_id = type or self.env.ref('smartpay_operations.wallet_type_cash') or self.env['website.wallet.type'].sudo().search([('name', '=', _('Cash'))])
            if not default_wallet_type_id:
                default_wallet_type_id = self.env['website.wallet.type'].sudo().create({'name': 'Cash'}) # , 'allow_payment': True
            partner_wallet_id = self.env['website.wallet'].sudo().create({
                'name': 'Main Wallet',
                'type':default_wallet_type_id.id,
                'partner_id': self.id
            })
            self.env.cr.commit()
        return partner_wallet_id

class website_wallet_reservation(models.Model):
    _name = 'website.wallet.reservation'
    _description = 'Customer Wallet Reserved Amounts'
    _order = 'id desc'

    wallet_id = fields.Many2one('website.wallet', string='Wallet Reference',
                                ondelete='restrict', index=True, copy=False, required=True)
    label = fields.Text('Label')
    reference = fields.Selection([
        ('manual', 'Manual'),
        ('sale_order', 'Sale Order'),
        ('request', 'Request')
    ], string='Reference', default='manual')
    sale_order_id = fields.Many2one('sale.order', 'Sale Order')
    request_id = fields.Many2one('smartpay_operations.request', 'Request',  index=True)
    reserved_amount = fields.Float('Reserved', required=True, digits=(16, 2))
    currency_id = fields.Many2one('res.currency', 'Currency', default=lambda self: self.env.user.company_id.currency_id.id)


# Next account_move_line class is temp code for >> Tamayoz TODO: Reconcile installment_move_line_id with prepaid wallet recharge payments and previous cashback credit note by installment_amount only
class account_move_line(models.Model):
    _inherit='account.move.line'

    deducted_from_wallet = fields.Boolean(default=False)
    wallet_transaction_id = fields.Many2one('website.wallet.transaction', string='Wallet Transaction Reference',
                                            ondelete='restrict', index=True, copy=False)


class website_wallet_transaction(models.Model):
    _inherit='website.wallet.transaction'

    wallet_id = fields.Many2one('website.wallet', string='Wallet Reference',
                                ondelete='restrict', index=True, copy=False) # , required=True
    request_id = fields.Many2one('smartpay_operations.request', 'Request',  index=True)
    wallet_transaction_info = fields.Text(string='Wallet Transaction Info', copy=False, readonly=True)
    reference = fields.Selection(selection_add=[('request', 'Request'),('cashback', 'Cash Back')], track_visibility='onchange')
    label = fields.Text('Label')
    status = fields.Selection(selection_add=[('cancel', 'Cancel')], track_visibility='onchange')
    wallet_transaction_line = fields.One2many('website.wallet.transaction.line', 'wallet_transaction_id',
                                              string='Wallet Transaction Lines',
                                              readonly=True, copy=False, auto_join=True)
    statement_id = fields.Many2one('account.bank.statement', help="The statement used for provider wallet reconciliation", index=True, copy=False)
    wallet_balance_before = fields.Char(string='Wallet Balance Before', copy=False, readonly=True)
    wallet_balance_after = fields.Char(string='Wallet Balance After', copy=False, readonly=True)

    '''
    def create_wallet_transaction(self, wallet_type, partner_id, reference, label, amount, currency_id, wallet_id=False,
                                  origin=False, notify_mode=False, notify_sms_template=False, notify_msg=False,
                                  counter_account=False, journal_entry_label=False):
        wallet_transaction_sudo = self.sudo()

        if not wallet_id:
            if len(partner_id.wallet_ids) > 0:
                wallet_id = partner_id.wallet_ids[0]
            else:
                return None, 0

        wallet_balance_before, wallet_balance_after, force_update = wallet_id.update_wallet_balance(wallet_type, amount, force_update=False if wallet_type == 'credit' else True)
        if not force_update:
            return None, 0

        wallet_transaction_values = {
            'wallet_id': wallet_id.id, 'wallet_type': wallet_type, 'partner_id': partner_id.id, 'reference': reference,
            'label': label, 'amount': amount, 'currency_id': currency_id.id, 'wallet_balance_before': wallet_balance_before,
            'wallet_balance_after': wallet_balance_after + (amount if wallet_type == 'credit' else -amount),
            'status': 'done'
        }
        if reference == 'request' and origin:
            wallet_transaction_values.update({'request_id': origin.id})

        wallet_transaction_id = wallet_transaction_sudo.create(wallet_transaction_values)
        self.env.cr.commit()

        # Create journal entry for increase AR balance for user.
        if counter_account:
            partner_receivable_account = partner_id.property_account_receivable_id
            account_move = self.env['account.move'].sudo().create({
                'journal_id': self.env['account.journal'].sudo().search([('type', '=', 'general')], limit=1).id,
                'ref': '%s: %s' % (origin.name if origin else label, journal_entry_label)
            })

            self.env['account.move.line'].with_context(check_move_validity=False).sudo().create({
                'name': '%s: %s' % (origin.name if origin else label, journal_entry_label),
                'move_id': account_move.id,
                'wallet_transaction_id': wallet_transaction_id.id,
                'account_id': partner_receivable_account.id if wallet_type == 'credit' else counter_account.id,
                'partner_id': partner_id.id,
                'credit': amount,
            })

            self.env['account.move.line'].with_context(check_move_validity=False).sudo().create({
                'name': '%s: %s' % (origin.name if origin else label, journal_entry_label),
                'move_id': account_move.id,
                'wallet_transaction_id': wallet_transaction_id.id,
                'account_id': counter_account.id if wallet_type == 'credit' else partner_receivable_account.id,
                'debit': amount,
            })
            account_move.post()

        # Tamayoz TODO: Create Schedule Action for Notify Partner
        """
        if notify_mode:
            # Notify partner
            irc_param = self.env['ir.config_parameter'].sudo()
            wallet_notify_mode = irc_param.get_param(notify_mode)
            if wallet_notify_mode == 'inbox':
                self.env['mail.thread'].sudo().message_notify(subject=label, body=notify_msg if notify_msg else '',
                                                              partner_ids=[(4, partner_id.id)])
            elif wallet_notify_mode == 'email':
                wallet_transaction_id.wallet_transaction_email_send()
            elif wallet_notify_mode == 'sms' and self.env.user.partner_id.mobile:
                wallet_transaction_id.sms_send_wallet_transaction(wallet_notify_mode, notify_sms_template, # notify_mode.split('.')[1].split('_notify_mode')[0] if notify_mode else '',
                                                                                                           # Tamayoz TODO: wallet_pay_service_bill_notify_mode ==> wallet_pay_service_bill_notify_mode,
                                                                                                           #  wallet_canel_service_payment_notify_mode ==> c in cancel not found
                                                                  partner_id.mobile, self.env.user.name, label,
                                                                  '%s %s' % (amount, _(currency_id.name)),
                                                                  partner_id.country_id.phone_code or '2')
        """
        return wallet_transaction_id, wallet_balance_after

    def auto_deduct_installment_from_customer_wallet(self, max_deduction_count=1):
        try:
            """
            request_pool = self.env['smartpay_operations.request']
            request_hours = int(self.env['ir.config_parameter'].sudo().get_param("smartpay_operations.request_hours"))

            timeout_request_ids=request_pool.search([('stage_id','=',self.env.ref('smartpay_operations.stage_new').id),('create_date','<=',str(datetime.now() - timedelta(hours=request_hours)))])
            for request in timeout_request_ids:
                request.write({'stage_id': self.env.ref('smartpay_operations.stage_expired').id})
            """
            receivable_account_ids = self.env['account.account'].sudo().search([('user_type_id', '=', self.env.ref('account.data_account_type_receivable').id)])
            installment_move_line_ids = self.env['account.move.line'].sudo().search([('account_id', 'in', receivable_account_ids.ids),
                                                                                     ('invoice_id', '!=', None),
                                                                                     ('invoice_id.origin', 'ilike', 'SO'),
                                                                                     # ('invoice_id.name', '=', None),
                                                                                     # ('name', '=', None),
                                                                                     ('amount_residual', '>', 0),
                                                                                     # Next line is temp code for >> Tamayoz TODO: Reconcile installment_move_line_id with prepaid wallet recharge payments and previous cashback credit note by installment_amount only
                                                                                     ('deducted_from_wallet', '=', False),
                                                                                     ('date_maturity', '<=', fields.Date.today())])
            _logger.info("@@@@@@@@@@@@@@@@@@@ Start Auto deduction from wallet for [%s] installments" % (len(installment_move_line_ids)))
            deduction_counts = {}
            for installment_move_line_id in installment_move_line_ids:
                deduction_count = deduction_counts.get(installment_move_line_id.invoice_id.id) or 0
                if deduction_count >= max_deduction_count:  # Deduct only installments count less than max_deduction_count for each customer
                    continue
                deduction_counts.update({installment_move_line_id.invoice_id.id: deduction_count + 1})
                _logger.info("@@@@@@@@@@@@@@@@@@@ Auto deduction from wallet for installment [%s]" % (installment_move_line_id.display_name))
                installment_invoice_id = installment_move_line_id.invoice_id
                installment_amount = installment_move_line_id.amount_residual
                installment_partner_id = installment_move_line_id.partner_id
                # Tamayoz TODO: VERY IMPORTANT: Reconcile installment_move_line_id with prepaid wallet recharge payments and previous cashback credit note by installment_amount only
                """
                # Auto Reconcile installment invoice with prepaid wallet recharge payments and previous cashback credit note by installment_amount only
                domain = [('account_id', '=', installment_invoice_id.account_id.id),
                          ('partner_id', '=',
                           self.env['res.partner']._find_accounting_partner(installment_invoice_id.partner_id).id),
                          ('reconciled', '=', False),
                          '|',
                          '&', ('amount_residual_currency', '!=', 0.0), ('currency_id', '!=', None),
                          '&', ('amount_residual_currency', '=', 0.0), '&', ('currency_id', '=', None),
                          ('amount_residual', '!=', 0.0)]
                domain.extend([('credit', '>', 0), ('debit', '=', 0)])
                lines = self.env['account.move.line'].sudo().search(domain)
                for line in lines:
                    # get the outstanding residual value in invoice currency
                    if line.currency_id and line.currency_id == installment_invoice_id.currency_id:
                        amount_residual_currency = abs(line.amount_residual_currency)
                    else:
                        currency = line.company_id.currency_id
                        amount_residual_currency = currency._convert(abs(line.amount_residual),
                                                                     installment_invoice_id.currency_id,
                                                                     installment_invoice_id.company_id,
                                                                     line.date or fields.Date.today())
                    if float_is_zero(amount_residual_currency,
                                     precision_rounding=installment_invoice_id.currency_id.rounding):
                        continue

                    installment_invoice_id.assign_outstanding_credit(line.id)
                    if installment_invoice_id.state == 'paid':
                        break
                wallet_transaction_sudo = self.env['website.wallet.transaction'].sudo()
                label = _('Collect payment for invoice [%s]') % (installment_invoice_id.number)
                partner_wallet_id = installment_partner_id.get_transaction_wallet()
                partner_id_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
                machine_wallet_create = wallet_transaction_sudo.create(
                    {'wallet_type': 'debit', 'partner_id': installment_partner_id.id, 'reference': 'manual',
                     'label': label, 'amount': installment_amount, 'currency_id': installment_invoice_id.currency_id.id,
                     'wallet_balance_before': partner_id_wallet_balance,
                     'wallet_balance_after': partner_id_wallet_balance - installment_amount,
                     'status': 'done'})
                # self.env.cr.commit()

                installment_partner_id.update(
                    {'wallet_balance': partner_id_wallet_balance - installment_amount})
                """
                machine_wallet_create, wallet_balance_after = self.create_wallet_transaction(
                    'debit', installment_partner_id, 'manual',
                    _('Collect payment for invoice [%s]') % (installment_invoice_id.number),
                    installment_amount, installment_invoice_id.currency_id, False,
                    'smartpay_operations.wallet_pay_invoice_notify_mode', 'wallet_pay_invoice',
                    _('<p>%s %s successfully deducted from your wallet.</p>') % (
                        installment_amount, _(installment_invoice_id.currency_id.name))
                )

                # Next line is temp code for >> Tamayoz TODO: Reconcile installment_move_line_id with prepaid wallet recharge payments and previous cashback credit note by installment_amount only
                installment_move_line_id.update({'deducted_from_wallet': True})
                self.env.cr.commit()

                """
                # Notify customer
                irc_param = self.env['ir.config_parameter'].sudo()
                wallet_pay_invoice_notify_mode = irc_param.get_param(
                    "smartpay_operations.wallet_pay_invoice_notify_mode")
                if wallet_pay_invoice_notify_mode == 'inbox':
                    self.env['mail.thread'].sudo().message_notify(
                        subject=label,
                        body=_('<p>%s %s successfully deducted from your wallet.</p>') % (
                            installment_amount, _(installment_invoice_id.currency_id.name)),
                        partner_ids=[(4, installment_partner_id.id)],
                    )
                elif wallet_pay_invoice_notify_mode == 'email':
                    machine_wallet_create.wallet_transaction_email_send()
                elif wallet_pay_invoice_notify_mode == 'sms' and installment_partner_id.mobile:
                    machine_wallet_create.sms_send_wallet_transaction(wallet_pay_invoice_notify_mode,
                                                                      'wallet_pay_invoice',
                                                                      # Tamayoz TODO: Add 'wallet_deduction' sms template
                                                                      installment_partner_id.mobile,
                                                                      installment_partner_id.name, label,
                                                                      '%s %s' % (installment_amount,
                                                                                 _(
                                                                                     installment_invoice_id.currency_id.name)),
                                                                      installment_partner_id.country_id.phone_code or '2')
                """
        except Exception as e:
            _logger.error("%s", e)
            return "internal error"
    '''


class website_wallet_transaction_line(models.Model):
    _name = 'website.wallet.transaction.line'
    _order = 'id desc'

    @api.model
    def create(self, vals):
        vals['name'] = self.env['ir.sequence'].next_by_code('website.wallet.transaction.line') or 'New'
        res = super(website_wallet_transaction_line, self).create(vals)
        return res

    wallet_transaction_id = fields.Many2one('website.wallet.transaction', string='Wallet Transaction Reference',
                                            ondelete='restrict', index=True, copy=False, # required=True
                                            )
    name = fields.Char('Name')
    wallet_type = fields.Selection([
        ('credit', 'Credit'),
        ('debit', 'Debit')
    ], string='Type', default='credit')
    partner_id = fields.Many2one('res.partner', 'Customer')
    # sale_order_id = fields.Many2one('sale.order', 'Sale Order')
    request_id = fields.Many2one('smartpay_operations.request', 'Request',  index=True)
    # wallet_id = fields.Many2one('res.partner', 'Wallet')
    reference = fields.Selection([
        ('manual', 'Manual'),
        # ('sale_order', 'Sale Order'),
        ('request', 'Request')
    ], string='Reference', default='manual')
    label = fields.Text('Label')
    amount = fields.Char('Amount') # Tamayoz TODO: Convert its type and amount field type in website.wallet.transaction to float
    currency_id = fields.Many2one('res.currency', 'Currency', default=lambda self: self.env.user.company_id.currency_id.id)
    status = fields.Selection([
        ('draft', 'Draft'),
        ('cancel', 'Cancel'),
        ('done', 'Done')
    ], string='Status', readonly=True, default='draft')

    statement_line_id = fields.Many2one('account.bank.statement.line', index=True, string='Statement Line',
                                        help='statement line reconciled with provider refund', copy=False,
                                        readonly=True)
    statement_id = fields.Many2one('account.bank.statement', related='statement_line_id.statement_id',
                                   string='Statement', store=True,
                                   help="The statement used for provider wallet reconciliation", index=True, copy=False)


class Wallet(models.TransientModel):
    _register = False

    name = fields.Char(string='Reason', required=True)
    amount = fields.Float(string='Amount', digits=0, required=True)

    @api.multi
    def run(self):
        context = dict(self._context or {})
        active_model = context.get('active_model', False)
        active_ids = context.get('active_ids', [])

        records = self.env[active_model].browse(active_ids)

        return self._run(records)

    @api.multi
    def _run(self, records):
        for wallet in self:
            for record in records:
                wallet.create_wallet_transaction(record)
        return {}

    @api.one
    def create_wallet_transaction(self, record):
        self._create_wallet_transaction(record)


class WalletIn(Wallet):
    _name = 'wallet.in'
    _description = 'Wallet In'

    ref = fields.Char('Reference')
    expense_account = fields.Many2one('account.account', string='Expense account', required=True, domain=[('deprecated', '=', False)])

    @api.multi
    def _create_wallet_transaction(self, record):
        '''
        wallet_transaction_sudo = self.env['website.wallet.transaction'].sudo()
        label = self.name
        partner_wallet_id = record.get_transaction_wallet()
        customer_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
        customer_wallet_create = wallet_transaction_sudo.create(
            {'wallet_type': 'credit', 'partner_id': record.id, 'reference': 'manual', 'label': label,
             'amount': self.amount or 0.0, 'currency_id': self.env.user.company_id.currency_id.id,
             'wallet_balance_before': customer_wallet_balance,
             'wallet_balance_after': customer_wallet_balance + self.amount or 0.0,
             'status': 'done'})
        # self.env.cr.commit()

        record.update({'wallet_balance': customer_wallet_balance + self.amount or 0.0})
        self.env.cr.commit()

        # Create journal entry for wallet in.
        receivable_account = record.property_account_receivable_id
        account_move = self.env['account.move'].sudo().create({
            'journal_id': self.env['account.journal'].sudo().search([('type', '=', 'general')], limit=1).id,
        })
        self.env['account.move.line'].with_context(check_move_validity=False).sudo().create({
            'name': record.name + ': Wallet In',
            'move_id': account_move.id,
            'account_id': self.expense_account.id,
            'debit': self.amount,
        })
        self.env['account.move.line'].with_context(check_move_validity=False).sudo().create({
            'name': record.name + ': Wallet In',
            'move_id': account_move.id,
            'account_id': receivable_account.id,
            'partner_id': record.id,
            'credit': self.amount,
        })
        account_move.post()
        self.env.cr.commit()

        # Notify Customer
        irc_param = self.env['ir.config_parameter'].sudo()
        wallet_bouns_notify_mode = irc_param.get_param("smartpay_operations.wallet_bouns_notify_mode")
        if wallet_bouns_notify_mode == 'inbox':
            self.env['mail.thread'].sudo().message_notify(
                subject=label,
                body=_('<p>%s %s successfully added to your wallet.</p>') % (
                    self.amount or 0.0, _(self.env.user.company_id.currency_id.name)),
                partner_ids=[(4, record.id)],
            )
        elif wallet_bouns_notify_mode == 'email':
            customer_wallet_create.wallet_transaction_email_send()
        elif wallet_bouns_notify_mode == 'sms' and record.mobile:
            customer_wallet_create.sms_send_wallet_transaction(wallet_bouns_notify_mode,
                                                               'wallet_bouns',
                                                               record.mobile,
                                                               record.name, label,
                                                               '%s %s' % (self.amount or 0.0,
                                                                          _(self.env.user.company_id.currency_id.name)),
                                                               record.country_id.phone_code or '2')
        '''
        partner_wallet_id = record
        customer_wallet_create, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
            'credit', record.partner_id, 'manual', self.name,
            self.amount, self.env.user.company_id.currency_id, False,
            'smartpay_operations.wallet_bouns_notify_mode', 'wallet_bouns',
            _('<p>%s %s successfully added to your wallet.</p>') % (
                self.amount or 0.0, _(self.env.user.company_id.currency_id.name)),
            self.expense_account, _('Wallet In')
        )
        # Check Customer Wallet Balance Maximum Balance
        if not customer_wallet_create:
            raise UserError(_("Wallet [%s] maximum balance exceeded!") % partner_wallet_id.name)


class WalletOut(Wallet):
    _name = 'wallet.out'
    _description = 'Wallet Out'

    income_account = fields.Many2one('account.account', string='Income account', required=True, domain=[('deprecated', '=', False)])

    @api.multi
    def _create_wallet_transaction(self, record):
        '''
        wallet_transaction_sudo = self.env['website.wallet.transaction'].sudo()
        label = self.name
        partner_wallet_id = record.get_transaction_wallet()
        partner_id_wallet_balance = partner_wallet_id.balance_amount if partner_wallet_id else 0
        customer_wallet_create = wallet_transaction_sudo.create(
            {'wallet_type': 'debit', 'partner_id': record.id, 'reference': 'manual', 'label': label,
             'amount': self.amount or 0.0, 'currency_id': self.env.user.company_id.currency_id.id,
             'wallet_balance_before': partner_id_wallet_balance,
             'wallet_balance_after': partner_id_wallet_balance - self.amount or 0.0,
             'status': 'done'})
        # self.env.cr.commit()

        record.update(
            {'wallet_balance': partner_id_wallet_balance - self.amount or 0.0})
        self.env.cr.commit()

        # Create journal entry for wallet out.
        receivable_account = record.property_account_receivable_id
        account_move = self.env['account.move'].sudo().create({
            'journal_id': self.env['account.journal'].sudo().search([('type', '=', 'general')], limit=1).id,
        })
        self.env['account.move.line'].with_context(check_move_validity=False).sudo().create({
            'name': record.name + ': Wallet Out',
            'move_id': account_move.id,
            'account_id': receivable_account.id,
            'partner_id': record.id,
            'debit': self.amount,
        })
        self.env['account.move.line'].with_context(check_move_validity=False).sudo().create({
            'name': record.name + ': Wallet Out',
            'move_id': account_move.id,
            'account_id': self.income_account.id,
            'credit': self.amount,
        })
        account_move.post()
        self.env.cr.commit()

        # Notify customer
        irc_param = self.env['ir.config_parameter'].sudo()
        wallet_pay_invoice_notify_mode = irc_param.get_param("smartpay_operations.wallet_pay_invoice_notify_mode")
        if wallet_pay_invoice_notify_mode == 'inbox':
            self.env['mail.thread'].sudo().message_notify(
                subject=label,
                body=_('<p>%s %s successfully deducted from your wallet.</p>') % (
                    self.amount or 0.0, _(self.env.user.company_id.currency_id.name)),
                partner_ids=[(4, record.id)],
            )
        elif wallet_pay_invoice_notify_mode == 'email':
            customer_wallet_create.wallet_transaction_email_send()
        elif wallet_pay_invoice_notify_mode == 'sms' and record.mobile:
            customer_wallet_create.sms_send_wallet_transaction(wallet_pay_invoice_notify_mode,
                                                              'wallet_pay_invoice', # Tamayoz TODO: Add 'wallet_deduction' sms template
                                                              record.mobile,
                                                              record.name, label,
                                                              '%s %s' % (self.amount or 0.0,
                                                                         _(self.env.user.company_id.currency_id.name)),
                                                              record.country_id.phone_code or '2')
        '''
        partner_wallet_id = record
        customer_wallet_create, wallet_balance_after = partner_wallet_id.create_wallet_transaction(
            'debit', record.partner_id, 'manual', self.name,
            self.amount, self.env.user.company_id.currency_id, False,
            'smartpay_operations.wallet_pay_invoice_notify_mode', 'wallet_pay_invoice', # TODO: create notify_mode for wallet out
            _('<p>%s %s successfully deducted from your wallet.</p>') % (
                self.amount or 0.0, _(self.env.user.company_id.currency_id.name)),
            self.income_account, _('Wallet Out'), record.partner_id
        )