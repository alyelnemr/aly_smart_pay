# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

from odoo import fields, models


class ProductTemplate(models.Model):
    _inherit = 'product.template'

    def _default_input_method(self):
        input_method = self.env['account.input.method'].sudo().search([('name', '=', 'KP')])
        return input_method.id

    has_sale_limit = fields.Boolean('Has Sale Limit')
    sale_limit_ids = fields.One2many('product.sale.limit', 'product_tmpl_id', 'Sale limits', help="Define sale limits.")
    variant_sale_limit_ids = fields.One2many('product.sale.limit', 'product_tmpl_id')

    # Standard Service Fields
    # ['BillTypeCode', '', '', '', '', '', '', '', '', '',
    # '', '', '', '', '', '', '', '', '', '',
    # '', '', '', '', '', '', '', '', '', '',
    # '', '', '', '', '', '', '', '', '', '',
    # '', '', '', '', '', '', '', '', '']
    bill_type_code = fields.Char(string='Bill Type Code')
    is_hidden = fields.Boolean(string='Hidden')
    bill_ref_type = fields.Boolean(string='Bill Ref Type')
    pmt_type_id = fields.Many2one('pmt.type', string='PMT Type')
    service_type_id = fields.Many2one('service.type', string='Service Type')
    service_name = fields.Char(string='Service Name')
    bill_type_acct_label = fields.Char(string='Bill Type Account Label')
    acct_input_method_id = fields.Many2one('account.input.method', string='Account Input Method',
                                           default=_default_input_method)
    acct_input_method = fields.Selection(
        [('kp', 'KP'), ('cr', 'CR'), ('kc', 'KC'), ('sc', 'SC'), ('ni', 'NI'), ('sk', 'SK')],
        string='Acct Input Method')
    allow_timeout_receipt = fields.Boolean(string='Allow Timeout Receipt')
    bill_type_extra_ref_keys_ids = fields.One2many('bill.type.ref.key', 'product_id')
    receipt_header = fields.Text(string='Receipt Header', translate=True)
    receipt_footer = fields.Text(string='Receipt Footer', translate=True)
    ## payment_rules = fields.Selection([('isinqrqr', 'IsInqRqr')],string='Payment Rules')
    payment_rules_ids = fields.One2many('payment.rules', 'product_id')
    service_fees_ids = fields.One2many('service.fees', 'product_id')
    tax_amount = fields.Float(string='Tax')
    payment_ranges = fields.One2many('payment.ranges', 'lower')
    allow_rct_re_print = fields.Boolean(string='Allow Receipt Reprint')
    bill_type_status = fields.Selection(
        [('available', 'Available'), ('availpend', 'AvailPend'), ('deleted', 'Deleted'), ('delpend', 'DelPend')],
        default='available', string='Bill Type Status')
    bill_type_nature = fields.Selection([('cashout_inq', 'CASHOUT_INQ'), ('cashout_corr', 'CASHOUT_CORR')],
                                        string='PMT Type')
    corr_bill_type_code = fields.Char(string='Corr Bill Type Code')
    otp_enabled = fields.Boolean(string='OTP Enabled')
    opt_required = fields.Boolean(string='OTP Required')
    support_pmt_reverse = fields.Boolean(string='Support PMT Reverse')
    timeout = fields.Selection([('', '')], string='Timeout')
    is_internal_cancel = fields.Boolean(string='Internal Cancel')
    has_correlation = fields.Boolean(string='Correlation')
