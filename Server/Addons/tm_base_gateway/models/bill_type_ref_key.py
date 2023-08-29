# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

from odoo import fields, models


class BillTypeExtraRefKeys(models.Model):
    _name = 'bill.type.ref.key'
    _description = 'Bill Type Extra Ref Keys'

    def _default_input_method(self):
        input_method = self.env['account.input.method'].sudo().search([('name', '=', 'KP')])
        return input_method.id

    name = fields.Char('Label', translate=True, required=True)
    product_id = fields.Many2one('product.template', string='Product')
    billing_account_key_type_id = fields.Many2one('billing.account.key.type', string='Key')
    is_print_key_part = fields.Boolean(string='Print Key Part', default=True)
    is_required = fields.Boolean(string='Required', default=True)
    is_cnfrm_required = fields.Boolean(string='Is Confirm Required')
    is_ba_key_part = fields.Boolean(string='Is BA KeyPart')
    is_encrypt_required = fields.Boolean(string='Is Encrypt Required')
    is_encrypt_key_profile = fields.Boolean(string='Encrypt Key Profile')
    input_method_id = fields.Many2one('account.input.method', string='Account Input Method',
                                           default=_default_input_method)
    is_masked_input = fields.Boolean(string='Encrypt Key Profile')
    value_type_id = fields.Many2one('value.type', string='Value Type')
    enum_value_ids = fields.One2many('enum.values', 'bill_type_ref_key_id')
