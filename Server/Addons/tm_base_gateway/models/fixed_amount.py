# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

from odoo import fields, models


class FixedAmount(models.Model):
    _name = 'fixed.amount'
    _description = 'Fixed Amount'

    name = fields.Char('Title', required=True)
    amount = fields.Float(string='Amount')
    currency_code = fields.Selection([('egp', 'EGP')], string='Cur Code')
    currency_code_id = fields.Many2one('currency.code', 'Currency Code')
    service_fees_tier_id = fields.Many2one('service.fees.tier', 'Tier')
