# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

from odoo import fields, models


class ServiceFeesTier(models.Model):
    _name = 'service.fees.tier'
    _description = 'Service Fees Tier'

    name = fields.Char('Tier Name', required=True)
    fees_id = fields.Many2one('service.fees', string='Value Type')
    lower_amt = fields.Float('Lower Amount')
    upper_amt = fields.Float('Upper Amount')
    fixed_amount_ids = fields.One2many('fixed.amount', 'service_fees_tier_id')
    percent_range_ids = fields.One2many('percent.range', 'service_fees_tier_id')
    start_date = fields.Datetime('Start Date')
    expiry_date = fields.Datetime('Expiration Date')
