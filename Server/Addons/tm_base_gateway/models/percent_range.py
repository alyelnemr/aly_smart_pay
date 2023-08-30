# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

from odoo import fields, models


class PercentRange(models.Model):
    _name = 'percent.range'
    _description = 'Percent Range'

    name = fields.Char('Percent Title', required=True)
    value = fields.Float('Value')
    min_amt = fields.Float('Min Amount')
    max_amt = fields.Float('Max Amount')
    service_fees_tier_id = fields.Many2one('service.fees.tier', 'Tier')
