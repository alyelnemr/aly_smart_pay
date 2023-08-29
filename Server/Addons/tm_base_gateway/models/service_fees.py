# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

from odoo import fields, models


class ServiceFees(models.Model):
    _name = 'service.fees'
    _description = 'Service Fees'

    name = fields.Char('Fees Title', required=True)
    product_id = fields.Many2one('product.template', string='Product')
    service_fees_tier_ids = fields.One2many('service.fees.tier', 'fees_id')
    is_embedded_fees = fields.Boolean(string='Is Embedded Fees')
