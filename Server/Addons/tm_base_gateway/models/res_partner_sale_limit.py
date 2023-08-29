# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

from odoo import fields, models
from odoo.addons import decimal_precision as dp


class PartnerSaleLimit(models.Model):
    _name = 'res.partner.sale.limit'

    partner_id = fields.Many2one('res.partner', 'Partner', readonly=True)
    product_id = fields.Many2one('product.product', 'Product Variant', readonly=True)
    limit_type = fields.Selection([('daily', 'Daily'), ('weekly', 'Weekly'), ('monthly', 'Monthly')], 'Limit Type',
                                  default='daily', readonly=True)
    day = fields.Integer('Day of Year', readonly=True)
    week = fields.Integer('Week of Year', readonly=True)
    month = fields.Integer('Month of Year', readonly=True)
    year = fields.Integer('Year', readonly=True)

    sold_amount = fields.Float(
        'Sold Amount',
        digits=dp.get_precision('Product Price'),
        help="Total Sold Amount at which the product is sold to partner.", readonly=True)
