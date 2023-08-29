# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

from odoo import fields, models
from odoo.addons import decimal_precision as dp


class ProductSaleLimit(models.Model):
    _name = 'product.sale.limit'
    _description = "Product Sale Limit"
    _order = 'sequence, limit_type'

    sequence = fields.Integer(
        'Sequence', default=1, help="Assigns the priority to the list of sale limit.")
    limit_type = fields.Selection([('daily', 'Daily'), ('weekly', 'Weekly'), ('monthly', 'Monthly')], 'Limit Type',
                                  default='daily', required=True)
    limit_amount = fields.Float(
        'Limit Amount', default=1.0, required=True,
        digits=dp.get_precision('Product Price'),
        help="Sale Limit at which the product is sold to customers.")

    has_over_limit_fees = fields.Boolean('Has Over Limit Fees')
    over_limit_fees_ids = fields.One2many('product.sale.limit.fees', 'product_sale_limit_id', 'Sale Over Limit Fees',
                                          help="Define sale over limit fees.")

    company_id = fields.Many2one(
        'res.company', 'Company',
        default=lambda self: self.env.user.company_id.id, index=1)
    currency_id = fields.Many2one(
        'res.currency', 'Currency',
        default=lambda self: self.env.user.company_id.currency_id.id,
        required=True)
    date_start = fields.Date('Start Date', help="Start date for this sale limit")
    date_end = fields.Date('End Date', help="End date for this sale limit")
    product_id = fields.Many2one(
        'product.product', 'Product Variant',
        help="If not set, the sale limit will apply to all variants of this product.")
    product_tmpl_id = fields.Many2one(
        'product.template', 'Product Template',
        index=True, ondelete='cascade', oldname='product_id')
