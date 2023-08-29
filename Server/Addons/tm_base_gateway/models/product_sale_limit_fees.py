# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

from odoo import fields, models
from odoo.addons import decimal_precision as dp


class ProductSaleLimitFees(models.Model):
    _name = 'product.sale.limit.fees'
    _description = "Product Sale Over Limit Fees"
    _order = 'sequence, sale_amount_from, sale_amount_to'

    sequence = fields.Integer(
        'Sequence', default=1, help="Assigns the priority to the list of sale over limit fees.")
    sale_amount_from = fields.Float('From Amount', required=True, digits=dp.get_precision('Product Price'),
                                    help="Sale Amount From.")
    sale_amount_to = fields.Float('To Amount', required=True, digits=dp.get_precision('Product Price'),
                                  help="Sale Amount To.")
    fees_amount = fields.Float('Fees Amount', required=True, digits=dp.get_precision('Product Price'),
                               help="Fees Amount.")
    fees_amount_percentage = fields.Float('Fees Amount %', required=True, digits=dp.get_precision('Product Price'),
                                          help="Fees Amount %")

    product_sale_limit_id = fields.Many2one('product.sale.limit', 'Product Sale Limit', index=True, ondelete='cascade')
    product_id = fields.Many2one('product.product', 'Product Variant', related='product_sale_limit_id.product_id')
    product_tmpl_id = fields.Many2one('product.template', 'Product Template',
                                      related='product_sale_limit_id.product_tmpl_id')

    company_id = fields.Many2one(
        'res.company', 'Company',
        default=lambda self: self.env.user.company_id.id, index=1)
    currency_id = fields.Many2one(
        'res.currency', 'Currency',
        default=lambda self: self.env.user.company_id.currency_id.id,
        required=True)
