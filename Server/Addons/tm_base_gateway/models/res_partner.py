# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

from odoo.addons import decimal_precision as dp
from odoo import fields, models


class PartnerProductSaleLimitFees(models.Model):
    _name = 'res.partner.product.sale.limit.fees'
    _description = "Partner Sale Over Limit Fees per Product"
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

    partner_product_sale_limit_id = fields.Many2one('res.partner.product.sale.limit', 'Product Sale Limit', index=True, ondelete='cascade')
    product_id = fields.Many2one('product.product', 'Product Variant', related='partner_product_sale_limit_id.product_id')
    product_tmpl_id = fields.Many2one('product.template', 'Product Template', related='partner_product_sale_limit_id.product_tmpl_id')

    company_id = fields.Many2one(
        'res.company', 'Company',
        default=lambda self: self.env.user.company_id.id, index=1)
    currency_id = fields.Many2one(
        'res.currency', 'Currency',
        default=lambda self: self.env.user.company_id.currency_id.id,
        required=True)


class PartnerProductSaleLimit(models.Model):
    _name = 'res.partner.product.sale.limit'
    _description = "Partner Sale Limit per Product"
    _order = 'sequence, limit_type'

    sequence = fields.Integer(
        'Sequence', default=1, help="Assigns the priority to the list of sale limit.")
    product_id = fields.Many2one(
        'product.product', 'Product Variant', domain=[('product_tmpl_id.has_sale_limit', '=', True)],
        help="If not set, the sale limit will apply to all variants of this product.")
    product_tmpl_id = fields.Many2one(
        'product.template', 'Product Template', domain=[('has_sale_limit', '=', True)],
        index=True, ondelete='cascade', oldname='product_id', required=True)
    limit_type = fields.Selection([('daily', 'Daily'), ('weekly', 'Weekly'), ('monthly', 'Monthly')], 'Limit Type',
                                  default='daily', required=True)
    limit_amount = fields.Float(
        'Limit Amount', default=1.0,
        digits=dp.get_precision('Product Price'),
        help="Sale Limit at which the product is sold to customers.", required=True)

    # has_over_limit_fees = fields.Boolean('Has Over Limit Fees')
    over_limit_fees_policy = fields.Selection([('no_over_limit_fees', 'No Over Limit Fees'),
                                               ('product_over_limit_fees', 'Product Over Limit Fees'),
                                               ('custom_over_limit_fees', 'Custom Over Limit Fees')], 'Over Limit Fees Poloicy',
                                              default='no_over_limit_fees', required=True)
    product_over_limit_fees_ids = fields.One2many('product.sale.limit.fees', string='Product Sale Over Limit Fees',
                                                  related='product_tmpl_id.sale_limit_ids.over_limit_fees_ids')
    over_limit_fees_ids = fields.One2many('res.partner.product.sale.limit.fees', 'partner_product_sale_limit_id', 'Custom Sale Over Limit Fees',
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
    partner_id = fields.Many2one('res.partner', 'Partner')


class ResPartner(models.Model):
    _inherit = 'res.partner'

    sale_limit_ids = fields.One2many('res.partner.product.sale.limit', 'partner_id', 'Sale limits', help="Define sale limits.")
