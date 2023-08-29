# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

from odoo import fields, models


class ProductSupplierInfoMapping(models.Model):
    _name = 'product.supplierinfo.mapping'

    name = fields.Many2one(
        'res.partner', 'Vendor',
        domain=[('supplier', '=', True)], ondelete='cascade', required=True,
        help="Vendor of this product")
    product_code = fields.Char(
        'Vendor Product Code',
        help="This vendor's product code will be used when printing a request for quotation. Keep empty to use the internal one.")
    product_name = fields.Char(
        'Vendor Product Name',
        help="This vendor's product name will be used when printing a request for quotation. Keep empty to use the internal one.")
    sequence = fields.Integer(
        'Sequence', default=1, help="Assigns the priority to the list of product vendor.")
    product_tmpl_id = fields.Many2one(
        'product.template.mapping', 'Product Template',
        index=True, ondelete='cascade', oldname='product_id')
    product_id = fields.Many2one(
        'product.product.mapping', 'Product Variant',
        help="If not set, the vendor price will apply to all variants of this product.")
    biller_info = fields.Text('Biller Info', translate=True)
    # commission = fields.One2many('product.supplierinfo.commission', 'product_supplierinfo_id', string='Commestions', copy=True)

    company_id = fields.Many2one(
        'res.company', 'Company',
        default=lambda self: self.env.user.company_id.id, index=1)
