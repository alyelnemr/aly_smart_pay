# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

from odoo import fields, models


class ProductSupplierInfoBillerInfoMapping(models.Model):
    _name = 'product.supplierinfo.billerinfo.mapping'
    _description = "Biller Info Mapping"

    MAPPING_FIELDS = ['name']

    product_supplierinfo_id = fields.Many2one('product.supplierinfo', 'Product Supplier Info', index=True,
                                              ondelete='cascade')
    '''
    product_id = fields.Many2one(
        'product.product', related='product_supplierinfo_id.product_id', string='Service Variant',
        help='If not set, the vendor price will apply to all variants of this product.', store=False, readonly=True)
    product_tmpl_id = fields.Many2one(
        'product.template', related='product_supplierinfo_id.product_tmpl_id', string='Service',
        index=True, ondelete='cascade', oldname='product_id', store=True, readonly=True)
    vendor = fields.Many2one('res.partner', related='product_supplierinfo_id.name', string='Vendor', store=True,
                             readonly=True)
    vendor_product_name = fields.Char(related='product_supplierinfo_id.product_name', string='Vendor Service Name',
                                      store=False, readonly=True)
    vendor_product_code = fields.Char(related='product_supplierinfo_id.product_code', string='Vendor Service Code',
                                      store=True, readonly=True)
    '''
    col1 = fields.Many2one('ir.model.fields', string='Field', required=True,
                           domain=lambda self: [('model', '=', 'product.template'), ('name', 'in',
                                                                                     self.MAPPING_FIELDS)])  # tm_sps_ abbrevation of Tamayoz Standard Provider Service
