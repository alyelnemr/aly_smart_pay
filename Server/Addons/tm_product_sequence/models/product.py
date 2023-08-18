# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

from odoo import fields, models, api


class ProductProduct(models.Model):
    _inherit = 'product.product'
    _order = 'sequence, default_code, name, id'

class ProductTemplate(models.Model):
    _inherit = 'product.template'
    _order = 'sequence, name'

    sequence = fields.Integer(string='Sequence', help='product display base on product sequence number')

    @api.model
    def create(self, vals):
        res = super(ProductTemplate, self).create(vals)
        if res:
            rec = self.search([])
            if rec:
                seq = max(self.search([]).mapped('sequence'))
                if seq:
                    res.sequence = seq + 1;
        return res

class ProductCategory(models.Model):
    _inherit = 'product.category'
    _order = 'sequence, display_name, id'

    sequence = fields.Integer(string='Sequence', help='product category display base on product sequence number')

    @api.model
    def create(self, vals):
        res = super(ProductCategory, self).create(vals)
        if res:
            rec = self.search([])
            if rec:
                seq = max(self.search([]).mapped('sequence'))
                if seq:
                    res.sequence = seq + 1;
        return res