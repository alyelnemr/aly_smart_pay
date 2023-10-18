# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

from odoo import api, fields, models, tools


class ProductCategoryMapping(models.Model):
    _name = 'product.category.mapping'
    _description = "Service Category Mapping"
    _parent_name = "parent_id"
    _parent_store = True
    _rec_name = 'complete_name'
    _order = 'complete_name'

    name = fields.Char('Name', index=True, required=True, translate=True)
    complete_name = fields.Char(
        'Complete Name', compute='_compute_complete_name',
        store=True)
    parent_id = fields.Many2one('product.category.mapping', 'Parent Category', index=True, ondelete='cascade')
    parent_path = fields.Char(index=True)
    child_id = fields.One2many('product.category', 'parent_id', 'Child Categories')
    property_cost_method = fields.Selection([
        ('standard', 'Standard Price'),
        ('fifo', 'First In First Out (FIFO)'),
        ('average', 'Average Cost (AVCO)')], string="Costing Method",
        company_dependent=True, copy=True, required=True,
        help="""Standard Price: The products are valued at their standard cost defined on the product.
            Average Cost (AVCO): The products are valued at weighted average cost.
            First In First Out (FIFO): The products are valued supposing those that enter the company first will also leave it first.
            """)
    provider_ids = fields.One2many('product_category.providerinfo.mapping', 'product_categ_id', 'Providers',
                                   help="Define product category providers.")

    # image: all image fields are base64 encoded and PIL-supported
    image = fields.Binary(
        "Image", attachment=True,
        help="This field holds the image used as image for the product, limited to 1024x1024px.")
    image_medium = fields.Binary(
        "Medium-sized image", attachment=True,
        help="Medium-sized image of the product. It is automatically "
             "resized as a 128x128px image, with aspect ratio preserved, "
             "only when the image exceeds one of those sizes. Use this field in form views or some kanban views.")
    image_small = fields.Binary(
        "Small-sized image", attachment=True,
        help="Small-sized image of the product. It is automatically "
             "resized as a 64x64px image, with aspect ratio preserved. "
             "Use this field anywhere a small image is required.")

    company_id = fields.Many2one(
        'res.company', 'Company',
        default=lambda self: self.env.user.company_id.id, index=1)

    @api.depends('name', 'parent_id.complete_name')
    def _compute_complete_name(self):
        for category in self:
            if category.parent_id:
                category.complete_name = '%s / %s' % (category.parent_id.complete_name, category.name)
            else:
                category.complete_name = category.name

    @api.model
    def create(self, vals):
        tools.image_resize_images(vals)
        return super(ProductCategoryMapping, self).create(vals)

    @api.multi
    def write(self, vals):
        tools.image_resize_images(vals)
        return super(ProductCategoryMapping, self).write(vals)


class ProviderInfoMapping(models.Model):
    _name = "product_category.providerinfo.mapping"
    _description = "Service Category Provider Mapping"
    _order = 'sequence'

    provider_id = fields.Many2one('payment.acquirer', 'Provider',
                                  domain=[('sevice_provider', '=', True)], required=True,
                                  help="Provider of this service category")
    product_categ_name = fields.Char('Provider Service Category Name')
    product_categ_code = fields.Char('Provider Service Category Code')
    sequence = fields.Integer('Sequence', default=1,
                              help="Assigns the priority to the list of service category provider.")
    product_categ_id = fields.Many2one('product.category.mapping', 'Service Category', ondelete='cascade')
    company_id = fields.Many2one(
        'res.company', 'Company',
        default=lambda self: self.env.user.company_id.id, index=1)


class ProductCategory(models.Model):
    _inherit = 'product.category'

    provider_ids = fields.One2many('product_category.providerinfo', 'product_categ_id', 'Providers',
                                   help="Define product category providers.")

    # image: all image fields are base64 encoded and PIL-supported
    image = fields.Binary(
        "Image", attachment=True,
        help="This field holds the image used as image for the product, limited to 1024x1024px.")
    image_medium = fields.Binary(
        "Medium-sized image", attachment=True,
        help="Medium-sized image of the product. It is automatically "
             "resized as a 128x128px image, with aspect ratio preserved, "
             "only when the image exceeds one of those sizes. Use this field in form views or some kanban views.")
    image_small = fields.Binary(
        "Small-sized image", attachment=True,
        help="Small-sized image of the product. It is automatically "
             "resized as a 64x64px image, with aspect ratio preserved. "
             "Use this field anywhere a small image is required.")

    @api.model
    def create(self, vals):
        tools.image_resize_images(vals)
        return super(ProductCategory, self).create(vals)

    @api.multi
    def write(self, vals):
        tools.image_resize_images(vals)
        return super(ProductCategory, self).write(vals)


class ProviderInfo(models.Model):
    _name = "product_category.providerinfo"
    _description = "Service Category Provider"
    _order = 'sequence'

    provider_id = fields.Many2one('payment.acquirer', 'Provider',
                                  domain=[('sevice_provider', '=', True)], required=True,
                                  help="Provider of this service category")
    product_categ_name = fields.Char('Provider Service Category Name')
    product_categ_code = fields.Char('Provider Service Category Code')
    sequence = fields.Integer('Sequence', default=1,
                              help="Assigns the priority to the list of service category provider.")
    product_categ_id = fields.Many2one('product.category', 'Service Category', ondelete='cascade')
    company_id = fields.Many2one(
        'res.company', 'Company',
        default=lambda self: self.env.user.company_id.id, index=1)
