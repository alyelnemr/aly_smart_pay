import logging

from odoo import api, fields, models,_
from odoo.exceptions import ValidationError

_logger = logging.getLogger(__name__)

class ProductCategories(models.Model):
    _inherit = "product.category"

    tag_ids = fields.Many2many('product.tags', string='Tags', compute='compute_tags', store=True, readonly=1)
    product_tmpl_ids = fields.One2many('product.template', 'categ_id', 'Child Product Templates')

    company_id = fields.Many2one('res.company', 'Company', default=lambda self: self.env.user.company_id.id, index=1)

    @api.depends('product_tmpl_ids.tag_ids', 'child_id.tag_ids')
    def compute_tags(self):
        '''
        for line in self:
            tag_ids = line.tag_ids
            product_ids = line.env['product.template'].search([('categ_id', 'child_of', line.id)])
            for product_id in product_ids:
                if not tag_ids:
                    tag_ids = product_id.tag_ids
                else:
                    tag_ids += product_id.tag_ids
            line.write({'tag_ids': tag_ids})
        '''
        tag_ids = []
        for product_tmpl_id in self.product_tmpl_ids:
            for tag_id in product_tmpl_id.tag_ids:
                tag_ids.append(tag_id.id)
        for child_id in self.child_id:
            for tag_id in child_id.tag_ids:
                tag_ids.append(tag_id.id)
        self.tag_ids = self.env['product.tags'].sudo().search([('id','in',tag_ids)])

class product_template(models.Model):
    _inherit = 'product.template'

    tag_ids = fields.Many2many('product.tags', string='Tags')

    '''
    @api.onchange('tag_ids')
    @api.multi
    def on_change_tag_ids(self):
        for product_id in self:
            if product_id.tag_ids:
                parent_categ_tag_ids = product_id.categ_id.tag_ids
                parent_categ_tag_ids += product_id.tag_ids
                product_id.categ_id.write({'tag_ids':parent_categ_tag_ids})
                if not line.tag_ids:
                    line.tag_ids = product_id.tag_ids
                else:
                    line.tag_ids += product_id.tag_ids
                parent_categories = product_id.env['product.category'].search([('id', 'parent_of', product_id.categ_id.id)])
                for parent_category in parent_categories:
                    parent_category.tag_ids += product_id.tag_ids
    '''