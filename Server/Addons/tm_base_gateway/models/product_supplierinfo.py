# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

import json

from odoo.addons.restful.common import default

from odoo import api, fields, models


class ProductSupplierInfo(models.Model):
    _inherit = 'product.supplierinfo'

    provider_biller_info = fields.Text('Original Biller Info', translate=True)
    mapping_biller_info = fields.Text('Biller Info Mapping', compute='_compute_mapping_biller_info', store=True,
                                      translate=True)
    custom_biller_info = fields.Text('Additional Biller Info', translate=True)
    biller_info = fields.Text('Biller Info', translate=True)
    biller_info_mapping = fields.One2many('product.supplierinfo.billerinfo.mapping', 'product_supplierinfo_id',
                                          string='Biller Info Mapping', copy=False)

    commission = fields.One2many('product.supplierinfo.commission', 'product_supplierinfo_id', string='Commissions',
                                 copy=True)

    @api.depends('provider_biller_info')
    def _compute_mapping_biller_info(self):
        for record in self:
            record.mapping_biller_info = record.provider_biller_info  # Tamayoz TODO: Must be mapping provider_biller_info in standard api
            # Tamayoz TODO: # Translate mapping_biller_info
            # record.with_context(lang='ar_AA').mapping_biller_info = record.with_context(lang='ar_AA').provider_biller_info
            # self.translate_mapping_biller_info()

    def translate_mapping_biller_info(self):
        providerBillerInfo_translate = self.env['ir.translation'].sudo().search([
            ('type', '=', 'model'),
            ('name', '=', 'product.supplierinfo,provider_biller_info'),
            # ('module', '=', 'product'),
            ('lang', '=', 'ar_AA'),
            ('res_id', '=', self.id),
            # ('state', '=', 'translated')
        ])

        if providerBillerInfo_translate:
            providerBillerInfo_translate_value = providerBillerInfo_translate.value
        else:
            providerBillerInfo_translate_value = self.provider_biller_info

        mappingBillerInfo_translate = self.env['ir.translation'].sudo().search([
            ('type', '=', 'model'),
            ('name', '=', 'product.supplierinfo,mapping_biller_info'),
            # ('module', '=', 'product'),
            ('lang', '=', 'ar_AA'),
            ('res_id', '=', self.id),
            # ('state', '=', 'translated')
        ])

        if not mappingBillerInfo_translate:
            mappingBillerInfo_translate = self.env['ir.translation'].sudo().create({
                'type': 'model',
                'name': 'product.supplierinfo,mapping_biller_info',
                'module': 'product',
                'lang': 'ar_AA',
                'res_id': self.id,
                'source': self.mapping_biller_info,
                'value': providerBillerInfo_translate_value,
                'state': 'translated',
            })
        else:
            mappingBillerInfo_translate.sudo().write({"value": providerBillerInfo_translate_value})

    @api.onchange('custom_biller_info')
    def build_biller_info(self):
        if self.mapping_biller_info or self.custom_biller_info:
            mapping_biller_info = json.loads(self.mapping_biller_info or self.biller_info or '{}', strict=False)
            custom_biller_info = json.loads(self.custom_biller_info or '{}', strict=False)
            self.biller_info = json.dumps({**mapping_biller_info, **custom_biller_info}, ensure_ascii=False,
                                          default=default)
            # Translate biller_info
            '''
            mapping_biller_info = json.loads(self.with_context(lang='ar_AA').mapping_biller_info or
                                             self.with_context(lang='ar_AA').biller_info or '{}', strict=False)
            custom_biller_info = json.loads(self.with_context(lang='ar_AA').custom_biller_info or '{}', strict=False)
            self.with_context(lang='ar_AA').biller_info = json.dumps({**mapping_biller_info, **custom_biller_info},
                                                                     default=default)
            '''
            self.translate_biller_info()

    def translate_biller_info(self):
        providerBillerInfo_translate = self.env['ir.translation'].sudo().search([
            ('type', '=', 'model'),
            ('name', '=', 'product.supplierinfo,provider_biller_info'),
            # ('module', '=', 'product'),
            ('lang', '=', 'ar_AA'),
            ('res_id', '=', self.id),
            # ('state', '=', 'translated')
        ])

        if providerBillerInfo_translate:
            providerBillerInfo_translate_value = providerBillerInfo_translate.value
        else:
            providerBillerInfo_translate_value = self.provider_biller_info

        mappingBillerInfo_translate = self.env['ir.translation'].sudo().search([
            ('type', '=', 'model'),
            ('name', '=', 'product.supplierinfo,mapping_biller_info'),
            # ('module', '=', 'product'),
            ('lang', '=', 'ar_AA'),
            ('res_id', '=', self.id),
            # ('state', '=', 'translated')
        ])

        if mappingBillerInfo_translate:
            mappingBillerInfo_translate_value = mappingBillerInfo_translate.value
        else:
            mappingBillerInfo_translate_value = providerBillerInfo_translate_value or self.mapping_biller_info

        customBillerInfo_translate = self.env['ir.translation'].sudo().search([
            ('type', '=', 'model'),
            ('name', '=', 'product.supplierinfo,custom_biller_info'),
            # ('module', '=', 'product'),
            ('lang', '=', 'ar_AA'),
            ('res_id', '=', self.id),
            # ('state', '=', 'translated')
        ])

        if customBillerInfo_translate:
            customBillerInfo_translate_value = customBillerInfo_translate.value
        else:
            customBillerInfo_translate_value = self.custom_biller_info

        billerInfo_translate = self.env['ir.translation'].sudo().search([
            ('type', '=', 'model'),
            ('name', '=', 'product.supplierinfo,biller_info'),
            # ('module', '=', 'product'),
            ('lang', '=', 'ar_AA'),
            ('res_id', '=', self.id),
            # ('state', '=', 'translated')
        ])

        mapping_biller_info = json.loads(mappingBillerInfo_translate_value or
                                         (
                                             billerInfo_translate.value if billerInfo_translate else self.biller_info) or
                                         '{}', strict=False)
        custom_biller_info = json.loads(customBillerInfo_translate_value or '{}', strict=False)
        billerInfo_translate_value = json.dumps({**mapping_biller_info, **custom_biller_info}, ensure_ascii=False,
                                                default=default)

        if not billerInfo_translate:
            billerInfo_translate = self.env['ir.translation'].sudo().create({
                'type': 'model',
                'name': 'product.supplierinfo,biller_info',
                'module': 'product',
                'lang': 'ar_AA',
                'res_id': self.id,
                'source': self.biller_info,
                'value': billerInfo_translate_value,
                'state': 'translated',
            })
        else:
            billerInfo_translate.sudo().write({"value": billerInfo_translate_value})

    @api.multi
    def write(self, values):
        for supplier_info in self:
            if values.get('custom_biller_info') and supplier_info.mapping_biller_info:
                mapping_biller_info = json.loads(supplier_info.mapping_biller_info or supplier_info.biller_info or '{}',
                                                 strict=False)
                custom_biller_info = json.loads(values.get('custom_biller_info') or '{}', strict=False)
                values.update(
                    {'biller_info': json.dumps({**mapping_biller_info, **custom_biller_info}, ensure_ascii=False,
                                               default=default)})
                # Translate biller_info
                '''
                mapping_biller_info = json.loads(supplier_info.with_context(lang='ar_AA').mapping_biller_info or
                                                 supplier_info.with_context(lang='ar_AA').biller_info or '{}', strict=False)
                custom_biller_info = json.loads(supplier_info.with_context(lang='ar_AA').custom_biller_info or '{}', strict=False)
                supplier_info.with_context(lang='ar_AA').biller_info = json.dumps({**mapping_biller_info, **custom_biller_info},
                                                                         default=default)
                '''
                customBillerInfo_translate = self.env['ir.translation'].sudo().search([
                    ('type', '=', 'model'),
                    ('name', '=', 'product.supplierinfo,custom_biller_info'),
                    # ('module', '=', 'product'),
                    ('lang', '=', 'ar_AA'),
                    ('res_id', '=', supplier_info.id),
                    # ('state', '=', 'translated')
                ])
                if not customBillerInfo_translate:
                    customBillerInfo_translate = self.env['ir.translation'].sudo().create({
                        'type': 'model',
                        'name': 'product.supplierinfo,custom_biller_info',
                        'module': 'product',
                        'lang': 'ar_AA',
                        'res_id': supplier_info.id,
                        'source': values.get('custom_biller_info'),
                        'value': values.get('custom_biller_info'),
                        'state': 'translated',
                    })
                else:
                    customBillerInfo_translate.sudo().write({"value": values.get('custom_biller_info')})
                self.env.cr.commit()
                supplier_info.translate_biller_info()

        return super(ProductSupplierInfo, self).write(values)
