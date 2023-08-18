# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

import json

from odoo.addons import decimal_precision as dp
from odoo.addons.restful.common import default

from odoo import api, fields, models, _
from odoo.exceptions import RedirectWarning


class ProductTemplateMapping(models.Model):
    _name = 'product.template.mapping'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _description = "Product Template Mapping"
    _order = "name"

    def _get_default_category_id(self):
        if self._context.get('categ_id') or self._context.get('default_categ_id'):
            return self._context.get('categ_id') or self._context.get('default_categ_id')
        category = self.env.ref('tm_base_gateway.product_category_mapping_all', raise_if_not_found=False)
        if not category:
            category = self.env['product.category.mapping'].search([], limit=1)
        if category:
            return category.id
        else:
            err_msg = _('You must define at least one product category in order to be able to create products.')
            redir_msg = _('Go to Internal Categories')
            raise RedirectWarning(err_msg, self.env.ref('tm_base_gateway.product_category_mapping_action_form').id,
                                  redir_msg)

    def _get_default_uom_id(self):
        return self.env["uom.uom"].search([], limit=1, order='id').id

    name = fields.Char('Name', index=True, required=True, translate=True)
    type = fields.Selection([
        ('consu', 'Consumable'),
        ('service', 'Service')], string='Product Type', default='consu', required=True,
        help='A storable product is a product for which you manage stock. The Inventory app has to be installed.\n'
             'A consumable product is a product for which stock is not managed.\n'
             'A service is a non-material product you provide.')
    categ_id = fields.Many2one(
        'product.category.mapping', 'Product Category',
        change_default=True, default=_get_default_category_id,
        required=True, help="Select category for the current product")

    seller_ids = fields.One2many('product.supplierinfo.mapping', 'product_tmpl_id', 'Vendors',
                                 help="Define vendor pricelists.")
    taxes_id = fields.Many2many('account.tax', 'product_taxes_rel', 'prod_id', 'tax_id',
                                help="Default taxes used when selling the product.", string='Customer Taxes',
                                domain=[('type_tax_use', '=', 'sale')],
                                default=lambda self: self.env.user.company_id.account_sale_tax_id)
    supplier_taxes_id = fields.Many2many('account.tax', 'product_supplier_taxes_rel', 'prod_id', 'tax_id',
                                         string='Vendor Taxes', help='Default taxes used when buying the product.',
                                         domain=[('type_tax_use', '=', 'purchase')],
                                         default=lambda self: self.env.user.company_id.account_purchase_tax_id)
    sale_ok = fields.Boolean('Can be Sold', default=True)
    purchase_ok = fields.Boolean('Can be Purchased', default=True)
    invoice_policy = fields.Selection([
        ('order', 'Ordered quantities'),
        ('delivery', 'Delivered quantities')], string='Invoicing Policy',
        help='Ordered Quantity: Invoice quantities ordered by the customer.\n'
             'Delivered Quantity: Invoice quantities delivered to the customer.',
        default='order')
    # list_price: catalog price, user defined
    list_price = fields.Float(
        'Sales Price', default=1.0,
        digits=dp.get_precision('Product Price'),
        help="Price at which the product is sold to customers.")
    # lst_price: catalog price for template, but including extra for variants
    lst_price = fields.Float(
        'Public Price', related='list_price', readonly=False,
        digits=dp.get_precision('Product Price'))
    currency_id = fields.Many2one(
        'res.currency', 'Currency', compute='_compute_currency_id')
    uom_id = fields.Many2one(
        'uom.uom', 'Unit of Measure',
        default=_get_default_uom_id, required=True,
        help="Default unit of measure used for all stock operations.")
    uom_name = fields.Char(string='Unit of Measure Name', related='uom_id.name', readonly=True)
    uom_po_id = fields.Many2one(
        'uom.uom', 'Purchase Unit of Measure',
        default=_get_default_uom_id, required=True,
        help="Default unit of measure used for purchase orders. It must be in the same category as the default unit of measure.")

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

    active = fields.Boolean('Active', default=True,
                            help="If unchecked, it will allow you to hide the product without removing it.")
    company_id = fields.Many2one(
        'res.company', 'Company',
        default=lambda self: self.env.user.company_id.id, index=1)

    @api.multi
    def _compute_currency_id(self):
        main_company = self.env['res.company']._get_main_company()
        for template in self:
            template.currency_id = template.company_id.sudo().currency_id.id or main_company.currency_id.id


class ProductProductMapping(models.Model):
    _name = 'product.product.mapping'
    _description = "Product Mapping"
    _inherits = {'product.template.mapping': 'product_tmpl_id'}
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'name, id'

    product_tmpl_id = fields.Many2one(
        'product.template.mapping', 'Product Template',
        auto_join=True, index=True, ondelete="cascade", required=True)

    # image: all image fields are base64 encoded and PIL-supported
    image_variant = fields.Binary(
        "Variant Image", attachment=True,
        help="This field holds the image used as image for the product variant, limited to 1024x1024px.")
    image = fields.Binary(
        "Big-sized image", compute='_compute_images', inverse='_set_image',
        help="Image of the product variant (Big-sized image of product template if false). It is automatically "
             "resized as a 1024x1024px image, with aspect ratio preserved.")
    image_small = fields.Binary(
        "Small-sized image", compute='_compute_images', inverse='_set_image_small',
        help="Image of the product variant (Small-sized image of product template if false).")
    image_medium = fields.Binary(
        "Medium-sized image", compute='_compute_images', inverse='_set_image_medium',
        help="Image of the product variant (Medium-sized image of product template if false).")

    active = fields.Boolean(
        'Active', default=True,
        help="If unchecked, it will allow you to hide the product without removing it.")
    company_id = fields.Many2one(
        'res.company', 'Company',
        default=lambda self: self.env.user.company_id.id, index=1)


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


class ProductSupplierInfoCommession(models.Model):
    _name = 'product.supplierinfo.commission'
    _description = "Supplier Commission"
    _order = 'vendor_product_code, Amount_Range_From, Amount_Range_To'

    product_supplierinfo_id = fields.Many2one('product.supplierinfo', 'Product Supplier Info', index=True,
                                              ondelete='cascade')
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
    date_start = fields.Date('Start Date', help="Start date for this vendor commission")
    date_end = fields.Date('End Date', help="End date for this vendor commission")
    Amount_Range_From = fields.Float('Amount Range From', required=True)
    Amount_Range_To = fields.Float('Amount Range To', required=True)
    Mer_Comm_Full_Fix_Amt = fields.Float('Merchant Cashback Amt', help='Merchant Commession Full Fix Amt',
                                         track_visibility="onchange")
    Cust_Comm_Full_Fix_Amt = fields.Float('Customer Cashback Amt', help='Customer Commession Full Fix Amt',
                                          compute='_compute_amount_all', readonly=True)
    Comp_Comm_Full_Fix_Amt = fields.Float('SmartPay Cashback Amt', help='SmartPay Commession Full Fix Amt')
    Mer_Comm_Partial_Fix_Amt = fields.Float('Partial Fix Amt', help='Merchant Commession Partial Fix Amt')
    Bill_Merchant_Comm_Prc = fields.Float('Merchant Cashback Prc', help='Bill Merchant Commession Prc',
                                          track_visibility="onchange")
    Bill_Customer_Comm_Prc = fields.Float('Customer Cashback Prc', help='Bill Customer Commession Prc',
                                          compute='_compute_amount_all', readonly=True)
    Bill_Company_Comm_Prc = fields.Float('SmartPay Cashback Prc', help='Bill SmartPay Commession Prc')
    Mer_Fee_Amt = fields.Float('Provider Fee Amt', help='Provider Fee Amt', compute='_compute_merchant_fee',
                               readonly=True, store=True)
    Mer_Fee_Prc = fields.Float('Provider Fee Prc', help='Provider Fee Prc', compute='_compute_merchant_fee',
                               readonly=True, store=True)
    Mer_Fee_Prc_MinAmt = fields.Float('Provider Fee Prc Min Amt', help='Min allowed calculated fees amount',
                                      compute='_compute_merchant_fee', readonly=True, store=True)
    Mer_Fee_Prc_MaxAmt = fields.Float('Provider Fee Prc Max Amt', help='Max allowed calculated fees amount',
                                      compute='_compute_merchant_fee', readonly=True, store=True)
    Extra_Fee_Amt = fields.Float('SmartPay Extra Fees Amt', help='SmartPay Extra Fee Amt')
    Extra_Fee_Prc = fields.Float('SmartPay Extra Fees Prc', help='SmartPay Extra Fee Prc')
    Comp_Total_Comm_Amt = fields.Float('SmartPay Total Cashback Amt', help='SmartPay Total Cashback Amt',
                                       compute='_compute_amount_all', readonly=True)
    Comp_Total_Comm_Prc = fields.Float('SmartPay Total Cashback Prc', help='SmartPay Total Cashback Prc',
                                       compute='_compute_amount_all', readonly=True)
    Mer_Comm_Var_Cust_Fee = fields.Float('Var Cust Fee', help='Merchant Commession Var Cust Fee')
    Mer_Comm_Var_Biller_Fee = fields.Float('Var Biller Fee', help='Merchant Commession Var Biller Fee')
    Mer_Comm_Trx_Limit_Min = fields.Float('Trx Limit Min', help='Merchant Commession Trx Limit Min')
    Mer_Comm_Trx_Limit_Max = fields.Float('Trx Limit Max', help='Merchant Commession Trx Limit Max')
    Mer_Comm_Daily_Limit = fields.Float('Daily Limit', help='Merchant Commession Daily Limit')

    company_id = fields.Many2one(
        'res.company', 'Company',
        default=lambda self: self.env.user.company_id.id, index=1)

    @api.multi
    @api.depends('Mer_Comm_Full_Fix_Amt', 'Comp_Comm_Full_Fix_Amt', 'Extra_Fee_Amt', 'Bill_Merchant_Comm_Prc',
                 'Bill_Company_Comm_Prc', 'Extra_Fee_Prc')
    def _compute_amount_all(self):
        for commission in self:
            commission.update({
                'Cust_Comm_Full_Fix_Amt': commission.Mer_Comm_Full_Fix_Amt - commission.Comp_Comm_Full_Fix_Amt,
                'Comp_Total_Comm_Amt': commission.Comp_Comm_Full_Fix_Amt + commission.Extra_Fee_Amt,
                'Bill_Customer_Comm_Prc': commission.Bill_Merchant_Comm_Prc - commission.Bill_Company_Comm_Prc,
                'Comp_Total_Comm_Prc': commission.Bill_Company_Comm_Prc + commission.Extra_Fee_Prc,
            })

    @api.multi
    def _compute_merchant_fee(self):
        for commission in self:
            Mer_Fee_Amt = 0.0
            Mer_Fee_Prc = 0.0
            Mer_Fee_Prc_MinAmt = 0.0
            Mer_Fee_Prc_MaxAmt = 0.0
            biller_info = json.loads(commission.product_supplierinfo_id.biller_info, strict=False)
            provider = self.env['payment.acquirer'].sudo().search(
                [("related_partner", "=", commission.product_supplierinfo_id.name.id)])
            if provider:
                if provider.provider == "fawry":
                    if biller_info.get('Fees'):
                        for fee in biller_info.get('Fees'):
                            for tier in fee.get('Tier'):
                                LowerAmt = tier.get('LowerAmt')
                                UpperAmt = tier.get('UpperAmt')
                                if tier.get('FixedAmt'):
                                    Mer_Fee_Amt = tier.get('FixedAmt').get('Amt')
                                    # Tamayoz TODO: Multi Currency
                                    FixedAmtCurCode = tier.get('FixedAmt').get('CurCode')
                                if tier.get('Percent'):
                                    Mer_Fee_Prc = tier.get('Percent').get('Value')
                                    if tier.get('Percent').get('MinAmt'):
                                        Mer_Fee_Prc_MinAmt = tier.get('Percent').get('MinAmt')
                                    if tier.get('Percent').get('MaxAmt'):
                                        Mer_Fee_Prc_MaxAmt = tier.get('Percent').get('MaxAmt')
                                if LowerAmt == commission.Amount_Range_From and UpperAmt == commission.Amount_Range_To:
                                    break

                        commission.Mer_Fee_Amt = Mer_Fee_Amt
                        commission.Mer_Fee_Prc = Mer_Fee_Prc
                        commission.Mer_Fee_Prc_MinAmt = Mer_Fee_Prc_MinAmt
                        commission.Mer_Fee_Prc_MaxAmt = Mer_Fee_Prc_MaxAmt



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
                           domain=lambda self: [('model', '=', 'product.template'), ('name', 'in', self.MAPPING_FIELDS)]) # tm_sps_ abbrevation of Tamayoz Standard Provider Service


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
            record.mapping_biller_info = record.provider_biller_info # Tamayoz TODO: Must be mapping provider_biller_info in standard api
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
            self.biller_info = json.dumps({**mapping_biller_info, **custom_biller_info}, ensure_ascii=False, default=default)
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
        billerInfo_translate_value = json.dumps({**mapping_biller_info, **custom_biller_info}, ensure_ascii=False, default=default)

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
                mapping_biller_info = json.loads(supplier_info.mapping_biller_info or supplier_info.biller_info or '{}', strict=False)
                custom_biller_info = json.loads(values.get('custom_biller_info') or '{}', strict=False)
                values.update({'biller_info': json.dumps({**mapping_biller_info, **custom_biller_info}, ensure_ascii=False,
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
    product_tmpl_id = fields.Many2one('product.template', 'Product Template', related='product_sale_limit_id.product_tmpl_id')

    company_id = fields.Many2one(
        'res.company', 'Company',
        default=lambda self: self.env.user.company_id.id, index=1)
    currency_id = fields.Many2one(
        'res.currency', 'Currency',
        default=lambda self: self.env.user.company_id.currency_id.id,
        required=True)


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
    over_limit_fees_ids = fields.One2many('product.sale.limit.fees', 'product_sale_limit_id', 'Sale Over Limit Fees', help="Define sale over limit fees.")

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


class ProductTemplate(models.Model):
    _inherit = 'product.template'

    has_sale_limit = fields.Boolean('Has Sale Limit')
    sale_limit_ids = fields.One2many('product.sale.limit', 'product_tmpl_id', 'Sale limits', help="Define sale limits.")
    variant_sale_limit_ids = fields.One2many('product.sale.limit', 'product_tmpl_id')

    # Standard Service Fields
    # ['BillTypeCode', '', '', '', '', '', '', '', '', '',
    # '', '', '', '', '', '', '', '', '', '',
    # '', '', '', '', '', '', '', '', '', '',
    # '', '', '', '', '', '', '', '', '', '',
    # '', '', '', '', '', '', '', '', '']
    bill_type_code = fields.Char(string='Bill Type Code')
    is_hidden = fields.Boolean(string='Hidden')
    bill_ref_type = fields.Boolean(string='Bill Ref Type')
    pmt_type = fields.Selection([('post', 'POST'), ('prep', 'PREP'), ('voch', 'VOCH')], string='PMT Type')
    service_type = fields.Selection(
        [('cip', 'CIP'), ('elc', 'ELC'), ('phn', 'PHN'), ('ins', 'INS'), ('bks', 'BKS'), ('gov', 'GOV'), ('med', 'MED'),
         ('ccr', 'CCR'), ('utl', 'UTL'), ('exm', 'EXM'), ('trv', 'TRV')], string='Service Type', default='phn')
    # service_name = fields.Char(string='Service Name')
    bill_type_acctlabel = fields.Char(string='Bill Type Label')
    acct_input_method = fields.Selection(
        [('kp', 'KP'), ('cr', 'CR'), ('kc', 'KC'), ('sc', 'SC'), ('ni', 'NI'), ('sk', 'SK')],
        string='Acct Input Method')
    allow_timeout_receipt = fields.Boolean(string='Allow Timeout Receipt')
    bill_type_extra_ref_keys = fields.One2many('bill.type.ref.key', 'name')
    receipt_header = fields.Text(string='Receipt Header')
    receipt_footer = fields.Text(string='Receipt Footer')
    ## payment_rules = fields.Selection([('isinqrqr', 'IsInqRqr')],string='Payment Rules')
    payment_rules = fields.One2many('payment.rules', 'is_inq_rqr')
    Fees = fields.One2many('fees', 'tier')
    tax = fields.Float(string='Tax')
    payment_ranges = fields.One2many('payment.ranges', 'lower')
    allow_rct_re_print = fields.Boolean(string='Allow Receipt Reprint')
    bill_type_status = fields.Selection(
        [('available', 'Available'), ('availpend', 'AvailPend'), ('deleted', 'Deleted'), ('delpend', 'DelPend')],
        default='available', string='Bill Type Status')
    bill_type_nature = fields.Selection([('cashout_inq', 'CASHOUT_INQ'), ('cashout_corr', 'CASHOUT_CORR')],
                                        string='PMT Type')
    corr_bill_type_code = fields.Char(string='Corr Bill Type Code')
    otp_enabled = fields.Boolean(string='OTP Enabled')
    opt_required = fields.Boolean(string='OTP Required')
    support_pmt_reverse = fields.Boolean(string='Support PMT Reverse')
    timeout = fields.Selection([('', '')], string='Timeout')
    is_internal_cancel = fields.Boolean(string='Internal Cancel')
    has_correlation = fields.Boolean(string='Correlation')


class BillTypeExtraRefKeys(models.Model):
    _name = 'bill.type.ref.key'
    _description = 'Bill Type Extra Ref Keys'

    name = fields.Char('Label')
    Key = fields.Selection(
        [('key1', 'Key1'), ('key2', 'Key2'), ('key3', 'Key3'), ('key4', 'Key4'), ('key5', 'Key5'), ('key6', 'Key6'), ],
        string='Kye')
    is_print_keypart = fields.Boolean(string='Print Key Part')
    required = fields.Boolean(string='Required')
    is_cnfrm_required = fields.Boolean(string='Is Confirm Required')
    is_ba_keypart = fields.Boolean(string='Is BA KeyPart')


class PaymentRules(models.Model):
    _name = 'payment.rules'
    _description = 'Payment Rules'

    is_inq_rqr = fields.Boolean(string='IsInqRer')
    is_mob_ntfy = fields.Boolean(string='IsMobNtfy')
    is_frac_acpt = fields.Boolean(string='IsFracAcpt')
    is_prt_acpt = fields.Boolean(string='IsPrtAcpt')
    is_ovr_acpt = fields.Boolean(string='IsOvrAcpt')
    is_adv_acpt = fields.Boolean(string='IsAdvAcpt')
    is_acpt_card_pmt = fields.Boolean(string='IsAcptCardPmt')


class PaymentRanges(models.Model):
    _name = 'payment.ranges'
    _description = 'Payment Ranges'
    lower = fields.One2many('fixed.amount', 'amount')
    upper = fields.One2many('fixed.amount', 'amount')
    description = fields.Char(string='Description')


class FixedAmount(models.Model):
    _name = 'fixed.amount'
    _description = 'Fixed Amount'
    amount = fields.Float(string='Amount')
    cur_code = fields.Selection([('egp', 'EGP')], string='Cur Code')


class Fees(models.Model):
    _name = 'fees'
    _description = 'Fees'
    tier = fields.One2many('tier', 'lower_amt')
    is_embedded_fees = fields.Boolean(string='IsEmbeddedFees')


class Tier(models.Model):
    _name = 'tier'
    _description = 'Tier'
    lower_amt = fields.Float('LowerAmt')
    upper_amt = fields.Float('UpperAmt')
    fixed_amount = fields.One2many('fixed.amount', 'amount')
    percent = fields.One2many('percent', 'value')
    start_date = fields.Datetime()
    expiry_date = fields.Datetime()


class Percent(models.Model):
    _name = 'percent'
    _description = 'Percent'
    value = fields.Float('Value')
    min_amt = fields.Float('Min Amount')
    max_amt = fields.Float('Max Amount')


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


class PartnerSaleLimitFees(models.Model):
    _name = 'res.partner.sale.limit.fees'

    # partner_id = fields.Many2one('res.partner', 'Partner', readonly=True)
    # product_id = fields.Many2one('product.product', 'Product Variant', readonly=True)
    user_request_id = fields.Many2one('smartpay_operations.request', 'Request', readonly=True)
    limit_type = fields.Selection([('daily', 'Daily'), ('weekly', 'Weekly'), ('monthly', 'Monthly')], 'Limit Type',
                                  default='daily', readonly=True)
    fees_amount = fields.Float(
        'Fees Amount',
        digits=dp.get_precision('Product Price'),
        help="Over Limit Fees Amount at which the product is sold to partner.", readonly=True)

    wallet_transaction_id = fields.Many2one('website.wallet.transaction', 'Wallet Transaction', copy=False)

    refund_amount = fields.Float(
        'Fees Amount',
        digits=dp.get_precision('Product Price'),
        help="Over Limit Fees Amount at which the product is sold to partner.", readonly=True)

    refund_wallet_transaction_id = fields.Many2one('website.wallet.transaction', 'Wallet Transaction', copy=False)
