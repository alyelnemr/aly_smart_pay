# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

import json

from odoo import api, fields, models


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
