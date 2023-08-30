# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

from odoo import fields, models


class PaymentRanges(models.Model):
    _name = 'payment.ranges'
    _description = 'Payment Ranges'

    name = fields.Char('Title', required=True)
    lower_fixed_amount_id = fields.Many2one('fixed.amount', 'Lower Amount')
    upper_fixed_amount_id = fields.Many2one('fixed.amount', 'Upper Amount')
    description = fields.Char(string='Description')
    product_id = fields.Many2one('product.template', string='Product')
