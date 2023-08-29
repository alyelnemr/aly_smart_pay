# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

from odoo import fields, models


class PaymentRanges(models.Model):
    _name = 'payment.ranges'
    _description = 'Payment Ranges'
    lower = fields.One2many('fixed.amount', 'amount')
    upper = fields.One2many('fixed.amount', 'amount')
    description = fields.Char(string='Description')
