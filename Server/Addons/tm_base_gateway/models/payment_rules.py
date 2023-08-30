# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

import json

from odoo.addons import decimal_precision as dp
from odoo.addons.restful.common import default

from odoo import api, fields, models, _
from odoo.exceptions import RedirectWarning


class PaymentRules(models.Model):
    _name = 'payment.rules'
    _description = 'Payment Rules'

    name = fields.Char('Title', required=True)
    product_id = fields.Many2one('product.template', string='Product')
    is_inq_rqr = fields.Boolean(string='Is Inquiry Rerquired')
    is_mob_ntfy = fields.Boolean(string='Is Mobile Notify')
    is_frac_accept = fields.Boolean(string='Is Fraction Accept')
    is_prt_accept = fields.Boolean(string='Is Print Accept')
    is_ovr_accept = fields.Boolean(string='Is Over payment Accept')
    is_adv_accept = fields.Boolean(string='Is Advance payment Accept')
    is_accept_card_pmt = fields.Boolean(string='Is Accept Card Payment')
