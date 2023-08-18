# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

from odoo import fields, models


class AccountPayment(models.Model):
    _inherit = 'account.payment'

    request_id = fields.Many2one(
        comodel_name='smartpay_operations.request',
        string='Request', index=True,
        readonly=True, states={'draft': [('readonly', False)]}, copy=False,
    )
