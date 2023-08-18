# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

from odoo import api, fields, models

class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    group_manage_vendor_commission = fields.Boolean("Vendor Commissions",
        implied_group="tm_base_gateway.group_manage_vendor_commission")

    commission_difference_account = fields.Many2one('account.account', string="Vendor Commission Difference Account",
                                                    config_parameter="tm_base_gateway.commission_difference_account")
