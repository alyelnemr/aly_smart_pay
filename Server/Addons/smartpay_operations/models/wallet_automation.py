# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

import logging

from odoo import fields, models, api, _

_logger = logging.getLogger(__name__)


class AutomateSalesWallet(models.Model):
    _name = 'wallet.automation'
    _description = 'Automate Sales Wallet'

    name = fields.Char('Action Name', required=True)
    wallet_type_id = fields.Many2one('website.wallet.type', string='Wallet Type')
    tag_ids = fields.Many2many('res.partner.category', column1='partner_id', column2='wallet_id', string='Tags')
    wallet_balance = fields.Float('Wallet Balance', default=1.0, required=True)
    condition_operator = fields.Selection([('equal', 'Equal'), ('gt', 'Greater Than'), ('lt', 'Less Than')],
                                          string='Balance Operator', default='equal', required=True)
    wallet_status = fields.Selection([('active', 'Active'), ('inactive', 'Inactive')], 'Wallet Status',
                                     default='active', required=True)
    action_taken = fields.Selection([('inactive_w', 'Deactivate Wallet'), ('activate_w', 'Activate Wallet'),
                                     ('inactivate_c', 'Deactivate Customer'), ('activate_u', 'Activate User')],
                                    string='Action To Be Taken', default='active', required=True)
