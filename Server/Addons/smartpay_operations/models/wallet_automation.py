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
    wallet_type_id = fields.Many2one('website.wallet.type', string='Wallet Type', required=True)
    tag_ids = fields.Many2many('res.partner.category', column1='partner_id',
                               column2='wallet_id', string='Tags')
    wallet_balance = fields.Float('Wallet Balance', default=1.0, required=True)
    condition_operator = fields.Selection([('equal', 'Equal'), ('gt', 'Greater Than'), ('lt', 'Less Than')],
                                          'Balance Operator',
                                          default='equal', required=True)
    wallet_status = fields.Selection([('active', 'Active'), ('inactive', 'Inactive')], 'Wallet Status',
                                     default='active', required=True)
    action_taken = fields.Selection([('inactive_w', 'Deactivate Wallet'), ('activate_w', 'Activate Wallet'),
                                     ('inactivate_c', 'Deactivate Customer'), ('activate_u', 'Activate User')],
                                    string='Action To Be Taken', default='active', required=True)

    def automate_wallet(self, action_name=None):
        if action_name:
            wallet_automation = self.env['wallet.automation'].search(
                [('name', 'ilike', action_name)], limit=1)
            if wallet_automation:
                if wallet_automation.tag_ids:
                    customers = self.env['res.partner'].search([
                        ('category_id', 'in', wallet_automation.tag_ids.ids)])
                    wallet_status = wallet_automation.wallet_status == 'active'
                    for rec in customers:
                        wallets = rec.wallet_ids.filtered(
                            lambda x: x.type == wallet_automation.wallet_type_id.name and
                                      x.active == wallet_status
                        )
                        wallet = wallets and wallets[0]
                        if not wallet:
                            continue
                        # if wallet_automation.action_taken in ['inactive_w', 'activate_w']:
                        if (wallet_automation.condition_operator == 'gt'
                                and
                                not (wallet.balance_amount > wallet_automation.wallet_balance)):
                            continue
                        if (wallet_automation.condition_operator == 'lt'
                                and
                                not (wallet.balance_amount < wallet_automation.wallet_balance)):
                            continue
                        if wallet.balance_amount != wallet_automation.wallet_balance:
                            continue

                        if wallet_automation.action_taken == 'inactive_w':
                            wallet.active = False
                        elif wallet_automation.action_taken == 'activate_w':
                            wallet.active = True
                        elif wallet_automation.action_taken == 'activate_u':
                            rec.user_ids.write({'active': True})
                        elif wallet_automation.action_taken == 'inactivate_c':
                            rec.write({'active': False})
                return
