# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

from odoo import fields, models, api


class AccountInputMethod(models.Model):
    _name = 'account.input.method'
    _description = 'Account Input Method keypad, card reader, etc'

    name = fields.Char('Name')
    description = fields.Char('Description')

    @api.multi
    def name_get(self):
        result = []
        for rec in self:
            rec_name = rec.name + ' (' + rec.description + ')'
            result.append((rec.id, rec_name))
        return result
