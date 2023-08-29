# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

from odoo import fields, models, api


class EnumValues(models.Model):
    _name = 'enum.values'
    _description = 'Enum Values for Bill Type Ref Keys'

    name = fields.Char('Alias', required=True)
    enum_value = fields.Char('Value')
    parent_value = fields.Char('Parent Value')
    amount = fields.Float('Amount')
    bill_type_ref_key_id = fields.Many2one('bill.type.ref.key', string='Bill Type Extra Ref Key')

    @api.multi
    def name_get(self):
        result = []
        for rec in self:
            rec_name = rec.name + ' (' + rec.enum_value + ')'
            result.append((rec.id, rec_name))
        return result
