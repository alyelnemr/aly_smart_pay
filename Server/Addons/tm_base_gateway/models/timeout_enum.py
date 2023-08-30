# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

from odoo import fields, models, api


class TimeoutEnum(models.Model):
    _name = 'timeout.enum'
    _description = 'Timeout Open Enum'

    name = fields.Char('Timeout Title', required=True)
    description = fields.Char(string='Description')

    @api.multi
    def name_get(self):
        result = []
        for rec in self:
            rec_name = rec.name + ' (' + rec.description + ')'
            result.append((rec.id, rec_name))
        return result
