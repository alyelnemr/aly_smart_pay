# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

from odoo import fields, models, api


class PmtType(models.Model):
    _name = 'pmt.type'
    _description = 'Payment Type post-paid, pre-paid or voucher or other'

    name = fields.Char('Name', required=True)
    description = fields.Char('Description')

    @api.multi
    def name_get(self):
        result = []
        for rec in self:
            rec_name = rec.name + ' (' + rec.description + ')'
            result.append((rec.id, rec_name))
        return result
