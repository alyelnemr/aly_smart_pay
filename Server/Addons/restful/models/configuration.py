# -*- coding: utf-8 -*-
from odoo import fields, models

class RestfulSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    access_token_expires_in = fields.Integer(string='Seconds to expire token',
                                              config_parameter='restful.access_token_expires_in', default=31536000)