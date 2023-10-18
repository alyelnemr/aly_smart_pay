# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

from odoo import api, fields, models

class AccountJournal(models.Model):
    _inherit = 'account.journal'

    provider_id = fields.Many2one('payment.acquirer', 'Provider', domain=[('sevice_provider', '=', True)])