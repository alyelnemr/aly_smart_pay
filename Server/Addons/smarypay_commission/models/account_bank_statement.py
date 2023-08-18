# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

from odoo import api, models, _
from odoo.exceptions import UserError

import time


class AccountBankStatement(models.Model):
    _inherit = 'account.bank.statement'

    @api.multi
    def button_confirm_bank(self):
        """ Tamayoz: Override button_confirm_bank in tm_base_gateway add-on with the original button_confirm_bank in account add-on. """
        self._balance_check()
        statements = self.filtered(lambda r: r.state == 'open')
        for statement in statements:
            moves = self.env['account.move']
            # `line.journal_entry_ids` gets invalidated from the cache during the loop
            # because new move lines are being created at each iteration.
            # The below dict is to prevent the ORM to permanently refetch `line.journal_entry_ids`
            line_journal_entries = {line: line.journal_entry_ids for line in statement.line_ids}
            for st_line in statement.line_ids:
                # upon bank statement confirmation, look if some lines have the account_id set. It would trigger a journal entry
                # creation towards that account, with the wanted side-effect to skip that line in the bank reconciliation widget.
                journal_entries = line_journal_entries[st_line]
                st_line.fast_counterpart_creation()
                if not st_line.account_id and not journal_entries.ids and not st_line.statement_id.currency_id.is_zero(
                        st_line.amount):
                    raise UserError(
                        _('All the account entries lines must be processed in order to close the statement.'))
            moves = statement.mapped('line_ids.journal_entry_ids.move_id')
            if moves:
                moves = moves.filtered(lambda m: m.state != 'posted')
                if len(moves) > 0:
                    moves.post()
            statement.message_post(body=_('Statement %s confirmed, journal items were created.') % (statement.name,))
        statements.write({'state': 'confirm', 'date_done': time.strftime("%Y-%m-%d %H:%M:%S")})