# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

from odoo import api, models, _
from odoo.tools import misc, float_is_zero
from odoo.tools.misc import formatLang

class AccountReconcileModel(models.Model):
    _inherit = 'account.reconcile.model'

    @api.multi
    def _prepare_reconciliation(self, st_line, move_lines=None, partner=None):
        reconciliation_results = super(AccountReconcileModel, self)._prepare_reconciliation(st_line, move_lines, partner=partner)
        if partner:
            provider = self.env['payment.acquirer'].sudo().search([("related_partner", "=", partner.id)])
            open_balance_dict = reconciliation_results['open_balance_dict']
            if open_balance_dict and provider:
                irc_param = self.env['ir.config_parameter'].sudo()
                commission_difference_account_id = irc_param.get_param("tm_base_gateway.commission_difference_account")
                # commission_difference_account = self.env['account.account'].sudo().browse(int(commission_difference_account_id)).exists()
                if commission_difference_account_id:
                    open_balance_dict.update({'name': '%s : %s' % (st_line.name, _('Commission Difference')), 'account_id': int(commission_difference_account_id)})
                    reconciliation_results.update({'open_balance_dict': open_balance_dict})
        return reconciliation_results

    @api.multi
    def _apply_rules(self, st_lines, excluded_ids=None, partner_map=None):
        ''' Apply criteria to get candidates for all reconciliation models.
        :param st_lines:        Account.bank.statement.lines recordset.
        :param excluded_ids:    Account.move.lines to exclude.
        :param partner_map:     Dict mapping each line with new partner eventually.
        :return:                A dict mapping each statement line id with:
            * aml_ids:      A list of account.move.line ids.
            * model:        An account.reconcile.model record (optional).
            * status:       'reconciled' if the lines has been already reconciled, 'write_off' if the write-off must be
                            applied on the statement line.
        '''
        available_models = self.filtered(lambda m: m.rule_type != 'writeoff_button')

        results = dict((r.id, {'aml_ids': []}) for r in st_lines)

        if not available_models:
            return results

        ordered_models = available_models.sorted(key=lambda m: (m.sequence, m.id))

        grouped_candidates = {}

        # Type == 'invoice_matching'.
        # Map each (st_line.id, model_id) with matching amls.
        invoices_models = ordered_models.filtered(lambda m: m.rule_type == 'invoice_matching')
        if invoices_models:
            query, params = invoices_models._get_invoice_matching_query(st_lines, excluded_ids=excluded_ids,
                                                                        partner_map=partner_map)
            self._cr.execute(query, params)
            query_res = self._cr.dictfetchall()

            for res in query_res:
                grouped_candidates.setdefault(res['id'], {})
                grouped_candidates[res['id']].setdefault(res['model_id'], [])
                grouped_candidates[res['id']][res['model_id']].append(res)

        # Type == 'writeoff_suggestion'.
        # Map each (st_line.id, model_id) with a flag indicating the st_line matches the criteria.
        write_off_models = ordered_models.filtered(lambda m: m.rule_type == 'writeoff_suggestion')
        if write_off_models:
            query, params = write_off_models._get_writeoff_suggestion_query(st_lines, excluded_ids=excluded_ids,
                                                                            partner_map=partner_map)
            self._cr.execute(query, params)
            query_res = self._cr.dictfetchall()

            for res in query_res:
                grouped_candidates.setdefault(res['id'], {})
                grouped_candidates[res['id']].setdefault(res['model_id'], True)

        # Keep track of already processed amls.
        amls_ids_to_exclude = set()

        # Keep track of already reconciled amls.
        reconciled_amls_ids = set()

        # Iterate all and create results.
        for line in st_lines:
            line_currency = line.currency_id or line.journal_id.currency_id or line.company_id.currency_id
            line_residual = line.currency_id and line.amount_currency or line.amount

            # Search for applicable rule.
            # /!\ BREAK are very important here to avoid applying multiple rules on the same line.
            for model in ordered_models:
                # No result found.
                if not grouped_candidates.get(line.id) or not grouped_candidates[line.id].get(model.id):
                    continue

                excluded_lines_found = False

                if model.rule_type == 'invoice_matching':
                    candidates = grouped_candidates[line.id][model.id]

                    # If some invoices match on the communication, suggest them.
                    # Otherwise, suggest all invoices having the same partner.
                    # N.B: The only way to match a line without a partner is through the communication.
                    first_batch_candidates = []
                    second_batch_candidates = []
                    partner = partner_map and partner_map.get(line.id) and self.env['res.partner'].browse(
                        partner_map[line.id])
                    provider = self.env['payment.acquirer'].sudo().search([("related_partner", "=", partner.id)])
                    for c in candidates:
                        # Don't take into account already reconciled lines.
                        if c['aml_id'] in reconciled_amls_ids:
                            continue

                        # Dispatch candidates between lines matching invoices with the communication or only the partner.
                        if c['communication_flag']:
                            first_batch_candidates.append(c)
                        elif not first_batch_candidates and not provider:
                            second_batch_candidates.append(c)
                    available_candidates = first_batch_candidates or second_batch_candidates

                    # Special case: the amount are the same, submit the line directly.
                    for c in available_candidates:
                        residual_amount = c['aml_currency_id'] and c['aml_amount_residual_currency'] or c[
                            'aml_amount_residual']

                        if float_is_zero(residual_amount - line_residual, precision_rounding=line_currency.rounding):
                            available_candidates = [c]
                            break

                    # Needed to handle check on total residual amounts.
                    if first_batch_candidates or model._check_rule_propositions(line, available_candidates):
                        results[line.id]['model'] = model

                        # Add candidates to the result.
                        for candidate in available_candidates:

                            # Special case: the propositions match the rule but some of them are already consumed by
                            # another one. Then, suggest the remaining propositions to the user but don't make any
                            # automatic reconciliation.
                            if candidate['aml_id'] in amls_ids_to_exclude:
                                excluded_lines_found = True
                                continue

                            results[line.id]['aml_ids'].append(candidate['aml_id'])
                            amls_ids_to_exclude.add(candidate['aml_id'])

                        if excluded_lines_found:
                            break

                        # Create write-off lines.
                        move_lines = self.env['account.move.line'].browse(results[line.id]['aml_ids'])
                        reconciliation_results = model._prepare_reconciliation(line, move_lines, partner=partner)

                        # A write-off must be applied.
                        if reconciliation_results['new_aml_dicts']:
                            results[line.id]['status'] = 'write_off'

                        # Process auto-reconciliation.
                        if model.auto_reconcile:
                            # An open balance is needed but no partner has been found or provider found.
                            if reconciliation_results['open_balance_dict'] is False or (provider and reconciliation_results['open_balance_dict']):
                                break

                            new_aml_dicts = reconciliation_results['new_aml_dicts']
                            if reconciliation_results['open_balance_dict']:
                                new_aml_dicts.append(reconciliation_results['open_balance_dict'])
                            if not line.partner_id and partner:
                                line.partner_id = partner
                            counterpart_moves = line.process_reconciliation(
                                counterpart_aml_dicts=reconciliation_results['counterpart_aml_dicts'],
                                payment_aml_rec=reconciliation_results['payment_aml_rec'],
                                new_aml_dicts=new_aml_dicts,
                            )
                            results[line.id]['status'] = 'reconciled'
                            results[line.id]['reconciled_lines'] = counterpart_moves.mapped('line_ids')

                            # The reconciled move lines are no longer candidates for another rule.
                            reconciled_amls_ids.update(move_lines.ids)

                        # Break models loop.
                        break

                elif model.rule_type == 'writeoff_suggestion' and grouped_candidates[line.id][model.id]:
                    results[line.id]['model'] = model
                    results[line.id]['status'] = 'write_off'

                    # Create write-off lines.
                    partner = partner_map and partner_map.get(line.id) and self.env['res.partner'].browse(
                        partner_map[line.id])
                    reconciliation_results = model._prepare_reconciliation(line, partner=partner)

                    # An open balance is needed but no partner has been found.
                    if reconciliation_results['open_balance_dict'] is False:
                        break

                    # Process auto-reconciliation.
                    if model.auto_reconcile:
                        new_aml_dicts = reconciliation_results['new_aml_dicts']
                        if reconciliation_results['open_balance_dict']:
                            new_aml_dicts.append(reconciliation_results['open_balance_dict'])
                        if not line.partner_id and partner:
                            line.partner_id = partner
                        counterpart_moves = line.process_reconciliation(
                            counterpart_aml_dicts=reconciliation_results['counterpart_aml_dicts'],
                            payment_aml_rec=reconciliation_results['payment_aml_rec'],
                            new_aml_dicts=new_aml_dicts,
                        )
                        results[line.id]['status'] = 'reconciled'
                        results[line.id]['reconciled_lines'] = counterpart_moves.mapped('line_ids')

                    # Break models loop.
                    break
        return results

class AccountReconciliation(models.AbstractModel):
    _inherit = 'account.reconciliation.widget'

    @api.model
    def _get_statement_line(self, st_line):
        """ Returns the data required by the bank statement reconciliation widget to display a statement line """

        statement_currency = st_line.journal_id.currency_id or st_line.journal_id.company_id.currency_id
        if st_line.amount_currency and st_line.currency_id:
            amount = st_line.amount_currency
            amount_currency = st_line.amount
            amount_currency_str = formatLang(self.env, abs(amount_currency), currency_obj=statement_currency)
        else:
            amount = st_line.amount
            amount_currency = amount
            amount_currency_str = ""
        amount_str = formatLang(self.env, abs(amount), currency_obj=st_line.currency_id or statement_currency)
        date = misc.format_date(self.env, st_line.date, lang_code=self.env.user.lang)

        data = {
            'id': st_line.id,
            'ref': st_line.ref,
            'note': st_line.note or "",
            'name': st_line.name,
            'date': date,
            'amount': amount,
            'amount_str': amount_str,  # Amount in the statement line currency
            'currency_id': st_line.currency_id.id or statement_currency.id,
            'partner_id': st_line.partner_id.id,
            'journal_id': st_line.journal_id.id,
            'statement_id': st_line.statement_id.id,
            'account_id': [st_line.journal_id.default_debit_account_id.id,
                           st_line.journal_id.default_debit_account_id.display_name],
            'account_code': st_line.journal_id.default_debit_account_id.code,
            'account_name': st_line.journal_id.default_debit_account_id.name,
            'partner_name': st_line.partner_id.name,
            'communication_partner_name': st_line.partner_name,
            'amount_currency_str': amount_currency_str,  # Amount in the statement currency
            'amount_currency': amount_currency,  # Amount in the statement currency
            'has_no_partner': not st_line.partner_id.id,
            'company_id': st_line.company_id.id,
        }
        if st_line.partner_id:
            provider = self.env['payment.acquirer'].sudo().search([("related_partner", "=", st_line.partner_id.id)])
            if provider:
                irc_param = self.env['ir.config_parameter'].sudo()
                commission_difference_account_id = irc_param.get_param("tm_base_gateway.commission_difference_account")
                # commission_difference_account = self.env['account.account'].sudo().browse(int(commission_difference_account_id)).exists()
            if provider and commission_difference_account_id:
                data['open_balance_account_id'] = int(commission_difference_account_id)
            else:
                if amount > 0:
                    data['open_balance_account_id'] = st_line.partner_id.property_account_receivable_id.id
                else:
                    data['open_balance_account_id'] = st_line.partner_id.property_account_payable_id.id

        return data