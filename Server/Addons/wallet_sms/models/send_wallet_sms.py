# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

from odoo import api, models, _

import logging
_logger = logging.getLogger("------ SEND WALLET SMS -------")

class SendWalletSMS(models.Model):
    _inherit = 'website.wallet.transaction'

    @api.multi
    def sms_send_wallet_transaction(self, wallet_notification_mode, sms_template_condition, mobile, userName, label, amount, phone_code):
        # wallet_notification_mode = self.env['ir.default'].sudo().get('smartpay.operations.settings', notification_mode)
        if wallet_notification_mode == 'sms':
            try:
                if not userName:
                    userObj = self.env["res.users"].sudo().search([("mobile", "=", mobile)], limit=1)
                    userName = userObj.name
                sms_template_objs = self.env["sms.template"].sudo().search(
                    [('condition', '=', sms_template_condition),('globally_access','=',False)])
                if mobile:
                    for sms_template_obj in sms_template_objs:
                        ctx = dict(sms_template_obj._context or {})
                        ctx['name'] = userName or 'User'
                        ctx['label'] = label
                        ctx['amount'] = amount
                        if phone_code:
                            if mobile[:1] == '0':
                                mobile = "+{}{}".format(phone_code, mobile[1:])
                            elif "+" not in mobile:
                                mobile = "+{}{}".format(phone_code, mobile)
                        response = sms_template_obj.with_context(ctx).send_sms_using_template(
                            mobile, sms_template_obj, obj=self)
                        return response
            except Exception as e:
                _logger.info("---Exception raised : %r while sending Wallet Transaction", e)
        return self
