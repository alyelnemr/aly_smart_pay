# -*- coding: utf-8 -*-
##########################################################################
# Author      : Webkul Software Pvt. Ltd. (<https://webkul.com/>)
# Copyright(c): 2017-Present Webkul Software Pvt. Ltd.
# All Rights Reserved.
#
#
#
# This program is copyright property of the author mentioned above.
# You can`t redistribute it and/or modify it.
#
#
# You should have received a copy of the License along with this program.
# If not, see <https://store.webkul.com/license.html/>
##########################################################################

from odoo import models, fields, api, _


import logging
_logger = logging.getLogger(__name__)


class SaleOrder(models.Model):
    _inherit = "sale.order"

    @api.multi
    def action_confirm(self):
        self.ensure_one()
        res = super(SaleOrder, self).action_confirm()
        # Code to send sms to customer of the order.
        sms_template_objs = self.env["sms.template"].sudo().search(
            [('condition', '=', 'order_confirm'),('globally_access','=',False)])
        for sms_template_obj in sms_template_objs:
            mobile = sms_template_obj._get_partner_mobile(self.partner_id)
            if mobile:
                sms_template_obj.send_sms_using_template(
                    mobile, sms_template_obj, obj=self)
        return res

    @api.multi
    def action_cancel(self):
        res = super(SaleOrder, self).action_cancel()
        sms_template_objs = self.env["sms.template"].sudo().search(
            [('condition', '=', 'order_cancel'),('globally_access','=',False)])
        for obj in self:

            for sms_template_obj in sms_template_objs:
                mobile = sms_template_obj._get_partner_mobile(obj.partner_id)
                if mobile:
                    sms_template_obj.send_sms_using_template(
                        mobile, sms_template_obj, obj=obj)
        return res

    @api.multi
    def write(self, vals):
        result = super(SaleOrder, self).write(vals)
        for res in self:
            if res and vals.get("state", False) == 'sent':
                sms_template_objs = self.env["sms.template"].sudo().search(
                    [('condition', '=', 'order_placed'),('globally_access','=',False)])
                for sms_template_obj in sms_template_objs:
                    mobile = sms_template_obj._get_partner_mobile(
                        res.partner_id)
                    if mobile:
                        sms_template_obj.send_sms_using_template(
                            mobile, sms_template_obj, obj=res)
        return result


class stock_picking(models.Model):
    _inherit = "stock.picking"

    @api.multi
    def write(self, vals):
        result = super(stock_picking, self).write(vals)
        for res in self:
            if res and vals.get("date_done", False):
                res.send_picking_done_message()
        return result

    # method to send msg on picking done
    def send_picking_done_message(self):
        sms_template_objs = self.env["sms.template"].sudo().search(
            [('condition', '=', 'order_delivered'),('globally_access','=',False)])
        for sms_template_obj in sms_template_objs:
            mobile = sms_template_obj._get_partner_mobile(
                self.partner_id)
            if mobile:
                sms_template_obj.send_sms_using_template(
                    mobile, sms_template_obj, obj=self)



class account_invoice(models.Model):
    _inherit = "account.invoice"

    @api.multi
    def write(self, vals):
        result = super(account_invoice, self).write(vals)
        for res in self:
            if res and vals.get("state", False) in ["open", "paid"]:
                res.send_invoice_message(vals.get("state"))
        return result

    # method to send msg for open or paid invoice
    def send_invoice_message(self,state):
        if state == 'open':
            sms_template_objs = self.env["sms.template"].sudo().search(
                [('condition', '=', 'invoice_vaildate'),('globally_access','=',False)])
            for sms_template_obj in sms_template_objs:
                mobile = sms_template_obj._get_partner_mobile(
                    self.partner_id)
                if mobile:
                    sms_template_obj.send_sms_using_template(
                    mobile, sms_template_obj, obj=self)
        elif state == 'paid':
            sms_template_objs = self.env["sms.template"].sudo().search(
                [('condition', '=', 'invoice_paid'),('globally_access','=',False)])
            for sms_template_obj in sms_template_objs:
                mobile = sms_template_obj._get_partner_mobile(
                    self.partner_id)
                if mobile:
                    sms_template_obj.send_sms_using_template(
                                mobile, sms_template_obj, obj=self)

