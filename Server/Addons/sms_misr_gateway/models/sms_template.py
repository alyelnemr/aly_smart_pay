# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

import logging

from odoo import api, models


_logger = logging.getLogger(__name__)


class SmsTemplate(models.Model):
    _inherit = "sms.template"

    @api.model
    def send_sms_using_template(self, mob_no, sms_tmpl, sms_gateway=None, obj=None):
        if mob_no:
            mob_no = mob_no.replace('+','')
        return super(SmsTemplate, self).send_sms_using_template(mob_no, sms_tmpl, sms_gateway=sms_gateway, obj=obj)
