# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

import logging
_logger = logging.getLogger(__name__)

from odoo import models, fields, api, _
from odoo.exceptions import Warning
from . sms_misr_messaging import send_sms_using_sms_misr


class SmsMailServer(models.Model):
    """Configure the sms misr gateway."""

    _inherit = "sms.mail.server"
    _name = "sms.mail.server"
    _description = "SMS Misr"

    username = fields.Char(string="Username")
    password = fields.Char(string="Password")
    sender = fields.Char(string="Sender")
    language = fields.Integer(string="language", default=2, help="1: For English 2: For Arabic 3: For Unicode")
    sms_url = fields.Char(string="SMS URL")
    balance_status_url = fields.Char(string="Balance and Status URL")

    @api.one
    def test_conn_sms_misr(self):
        sms_body = "SMS Misr Test Connection Successful........"
        mobile_number = self.user_mobile_no
        response = send_sms_using_sms_misr(
            sms_body, mobile_number, language=self.language, delay_until=None, sms_gateway=self)
        # _logger.info('================%r', response.get(
        #     mobile_number).get('code'))
        if response.get(mobile_number) and response[mobile_number].get('SMSID'):
            if self.sms_debug:
                _logger.info(
                    "===========Test Connection status has been sent on %r mobile number", mobile_number)
            raise Warning(
                "Test Connection status has been sent on %s mobile number" % mobile_number)
        else:
            if self.sms_debug:
                _logger.error(
                    "==========One of the information given by you is wrong. It may be [Mobile Number] or [Sender] or [Username] or [Password]======")
            raise Warning(
                "One of the information given by you is wrong. It may be [Mobile Number] or [Sender] or [Username] or [Password]")

    @api.model
    def get_reference_type(self):
        selection = super(SmsMailServer, self).get_reference_type()
        selection.append(('sms_misr', 'SMS Misr'))
        return selection
