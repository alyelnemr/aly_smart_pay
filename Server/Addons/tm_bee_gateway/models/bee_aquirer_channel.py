# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

import logging
import psycopg2
import uuid

from odoo import api, fields, models, registry, SUPERUSER_ID, tools, _
from odoo.exceptions import ValidationError

from .momken_request import MOMKENRequest

_logger = logging.getLogger(__name__)


class AcquirerBeeChannel(models.Model):
    _inherit = 'payment.acquirer.channel'
    _order = "sequence"

    bee_login = fields.Char('Login', required_if_provider='bee', groups='base.group_user')  # login:
    bee_password = fields.Char('Password', required_if_provider='bee', groups='base.group_user')  # password:
    bee_terminalId = fields.Char('Terminal ID', required_if_provider='bee',
                                 groups='base.group_user')  # terminalId: 123
    bee_account_number = fields.Char('Account Number', groups='base.group_user')  # accountNumber:
    bee_service_version = fields.Integer("Service List Version")  # serviceVersion: 0
