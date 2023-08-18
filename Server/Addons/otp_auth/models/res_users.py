# -*- coding: utf-8 -*-
#################################################################################
#
#   Copyright (c) 2015-Present Webkul Software Pvt. Ltd. (<https://webkul.com/>)
#   See LICENSE file for full copyright and licensing details.
#   If not, see <https://store.webkul.com/license.html/>
#
#################################################################################

from odoo import api, models, _
from odoo.http import request
from logging import getLogger
_logger = getLogger(__name__)

class Users(models.Model):
    _inherit = 'res.users'

    @api.model
    def _check_credentials(self, password):
        totp = request.session.get('otploginobj')
        if totp:
            if password.isdigit() and totp.isdigit():
                if int(totp) == int(password):
                    request.session['otpverified'] = True
                else:
                    request.session['otpverified'] = False
                    super(Users, self)._check_credentials(password)
            else:
                super(Users, self)._check_credentials(password)
        else:
            super(Users, self)._check_credentials(password)
