# -*- coding: utf-8 -*-
#################################################################################
# Author      : Webkul Software Pvt. Ltd. (<https://webkul.com/>)
# Copyright(c): 2015-Present Webkul Software Pvt. Ltd.
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
#################################################################################
{
  "name"                 :  "Odoo SMS OTP Authentication",
  "summary"              :  """SMS OTP Authentication allows the customers to use One-time-password as an alternative to the password to sign-in to their Odoo website account.""",
  "category"             :  "Extra Tools",
  "version"              :  "1.0.2",
  "sequence"             :  1,
  "author"               :  "Webkul Software Pvt. Ltd.",
  "license"              :  "Other proprietary",
  "website"              :  "https://store.webkul.com/Odoo-SMS-OTP-Authentication.html",
  "description"          :  """OTP
One Time Password
SMS OTP Authentication
Odoo SMS OTP Authentication
SMS OTP Authentication in Odoo
OTP Authentication
SMS Authentication
Send Transactional SMS
One Time Password Authentication
SMS One Time Password Authentication
Short Message Service One Time Password Authentication
Secure login with One Time Passwords
OTP Via SMS""",
  "live_test_url"        :  "http://odoodemo.webkul.com/?module=otp_sms_auth",
  "depends"              :  [
                             'sms_notification',
                             'otp_auth',
                            ],
  "data"                 :  [
                             'data/data_smsotp.xml',
                             'views/res_config_views.xml',
                             'views/auth_signup_login_templates.xml',
                             'edi/sms_template_for_otp_sms.xml',
                             'views/res_users_view.xml',
                             'views/webclient_templates.xml',
                            ],
  "images"               :  ['static/description/Banner.png'],
  "application"          :  True,
  "installable"          :  True,
  "auto_install"         :  False,
  "price"                :  45,
  "currency"             :  "USD",
  "pre_init_hook"        :  "pre_init_check",
}