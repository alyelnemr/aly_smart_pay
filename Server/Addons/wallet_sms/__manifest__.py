# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

{
  "name"                 :  "Wallet Notification Via SMS",
  "summary"              :  """Send Wallet Notification Via SMS.""",
  "category"             :  "Extra Tools",
  "version"              :  "12.0.0.1",
  "sequence"             :  1,
  "website"              : 'https://tamayoz-soft.com',
  "author"               : 'Tamayozsoft',
  "license"              :  "Other proprietary",
  "description"          :  """Wallet Notification Via SMS""",
  "depends"              :  [
                             'sms_notification',
                             'odoo_website_wallet',
                            ],
  "data"                 :  [
                             'data/data_smswallet.xml',
                             'edi/sms_template_for_wallet_sms.xml',
                            ],
  "images"               :  ['static/description/Banner.png'],
  "application"          :  True,
  "installable"          :  True,
  "auto_install"         :  False,
  "price"                :  20,
  "currency"             :  "USD",
  # "pre_init_hook"        :  "pre_init_check",
}