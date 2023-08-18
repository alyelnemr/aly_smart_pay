# -*- coding: utf-8 -*-
##########################################################################
# Author      : Tamayozsoft. (<https://tamayoz-soft.com/>)
# Copyright(c): 2015-Present Tamayozsoft.
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
{
    "name":  "SMS Misr Gateway",
    "summary":  "Send sms notifications using sms misr gateway.",
    "category":  "Marketing",
    "version":  "12.0.0.1",
    "sequence":  1,
    "license":  "Other proprietary",
    "website": "https://tamayoz-soft.com",
    "author": "Tamayozsoft",
    "depends":  [
        'base_setup',
        'sms_notification',
    ],
    "data":  [
        'views/sms_misr_config_view.xml',
        'views/sms_report.xml',
    ],
    "images":  ['static/description/Banner.png'],
    "application":  True,
    "installable":  True,
    "auto_install":  False,
    "price":  20,
    "currency":  "EUR",
    # "pre_init_hook":  "pre_init_check",
    # "external_dependencies": {
        #'python': ['urllib'],
    #},
}
