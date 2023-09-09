# -*- coding: utf-8 -*-
{
    'name': "SmartPay  Multi Devices",
    'summary': """
        SmartPay Multi Devices provides multi login under same account
        """,
    'description': """
        Smartbe Multi Devices provides:
            1- Multi device under the same login each login have the following;
                - Username
                - Password
                - Status
                - Machine serial
                - Access token
                - Service tags
                - Is allow commission
            2- We can enable or disable account over all logins
    """,
    'author': "SmartPay",
    'website': "https://smartpayeg.com/",
    'maintainer': 'Muhammed-Ashraf,eng.mohammedashraf96@gmail.com',
    'category': 'Tools',
    'version': '12.0.0.1',
    'depends': ['base_smartpay_otp', 'dev_product_tags', 'restful'],
    'data': [
        'security/groups.xml',
        'views/access_token_login.xml',
        'views/res_users.xml',
        'wizard/change_password_device.xml',
        'wizard/temp_password_device.xml',
        'data/cron_job.xml',
    ],
    "license": "LGPL-3",
    "installable": True,
    "auto_install": False,
}
