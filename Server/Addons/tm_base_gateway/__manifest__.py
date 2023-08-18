# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.
{
    'name': "Tamayoz Base Payment Gatway",
    'description': "Tamayoz Base Payment Gateway",
    'version': '12.0.1.0.0',
    'category': 'Accounting',
    'website': 'https://tamayoz-soft.com',
    'author': 'Tamayozsoft',
    'depends': ['sale', 'account', 'product', 'smartpay_operations'],
    'data': [
        'security/ir.model.access.csv',
        'security/base_gateway_security.xml',
        'data/base_gateway_data.xml',
        'views/base_gateway_view.xml',
        'views/res_config_settings_views.xml',
    ],
    'license': 'OEEL-1',
}
