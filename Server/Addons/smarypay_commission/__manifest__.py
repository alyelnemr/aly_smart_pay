# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.
{
    'name': "Odoo SmartPay Commissions",
    'description': "Odoo SmartPay Commissions",
    'version': '12.0.1.0.0',
    'category': 'Accounting',
    'website': 'https://tamayozsoft.com',
    'author': 'Tamayozsoft',
    'depends': [
        'tm_base_gateway', 'smartpay_operations'
    ],
    'data': [
        'views/commission_view.xml',
    ],
    'license': 'OEEL-1',
    # 'post_init_hook': 'post_init_hook',
}
