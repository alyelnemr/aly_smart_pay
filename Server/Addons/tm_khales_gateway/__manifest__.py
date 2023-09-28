# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.
{
    'name': "Khales Payment",
    'description': "Khales Payment Gateway Integration",
    'version': '12.0.1.0.0',
    'category': 'Accounting',
    'website': 'http://tamayozsoft.com',
    'author': 'Tamayozsoft',
    'depends': ['account', 'mail', 'tm_base_gateway'],
    'data': [
        'data/khales_gateway_data.xml',
        'data/cron_job.xml',
        'views/khales_gateway_view.xml',
    ],
    'license': 'OEEL-1',
}
