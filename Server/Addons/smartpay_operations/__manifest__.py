# -*- coding: utf-8 -*-
{
    'name': "Odoo SmartPay Operations",
    'version': "12.0.0.1",
    'website': 'https://tamayozsoft.com',
    'author': 'Tamayozsoft',
    'category': "Tools",
    'summary': "Odoo SmartPay Operations System",
    'description': """
        Easy to manage SmartPay operations
        with teams and website portal
    """,
    'data': [
        'data/ir_sequence_data.xml',
        'data/wallet_type_data.xml',
        'security/helpdesk_security.xml',
        'security/ir.model.access.csv',
        'views/helpdesk_requests.xml',
        'views/helpdesk_team_views.xml',
        'views/helpdesk_stage_views.xml',
        'views/helpdesk_data.xml',
        'views/helpdesk_templates.xml',
        'views/configuration.xml',
        'views/wallet.xml',
        'views/wallet_automation.xml',
    ],
    'demo': [
        'demo/helpdesk_demo.xml',
    ],
    'images': ['static/description/banner.jpg'],
    'depends': ['base', 'mail', 'portal', 'account', 'odoo_website_wallet'],
    'application': True,
    'installable': True,
    'auto_install': False,
}
