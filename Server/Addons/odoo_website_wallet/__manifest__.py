# -*- coding: utf-8 -*-
# Part of BrowseInfo. See LICENSE file for full copyright and licensing details.

{
    'name': 'Website Wallet On Odoo',
    'summary': 'This apps helps to use Wallet on website and pay order using wallet balance',
    'description': """Website Wallet
        Wallet on website and pay order using wallet balance
        eCommerce Wallet payment
        payment using wallet
        wallet balance.
        shop Wallet payment
        website wallet payment
        payment wallet
        payment on website using wallet
        wallet payment method
        
        
""" ,
    'category': 'eCommerce',
    'version': '11.0.0.2',
    "price": 89,
    "currency": 'EUR',
    'author': 'BrowseInfo',
    'depends': ['website','website_sale'],
    'data': [
        'data/data.xml',
        'views/wallet.xml',
        'views/template.xml',
        'views/portal_template.xml',
    ],
    'application': True,
    'installable': True,
    "images":["static/description/Banner.png"],
}

# vim:expandtab:smartindent:tabstop=4:softtabstop=4:shiftwidth=4:
