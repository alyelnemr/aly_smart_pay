{
    "name": "Odoo SmartPay RESTFUL API",
    "version": "12.0.0.1",
    "category": "API",
    'website': 'https://tamayoz-soft.com',
    'author': 'Tamayozsoft',
    "summary": "Odoo SmartPay RESTFUL API",
    "description": """ RESTFUL API For Odoo for SmartPay integration
====================
With use of this module user can enable REST API in any Odoo applications/modules
""",
    "depends": ["restful", "auth_signup", "website_form", "tm_base_gateway", "tm_product_sequence", "dev_product_tags"],
    "data": [
        "views/res_users.xml",
        "views/product_category.xml",
    ],
    "images": ["static/description/main_screenshot.png"],
    "installable": True,
    "auto_install": False,
}
