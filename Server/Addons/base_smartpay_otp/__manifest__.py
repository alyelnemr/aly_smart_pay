{
    'name': 'OTP Reset Password',
    'version': '12.0',
    'summary': 'OTP Reset Password',
    'description': 'OTP Reset Password',
    'category': 'Tools',
    'author': "Smartbe",
    'website': "",
    'maintainer': 'Muhammed-Ashraf,eng.mohammedashraf96@gmail.com',
    'license': '',
    'depends': ['base_setup', 'restful'],
    'data': [
        'security/groups.xml',
        'wizard/temp_password.xml',
        'views/res_users.xml',
        'views/res_config_settings_views.xml',
    ],
    'installable': True,
    'auto_install': False
}
