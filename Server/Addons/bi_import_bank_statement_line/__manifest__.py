# -*- coding: utf-8 -*-
# Part of BrowseInfo. See LICENSE file for full copyright and licensing details.

{
    'name': 'Import Bank Statement Lines from Excel/CSV file',
    'version': '10.0.0.5',
    'summary': 'This module helps you to import bank statement line on Odoo using Excel and CSV file',
    'description': """
	Import Bank Statement Lines from Excel
	Import Cash Statement Lines from Excel
	This module allow you to Import Bank Statement Lines from Excel file.
	This module will allow import Bank and Cash Statements from EXCEL.
	This module will allow import Cash Register Statements From Excel.
	Import Bank Statement Lines from CSV
	Import Cash Statement Lines from CSV
	This module allow you to Import Bank Statement Lines from CSV file.
	This module will allow import Bank and Cash Statements from CSV.
	This module will allow import Cash Register Statements from CSV.
	Excel Bank statement import
	CSV bank statement import
	Excel Cash statement import
	CSV cash statement import
	import bulk statement line, import statement lines
	This module use for import bulk bank statement lines from Excel file. Import statement lines from CSV or Excel file.
	Import statements, Import statement line, Bank statement Import, Add Bank statement from Excel.Add Excel Bank statement lines.Add CSV file.Import invoice data. Import excel file

	Import Bank Statement Lines from XLS
	Import Cash Statement Lines from XLS
	This module allow you to Import Bank Statement Lines from XLS file.
	This module will allow import Bank and Cash Statements from XLS.
	This module will allow import Cash Register Statements From XLS.
	xls Bank statement import
	xls Cash statement import
    """,
    'author': 'BrowseInfo',
    "price": 10,
    "currency": 'EUR',
    'website': 'http://www.browseinfo.in',
    'depends': ['base','account'],
    'data': ["views/bank_statement.xml"
             ],
	'qweb': [
		],
    'demo': [],
    'test': [],
    'installable': True,
    'auto_install': False,
    "live_test_url":'https://youtu.be/Wfvp4mqQ2rc',
    "images":['static/description/Banner.png'],
}
# vim:expandtab:smartindent:tabstop=4:softtabstop=4:shiftwidth=4:
