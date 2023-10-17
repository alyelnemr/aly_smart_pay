from odoo import fields, models, api


class InheritIrCron(models.Model):
    _inherit = 'ir.cron'

    interval_type = fields.Selection([('seconds', 'Seconds'),
                                      ('minutes', 'Minutes'),
                                      ('hours', 'Hours'),
                                      ('days', 'Days'),
                                      ('weeks', 'Weeks'),
                                      ('months', 'Months')], string='Interval Unit', default='months')
