from odoo.addons.base.models import ir_cron
from dateutil.relativedelta import relativedelta

custom_intervalTypes = {
    'days': lambda interval: relativedelta(days=interval),
    'hours': lambda interval: relativedelta(hours=interval),
    'weeks': lambda interval: relativedelta(days=7 * interval),
    'months': lambda interval: relativedelta(months=interval),
    'minutes': lambda interval: relativedelta(minutes=interval),
    'seconds': lambda interval: relativedelta(seconds=interval),
}

ir_cron._intervalTypes = custom_intervalTypes
