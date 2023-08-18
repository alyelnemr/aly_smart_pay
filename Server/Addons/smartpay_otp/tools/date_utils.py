from odoo import fields
from dateutil.relativedelta import relativedelta


def get_timedelta(qty, granularity):
    """
        Helper to get a `relativedelta` object for the given quantity and interval unit.
        :param qty: the number of unit to apply on the timedelta to return
        :param granularity: Type of period in string, can be year, quarter, month, week, day, hour or minute.

    """
    switch = {
        'minute': relativedelta(minutes=qty),
        'hour': relativedelta(hours=qty),
        'day': relativedelta(days=qty),
        'week': relativedelta(weeks=qty),
        'month': relativedelta(months=qty),
        'year': relativedelta(years=qty),
    }
    return switch[granularity]


def convert_datetime_client_tz(record, timestamp):
    """Returns the given timestamp converted to the client's timezone.

      :param record: recordset from which the timezone will be obtained.
      :param datetime timestamp: naive datetime value (expressed in UTC)
            to be converted to the client timezone.
      :rtype: datetime
      :return: timestamp converted to timezone-aware datetime in context timezone.
    """
    return fields.Datetime.context_timestamp(record=record, timestamp=timestamp).replace(tzinfo=None)


def convert_date_client_tz(record, timestamp=None):
    """Return the current date as seen in the client's timezone.

        :param record: recordset from which the timezone will be obtained.
        :param datetime timestamp: optional datetime value to use instead of
            the current date and time (must be a datetime, regular dates
            can't be converted between timezones).
        :rtype: date
        """
    return fields.Date.context_today(record=record, timestamp=timestamp).replace(tzinfo=None)
