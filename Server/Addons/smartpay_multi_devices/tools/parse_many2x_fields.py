import logging

from odoo.models import lazy_name_get

_logger = logging.getLogger(__name__)


def parse_many2x_fields(object_sudo, data, fields, custom_fields):
    """Parse many2one fields and return a dict with the ids and the values.
    @param object_sudo: The object on which to parse the many2one fields of it
    @param data: The data to parse
    @param fields: All fields related to object_sudo
    @param custom_fields: Only fields with name in custom_fields will be parsed

    @rtype: List
    @return: A list of dicts with the field_name and values
    """
    many2one_fields = {field_name: field for field_name, field in fields.items() if
                      field.type in ['many2many', 'one2many'] and field_name in custom_fields}
    for field in many2one_fields:
        ids_set = [d[field] for d in data if d[field]]
        m2o_records = object_sudo.env[object_sudo._fields[field].comodel_name].browse(*ids_set)
        data_dict = dict(lazy_name_get(m2o_records.sudo()))
        for d in data:
            d[field] = [(key_id, str(item)) for key_id, item in data_dict.items() if item is not False]
