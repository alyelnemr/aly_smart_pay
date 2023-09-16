import logging

from odoo.models import lazy_name_get

_logger = logging.getLogger(__name__)


def parse_many2x_fields(object_sudo, data, fields, custom_fields):
    many2onefields = {field_name: field for field_name, field in fields.items() if
                      field.type in ['many2many'] and field_name in custom_fields}
    # _logger.info("data: {}, fields: {}".format(data, fields))
    _logger.info("many2onefields: {}".format(many2onefields))
    _logger.info("data: {}".format(data))
    _logger.info("fields: {}".format(fields))
    for field in many2onefields:
        ids_set = [d[field] for d in data if d[field]]
        m2o_records = object_sudo.env[object_sudo._fields[field].comodel_name].browse(*ids_set)
        data_dict = dict(lazy_name_get(m2o_records.sudo()))
        for d in data:
            d[field] = [(key_id, str(item)) for key_id, item in data_dict.items() if item is not False]
