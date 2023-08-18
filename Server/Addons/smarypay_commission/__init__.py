# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

from . import models
from odoo.api import Environment, SUPERUSER_ID
'''
def post_init_hook(cr, registry):
    env = Environment(cr, SUPERUSER_ID, {})
    request_pool = env['smartpay_operations.request'].sudo()

    domain = [('stage_id', '=', env.ref('smartpay_operations.stage_done').id),
              ('request_type', '=', 'pay_service_bill'),
              ('provider_response', 'not ilike', 'error_message'),
              ('provider_response', 'not ilike', 'provider_cancel_response'),
              # '|',
              ('customer_invoice_ids_count', '>', 0),
              # ('provider_invoice_ids_count', '>', 0)
              ]
    requests = request_pool.search(domain, order='id')
    for request in requests:
        request_customer_credit_notes = request.customer_invoice_ids.filtered(lambda x: x.type == 'out_refund')
        if len(request_customer_credit_notes) > 0 and request_customer_credit_notes[0].state not in ('draft','cancel'):
            request.update({'commission_paid': True})
'''