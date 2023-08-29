# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

from odoo import fields, models
from odoo.addons import decimal_precision as dp


class PartnerSaleLimitFees(models.Model):
    _name = 'res.partner.sale.limit.fees'

    # partner_id = fields.Many2one('res.partner', 'Partner', readonly=True)
    # product_id = fields.Many2one('product.product', 'Product Variant', readonly=True)
    user_request_id = fields.Many2one('smartpay_operations.request', 'Request', readonly=True)
    limit_type = fields.Selection([('daily', 'Daily'), ('weekly', 'Weekly'), ('monthly', 'Monthly')], 'Limit Type',
                                  default='daily', readonly=True)
    fees_amount = fields.Float(
        'Fees Amount',
        digits=dp.get_precision('Product Price'),
        help="Over Limit Fees Amount at which the product is sold to partner.", readonly=True)

    wallet_transaction_id = fields.Many2one('website.wallet.transaction', 'Wallet Transaction', copy=False)

    refund_amount = fields.Float(
        'Fees Amount',
        digits=dp.get_precision('Product Price'),
        help="Over Limit Fees Amount at which the product is sold to partner.", readonly=True)

    refund_wallet_transaction_id = fields.Many2one('website.wallet.transaction', 'Wallet Transaction', copy=False)
