# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

import logging
import psycopg2
import uuid

from odoo import api, fields, models, registry, SUPERUSER_ID, tools, _
from odoo.exceptions import ValidationError

from .bee_request import BeeRequest

_logger = logging.getLogger(__name__)


class AcquirerBee(models.Model):
    _inherit = 'payment.acquirer'

    provider = fields.Selection(selection_add=[('bee', 'bee')])

    bee_version = fields.Integer("Interface Version", required_if_provider='bee', default=1)
    bee_test_url = fields.Char("Test url", required_if_provider='bee',
                                  default='https://test.bee.org/gateway/api/v2/')
    bee_prod_url = fields.Char("Production url", required_if_provider='bee',
                                  default='https://test.bee.org/gateway/api/v2/')
    bee_channel_ids = fields.One2many('payment.acquirer.channel', 'acquirer_id', string='Bee Channels',
                                         copy=False)

    def log_xml(self, xml_string, func):
        self.ensure_one()

        if self.debug_logging:
            db_name = self._cr.dbname

            # Use a new cursor to avoid rollback that could be caused by an upper method
            try:
                db_registry = registry(db_name)
                with db_registry.cursor() as cr:
                    env = api.Environment(cr, SUPERUSER_ID, {})
                    IrLogging = env['ir.logging']
                    IrLogging.sudo().create({'name': 'payment.acquirer',
                                             'type': 'server',
                                             'dbname': db_name,
                                             'level': 'DEBUG',
                                             'message': xml_string,
                                             'path': self.provider,
                                             'func': func,
                                             'line': 1})
            except psycopg2.Error:
                pass

    @api.onchange('bee_prod_url', 'bee_test_url')
    def _onchange_bee_url(self):
        self.server_url = self.bee_prod_url
        if self.environment == "test":
            self.server_url = self.bee_test_url

    def get_bee_category_service_details(self, bee_channel=None):
        superself = self.sudo()
        result = {}

        if not bee_channel and superself.bee_channel_ids:
            bee_channel = superself.bee_channel_ids[0]
        elif not bee_channel and not superself.bee_channel_ids:
            raise ValidationError(
                _('The fetch of bee category services details cannot be processed because the bee has not any chennel in confiquration!'))

        # Production and Testing url
        endurl = superself.bee_prod_url
        if superself.environment == "test":
            endurl = superself.bee_test_url

        srm = BeeRequest(debug_logger=self.log_xml, endurl=endurl, env=self.env,
                            username=bee_channel.bee_login, password=bee_channel.bee_password,
                            version=superself.bee_version,
                            service_version=bee_channel.bee_service_version,
                            account_id=bee_channel.bee_account_number)

        custLangPref = 'AR'
        result_category_service = srm.get_service_details(custLangPref, data={})
        if result_category_service.get('categoryServiceData'):
            result['categoryServiceData_' + custLangPref] = result_category_service['categoryServiceData']
        else:
            result = result_category_service

        return result

    def auto_fetch_bee_biller_details(self):
        fetch_success = False
        bee = self.env['payment.acquirer'].sudo().search([("provider", "=", "bee")])
        result_category_service = bee.get_bee_category_service_details()

        for custLangPref in ['AR', 'EN']:
            # Get Category List
            categoryData = ''  # result_category.get('categoryData_' + custLangPref)
            if categoryData:
                for category in categoryData['category_list']:
                    _logger.info(" ====================================== Category Fetch Data Begin " + str(
                        category['id']) + ": " + custLangPref + " =========================================")
                    categoryId = category['id']
                    categoryName = category['name']
                    categoryNameAr = category['name_ar']

                    # Fetch bee Service Category
                    service_categ_providerinfo = self.env['product_category.providerinfo.mapping'].sudo().search([
                        ('product_categ_code', '=', categoryId), ('provider_id', '=', bee.id)
                    ])
                    if not service_categ_providerinfo:
                        service_category_vals = {
                            'name': categoryName,
                            'parent_id': self.env.ref("tm_base_gateway.product_category_mapping_services").id,
                            'property_cost_method': 'standard',
                            'provider_ids': [(0, 0, {
                                'product_categ_code': categoryId,
                                'product_categ_name': categoryName,
                                'provider_id': bee.id,
                            })],
                        }
                        service_category = self.env['product.category.mapping'].sudo().create(service_category_vals)
                        service_categ_providerinfo = service_category.provider_ids[0]
                        # service_category_providerinfo = self.env['product_category.providerinfo.mapping'].sudo().create({
                        #     'product_categ_code': categoryId,
                        #     'product_categ_name': categoryName,
                        #     'provider_id': bee.id,
                        #     'product_categ_id': service_category.id
                        # })

                        categoryName_translate = self.env['ir.translation'].sudo().create({
                            'type': 'model',
                            'name': 'product.category.mapping,name',
                            'module': 'tm_base_gateway',
                            'lang': 'ar_AA',
                            'res_id': service_categ_providerinfo.product_categ_id.id,
                            'value': categoryNameAr,
                            'state': 'translated',
                        })
                    else:
                        service_categ_providerinfo.sudo().write({'product_categ_name': categoryName})
                        categoryName_translate = self.env['ir.translation'].sudo().search([
                            ('type', '=', 'model'),
                            ('name', '=', 'product.category.mapping,name'),
                            ('module', '=', 'tm_base_gateway'),
                            ('lang', '=', 'ar_AA'),
                            ('res_id', '=', service_categ_providerinfo.product_categ_id.id),
                            ('state', '=', 'translated')
                        ])

                        if not categoryName_translate:
                            categoryName_translate = self.env['ir.translation'].sudo().create({
                                'type': 'model',
                                'name': 'product.category.mapping,name',
                                'module': 'tm_base_gateway',
                                'lang': 'ar_AA',
                                'res_id': service_categ_providerinfo.product_categ_id.id,
                                'value': categoryNameAr,
                                'state': 'translated',
                            })
                        else:
                            categoryName_translate.sudo().write({"value": categoryNameAr})
                    _logger.info(
                        " ====================================== Category Fetch Data End " + str(
                            category['id']) + ": " + custLangPref + " =========================================")

            # Get Category Service List
            categoryServiceDict = {}
            categoryServiceData = result_category_service.get('categoryServiceData_' + custLangPref)
            if categoryServiceData:
                for categoryService in categoryServiceData['category_service_list']:
                    categoryId = categoryService['category_id']
                    serviceId = categoryService['service_id']
                    # serviceList = categoryServiceDict.get(categoryId)
                    # if not serviceList:
                    # serviceList = []
                    # serviceList.append(serviceId)
                    # categoryServiceDict.update({categoryId:serviceList})
                    categoryServiceDict.update({serviceId: categoryId})

        if not fetch_success:
            _logger.exception("Failed processing bee biller inquiry")
            return False
        else:
            return True

    def pay_bee_bill(self, lang, billTypeCode, amt, feeAmt,
                        inquiryTransactionId=None, quantity=None,
                        inputParameterList=None, bee_channel=None):
        superself = self.sudo()
        result = {}

        if not bee_channel and superself.bee_channel_ids:
            bee_channel = superself.bee_channel_ids[0]
        elif not bee_channel and not superself.bee_channel_ids:
            raise ValidationError(
                _('The pay of bee bill cannot be processed because the bee has not any chennel in confiquration!'))

        # Production and Testing url
        endurl = superself.bee_prod_url
        if superself.environment == "test":
            endurl = superself.bee_test_url

        srm = BeeRequest(debug_logger=self.log_xml, endurl=endurl, env=self.env,
                            login=bee_channel.bee_login, password=bee_channel.bee_password,
                            version=superself.bee_version, terminalId=bee_channel.bee_terminalId)

        custLangPref = 'EN'
        if lang == 'ar_AA' or (lang != 'en_US' and self.env.user.lang == 'ar_AA'):
            custLangPref = 'AR'

        accountNumber = bee_channel.bee_account_number
        if not accountNumber:
            result_account = self.get_bee_account_details(bee_channel)
            if (result_account.get("accountData")):
                accountNumber = result_account["accountData"]["account_list"][0]["account_number"]
                bee_channel.sudo().update({'bee_account_number': accountNumber})

        total_amount = float(amt) + float(feeAmt)
        data = {"external_id": str(uuid.uuid1().time_low), "service_version": bee_channel.bee_service_version,
                "account_number": accountNumber, "service_id": billTypeCode, "amount": float(amt),
                "service_charge": float(feeAmt), "total_amount": total_amount}
        if inquiryTransactionId:
            data.update({"inquiry_transaction_id": inquiryTransactionId})
        if quantity:
            data.update({"quantity": quantity})
        if inputParameterList:
            data.update({"input_parameter_list": inputParameterList})
        _logger.info("data             >>>>>>>>>>>>>>>>>>>>> " + str(data))
        result_bill = srm.pay_bill(custLangPref, data=data)
        if result_bill.get('pmtInfoData'):
            result['Success'] = result_bill['pmtInfoData']
        else:
            result = result_bill

        return result
