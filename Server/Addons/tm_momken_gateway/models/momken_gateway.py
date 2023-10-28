# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

import logging
import psycopg2
import uuid

from odoo import api, fields, models, registry, SUPERUSER_ID, tools, _
from odoo.exceptions import ValidationError

from .momken_request import MOMKENRequest

_logger = logging.getLogger(__name__)


class AcquirerMomkenChannel(models.Model):
    _inherit = 'payment.acquirer.channel'
    _order = "sequence"

    momken_login = fields.Char('Login', required_if_provider='momken', groups='base.group_user')  # login:
    momken_password = fields.Char('Password', required_if_provider='momken', groups='base.group_user')  # password:
    momken_terminalId = fields.Char('Terminal ID', required_if_provider='momken',
                                    groups='base.group_user')  # terminalId: 123
    momken_account_number = fields.Char('Account Number', groups='base.group_user')  # accountNumber:
    momken_service_version = fields.Integer("Service Version")  # serviceVersion: 0


class AcquirerMomken(models.Model):
    _inherit = 'payment.acquirer'

    provider = fields.Selection(selection_add=[('momken', 'Momken')])

    momken_version = fields.Integer("Interface Version", required_if_provider='momken', default=2)  # version: 2
    momken_test_url = fields.Char("Test url", required_if_provider='momken',
                                  default='https://test.momkn.org/gateway/api/v2')
    momken_prod_url = fields.Char("Production url", required_if_provider='momken',
                                  default='https://test.momkn.org/gateway/api/v2')

    momken_channel_ids = fields.One2many('payment.acquirer.channel', 'acquirer_id', string='Momken Channels',
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

    @api.onchange('momken_prod_url', 'momken_test_url')
    def _onchange_momken_url(self):
        self.server_url = self.momken_prod_url
        if self.environment == "test":
            self.server_url = self.momken_test_url

    def get_momken_biller_details(self, momken_channel=None):
        superself = self.sudo()
        result = {}

        if not momken_channel and superself.momken_channel_ids:
            momken_channel_channel = superself.momken_channel_ids[0]
        elif not momken_channel and not superself.momken_channel_ids:
            raise ValidationError(
                _('The fetch of momken biller details cannot be processed because the masary has not any chennel in confiquration!'))

        # Production and Testing url
        endurl = superself.momken_prod_url
        if superself.environment == "test":
            endurl = superself.momken_test_url

        srm = MOMKENRequest(debug_logger=self.log_xml, endurl=endurl, env=self.env, login=momken_channel.masary_login,
                            password=momken_channel.masary_password,
                            version=superself.masary_version, terminalId=momken_channel.masary_terminalId)

        custLangPref = 'AR'
        result_biller = srm.get_biller_details(custLangPref,
                                               data={"service_version": momken_channel.momken_service_version})
        if result_biller.get('billerData'):
            result['billerData_' + custLangPref] = result_biller['billerData']
            momken_channel.sudo().update({'momken_service_version': result_biller['billerData']['service_version']})
        else:
            result = result_biller

        return result

    def get_momken_service_details(self, biller_id, momken_channel=None):
        superself = self.sudo()
        result = {}

        if not momken_channel and superself.momken_channel_ids:
            momken_channel = superself.momken_channel_ids[0]
        elif not momken_channel and not superself.momken_channel_ids:
            raise ValidationError(
                _('The fetch of masary service details cannot be processed because the masary has not any chennel in confiquration!'))

        # Production and Testing url
        endurl = superself.momken_prod_url
        if superself.environment == "test":
            endurl = superself.momken_test_url

        # _logger.info("endurl             >>>>>>>>>>>>>>>>>>>>> " + endurl)
        # _logger.info("login              >>>>>>>>>>>>>>>>>>>>> " + momken_channel.masary_login)
        # _logger.info("password           >>>>>>>>>>>>>>>>>>>>> " + momken_channel.masary_password)
        # _logger.info("version            >>>>>>>>>>>>>>>>>>>>> " + str(superself.masary_version))
        # _logger.info("terminalId         >>>>>>>>>>>>>>>>>>>>> " + momken_channel.masary_terminalId)
        srm = MOMKENRequest(debug_logger=self.log_xml, endurl=endurl, env=self.env,
                            login=momken_channel.masary_login, password=momken_channel.masary_password,
                            version=superself.masary_version, terminalId=momken_channel.masary_terminalId)

        custLangPref = 'AR'
        result_service = srm.get_service_details(custLangPref, data={"provider_id": biller_id})
        if result_service.get('serviceData'):
            result['serviceData_' + custLangPref] = result_service['serviceData']
        else:
            result = result_service

        return result

    def get_momken_service_input_parameters_details(self, service_id, momken_channel=None):
        superself = self.sudo()
        result = {}

        if not momken_channel and superself.momken_channel_ids:
            momken_channel = superself.momken_channel_ids[0]
        elif not momken_channel and not superself.momken_channel_ids:
            raise ValidationError(
                _('The fetch of masary service input parameters details cannot be processed because the masary has not any chennel in confiquration!'))

        # Production and Testing url
        endurl = superself.momken_prod_url
        if superself.environment == "test":
            endurl = superself.momken_test_url

        # _logger.info("endurl             >>>>>>>>>>>>>>>>>>>>> " + endurl)
        # _logger.info("login              >>>>>>>>>>>>>>>>>>>>> " + momken_channel.masary_login)
        # _logger.info("password           >>>>>>>>>>>>>>>>>>>>> " + momken_channel.masary_password)
        # _logger.info("version            >>>>>>>>>>>>>>>>>>>>> " + str(superself.masary_version))
        # _logger.info("terminalId         >>>>>>>>>>>>>>>>>>>>> " + momken_channel.masary_terminalId)
        srm = MOMKENRequest(debug_logger=self.log_xml, endurl=endurl, env=self.env,
                            login=momken_channel.masary_login, password=momken_channel.masary_password,
                            version=superself.masary_version, terminalId=momken_channel.masary_terminalId)

        custLangPref = 'AR'
        result_service_input_parameters = srm.get_service_input_parameters_details(custLangPref,
                                                                                   data={"service_id": service_id})
        if result_service_input_parameters.get('serviceInputParameterData'):
            result['serviceInputParameterData_' + custLangPref] = result_service_input_parameters[
                'serviceInputParameterData']
        else:
            result = result_service_input_parameters

        return result

    def get_momken_service_output_parameters_details(self, service_id, momken_channel=None):
        superself = self.sudo()
        result = {}

        if not momken_channel and superself.momken_channel_ids:
            momken_channel = superself.momken_channel_ids[0]
        elif not momken_channel and not superself.momken_channel_ids:
            raise ValidationError(
                _('The fetch of masary service output parameters details cannot be processed because the masary has not any chennel in confiquration!'))

        # Production and Testing url
        endurl = superself.momken_prod_url
        if superself.environment == "test":
            endurl = superself.momken_test_url

        # _logger.info("endurl             >>>>>>>>>>>>>>>>>>>>> " + endurl)
        # _logger.info("login              >>>>>>>>>>>>>>>>>>>>> " + momken_channel.masary_login)
        # _logger.info("password           >>>>>>>>>>>>>>>>>>>>> " + momken_channel.masary_password)
        # _logger.info("version            >>>>>>>>>>>>>>>>>>>>> " + str(superself.masary_version))
        # _logger.info("terminalId         >>>>>>>>>>>>>>>>>>>>> " + momken_channel.masary_terminalId)
        srm = MOMKENRequest(debug_logger=self.log_xml, endurl=endurl, env=self.env,
                            login=momken_channel.masary_login, password=momken_channel.masary_password,
                            version=superself.masary_version, terminalId=momken_channel.masary_terminalId)

        custLangPref = 'AR'
        result_service_output_parameters = srm.get_service_output_parameters_details(custLangPref,
                                                                                     data={'service_id': service_id})
        if result_service_output_parameters.get('serviceOutputParameterData'):
            result['serviceOutputParameterData_' + custLangPref] = result_service_output_parameters[
                'serviceOutputParameterData']
        else:
            result = result_service_output_parameters

        return result

    def get_momken_category_details(self, momken_channel=None):
        superself = self.sudo()
        result = {}

        if not momken_channel and superself.momken_channel_ids:
            momken_channel = superself.momken_channel_ids[0]
        elif not momken_channel and not superself.momken_channel_ids:
            raise ValidationError(
                _('The fetch of masary category details cannot be processed because the masary has not any chennel in confiquration!'))

        # Production and Testing url
        endurl = superself.momken_prod_url
        if superself.environment == "test":
            endurl = superself.momken_test_url

        # _logger.info("endurl             >>>>>>>>>>>>>>>>>>>>> " + endurl)
        # _logger.info("login              >>>>>>>>>>>>>>>>>>>>> " + momken_channel.masary_login)
        # _logger.info("password           >>>>>>>>>>>>>>>>>>>>> " + momken_channel.masary_password)
        # _logger.info("version            >>>>>>>>>>>>>>>>>>>>> " + str(superself.masary_version))
        # _logger.info("terminalId         >>>>>>>>>>>>>>>>>>>>> " + momken_channel.masary_terminalId)
        srm = MOMKENRequest(debug_logger=self.log_xml, endurl=endurl, env=self.env,
                            login=momken_channel.masary_login, password=momken_channel.masary_password,
                            version=superself.masary_version, terminalId=momken_channel.masary_terminalId)

        custLangPref = 'AR'
        result_category = srm.get_category_details(custLangPref, data={})
        if result_category.get('categoryData'):
            result['categoryData_' + custLangPref] = result_category['categoryData']
        else:
            result = result_category

        return result

    def get_momken_category_service_details(self, momken_channel=None):
        superself = self.sudo()
        result = {}

        if not momken_channel and superself.momken_channel_ids:
            momken_channel = superself.momken_channel_ids[0]
        elif not momken_channel and not superself.momken_channel_ids:
            raise ValidationError(
                _('The fetch of momken category services details cannot be processed because the momken has not any chennel in confiquration!'))

        # Production and Testing url
        endurl = superself.momken_prod_url
        if superself.environment == "test":
            endurl = superself.momken_test_url

        # _logger.info("endurl             >>>>>>>>>>>>>>>>>>>>> " + endurl)
        # _logger.info("login              >>>>>>>>>>>>>>>>>>>>> " + momken_channel.masary_login)
        # _logger.info("password           >>>>>>>>>>>>>>>>>>>>> " + momken_channel.masary_password)
        # _logger.info("version            >>>>>>>>>>>>>>>>>>>>> " + str(superself.masary_version))
        # _logger.info("terminalId         >>>>>>>>>>>>>>>>>>>>> " + momken_channel.masary_terminalId)
        srm = MOMKENRequest(debug_logger=self.log_xml, endurl=endurl, env=self.env,
                            login=momken_channel.momken_login, password=momken_channel.momken_password,
                            version=superself.momken_version, terminalId=momken_channel.momken_terminalId)

        custLangPref = 'AR'
        result_category_service = srm.get_category_service_details(custLangPref, data={})
        if result_category_service.get('categoryServiceData'):
            result['categoryServiceData_' + custLangPref] = result_category_service['categoryServiceData']
        else:
            result = result_category_service

        return result

    def auto_fetch_momken_biller_details(self):
        fetch_success = False
        masary = self.env['payment.acquirer'].sudo().search([("provider", "=", "masary")])
        result_category = masary.get_masary_category_details()
        result_category_service = masary.get_masary_category_service_details()
        result_biller = masary.get_masary_biller_details()

        for custLangPref in ['AR', 'EN']:
            # Get Category List
            categoryData = result_category.get('categoryData_' + custLangPref)
            if categoryData:
                for category in categoryData['category_list']:
                    _logger.info(" ====================================== Category Fetch Data Begin " + str(
                        category['id']) + ": " + custLangPref + " =========================================")
                    categoryId = category['id']
                    categoryName = category['name']
                    categoryNameAr = category['name_ar']

                    # Fetch Masary Service Category
                    service_categ_providerinfo = self.env['product_category.providerinfo.mapping'].sudo().search([
                        ('product_categ_code', '=', categoryId), ('provider_id', '=', masary.id)
                    ])
                    if not service_categ_providerinfo:
                        service_category_vals = {
                            'name': categoryName,
                            'parent_id': self.env.ref("tm_base_gateway.product_category_mapping_services").id,
                            'property_cost_method': 'standard',
                            'provider_ids': [(0, 0, {
                                'product_categ_code': categoryId,
                                'product_categ_name': categoryName,
                                'provider_id': masary.id,
                            })],
                        }
                        service_category = self.env['product.category.mapping'].sudo().create(service_category_vals)
                        service_categ_providerinfo = service_category.provider_ids[0]
                        # service_category_providerinfo = self.env['product_category.providerinfo.mapping'].sudo().create({
                        #     'product_categ_code': categoryId,
                        #     'product_categ_name': categoryName,
                        #     'provider_id': masary.id,
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

            # Get Provider List
            billerData = result_biller.get('billerData_' + custLangPref)
            if billerData:
                for provider in billerData['provider_list']:
                    _logger.info(" ====================================== Biller Fetch Data Begin " + str(
                        provider['id']) + ": " + custLangPref + " =========================================")
                    billerId = provider['id']
                    billerName = provider['name']
                    billerNameAr = provider['name_ar']

                    # Fetch Masary Service Provider
                    service_provider_providerinfo = self.env['product_category.providerinfo.mapping'].sudo().search([
                        ('product_categ_code', '=', billerId),
                        ('provider_id', '=', masary.id),
                        # ('product_categ_id.parent_id', '=', service_categ_providerinfo.product_categ_id.id)
                    ])
                    if not service_provider_providerinfo:
                        service_provider_vals = {
                            'name': billerName,
                            # 'parent_id': service_categ_providerinfo.product_categ_id.id,
                            'property_cost_method': 'standard',
                            'provider_ids': [(0, 0, {
                                'product_categ_code': billerId,
                                'product_categ_name': billerName,
                                'provider_id': masary.id,
                            })],
                        }
                        service_provider = self.env['product.category.mapping'].sudo().create(service_provider_vals)
                        service_provider_providerinfo = service_provider.provider_ids[0]
                        # service_provider_providerinfo = self.env[
                        #     'product_category.providerinfo.mapping'].sudo().create({
                        #     'product_categ_code': billerId,
                        #     'product_categ_name': billerName,
                        #     'provider_id': masary.id,
                        #     'product_categ_id': service_provider.id
                        # })

                        billerName_translate = self.env['ir.translation'].sudo().create({
                            'type': 'model',
                            'name': 'product.category.mapping,name',
                            'module': 'tm_base_gateway',
                            'lang': 'ar_AA',
                            'res_id': service_provider_providerinfo.product_categ_id.id,
                            'value': billerNameAr,
                            'state': 'translated',
                        })
                    else:
                        service_provider_providerinfo.sudo().write({"product_categ_name": billerName})
                        billerName_translate = self.env['ir.translation'].sudo().search([
                            ('type', '=', 'model'),
                            ('name', '=', 'product.category.mapping,name'),
                            ('module', '=', 'tm_base_gateway'),
                            ('lang', '=', 'ar_AA'),
                            ('res_id', '=', service_provider_providerinfo.product_categ_id.id),
                            ('state', '=', 'translated')
                        ])

                        if not billerName_translate:
                            billerName_translate = self.env['ir.translation'].sudo().create({
                                'type': 'model',
                                'name': 'product.category.mapping,name',
                                'module': 'tm_base_gateway',
                                'lang': 'ar_AA',
                                'res_id': service_provider_providerinfo.product_categ_id.id,
                                'value': billerNameAr,
                                'state': 'translated',
                            })
                        else:
                            billerName_translate.sudo().write({"value": billerNameAr})

                    # Get Service List
                    result_service = masary.get_masary_service_details(billerId)
                    serviceData = result_service.get('serviceData_' + custLangPref)
                    if serviceData:
                        for service in serviceData['service_list']:
                            # _logger.info(" ===== serviceData >>>>> " + str(serviceData) + " =====")
                            serviceId = service['id']
                            serviceName = '%s: %s' % (billerName, service['name'])
                            serviceNameAr = '%s: %s' % (billerNameAr, service['name_ar'])

                            # Get service input parameters list
                            result_service_input_parameters = masary.get_masary_service_input_parameters_details(
                                serviceId)
                            serviceInputParameterData = result_service_input_parameters.get(
                                'serviceInputParameterData_' + custLangPref)
                            if serviceInputParameterData:
                                service.update(
                                    {'input_parameter_list': serviceInputParameterData['input_parameter_list']})

                            # Get service output parameters list
                            result_service_output_parameters = masary.get_masary_service_output_parameters_details(
                                serviceId)
                            serviceOutputParameterData = result_service_output_parameters.get(
                                'serviceOutputParameterData_' + custLangPref)
                            if serviceOutputParameterData:
                                service.update(
                                    {'output_parameter_list': serviceOutputParameterData['output_parameter_list']})

                            # Set Service Category
                            serviceCategoryId = categoryServiceDict.get(serviceId)
                            if serviceCategoryId:
                                service.update({'category_id': serviceCategoryId})
                                service_categ_providerinfo = self.env[
                                    'product_category.providerinfo.mapping'].sudo().search([
                                    ('product_categ_code', '=', serviceCategoryId), ('provider_id', '=', masary.id)
                                ])
                                if service_categ_providerinfo:
                                    if not service_provider_providerinfo.product_categ_id.parent_id:
                                        service_provider_providerinfo.product_categ_id.sudo().update(
                                            {'parent_id': service_categ_providerinfo.product_categ_id.id})
                                    elif service_provider_providerinfo.product_categ_id.parent_id.id != service_categ_providerinfo.product_categ_id.id \
                                            and len(
                                        service_provider_providerinfo.product_categ_id.parent_id.provider_ids) > 0:
                                        _logger.warning(
                                            "Masary services for biller [%s: %s] have more than one category (%s: %s, %s:%s)"
                                            % (billerId, billerName,
                                               service_provider_providerinfo.product_categ_id.parent_id.provider_ids[
                                                   0].product_categ_code,
                                               service_provider_providerinfo.product_categ_id.parent_id.provider_ids[
                                                   0].product_categ_name,
                                               service_categ_providerinfo.product_categ_code,
                                               service_categ_providerinfo.product_categ_name))
                            else:
                                _logger.warning(
                                    "Masary services [%s: %s] hasn't any category" % (serviceId, serviceName))
                                if not service_provider_providerinfo.product_categ_id.parent_id:
                                    service_provider_providerinfo.product_categ_id.sudo().update({
                                        'parent_id': self.env.ref(
                                            "tm_base_gateway.product_category_mapping_services").id})

                            # Fetch Masary Service
                            service_providerinfo = self.env['product.supplierinfo.mapping'].sudo().search([
                                ('product_code', '=', serviceId),
                                ('name', '=', masary.related_partner.id),
                                ('product_tmpl_id.categ_id', '=', service_provider_providerinfo.product_categ_id.id)
                            ])
                            if not service_providerinfo:
                                service_vals = {
                                    'name': serviceName,
                                    'type': 'service',
                                    'categ_id': service_provider_providerinfo.product_categ_id.id,
                                    'seller_ids': [(0, 0, {
                                        'name': masary.related_partner.id,
                                        'product_code': serviceId,
                                        'product_name': serviceName,
                                        'biller_info': service,
                                    })],
                                    'taxes_id': False,
                                    'supplier_taxes_id': False,
                                    'sale_ok': True,
                                    'purchase_ok': True,
                                    'invoice_policy': 'order',
                                    'lst_price': 0,  # Do not set a high value to avoid issue with coupon code
                                    'uom_id': self.env.ref("uom.product_uom_unit").id,
                                    'uom_po_id': self.env.ref("uom.product_uom_unit").id
                                }
                                product_service = self.env['product.product.mapping'].sudo().create(service_vals)
                                service_providerinfo = product_service.seller_ids[0]
                                # service_providerinfo = self.env['product.supplierinfo.mapping'].sudo().create({
                                #     'product_code': serviceId,
                                #     'product_name': serviceName,
                                #     'name': masary.related_partner.id,
                                #     'biller_info': service,
                                #     'product_id': service.id
                                # })

                                serviceName_translate = self.env['ir.translation'].sudo().create({
                                    'type': 'model',
                                    'name': 'product.template.mapping,name',
                                    'module': 'tm_base_gateway',
                                    'lang': 'ar_AA',
                                    'res_id': service_providerinfo.product_tmpl_id.id,
                                    'value': serviceNameAr,
                                    'state': 'translated',
                                })
                            else:
                                service_providerinfo.sudo().write({'product_name': serviceName, 'biller_info': service})
                                serviceName_translate = self.env['ir.translation'].sudo().search([
                                    ('type', '=', 'model'),
                                    ('name', '=', 'product.template.mapping,name'),
                                    ('module', '=', 'tm_base_gateway'),
                                    ('lang', '=', 'ar_AA'),
                                    ('res_id', '=', service_providerinfo.product_tmpl_id.id),
                                    ('state', '=', 'translated')
                                ])

                                if not serviceName_translate:
                                    serviceName_translate = self.env['ir.translation'].sudo().create({
                                        'type': 'model',
                                        'name': 'product.template.mapping,name',
                                        'module': 'tm_base_gateway',
                                        'lang': 'ar_AA',
                                        'res_id': service_providerinfo.product_tmpl_id.id,
                                        'value': serviceNameAr,
                                        'state': 'translated',
                                    })
                                else:
                                    serviceName_translate.sudo().write({"value": serviceNameAr})

                                billerInfo_translate = self.env['ir.translation'].sudo().search([
                                    ('type', '=', 'model'),
                                    ('name', '=', 'product.supplierinfo.mapping,biller_info'),
                                    ('module', '=', 'tm_base_gateway'),
                                    ('lang', '=', 'ar_AA'),
                                    ('res_id', '=', service_providerinfo.id),
                                    ('state', '=', 'translated')
                                ])

                                if not billerInfo_translate:
                                    billerInfo_translate = self.env['ir.translation'].sudo().create({
                                        'type': 'model',
                                        'name': 'product.supplierinfo.mapping,biller_info',
                                        'module': 'tm_base_gateway',
                                        'lang': 'ar_AA',
                                        'res_id': service_providerinfo.id,
                                        'value': service,
                                        'state': 'translated',
                                    })
                                else:
                                    billerInfo_translate.sudo().write({"value": service})

                    _logger.info(
                        " ====================================== Biller Fetch Data End " + str(
                            provider['id']) + ": " + custLangPref + " =========================================")
                fetch_success = True

        if not fetch_success:
            _logger.exception("Failed processing masary biller inquiry")
            return False
        else:
            return True

    def get_momken_account_details(self, momken_channel=None):
        superself = self.sudo()
        result = {}

        if not momken_channel and superself.momken_channel_ids:
            momken_channel = superself.momken_channel_ids[0]
        elif not momken_channel and not superself.momken_channel_ids:
            raise ValidationError(
                _('The fetch of masary account details cannot be processed because the masary has not any chennel in confiquration!'))

        # Production and Testing url
        endurl = superself.momken_prod_url
        if superself.environment == "test":
            endurl = superself.momken_test_url

        # _logger.info("endurl             >>>>>>>>>>>>>>>>>>>>> " + endurl)
        # _logger.info("login              >>>>>>>>>>>>>>>>>>>>> " + momken_channel.masary_login)
        # _logger.info("password           >>>>>>>>>>>>>>>>>>>>> " + momken_channel.masary_password)
        # _logger.info("version            >>>>>>>>>>>>>>>>>>>>> " + str(superself.masary_version))
        # _logger.info("terminalId         >>>>>>>>>>>>>>>>>>>>> " + momken_channel.masary_terminalId)
        srm = MOMKENRequest(debug_logger=self.log_xml, endurl=endurl, env=self.env,
                            login=momken_channel.masary_login, password=momken_channel.masary_password,
                            version=superself.masary_version, terminalId=momken_channel.masary_terminalId)

        custLangPref = 'AR'
        result_account = srm.get_account_details(custLangPref, data={})
        if result_account.get('accountData'):
            result['accountData'] = result_account['accountData']
        else:
            result = result_account

        return result

    def get_masary_bill_details(self, lang, billTypeCode, inputParameterList=None, momken_channel=None):
        superself = self.sudo()
        result = {}

        if not momken_channel and superself.momken_channel_ids:
            momken_channel = superself.momken_channel_ids[0]
        elif not momken_channel and not superself.momken_channel_ids:
            raise ValidationError(
                _('The fetch of masary bill details cannot be processed because the masary has not any chennel in confiquration!'))

        # Production and Testing url
        endurl = superself.momken_prod_url
        if superself.environment == "test":
            endurl = superself.momken_test_url

        # _logger.info("endurl             >>>>>>>>>>>>>>>>>>>>> " + endurl)
        # _logger.info("login              >>>>>>>>>>>>>>>>>>>>> " + momken_channel.masary_login)
        # _logger.info("password           >>>>>>>>>>>>>>>>>>>>> " + momken_channel.masary_password)
        # _logger.info("version            >>>>>>>>>>>>>>>>>>>>> " + str(superself.masary_version))
        # _logger.info("terminalId         >>>>>>>>>>>>>>>>>>>>> " + momken_channel.masary_terminalId)
        srm = MOMKENRequest(debug_logger=self.log_xml, endurl=endurl, env=self.env,
                            login=momken_channel.masary_login, password=momken_channel.masary_password,
                            version=superself.masary_version, terminalId=momken_channel.masary_terminalId)

        custLangPref = 'EN'
        if lang == 'ar_AA' or (lang != 'en_US' and self.env.user.lang == 'ar_AA'):
            custLangPref = 'AR'

        accountNumber = momken_channel.masary_account_number
        if not accountNumber:
            result_account = self.get_masary_account_details(momken_channel)
            if (result_account.get("accountData")):
                accountNumber = result_account["accountData"]["account_list"][0]["account_number"]
                momken_channel.sudo().update({'masary_account_number': accountNumber})

        data = {"service_version": momken_channel.momken_service_version, "account_number": accountNumber,
                "service_id": billTypeCode}
        if inputParameterList:
            data.update({"input_parameter_list": inputParameterList})
        result_bill = srm.get_bill_details(custLangPref, data=data)
        if result_bill.get('billData'):
            result['Success'] = result_bill['billData']
            '''
            elif result_bill.get("error_code") == '1025':
                
                # retry = True
                # while retry:
                    # # momken_channel.sudo().update({'momken_service_version': 0})
                    # self.auto_fetch_masary_biller_details()
                    # result = self.get_masary_bill_details(lang, billTypeCode, inputParameterList, momken_channel)
                    # if not result.get("error_code") or result.get("error_code") != '1025':
                        # retry = False
                self.auto_fetch_masary_biller_details()
                result = result_bill
            '''
        else:
            result = result_bill

        return result

    def pay_masary_bill(self, lang, billTypeCode, amt, feeAmt,
                        inquiryTransactionId=None, quantity=None,
                        inputParameterList=None, momken_channel=None):
        superself = self.sudo()
        result = {}

        if not momken_channel and superself.momken_channel_ids:
            momken_channel = superself.momken_channel_ids[0]
        elif not momken_channel and not superself.momken_channel_ids:
            raise ValidationError(
                _('The pay of masary bill cannot be processed because the masary has not any chennel in confiquration!'))

        # Production and Testing url
        endurl = superself.momken_prod_url
        if superself.environment == "test":
            endurl = superself.momken_test_url

        # _logger.info("endurl             >>>>>>>>>>>>>>>>>>>>> " + endurl)
        # _logger.info("login              >>>>>>>>>>>>>>>>>>>>> " + momken_channel.masary_login)
        # _logger.info("password           >>>>>>>>>>>>>>>>>>>>> " + momken_channel.masary_password)
        # _logger.info("version            >>>>>>>>>>>>>>>>>>>>> " + str(superself.masary_version))
        # _logger.info("terminalId         >>>>>>>>>>>>>>>>>>>>> " + momken_channel.masary_terminalId)
        srm = MOMKENRequest(debug_logger=self.log_xml, endurl=endurl, env=self.env,
                            login=momken_channel.masary_login, password=momken_channel.masary_password,
                            version=superself.masary_version, terminalId=momken_channel.masary_terminalId)

        custLangPref = 'EN'
        if lang == 'ar_AA' or (lang != 'en_US' and self.env.user.lang == 'ar_AA'):
            custLangPref = 'AR'

        accountNumber = momken_channel.masary_account_number
        if not accountNumber:
            result_account = self.get_masary_account_details(momken_channel)
            if (result_account.get("accountData")):
                accountNumber = result_account["accountData"]["account_list"][0]["account_number"]
                momken_channel.sudo().update({'masary_account_number': accountNumber})

        total_amount = float(amt) + float(feeAmt)
        data = {"external_id": str(uuid.uuid1().time_low), "service_version": momken_channel.momken_service_version,
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
            '''
            elif result_bill.get("error_code") == '1025':

                # retry = True
                # while retry:
                    # # momken_channel.sudo().update({'momken_service_version': 0})
                    # self.auto_fetch_masary_biller_details()
                    # result = self.get_masary_bill_details(lang, billTypeCode, inputParameterList, momken_channel)
                    # if not result.get("error_code") or result.get("error_code") != '1025':
                        # retry = False
                self.auto_fetch_masary_biller_details()
                result = result_bill
            '''
        else:
            result = result_bill

        return result
