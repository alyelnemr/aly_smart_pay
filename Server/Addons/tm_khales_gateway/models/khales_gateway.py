# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.
import threading
import logging
import psycopg2
import requests
import urllib3
import urllib.parse
from datetime import datetime, timedelta
from odoo import api, fields, models, registry, SUPERUSER_ID, tools, _
from odoo.exceptions import ValidationError

from .khales_request import KHALESRequest
from odoo.addons.tm_base_gateway.common import (
    suds_to_json,
)

_logger = logging.getLogger(__name__)

token_lock = threading.Lock()

logging.basicConfig(level=logging.INFO)
logging.getLogger('suds.client').setLevel(logging.DEBUG)
logging.getLogger('suds.transport').setLevel(logging.DEBUG)


class AcquirerKhalesChannel(models.Model):
    _inherit = 'payment.acquirer.channel'
    _order = "sequence"

    khales_sender = fields.Char('Sender', required_if_provider='khales', groups='base.group_user')  # sender: 0023
    khales_receiver = fields.Char('Receiver', required_if_provider='khales', groups='base.group_user')  # receiver: EPAY
    # khales_originatorCode = fields.Char('Originator Code', required_if_provider='khales', groups='base.group_user')             # originatorCode: SmartPay2
    # khales_terminalId = fields.Char('Terminal ID', required_if_provider='khales', groups='base.group_user')                     # terminalId: 104667
    # khales_posSerialNumber = fields.Char('POS Serial Number', groups='base.group_user')                                         # SerialNumber: 332-491-1222
    # khales_deliveryMethod = fields.Char('Delivery Method', required_if_provider='khales', groups='base.group_user')             # DeliveryMethod: MOB
    # khales_profileCode = fields.Char('Profile Code', required_if_provider='khales', groups='base.group_user')                   # ProfileCode: 22013
    khales_bankId = fields.Char('Bank ID', required_if_provider='khales', groups='base.group_user')  # bankId: 1023
    # khales_acctId = fields.Char('Account ID', required_if_provider='khales', groups='base.group_user')                          # acctId: 104667
    # khales_acctType = fields.Char("Account Type", required_if_provider='khales', groups='base.group_user', default='SDA')       # acctType: SDA
    # khales_acctKey = fields.Char('Account Key', required_if_provider='khales', groups='base.group_user')                        # acctKey: 1234
    # khales_secureAcctKey = fields.Char('Secure Account Key', required_if_provider='khales', groups='base.group_user')           # secureAcctKey: gdyb21LQTcIANtvYMT7QVQ==
    khales_acctCur = fields.Many2one("res.currency", string='Account Currency', required_if_provider='khales',
                                     groups='base.group_user',
                                     default=lambda self: self.env.user.company_id.currency_id)  # acctCur: EGP
    khales_acctCurCode = fields.Char('Account Currency Code', required_if_provider='khales', groups='base.group_user',
                                     default='818')  # acctCurCode: 818
    khales_pmtType = fields.Char('Payment Type', required_if_provider='khales', groups='base.group_user',
                                 default='BNKPTN')  # pmtType: BNKPTN
    khales_pmtMethod = fields.Char('Payment Method', required_if_provider='khales', groups='base.group_user',
                                   default='ACTDEB')  # pmtMethod: ACTDEB
    khales_accessChannel = fields.Selection(
        [('ATM', 'Bank ATM'), ('IVR', 'Interactive Voice Recognition System'), ('KIOSK', 'Bank Kiosk'),
         ('INTERNET', 'Internet Browser'), ('PORTAL', 'EPAY’s Portal for Bank/Biller Interfacing'),
         ('BTELLER', 'Bank Teller'), ('POS', 'Point of Sale'), ('DDS', 'Direct Debit Service')],
        string='Access Chennel', default='POS',
        required_if_provider='khales', groups='base.group_user')

    khales_client_id = fields.Char('Client ID', groups='base.group_user')
    khales_client_secret = fields.Char('Client Secret', groups='base.group_user')
    khales_client_grant_type = fields.Char('Client Grant Type', groups='base.group_user')
    khales_url_access_token = fields.Char('Khales Url Access Token', groups='base.group_user')

    def _generate_access_token(self):
        self.ensure_one()
        _logger.info("----->>>>>>>>> Generating access token")
        url = self.khales_url_access_token
        grant_type = self.khales_client_grant_type
        client_secret = self.khales_client_secret
        client_id = self.khales_client_id
        client_secret = urllib.parse.quote(client_secret, safe='!')
        payload = 'grant_type={}&client_secret={}&client_id={}'.format(grant_type, client_secret, client_id)

        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        urllib3.disable_warnings()
        _logger.info('---->> Payload {}'.format(payload))
        timeout = 3
        message = ''
        while timeout > 0:
            try:
                response = requests.post(url, headers=headers, data=payload, verify=False, timeout=5)
                token = response.json()
                _logger.info("Successfully generation access token {}".format(token))
                return token
            except Exception as e:
                message = 'Exception while generating access token: {}'.format(str(e))
            timeout -= 1
        _logger.error(message)
        return {}


class AcquirerKhales(models.Model):
    _inherit = 'payment.acquirer'

    provider = fields.Selection(selection_add=[('khales', 'Khales')])

    khales_access_token = fields.Char('Khales Access Token', copy=False)
    expiry_period = fields.Integer("Token Expire After(Seconds)", copy=False)
    date_time_expire = fields.Datetime("Datetime Token Expire", copy=False)

    # khales_sender = fields.Char('Sender', required_if_provider='khales', groups='base.group_user')                              # sender: SmartPay2_MOB                        ==> Per Channel
    # khales_receiver = fields.Char('Receiver', required_if_provider='khales', groups='base.group_user')                          # receiver: SmartPay2
    # khales_version =  fields.Char("Interface Version", required_if_provider='khales', default='V1.0')                           # version: V1.0
    # khales_originatorCode = fields.Char('Originator Code', required_if_provider='khales', groups='base.group_user')             # originatorCode: SmartPay2
    # khales_terminalId = fields.Char('Terminal ID', required_if_provider='khales', groups='base.group_user')                     # terminalId: 104667                           ==> Per Channel
    # khales_deliveryMethod = fields.Char('Delivery Method', required_if_provider='khales', groups='base.group_user')             # DeliveryMethod: MOB                          ==> Per Channel
    # khales_profileCode = fields.Char('Profile Code', required_if_provider='khales', groups='base.group_user')                   # ProfileCode: 22013                           ==> Per Channel
    # khales_posSerialNumber = fields.Char('POS Serial Number', required_if_provider='khales', groups='base.group_user')          # posSerialNumber: 332-491-1222
    # khales_bankId = fields.Char('Bank ID', required_if_provider='khales', groups='base.group_user')                             # bankId: SmartPay2
    # khales_acctId = fields.Char('Account ID', required_if_provider='khales', groups='base.group_user')                          # acctId: 104667                               ==> Per Channel
    # khales_acctType = fields.Char("Account Type", required_if_provider='khales', groups='base.group_user', default='SDA')       # acctType: SDA
    # khales_acctKey = fields.Char('Account Key', required_if_provider='khales', groups='base.group_user')                        # acctKey: 1234
    # khales_secureAcctKey = fields.Char('Secure Account Key', required_if_provider='khales', groups='base.group_user')           # secureAcctKey: gdyb21LQTcIANtvYMT7QVQ==
    # khales_acctCur = fields.Many2one("res.currency", string='Account Currency', required_if_provider='khales',
    #                                 groups='base.group_user', default=lambda self: self.env.user.company_id.currency_id)      # acctCur: EGP

    khales_test_url = fields.Char("Test url", required_if_provider='khales',
                                  default='http://10.60.0.138:9081/bulkpay/BillPaymentService')
    khales_prod_url = fields.Char("Production url", required_if_provider='khales',
                                  default='http://10.60.0.138:9081/bulkpay/BillPaymentService')

    khales_channel_ids = fields.One2many('payment.acquirer.channel', 'acquirer_id', string='Khales Channels',
                                         copy=False)

    def is_khales_token_valid(self):
        """Check if the token is valid."""
        self.ensure_one()
        if not (self.khales_access_token and self.date_time_expire):
            return False
        return self.date_time_expire and (self.date_time_expire + timedelta(seconds=-10)) > datetime.now()

    def _default_provider_channel(self):
        return self.search([('provider', '=', 'khales')], limit=1).khales_channel_ids

    @api.model
    def khales_generate_access_token(self):
        """Generate access token from Khales.
           Lock the access token generation process to avoid concurrency issues
           pass default_provider_channel or get _default_provider_channel
            """
        with token_lock:
            provider_channel = self._context.get('default_provider_channel') or self._default_provider_channel()
            provider_channel = provider_channel.filtered(lambda x:
                                                         x.khales_client_id and
                                                         x.khales_client_secret and
                                                         x.khales_client_grant_type and
                                                         x.khales_url_access_token)
            provider_channel = provider_channel and provider_channel[0]

            access_token = provider_channel.acquirer_id.khales_access_token
            if provider_channel.acquirer_id.is_khales_token_valid():
                return access_token
            # if not self.khales_channel.acquirer_id.is_khales_token_valid():
            _logger.info("->>>>>> Run generate access token cron job")

            if not provider_channel:
                _logger.info("Not found provider channel")
                return False
            token_data = provider_channel._generate_access_token()
            if not token_data:
                _logger.info("Failed to generate access token")
                return False
            """
            {'access_token': 'T1amGT21.Idup.e068be3f3e6deb40fe37e13a9972446b',
             'token_type': 'Bearer', 'expires_in': 59}
            """
            provider_channel.acquirer_id.write({
                'khales_access_token': token_data.get('access_token', False),
                'expiry_period': token_data.get('expires_in', False),
                'date_time_expire': datetime.now() +
                                    timedelta(seconds=int(token_data.get('expires_in', 0))),
            })
            self.env.cr.commit()
            return provider_channel.acquirer_id.khales_access_token

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

    @api.onchange('khales_prod_url', 'khales_test_url')
    def _onchange_khales_url(self):
        self.server_url = self.khales_prod_url
        if self.environment == "test":
            self.server_url = self.khales_test_url
        # _logger.info("[%s] ==> (%s, %s): %s" % (self.environment, self.khales_prod_url, self.khales_test_url, self.server_url))

    def get_khales_biller_details(self, khales_channel=None):
        superself = self.sudo()

        if not khales_channel and superself.khales_channel_ids:
            khales_channel = superself.khales_channel_ids[0]
        elif not khales_channel and not superself.khales_channel_ids:
            raise ValidationError(
                _('The fetch of khales biller details cannot be processed because the khales has not any chennel in confiquration!'))

        # Production and Testing url
        endurl = superself.khales_prod_url
        # suppressEcho = False
        if superself.environment == "test":
            endurl = superself.khales_test_url
            # suppressEcho = True

        '''
            sender, receiver, # version, originatorCode, terminalId, deliveryMethod,  # msgCode: BRSINQRQ, RBINQRQ, RFINQRQ, RPADVRQ and CNLPMTRQ
            # profileCode,                                                              # msgCode: BillerInqRq
            bankId,                                                                   # msgCode: RBINQRQ, RPADVRQ and CNLPMTRQ
            # acctId, acctType, acctKey, secureAcctKey, acctCur, posSerialNumber        # msgCode: PmtAddRq
            accessChannel,                                                            # msgCode: RBINQRQ, RPADVRQ and CNLPMTRQ
            acctCur                                                                   # msgCode: RFINQRQ, RPADVRQ and CNLPMTRQ
        '''
        # _logger.info("endurl             >>>>>>>>>>>>>>>>>>>>> " + endurl)
        # _logger.info("sender             >>>>>>>>>>>>>>>>>>>>> " + khales_channel.khales_sender)
        # _logger.info("receiver           >>>>>>>>>>>>>>>>>>>>> " + khales_channel.khales_receiver)
        # # _logger.info("version            >>>>>>>>>>>>>>>>>>>>> " + superself.khales_version)
        # # _logger.info("originatorCode     >>>>>>>>>>>>>>>>>>>>> " + khales_channel.khales_originatorCode)
        # # _logger.info("terminalId         >>>>>>>>>>>>>>>>>>>>> " + khales_channel.khales_terminalId)
        # # _logger.info("deliveryMethod     >>>>>>>>>>>>>>>>>>>>> " + khales_channel.khales_deliveryMethod)
        srm = KHALESRequest(debug_logger=self.log_xml, endurl=endurl, env=self.env, sender=khales_channel.khales_sender,
                            receiver=khales_channel.khales_receiver,
                            # version=superself.khales_version, originatorCode=khales_channel.khales_originatorCode
                            # terminalId=khales_channel.khales_terminalId, deliveryMethod=khales_channel.khales_deliveryMethod
                            khales_channel=khales_channel)

        result = {}
        # Tamayoz TODO: Loop for Khales languagePref enum
        for languagePref in ['en-gb'
                             # , 'ar-eg'
                             ]:
            result_biller = srm.get_biller_details(languagePref)
            if result_biller.get('serviceGroupTypes'):  # result_biller.get('billerRecTypes'):
                result['serviceGroupTypes_' + languagePref] = result_biller[
                    'serviceGroupTypes']  # result['billerRecTypes_'+languagePref] = result_biller['billerRecTypes']
            else:
                result = result_biller

        return result

    def auto_fetch_khales_biller_details(self):
        khales = self.env['payment.acquirer'].sudo().search([("provider", "=", "khales")])
        result = khales.get_khales_biller_details()
        fetch_success = False

        # Tamayoz TODO: Loop for Khales languagePref enum
        for languagePref in ['en-gb'
                             # , 'ar-eg'
                             ]:
            serviceGroupTypes = result.get('serviceGroupTypes_' + languagePref)
            if serviceGroupTypes:
                fetch_success = True
                for serviceGroupType in serviceGroupTypes:
                    _logger.info(
                        " ====================================== Biller Fetch Data Begin " + serviceGroupType.Code + ": " + languagePref + " =========================================")
                    serviceGroupCode = serviceGroupType.Code
                    serviceGroupName = serviceGroupType.Name

                    # Fetch Khales Service Category
                    service_categ_providerinfo = self.env['product_category.providerinfo'].sudo().search([
                        ('product_categ_code', '=', serviceGroupCode), ('provider_id', '=', khales.id)
                    ])
                    if not service_categ_providerinfo:
                        service_category_vals = {
                            'name': serviceGroupName,
                            'parent_id': self.env.ref("tm_base_gateway.product_category_services").id,
                            'property_cost_method': 'standard',
                            'provider_ids': [(0, 0, {
                                'product_categ_code': serviceGroupCode,
                                'product_categ_name': serviceGroupName,
                                'provider_id': khales.id,
                            })],
                        }
                        service_category = self.env['product.category'].sudo().create(service_category_vals)
                        service_categ_providerinfo = service_category.provider_ids[0]
                    else:
                        if languagePref == 'en-gb':
                            service_categ_providerinfo.sudo().write({'product_categ_name': serviceGroupName})
                        elif languagePref == 'ar-eg':
                            serviceGroupName_translate = self.env['ir.translation'].sudo().search([
                                ('type', '=', 'model'),
                                ('name', '=', 'product.category,name'),
                                ('module', '=', 'product'),
                                ('lang', '=', 'ar_AA'),
                                ('res_id', '=', service_categ_providerinfo.product_categ_id.id),
                                ('state', '=', 'translated')
                            ])

                            if not serviceGroupName_translate:
                                serviceGroupName_translate = self.env['ir.translation'].sudo().create({
                                    'type': 'model',
                                    'name': 'product.category,name',
                                    'module': 'product',
                                    'lang': 'ar_AA',
                                    'res_id': service_categ_providerinfo.product_categ_id.id,
                                    'value': serviceGroupName,
                                    'state': 'translated',
                                })
                            else:
                                serviceGroupName_translate.sudo().write({"value": serviceGroupName})

                    serviceTypes = serviceGroupType.ServiceTypeList.ServiceType
                    if serviceTypes:
                        for serviceType in serviceTypes:
                            # _logger.info(" ===== serviceType Json >>>>> " + suds_to_json(serviceType) + " =====")
                            serviceTypeCode = serviceType.Code
                            serviceTypeArName = serviceType.Ar_Name
                            serviceTypeEnName = serviceType.En_Name

                            # Fetch Khales Service Type
                            service_type_providerinfo = self.env['product_category.providerinfo'].sudo().search([
                                ('product_categ_code', '=', serviceTypeCode),
                                ('provider_id', '=', khales.id),
                                ('product_categ_id.parent_id', '=', service_categ_providerinfo.product_categ_id.id)
                            ])
                            if not service_type_providerinfo:
                                service_type_vals = {
                                    'name': serviceTypeEnName,
                                    'parent_id': service_categ_providerinfo.product_categ_id.id,
                                    'property_cost_method': 'standard',
                                    'provider_ids': [(0, 0, {
                                        'product_categ_code': serviceTypeCode,
                                        'product_categ_name': serviceTypeEnName,
                                        'provider_id': khales.id,
                                    })],
                                }
                                service_type = self.env['product.category'].sudo().create(service_type_vals)
                                service_type_providerinfo = service_type.provider_ids[0]

                                serviceTypeName_translate = self.env['ir.translation'].sudo().create({
                                    'type': 'model',
                                    'name': 'product.category,name',
                                    'module': 'product',
                                    'lang': 'ar_AA',
                                    'res_id': service_type_providerinfo.product_categ_id.id,
                                    'value': serviceTypeArName,
                                    'state': 'translated',
                                })
                            else:
                                if languagePref == 'en-gb':
                                    service_type_providerinfo.sudo().write({"product_categ_name": serviceTypeEnName})
                                elif languagePref == 'ar-eg':
                                    serviceTypeName_translate = self.env['ir.translation'].sudo().search([
                                        ('type', '=', 'model'),
                                        ('name', '=', 'product.category,name'),
                                        ('module', '=', 'product'),
                                        ('lang', '=', 'ar_AA'),
                                        ('res_id', '=', service_type_providerinfo.product_categ_id.id),
                                        ('state', '=', 'translated')
                                    ])

                                    if not serviceTypeName_translate:
                                        serviceType_translate = self.env['ir.translation'].sudo().create({
                                            'type': 'model',
                                            'name': 'product.category,name',
                                            'module': 'product',
                                            'lang': 'ar_AA',
                                            'res_id': service_type_providerinfo.product_categ_id.id,
                                            'value': serviceTypeArName,
                                            'state': 'translated',
                                        })
                                    else:
                                        serviceTypeName_translate.sudo().write({"value": serviceTypeArName})

                            billers = serviceType.BillerList.Biller
                            if billers:
                                for biller in billers:
                                    # _logger.info(" ===== biller Json >>>>> " + suds_to_json(biller) + " =====")
                                    billerCode = biller.Code
                                    billerParentCode = biller.ParentBillerCode
                                    billerArName = biller.Ar_Name
                                    billerEnName = biller.En_Name

                                    '''
                                    # Fetch Khales Service Provider
                                    service_provider_providerinfo = self.env[
                                        'product_category.providerinfo'].sudo().search([
                                        ('product_categ_code', '=', billerCode),
                                        ('provider_id', '=', khales.id),
                                        ('product_categ_id.parent_id', '=',
                                         service_type_providerinfo.product_categ_id.id)
                                    ])
                                    if not service_provider_providerinfo:
                                        service_provider_vals = {
                                            'name': billerEnName,
                                            'parent_id': service_type_providerinfo.product_categ_id.id,
                                            'property_cost_method': 'standard',
                                            'provider_ids': [(0, 0, {
                                                'product_categ_code': billerCode,
                                                'product_categ_name': billerEnName,
                                                'provider_id': khales.id,
                                            })],
                                        }
                                        service_provider = self.env['product.category'].sudo().create(service_provider_vals)
                                        service_provider_providerinfo = service_provider.provider_ids[0]

                                        serviceProviderName_translate = self.env['ir.translation'].sudo().create({
                                            'type': 'model',
                                            'name': 'product.category,name',
                                            'module': 'product',
                                            'lang': 'ar_AA',
                                            'res_id': service_provider_providerinfo.product_categ_id.id,
                                            'value': billerArName,
                                            'state': 'translated',
                                        })
                                    '''

                                    # Fetch Khales Service
                                    service_providerinfo = self.env['product.supplierinfo'].sudo().search([
                                        ('product_code', '=',  # billerCode + '#' +
                                         serviceTypeCode),
                                        ('name', '=', khales.related_partner.id),
                                        ('product_tmpl_id.categ_id', '=', service_type_providerinfo.product_categ_id.id
                                         # service_provider_providerinfo.product_categ_id.id
                                         )
                                    ])
                                    if not service_providerinfo:
                                        service_vals = {
                                            'name': billerEnName + ' ' + serviceTypeEnName,
                                            'type': 'service',
                                            'categ_id': service_type_providerinfo.product_categ_id.id,
                                            # service_provider_providerinfo.product_categ_id.id,
                                            'seller_ids': [(0, 0, {
                                                'name': khales.related_partner.id,
                                                'product_code':  # billerCode + '#' +
                                                    serviceTypeCode,
                                                'product_name': billerEnName + ' ' + serviceTypeEnName,
                                                'biller_info': suds_to_json(biller),
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
                                        service = self.env['product.product'].sudo().create(service_vals)
                                        service_providerinfo = service.seller_ids[0]

                                        serviceName_translate = self.env['ir.translation'].sudo().create({
                                            'type': 'model',
                                            'name': 'product.template,name',
                                            'module': 'product',
                                            'lang': 'ar_AA',
                                            'res_id': service_providerinfo.product_tmpl_id.id,
                                            'value': billerArName + ' ' + serviceTypeArName,
                                            'state': 'translated',
                                        })

                                        billerInfo_translate = self.env['ir.translation'].sudo().create({
                                            'type': 'model',
                                            'name': 'product.supplierinfo,biller_info',
                                            'module': 'product',
                                            'lang': 'ar_AA',
                                            'res_id': service_providerinfo.id,
                                            'value': suds_to_json(biller),
                                            'state': 'translated',
                                        })
                                    else:
                                        if languagePref == 'en-gb':
                                            service_providerinfo.sudo().write(
                                                {'product_name': billerEnName + ' ' + serviceTypeEnName,
                                                 'biller_info': suds_to_json(biller)
                                                 })
                                        elif languagePref == 'ar-eg':
                                            serviceName_translate = self.env['ir.translation'].sudo().search([
                                                ('type', '=', 'model'),
                                                ('name', '=', 'product.template,name'),
                                                ('module', '=', 'product'),
                                                ('lang', '=', 'ar_AA'),
                                                ('res_id', '=', service_providerinfo.product_tmpl_id.id),
                                                ('state', '=', 'translated')
                                            ])

                                            if not serviceName_translate:
                                                serviceName_translate = self.env['ir.translation'].sudo().create({
                                                    'type': 'model',
                                                    'name': 'product.template,name',
                                                    'module': 'product',
                                                    'lang': 'ar_AA',
                                                    'res_id': service_providerinfo.product_tmpl_id.id,
                                                    'value': billerArName + ' ' + serviceTypeArName,
                                                    'state': 'translated',
                                                })
                                            else:
                                                serviceName_translate.sudo().write(
                                                    {"value": billerArName + ' ' + serviceTypeArName})

                                            billerInfo_translate = self.env['ir.translation'].sudo().search([
                                                ('type', '=', 'model'),
                                                ('name', '=', 'product.supplierinfo,biller_info'),
                                                ('module', '=', 'product'),
                                                ('lang', '=', 'ar_AA'),
                                                ('res_id', '=', service_providerinfo.id),
                                                ('state', '=', 'translated')
                                            ])

                                            if not billerInfo_translate:
                                                billerInfo_translate = self.env['ir.translation'].sudo().create({
                                                    'type': 'model',
                                                    'name': 'product.supplierinfo,biller_info',
                                                    'module': 'product',
                                                    'lang': 'ar_AA',
                                                    'res_id': service_providerinfo.id,
                                                    'value': suds_to_json(biller),
                                                    'state': 'translated',
                                                })
                                            else:
                                                billerInfo_translate.sudo().write({"value": suds_to_json(biller)})
                                    '''
                                    else:
                                        if languagePref == 'en-gb':
                                            service_provider_providerinfo.sudo().write({"product_categ_name": billerEnName})
                                        elif languagePref == 'ar-eg':
                                            serviceProviderName_translate = self.env['ir.translation'].sudo().search([
                                                ('type', '=', 'model'),
                                                ('name', '=', 'product.category,name'),
                                                ('module', '=', 'product'),
                                                ('lang', '=', 'ar_AA'),
                                                ('res_id', '=', service_provider_providerinfo.product_categ_id.id),
                                                ('state', '=', 'translated')
                                            ])

                                            if not serviceProviderName_translate:
                                                serviceProviderName_translate = self.env['ir.translation'].sudo().create({
                                                    'type': 'model',
                                                    'name': 'product.category,name',
                                                    'module': 'product',
                                                    'lang': 'ar_AA',
                                                    'res_id': service_provider_providerinfo.product_categ_id.id,
                                                    'value': billerArName,
                                                    'state': 'translated',
                                                })
                                            else:
                                                serviceProviderName_translate.sudo().write({"value": billerArName})
                                    '''
                                    '''
                                    subBillers = biller.SubBillerList.Biller
                                    if subBillers:
                                        for subBiller in subBillers:
                                            # _logger.info(" ===== subBiller Json >>>>> " + suds_to_json(subBiller) + " =====")
                                            subBillerCode = subBiller.Code
                                            subBillerParentCode = subBiller.ParentBillerCode
                                            subBillerArName = subBiller.Ar_Name
                                            subBillerEnName = subBiller.En_Name
                                    '''

                    _logger.info(
                        " ====================================== Biller Fetch Data End " + serviceGroupType.Code + ": " + languagePref + " =========================================")

        if not fetch_success:
            _logger.exception("Failed processing khales biller inquiry")
            return False
        else:
            return True

    def get_khales_bill_details(self, lang, posSerialNumber,
                                # billTypeCode, billingAcct, extraBillingAcctKeys,
                                serviceType, billerId, billingAcct, additionInfo,
                                khales_channel=None, requestNumber=None):
        superself = self.sudo()

        if not khales_channel and superself.khales_channel_ids:
            khales_channel = superself.khales_channel_ids[0]
        elif not khales_channel and not superself.khales_channel_ids:
            raise ValidationError(
                _('The fetch of khales bill details cannot be processed because the khales has not any chennel in confiquration!'))

        # Production and Testing url
        endurl = superself.khales_prod_url
        # suppressEcho = False
        if superself.environment == "test":
            endurl = superself.khales_test_url
            # suppressEcho = True

        '''
            sender, receiver, # version, originatorCode, terminalId, deliveryMethod,  # msgCode: BRSINQRQ, RBINQRQ, RFINQRQ, RPADVRQ and CNLPMTRQ
            # profileCode,                                                              # msgCode: BillerInqRq
            bankId,                                                                   # msgCode: RBINQRQ, RPADVRQ and CNLPMTRQ
            # acctId, acctType, acctKey, secureAcctKey, acctCur, posSerialNumber        # msgCode: PmtAddRq
            accessChannel,                                                            # msgCode: RBINQRQ, RPADVRQ and CNLPMTRQ
            acctCur                                                                   # msgCode: RFINQRQ, RPADVRQ and CNLPMTRQ
        '''
        # _logger.info("endurl             >>>>>>>>>>>>>>>>>>>>> " + endurl)
        # _logger.info("sender             >>>>>>>>>>>>>>>>>>>>> " + khales_channel.khales_sender)
        # _logger.info("receiver           >>>>>>>>>>>>>>>>>>>>> " + khales_channel.khales_receiver)
        # # _logger.info("version            >>>>>>>>>>>>>>>>>>>>> " + superself.khales_version)
        # # _logger.info("originatorCode     >>>>>>>>>>>>>>>>>>>>> " + khales_channel.khales_originatorCode)
        # # _logger.info("terminalId         >>>>>>>>>>>>>>>>>>>>> " + khales_channel.khales_terminalId)
        # # _logger.info("deliveryMethod     >>>>>>>>>>>>>>>>>>>>> " + khales_channel.khales_deliveryMethod)
        # _logger.info("bankId             >>>>>>>>>>>>>>>>>>>>> " + khales_channel.khales_bankId)
        # _logger.info("accessChannel      >>>>>>>>>>>>>>>>>>>>> " + khales_channel.khales_accessChannel)
        srm = KHALESRequest(debug_logger=self.log_xml, endurl=endurl, env=self.env, sender=khales_channel.khales_sender,
                            receiver=khales_channel.khales_receiver,
                            # version=superself.khales_version, originatorCode=khales_channel.khales_originatorCode,
                            # terminalId=khales_channel.khales_terminalId, deliveryMethod=khales_channel.khales_deliveryMethod,
                            bankId=khales_channel.khales_bankId, accessChannel=khales_channel.khales_accessChannel,
                            khales_channel=khales_channel)

        result = {}
        languagePref = 'en-gb'
        if lang == 'ar_AA' or (lang != 'en_US' and self.env.user.lang == 'ar_AA'):
            languagePref = 'ar-eg'
        result_bill = srm.get_bill_details(languagePref, posSerialNumber, serviceType, billerId, billingAcct,
                                           additionInfo, requestNumber)
        if result_bill.get('billRecType'):
            result['Success'] = result_bill['billRecType']
        else:
            result = result_bill

        return result

    def get_khales_fees(self, lang, posSerialNumber,
                        ePayBillRecID, payAmts,
                        khales_channel=None, requestNumber=None):
        superself = self.sudo()

        if not khales_channel and superself.khales_channel_ids:
            khales_channel = superself.khales_channel_ids[0]
        elif not khales_channel and not superself.khales_channel_ids:
            raise ValidationError(
                _('The fetch of khales fees details cannot be processed because the khales has not any chennel in confiquration!'))

        # Production and Testing url
        endurl = superself.khales_prod_url
        # suppressEcho = False
        if superself.environment == "test":
            endurl = superself.khales_test_url
            # suppressEcho = True

        '''
            sender, receiver, # version, originatorCode, terminalId, deliveryMethod,  # msgCode: BRSINQRQ, RBINQRQ, RFINQRQ, RPADVRQ and CNLPMTRQ
            # profileCode,                                                              # msgCode: BillerInqRq
            bankId,                                                                   # msgCode: RBINQRQ, RPADVRQ and CNLPMTRQ
            # acctId, acctType, acctKey, secureAcctKey, acctCur, posSerialNumber        # msgCode: PmtAddRq
            accessChannel,                                                            # msgCode: RBINQRQ, RPADVRQ and CNLPMTRQ
            acctCur                                                                   # msgCode: RFINQRQ, RPADVRQ and CNLPMTRQ
        '''
        # _logger.info("endurl             >>>>>>>>>>>>>>>>>>>>> " + endurl)
        # _logger.info("sender             >>>>>>>>>>>>>>>>>>>>> " + khales_channel.khales_sender)
        # _logger.info("receiver           >>>>>>>>>>>>>>>>>>>>> " + khales_channel.khales_receiver)
        # # _logger.info("version            >>>>>>>>>>>>>>>>>>>>> " + superself.khales_version)
        # # _logger.info("originatorCode     >>>>>>>>>>>>>>>>>>>>> " + khales_channel.khales_originatorCode)
        # # _logger.info("terminalId         >>>>>>>>>>>>>>>>>>>>> " + khales_channel.khales_terminalId)
        # # _logger.info("deliveryMethod     >>>>>>>>>>>>>>>>>>>>> " + khales_channel.khales_deliveryMethod)
        # _logger.info("acctCur            >>>>>>>>>>>>>>>>>>>>> " + khales_channel.khales_acctCur)
        srm = KHALESRequest(debug_logger=self.log_xml, endurl=endurl, env=self.env, sender=khales_channel.khales_sender,
                            receiver=khales_channel.khales_receiver,
                            # version=superself.khales_version, originatorCode=khales_channel.khales_originatorCode,
                            # terminalId=khales_channel.khales_terminalId, deliveryMethod=khales_channel.khales_deliveryMethod,
                            bankId=khales_channel.khales_bankId,
                            acctCur=khales_channel.khales_acctCur,
                            khales_channel=khales_channel)

        result = {}  # ,
        languagePref = 'en-gb'
        if lang == 'ar_AA' or (lang != 'en_US' and self.env.user.lang == 'ar_AA'):
            languagePref = 'ar-eg'
        result_fees = srm.get_fees(languagePref, posSerialNumber, ePayBillRecID, payAmts, requestNumber)
        if result_fees.get('feeInqRsType'):
            result['Success'] = result_fees['feeInqRsType']
        else:
            result = result_fees

        return result

    def pay_khales_bill(self, lang, posSerialNumber,  # billTypeCode,
                        # billingAcct, extraBillingAcctKeys,
                        # amt, curCode, pmtMethod,
                        # notifyMobile, billRefNumber,
                        # billerId, pmtType,
                        billingAcct, additionInfo, billerId, ePayBillRecID,
                        payAmts, pmtId, pmtIdType, feesAmts,
                        billNumber, pmtMethod, pmtRefInfo,
                        khales_channel, requestNumber=None,
                        isAllowCancel=True, isAllowRetry=False):
        superself = self.sudo()

        if not khales_channel and superself.khales_channel_ids:
            khales_channel = superself.khales_channel_ids[0]
        elif not khales_channel and not superself.khales_channel_ids:
            raise ValidationError(
                _('The pay of khales bill cannot be processed because the khales has not any chennel in confiquration!'))

        # Production and Testing url
        endurl = superself.khales_prod_url
        # suppressEcho = False
        if superself.environment == "test":
            endurl = superself.khales_test_url
            # suppressEcho = True

        '''
            sender, receiver, # version, originatorCode, terminalId, deliveryMethod,  # msgCode: BRSINQRQ, RBINQRQ, RFINQRQ, RPADVRQ and CNLPMTRQ
            # profileCode,                                                              # msgCode: BillerInqRq
            bankId,                                                                   # msgCode: RBINQRQ, RPADVRQ and CNLPMTRQ
            # acctId, acctType, acctKey, secureAcctKey, acctCur, posSerialNumber        # msgCode: PmtAddRq
            accessChannel,                                                            # msgCode: RBINQRQ, RPADVRQ and CNLPMTRQ
            acctCur                                                                   # msgCode: RFINQRQ, RPADVRQ and CNLPMTRQ
        '''
        # _logger.info("endurl             >>>>>>>>>>>>>>>>>>>>> " + endurl)
        # _logger.info("sender             >>>>>>>>>>>>>>>>>>>>> " + khales_channel.khales_sender)
        # _logger.info("receiver           >>>>>>>>>>>>>>>>>>>>> " + khales_channel.khales_receiver)
        # # _logger.info("version            >>>>>>>>>>>>>>>>>>>>> " + superself.khales_version)
        # # _logger.info("originatorCode     >>>>>>>>>>>>>>>>>>>>> " + khales_channel.khales_originatorCode)
        # # _logger.info("terminalId         >>>>>>>>>>>>>>>>>>>>> " + khales_channel.khales_terminalId)
        # # _logger.info("deliveryMethod     >>>>>>>>>>>>>>>>>>>>> " + khales_channel.khales_deliveryMethod)
        # _logger.info("bankId             >>>>>>>>>>>>>>>>>>>>> " + khales_channel.khales_bankId)
        # _logger.info("accessChannel      >>>>>>>>>>>>>>>>>>>>> " + khales_channel.khales_accessChannel)
        # _logger.info("acctCur            >>>>>>>>>>>>>>>>>>>>> " + khales_channel.khales_acctCur)
        srm = KHALESRequest(debug_logger=self.log_xml, endurl=endurl, env=self.env, sender=khales_channel.khales_sender,
                            receiver=khales_channel.khales_receiver,
                            # version=superself.khales_version, originatorCode=khales_channel.khales_originatorCode,
                            # terminalId=khales_channel.khales_terminalId, deliveryMethod=khales_channel.khales_deliveryMethod,
                            # posSerialNumber=khales_channel.khales_posSerialNumber,
                            bankId=khales_channel.khales_bankId,
                            # acctId=khales_channel.khales_acctId, acctType=khales_channel.khales_acctType,
                            # acctKey=khales_channel.khales_acctKey, secureAcctKey=khales_channel.khales_secureAcctKey,
                            accessChannel=khales_channel.khales_accessChannel, acctCur=khales_channel.khales_acctCur,
                            khales_channel=khales_channel)

        result = {}
        languagePref = 'en-gb'
        if lang == 'ar_AA' or (lang != 'en_US' and self.env.user.lang == 'ar_AA'):
            languagePref = 'ar-eg'
        result_bill = srm.pay_bill(languagePref, posSerialNumber, billingAcct, billerId, ePayBillRecID,
                                   payAmts, pmtId, pmtIdType, feesAmts,
                                   billNumber, pmtMethod, pmtRefInfo, additionInfo, requestNumber, isAllowCancel,
                                   isAllowRetry)
        if result_bill.get('pmtAdviceRsType'):  # result_bill.get('pmtInfoValType'):
            result['Success'] = result_bill['pmtAdviceRsType']  # result_bill['pmtInfoValType']
        # elif result_bill.get('error_code') == '0' or (result_bill.get('error_code') == '-1' and superself.environment == "test"):
        elif result_bill.get('error_code') in ('0', '-1', '-2', '8005', '9006'):  # 0 ==> timeout,
            # -1 ==> IOError,
            # -2 ==> Exception,
            # 8005 ==> Repeated RqUID,
            # 9006 ==> Unable to Match Payment With Existing Bill
            result['Success'] = srm._simulate_pay_bill_response(billingAcct, billerId, ePayBillRecID,
                                                                payAmts, pmtId, pmtIdType, feesAmts,
                                                                billNumber, pmtMethod, pmtRefInfo)
        else:
            result = result_bill

        return result

    def cancel_khales_payment(self, lang, posSerialNumber,
                              billingAcct, billerId, ePayBillRecID,
                              payAmts, pmtId, pmtIdType, feesAmts,
                              billNumber, pmtMethod, pmtRefInfo, cancelReason,
                              khales_channel, requestNumber=None):
        superself = self.sudo()

        if not khales_channel and superself.khales_channel_ids:
            khales_channel = superself.khales_channel_ids[0]
        elif not khales_channel and not superself.khales_channel_ids:
            raise ValidationError(
                _('The cancel of khales payment cannot be processed because the khales has not any chennel in confiquration!'))

        # Production and Testing url
        endurl = superself.khales_prod_url
        # suppressEcho = False
        if superself.environment == "test":
            endurl = superself.khales_test_url
            # suppressEcho = True

        '''
            sender, receiver, # version, originatorCode, terminalId, deliveryMethod,  # msgCode: BRSINQRQ, RBINQRQ, RFINQRQ, RPADVRQ and CNLPMTRQ
            # profileCode,                                                              # msgCode: BillerInqRq
            bankId,                                                                   # msgCode: RBINQRQ, RPADVRQ and CNLPMTRQ
            # acctId, acctType, acctKey, secureAcctKey, acctCur, posSerialNumber        # msgCode: PmtAddRq
            accessChannel,                                                            # msgCode: RBINQRQ, RPADVRQ and CNLPMTRQ
            acctCur                                                                   # msgCode: RFINQRQ, RPADVRQ and CNLPMTRQ
        '''
        # _logger.info("endurl             >>>>>>>>>>>>>>>>>>>>> " + endurl)
        # _logger.info("sender             >>>>>>>>>>>>>>>>>>>>> " + khales_channel.khales_sender)
        # _logger.info("receiver           >>>>>>>>>>>>>>>>>>>>> " + khales_channel.khales_receiver)
        # # _logger.info("version            >>>>>>>>>>>>>>>>>>>>> " + superself.khales_version)
        # # _logger.info("originatorCode     >>>>>>>>>>>>>>>>>>>>> " + khales_channel.khales_originatorCode)
        # # _logger.info("terminalId         >>>>>>>>>>>>>>>>>>>>> " + khales_channel.khales_terminalId)
        # # _logger.info("deliveryMethod     >>>>>>>>>>>>>>>>>>>>> " + khales_channel.khales_deliveryMethod)
        # _logger.info("bankId             >>>>>>>>>>>>>>>>>>>>> " + khales_channel.khales_bankId)
        # _logger.info("accessChannel      >>>>>>>>>>>>>>>>>>>>> " + khales_channel.khales_accessChannel)
        # _logger.info("acctCur            >>>>>>>>>>>>>>>>>>>>> " + khales_channel.khales_acctCur)
        srm = KHALESRequest(debug_logger=self.log_xml, endurl=endurl, env=self.env, sender=khales_channel.khales_sender,
                            receiver=khales_channel.khales_receiver,
                            # version=superself.khales_version, originatorCode=khales_channel.khales_originatorCode,
                            # terminalId=khales_channel.khales_terminalId, deliveryMethod=khales_channel.khales_deliveryMethod,
                            # posSerialNumber=khales_channel.khales_posSerialNumber,
                            bankId=khales_channel.khales_bankId,
                            # acctId=khales_channel.khales_acctId, acctType=khales_channel.khales_acctType,
                            # acctKey=khales_channel.khales_acctKey, secureAcctKey=khales_channel.khales_secureAcctKey,
                            accessChannel=khales_channel.khales_accessChannel, acctCur=khales_channel.khales_acctCur,
                            khales_channel=khales_channel)

        result = {}
        languagePref = 'en-gb'
        if lang == 'ar_AA' or (lang != 'en_US' and self.env.user.lang == 'ar_AA'):
            languagePref = 'ar-eg'
        result_payment = srm.cancel_payment(languagePref, posSerialNumber, billingAcct, billerId, ePayBillRecID,
                                            payAmts, pmtId, pmtIdType, feesAmts,
                                            billNumber, pmtMethod, pmtRefInfo, cancelReason, requestNumber)
        if result_payment.get('cancelPmtRsType'):
            result['Success'] = result_payment['cancelPmtRsType']
        else:
            result = result_payment

        return result
