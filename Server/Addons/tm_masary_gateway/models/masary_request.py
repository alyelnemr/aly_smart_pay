# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

import logging

import suds
from suds.plugin import MessagePlugin

import requests
import json

from odoo import _

SUDS_VERSION = suds.__version__


_logger = logging.getLogger(__name__)
# uncomment to enable logging of SOAP requests and responses
# logging.getLogger('suds.transport').setLevel(logging.DEBUG)


MASARY_ERROR_MAP = {
    '1001': _("«login» is required"),
    '1002': _("«password» is required"),
    '1003': _("Incorrect login or password"),
    '1004': _("«action» is required"),
    '1005': _("Incorrect action name"),
    '1006': _("«version» is required"),
    '1007': _("Incorrect version"),
    '1008': _("«data» is required"),
    '1009': _("«data» is invalid"),
    '1010': _("Invalid user"),
    '1011': _("«language» is required"),
    '1012': _("Change password is required"),
    '1013': _("Permission denied"),
    '1014': _("Account number not found"),
    '1015': _("Receiver account not found"),
    '1016': _("Insufficient balance"),
    '1017': _("Wrong amount"),
    '1018': _("Unknown service"),
    '1019': _("Service has not inquiry feature"),
    '1020': _("Inquiry transaction ID is required"),
    '1021': _("Inquiry transaction not found"),
    '1022': _("Wrong service charge"),
    '1023': _("Duplicate transaction ID"),
    '1024': _("«terminal_id» is required"),
    '1025': _("Incorrect service version, service list update is required"),
    '2000': _("Internal server error"),
    '2001': _("Invalid HTTP content type"),
    '2002': _("Invalid HTTP charset"),
    '2003': _("Invalid HTTP content"),
    '2004': _("Unsupported HTTP method"),
    '2005': _("Invalid URL path"),
}

class LogPlugin(MessagePlugin):
    """ Small plugin for suds that catches out/ingoing XML requests and logs them"""
    def __init__(self, debug_logger):
        self.debug_logger = debug_logger

    def sending(self, context):
        self.debug_logger(context.envelope, 'masary_request')

    def received(self, context):
        self.debug_logger(context.reply, 'masary_response')

class MASARYRequest():
    def __init__(self, debug_logger, endurl, env,
                 login, password, version, terminalId,
                 acctCur=None
                 ):
        self.debug_logger = debug_logger
        # Production and Testing url
        self.endurl = endurl
        self.env = env

        # Basic detail require to authenticate
        self.login = login                           # login:                                     ==> Per Channel
        self.password = password                     # password:                                  ==> Per Channel
        self.version = version                       # version: 0
        self.terminalId = terminalId                 # terminalId: 123                            ==> Per Channel
        # if acctCur:
            # self.acctCur = acctCur.name              # acctCur: EGP                              ==> Per Channel

    def get_translated_message(self, msg):
        is_translated = False
        translated_msg = self.env['ir.translation'].sudo().search([
            ('type', '=', 'code'),
            ('name', '=', 'addons/tm_masary_gateway/models/masary_request.py'),
            ('source', '=', msg),
            ('lang', '=', self.env.user.lang),
            ('state', '=', 'translated')
        ])
        if translated_msg:
            msg = translated_msg.value or translated_msg.source
            is_translated = True
        return msg, is_translated

    def get_error_message(self, error_code, description):
        result = {}
        msg, is_translated = self.get_translated_message(MASARY_ERROR_MAP.get(str(error_code)))
        result['error_code'] = str(error_code)
        result['error_message'] = msg
        if not result['error_message']:
            msg, is_translated = self.get_translated_message(description)
            if is_translated:
                result['error_message'] = msg
            else:
                result['error_message_to_be_translated'] = msg
        return result

    def _buildRequest(self, action, custLangPref, data):
        payload = json.dumps({
            "login": self.login,
            "password": self.password,
            "terminal_id": self.terminalId,
            "action": action,
            "language": custLangPref,
            "version": self.version,
            "data": data
        })
        return payload

    def _buildResponse(masaryResponse):
        '''
        {
            "success": false,
            "error_code": <error code>,
            "description": "<error description>"
        }
        {
            "success": true,
            "action": "<action name>",
            "language": "<language code>",
            "version": 2,
            "data": {...}
        }
        '''
        _logger.info("Success: "+ masaryResponse['success'])
        if masaryResponse['success']:
            _logger.info("Action: "+ masaryResponse['action'])
            _logger.info("Language: " + masaryResponse['language'])
            _logger.info("Version: "+ masaryResponse['version'])
            _logger.info("Date: "+ masaryResponse['data'])
        else:
            _logger.info("Error Code: " + masaryResponse['error_code'])
            _logger.info("Description: " + masaryResponse['description'])

    def get_biller_details(self, custLangPref, data): # "data": {"service_version": 0}
        # Get Provider List
        payload = self._buildRequest(action="GetProviderList", custLangPref=custLangPref, data=data)
        # _logger.info("MS GetProviderList Request: " + str(payload))

        try:
            # Get All of billers data for a specific channel
            # _logger.info("Before Calling GetProviderList Masary Service")
            url =  '%s/service' % self.endurl
            headers = {
                'content-type': 'application/json;charset=UTF-8'
            }

            provider_req = requests.post(url, headers=headers, data=payload)
            provider_res = json.loads(provider_req.content.decode('utf-8'))
            # _logger.info("After Calling GetProviderList Masary Service")
            # _logger.info("MS GetProviderList Response: " + str(provider_res))

            # Check if process is not success then return reason for that
            if not provider_res['success']:
                _logger.error("MS Response ERROR: [" +
                              str(provider_res['error_code']) + "]: " + (provider_res.get('description') or provider_res.get('error_text')))
                return self.get_error_message(provider_res['error_code'], (provider_res.get('description') or provider_res.get('error_text')))

            # _logger.info("Before Calling GetProviderList _buildResponse")
            # self._buildResponse(provider_res)
            # _logger.info("After Calling GetProviderList _buildResponse")

            result = {}
            result['billerData'] = provider_res['data']
            # _logger.info("Masary Biller Details Result: " + str(result))

            return result

        except IOError as e:
            _logger.error("ERROR: " + str(e))
            return self.get_error_message('0', 'MS Server Not Found:\n%s' % e)

    def get_service_details(self, custLangPref, data): # "data": {"provider_id": provider['id']}
        # Get Service List
        payload = self._buildRequest(action="GetServiceList", custLangPref=custLangPref, data=data)
        # _logger.info("MS GetServiceList Request: " + str(payload))

        try:
            # Get All of services data for a specific channel
            # _logger.info("Before Calling GetServiceList Masary Service")
            url =  '%s/service' % self.endurl
            headers = {
                'content-type': 'application/json;charset=UTF-8'
            }

            service_req = requests.post(url, headers=headers, data=payload)
            service_res = json.loads(service_req.content.decode('utf-8'))
            # _logger.info("After Calling GetServiceList Masary Service")
            # _logger.info("MS GetServiceList Response: " + str(service_res))

            # Check if process is not success then return reason for that
            if not service_res['success']:
                _logger.error("MS Response ERROR: [" +
                              str(service_res['error_code']) + "]: " + (service_res.get('description') or service_res.get('error_text')))
                return self.get_error_message(service_res['error_code'], (service_res.get('description') or service_res.get('error_text')))

            # _logger.info("Before Calling GetServiceList _buildResponse")
            # self._buildResponse(service_res)
            # _logger.info("After Calling GetServiceList _buildResponse")

            result = {}
            result['serviceData'] = service_res['data']
            # _logger.info("Masary Service Details Result: " + str(result))

            return result

        except IOError as e:
            _logger.error("ERROR: " + str(e))
            return self.get_error_message('0', 'MS Server Not Found:\n%s' % e)

    def get_service_input_parameters_details(self, custLangPref, data): # "data": {"service_id": service['id']}
        # Get service input parameters list
        payload = self._buildRequest(action="GetServiceInputParameterList", custLangPref=custLangPref, data=data)
        # _logger.info("MS GetServiceInputParameterList Request: " + str(payload))

        try:
            # Get All of services Input Parameter data for a specific channel
            # _logger.info("Before Calling GetServiceInputParameterList Masary Service")
            url =  '%s/service' % self.endurl
            headers = {
                'content-type': 'application/json;charset=UTF-8'
            }

            service_input_parameters_req = requests.post(url, headers=headers, data=payload)
            service_input_parameters_res = json.loads(service_input_parameters_req.content.decode('utf-8'))
            # _logger.info("After Calling GetServiceInputParameterList Masary Service")
            # _logger.info("MS GetServiceInputParameterList Response: " + str(service_input_parameters_res))

            # Check if process is not success then return reason for that
            if not service_input_parameters_res['success']:
                _logger.error("MS Response ERROR: [" +
                              str(service_input_parameters_res['error_code']) + "]: " + (service_input_parameters_res.get('description') or service_input_parameters_res.get('error_text')))
                return self.get_error_message(service_input_parameters_res['error_code'], (service_input_parameters_res.get('description') or service_input_parameters_res.get('error_text')))

            # _logger.info("Before Calling GetServiceInputParameterList _buildResponse")
            # self._buildResponse(service_input_parameters_res)
            # _logger.info("After Calling GetServiceInputParameterList _buildResponse")

            result = {}
            result['serviceInputParameterData'] = service_input_parameters_res['data']
            # _logger.info("Masary Service Input Parameter Details Result: " + str(result))

            return result

        except IOError as e:
            _logger.error("ERROR: " + str(e))
            return self.get_error_message('0', 'MS Server Not Found:\n%s' % e)

    def get_service_output_parameters_details(self, custLangPref, data): # "data": {"service_id": service['id']}
        # Get service output parameters list
        payload = self._buildRequest(action="GetServiceOutputParameterList", custLangPref=custLangPref, data=data)
        # _logger.info("MS GetServiceOutputParameterList Request: " + str(payload))

        try:
            # Get All of services Output Parameter data for a specific channel
            # _logger.info("Before Calling GetServiceOutputParameterList Masary Service")
            url =  '%s/service' % self.endurl
            headers = {
                'content-type': 'application/json;charset=UTF-8'
            }

            service_output_parameters_req = requests.post(url, headers=headers, data=payload)
            service_output_parameters_res = json.loads(service_output_parameters_req.content.decode('utf-8'))
            # _logger.info("After Calling GetServiceOutputParameterList Masary Service")
            # _logger.info("MS GetServiceOutputParameterList Response: " + str(service_output_parameters_res))

            # Check if process is not success then return reason for that
            if not service_output_parameters_res['success']:
                _logger.error("MS Response ERROR: [" +
                              str(service_output_parameters_res['error_code']) + "]: " + (service_output_parameters_res.get('description') or service_output_parameters_res.get('error_text')))
                return self.get_error_message(service_output_parameters_res['error_code'], (service_output_parameters_res.get('description') or service_output_parameters_res.get('error_text')))

            # _logger.info("Before Calling GetServiceOutputParameterList _buildResponse")
            # self._buildResponse(service_output_parameters_res)
            # _logger.info("After Calling GetServiceOutputParameterList _buildResponse")

            result = {}
            result['serviceOutputParameterData'] = service_output_parameters_res['data']
            # _logger.info("Masary Service Output Parameter Details Result: " + str(result))

            return result

        except IOError as e:
            _logger.error("ERROR: " + str(e))
            return self.get_error_message('0', 'MS Server Not Found:\n%s' % e)

    def get_category_details(self, custLangPref, data): # "data": {}
        # Get Category List
        payload = self._buildRequest(action="GetCategoryList", custLangPref=custLangPref, data=data)
        # _logger.info("MS GetCategoryList Request: " + str(payload))

        try:
            # Get All of categories data for a specific channel
            # _logger.info("Before Calling GetCategoryList Masary Service")
            url =  '%s/service' % self.endurl
            headers = {
                'content-type': 'application/json;charset=UTF-8'
            }

            category_req = requests.post(url, headers=headers, data=payload)
            category_res = json.loads(category_req.content.decode('utf-8'))
            # _logger.info("After Calling GetCategoryList Masary Service")
            # _logger.info("MS GetCategoryList Response: " + str(category_res))

            # Check if process is not success then return reason for that
            if not category_res['success']:
                _logger.error("MS Response ERROR: [" +
                              str(category_res['error_code']) + "]: " + (category_res.get('description') or category_res.get('error_text')))
                return self.get_error_message(category_res['error_code'], (category_res.get('description') or category_res.get('error_text')))

            # _logger.info("Before Calling GetCategoryList _buildResponse")
            # self._buildResponse(category_res)
            # _logger.info("After Calling GetCategoryList _buildResponse")

            result = {}
            result['categoryData'] = category_res['data']
            # _logger.info("Masary Category Details Result: " + str(result))

            return result

        except IOError as e:
            _logger.error("ERROR: " + str(e))
            return self.get_error_message('0', 'MS Server Not Found:\n%s' % e)

    def get_category_service_details(self, custLangPref, data): # "data": {}
        # Get Category Service List
        payload = self._buildRequest(action="GetCategoryServiceList", custLangPref=custLangPref, data=data)
        # _logger.info("MS GetCategoryServiceList Request: " + str(payload))

        try:
            # Get All of category services data for a specific channel
            # _logger.info("Before Calling GetCategoryServiceList Masary Service")
            url =  '%s/service' % self.endurl
            headers = {
                'content-type': 'application/json;charset=UTF-8'
            }

            category_service_req = requests.post(url, headers=headers, data=payload)
            category_service_res = json.loads(category_service_req.content.decode('utf-8'))
            # _logger.info("After Calling GetCategoryServiceList Masary Service")
            # _logger.info("MS GetCategoryServiceList Response: " + str(category_service_res))

            # Check if process is not success then return reason for that
            if not category_service_res['success']:
                _logger.error("MS Response ERROR: [" +
                              str(category_service_res['error_code']) + "]: " + (category_service_res.get('description') or category_service_res.get('error_text')))
                return self.get_error_message(category_service_res['error_code'], (category_service_res.get('description') or category_service_res.get('error_text')))

            # _logger.info("Before Calling GetCategoryServiceList _buildResponse")
            # self._buildResponse(category_service_res)
            # _logger.info("After Calling GetCategoryServiceList _buildResponse")

            result = {}
            result['categoryServiceData'] = category_service_res['data']
            # _logger.info("Masary Category Services Details Result: " + str(result))

            return result

        except IOError as e:
            _logger.error("ERROR: " + str(e))
            return self.get_error_message('0', 'MS Server Not Found:\n%s' % e)

    def get_account_details(self, custLangPref, data): # "data": {}
        # Get Account List
        payload = self._buildRequest(action="GetAccountInfo", custLangPref=custLangPref, data=data)
        # _logger.info("MS GetAccountInfo Request: " + str(payload))

        try:
            # Get All of categories data for a specific channel
            # _logger.info("Before Calling GetAccountInfo Masary Service")
            url =  '%s/report' % self.endurl
            headers = {
                'content-type': 'application/json;charset=UTF-8'
            }

            account_req = requests.post(url, headers=headers, data=payload)
            account_res = json.loads(account_req.content.decode('utf-8'))
            # _logger.info("After Calling GetAccountInfo Masary Service")
            # _logger.info("MS GetAccountInfo Response: " + str(account_res))

            # Check if process is not success then return reason for that
            if not account_res['success']:
                _logger.error("MS Response ERROR: [" +
                              str(account_res['error_code']) + "]: " + (account_res.get('description') or account_res.get('error_text')))
                return self.get_error_message(account_res['error_code'], (account_res.get('description') or account_res.get('error_text')))

            # _logger.info("Before Calling GetAccountInfo _buildResponse")
            # self._buildResponse(account_res)
            # _logger.info("After Calling GetAccountInfo _buildResponse")

            result = {}
            result['accountData'] = account_res['data']
            # _logger.info("Masary Account Details Result: " + str(result))

            return result

        except IOError as e:
            _logger.error("ERROR: " + str(e))
            return self.get_error_message('0', 'MS Server Not Found:\n%s' % e)

    def get_bill_details(self, custLangPref, data): # "data": {"service_version": 0, "account_number": "",
                                                    #          "service_id": 0, "input_parameter_list": []}
                                                    # optional ==> input_parameter_list
        # Get Bill Details
        payload = self._buildRequest(action="TransactionInquiry", custLangPref=custLangPref, data=data)
        # _logger.info("MS GetBillDetails Request: " + str(payload))

        try:
            # _logger.info("Before Calling MS Bill Details")
            url =  '%s/transaction' % self.endurl
            headers = {
                'content-type': 'application/json;charset=UTF-8'
            }

            bill_req = requests.post(url, headers=headers, data=payload)
            bill_res = json.loads(bill_req.content.decode('utf-8'))
            # _logger.info("After Calling MS Bill Details")
            # _logger.info("MS GetBillDetails Response: " + str(bill_res))

            # Check if process is not success then return reason for that
            if not bill_res['success']:
                _logger.error("MS Response ERROR: [" +
                              str(bill_res['error_code']) + "]: " + (bill_res.get('description') or bill_res.get('error_text')))
                return self.get_error_message(bill_res['error_code'], (bill_res.get('description') or bill_res.get('error_text')))

            # _logger.info("Before Calling GetBillDetails _buildResponse")
            # self._buildResponse(bill_res)
            # _logger.info("After Calling GetBillDetails _buildResponse")

            result = {}
            result['billData'] = bill_res['data']
            # _logger.info("Masary Bill Details Result: " + str(result))

            return result

        except IOError as e:
            _logger.error("ERROR: " + str(e))
            return self.get_error_message('0', 'MS Server Not Found:\n%s' % e)
        except Exception as ex:
            _logger.error("ERROR: " + str(ex))
            return self.get_error_message('0', 'ERROR:\n%s' % ex)

    def pay_bill(self, custLangPref, data): # "data": {"external_id": "", "service_version": 0, "account_number": "",
                                            #          "inquiry_transaction_id": "","service_id": 0, "amount": 0.0,
                                            #          "service_charge": 0.0, "total_amount": 0.0, "quantity": 0,
                                            #          "input_parameter_list": []}
                                            # optional ==> inquiry_transaction_id, quantity, input_parameter_list
        # Pay Bill
        payload = self._buildRequest(action="TransactionPayment", custLangPref=custLangPref, data=data)
        # _logger.info("MS PayBill Request: " + str(payload))

        try:
            # Pay Bill
            # _logger.info("Before Calling MS Pay Bill")
            url = '%s/transaction' % self.endurl
            headers = {
                'content-type': 'application/json;charset=UTF-8'
            }

            pay_bill_req = requests.post(url, headers=headers, data=payload)
            pay_bill_res = json.loads(pay_bill_req.content.decode('utf-8'))
            # _logger.info("After Calling MS Pay Bill")
            # _logger.info("TransactionPayment MS Response: " + str(pay_bill_res))

            # Check if process is not success then return reason for that
            if not pay_bill_res['success']:
                _logger.error("MS Response ERROR: [" +
                              str(pay_bill_res['error_code']) + "]: " + (pay_bill_res.get('description') or pay_bill_res.get('error_text')))
                return self.get_error_message(pay_bill_res['error_code'], (pay_bill_res.get('description') or pay_bill_res.get('error_text')))

            # _logger.info("Before Calling TransactionPayment _buildResponse")
            # self._buildResponse(pay_bill_res)
            # _logger.info("After Calling TransactionPayment _buildResponse")

            result = {}
            result['pmtInfoData'] = pay_bill_res['data']
            # _logger.info("MS Pay Bill Result: " + str(result))

            return result

        except IOError as e:
            _logger.error("ERROR: " + str(e))
            return self.get_error_message('0', 'MS Server Not Found:\n%s' % e)

    '''
    def correlation_bill(self, custLangPref,
                         suppressEcho, billTypeCode,
                         billingAcct, # extraBillingAcctKeys,
                         amt, curCode, pmtMethod,
                         # notifyMobile, billRefNumber,
                         # billerId, pmtType,
                         pmtTransIds):
        client = self._set_client(self.wsdl)

        namespace = 'ns1'
        masaryType = self._buildRequest(client=client, msgCode="PmtAddCorrRq", custLangPref=custLangPref, suppressEcho=suppressEcho, namespace=namespace,
                                       # pmtType=pmtType,
                                       billTypeCode=billTypeCode, billingAcct=billingAcct, # extraBillingAcctKeys=extraBillingAcctKeys,
                                       amt=amt, curCode=curCode, pmtMethod=pmtMethod, # notifyMobile=notifyMobile,
                                       # billRefNumber=billRefNumber,
                                       # billerId=billerId,
                                       pmtTransIds=pmtTransIds
                                       ) # IsRetry, BillerId, PmtType
        # _logger.info("MasaryType Request: " + str(masaryType))

        try:
            # Pay Bill
            # _logger.info("Before Calling Masary Pay Bill")
            masaryResponse = client.service.process(masaryType)
            # _logger.info("After Calling Masary Pay Bill")
            # _logger.info("PmtAddRq MasaryType Response: " + str(masaryResponse))

            # Check if process is not success then return reason for that
            if not provider_res['success']:
                _logger.error("MS Response ERROR: [" +
                              str(provider_res['error_code']) + "]: " + (provider_res.get('description') or provider_res.get('error_text')))
                return self.get_error_message(provider_res['error_code'], (provider_res.get('description') or provider_res.get('error_text')))

            # _logger.info("Before Calling PmtAddRq _buildResponse")
            # self._buildResponse(masaryResponse)
            # _logger.info("After Calling PmtAddRq _buildResponse")

            result = {}
            result['pmtInfoData'] = provider_res['data']
            # _logger.info("Masary Pay Bill Result: " + str(result))

            return result

        except IOError as e:
            _logger.error("ERROR: " + str(e))
            return self.get_error_message('0', 'MS Server Not Found:\n%s' % e)
    '''
