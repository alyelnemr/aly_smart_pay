# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.
import datetime
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


MOMKEN_ERROR_MAP = {
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
        self.debug_logger(context.envelope, 'momken_request')

    def received(self, context):
        self.debug_logger(context.reply, 'momken_response')


class MOMKENRequest:
    def __init__(self, debug_logger, endurl, env,
                 username, password, account_id, version, service_version):
        self.debug_logger = debug_logger
        # Production and Testing url
        self.endurl = endurl
        self.env = env

        # Basic detail require to authenticate
        self.username = username
        self.password = password
        self.account_id = account_id
        self.version = version
        self.service_version = service_version

    def get_translated_message(self, msg):
        is_translated = False
        translated_msg = self.env['ir.translation'].sudo().search([
            ('type', '=', 'code'),
            ('name', '=', 'addons/tm_momken_gateway/models/momken_request.py'),
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
        msg, is_translated = self.get_translated_message(MOMKEN_ERROR_MAP.get(str(error_code)))
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
            "UserName": self.login,
            "Password": self.password,
            "ChannelCategory": self.terminalId,
            "action": action,
            "language": custLangPref,
            "version": self.version,
            "data": data
        })
        return payload

    def _buildResponse(momkenResponse):
        _logger.info("Success: " + momkenResponse['success'])
        if momkenResponse['success']:
            _logger.info("Action: " + momkenResponse['action'])
            _logger.info("Language: " + momkenResponse['language'])
            _logger.info("Version: " + momkenResponse['version'])
            _logger.info("Date: " + momkenResponse['data'])
        else:
            _logger.info("Error Code: " + momkenResponse['error_code'])
            _logger.info("Description: " + momkenResponse['description'])

    def _authenticate_request(self, channel_category=2, channel_type=2):
        payload = json.dumps({
            "UserName": self.username,
            "Password": self.password,
            "ChannelCategory": channel_category,
            "ChannelType": channel_type,
            "LocalDate": str(datetime.datetime.now()),
            "Version": self.version,
            "ServiceListVersion": self.service_version
        })
        return payload

    def get_service_details(self, custLangPref, data):  # "data": {"provider_id": provider['id']}
        # Get Service List
        payload = self._authenticate_request()

        try:
            # Get All of services data from Momken
            url = self.endurl + 'accounts/' + str(self.account_id) + '/authenticate'
            headers = {
                'content-type': 'application/json;charset=UTF-8'
            }

            authenticate_request = requests.post(url, headers=headers, data=payload)
            authenticate_response = json.loads(authenticate_request.content.decode('utf-8'))

            if (authenticate_response.get('Code') and authenticate_response.get('Code') != '200') or (
                    authenticate_response.get('code') and str(authenticate_response.get('code')) != '200'):
                err_msg = "Momken Response ERROR: [" + str(authenticate_response.get('Message]')) + "]"
                _logger.error(err_msg)
                return err_msg
            momken = self.env['payment.acquirer'].sudo().search([("provider", "=", "momken")])
            momken_channel = momken.momken_channel_ids[0] if momken.momken_channel_ids else None
            if authenticate_response.get('version'):
                momken.momken_version = authenticate_response.get('version')
            if momken_channel and authenticate_response.get('serviceListVersion'):
                momken_channel.momken_service_version = authenticate_response.get('serviceListVersion')

            service_url = self.endurl + 'categories/' + str(momken_channel.momken_service_version)
            service_request = requests.get(service_url, headers=headers)
            service_response = json.loads(service_request.content.decode('utf-8'))

            if (service_response.get('Code') and service_response.get('Code') != '200') or (
                    service_response.get('code') and str(service_response.get('code')) != '200'):
                err_msg = "Momken Response ERROR: [" + str(authenticate_response.get('Message]')) + "]"
                _logger.error(err_msg)
                return err_msg

            result = {'serviceData': service_response.get('serviceList')}
            # _logger.info("Masary Service Details Result: " + str(result))

            return result

        except IOError as e:
            _logger.error("ERROR: " + str(e))
            return self.get_error_message('0', 'MS Server Not Found:\n%s' % e)

    def pay_bill(self, custLangPref, data):  # "data": {"external_id": "", "service_version": 0, "account_number": "",
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
                              str(pay_bill_res['error_code']) + "]: " + (
                                      pay_bill_res.get('description') or pay_bill_res.get('error_text')))
                return self.get_error_message(pay_bill_res['error_code'],
                                              (pay_bill_res.get('description') or pay_bill_res.get('error_text')))

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
