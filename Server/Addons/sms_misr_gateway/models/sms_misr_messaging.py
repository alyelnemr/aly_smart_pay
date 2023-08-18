# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

import logging
_logger = logging.getLogger(__name__)

import urllib.parse
import requests
import json

from odoo import models, fields, api, _
from urllib3.exceptions import HTTPError

SMS_MISR_RESPONSE_FOR_SMS_MAP = {
    '1901': 'Success, Message Submitted Successfully',
    '1902': 'Invalid URL , This means that one of the parameters was not provided',
    '9999': 'Please Wait For A While , This means You Sent Alot Of API Request At The Same Time',
    '1903': 'Invalid value in username or password field',
    '1904': 'Invalid value in "sender" field',
    '1905': 'Invalid value in "mobile" field',
    '1906': 'Insufficient Credit selected.',
    '1907': 'Server under updating',
    '1908': 'Invalid Date & Time format in “DelayUntil=” parameter',
    '1909': 'Error In Message',
    '8001': 'Mobile IS Null',
    '8002': 'Message IS Null',
    '8003': 'Language IS Null',
    '8004': 'Sender IS Null',
    '8005': 'Username IS Null',
    '8006': 'Password IS Null'
}

SMS_MISR_RESPONSE_FOR_REQUEST_MAP = {
    '6000': 'Success, Request Submitted Successfully',
    'Error': 'Invalid URL , This means that one of the parameters was not provided or wrong information'
}

def send_sms_using_sms_misr(body_sms, mob_no, language=None, delay_until=None, sms_gateway=None):
    '''
    This function is designed for sending sms using SMS Misr API.

    :param body_sms: body of sms contains text
    :param mob_no: Here mob_no must be string having one or more number seprated by (,)
    :param language: language of sms contains text used in SMS Misr API (1: For English 2: For Arabic 3: For Unicode)
    :param delay_until: For scheduling Format: yyyy-mm-dd-HH-mm Ex. 2017-09-13-13-30
    :param sms_gateway: sms.mail.server config object for SMS Misr Credentials
    :return: response dictionary if sms successfully sent else empty dictionary
    '''
    if not sms_gateway or not body_sms or not mob_no:
        return {}
    if sms_gateway.gateway == "sms_misr":
        sms_misr_url = sms_gateway.sms_url
        sms_misr_username = sms_gateway.username
        sms_misr_password = sms_gateway.password
        sms_misr_sender = sms_gateway.sender
        sms_misr_language = 1
        if language:
            sms_misr_language = language
        try:
            if sms_misr_url and sms_misr_username and sms_misr_password and sms_misr_sender:
                response_dict = {}

                headers = {
                    'content-type': 'application/x-www-form-urlencoded',
                    # 'charset': 'utf-8'
                }
                data = {
                    "username": sms_misr_username,
                    "password": sms_misr_password,
                    "language": sms_misr_language,
                    "sender": sms_misr_sender,
                    "message": body_sms
                }
                if delay_until:
                    data.update({'DelayUntil': delay_until})

                for mobi_no in mob_no.split(','):
                    data.update({'mobile': mobi_no})
                    response = requests.post("%s?%s" % (sms_misr_url, urllib.parse.urlencode(data, doseq=True))
                        , headers=headers
                        )
                    response_dict.update({mobi_no: json.loads(response.content.decode('utf-8'))})
                return response_dict
        except HTTPError as e:
            logging.info(
                '---------------SMS Misr HTTPError----------------------', exc_info=True)
            _logger.info(
                "---------------SMS Misr HTTPError While Sending SMS ----%r---------", e)
            return {}
        except Exception as e:
            logging.info(
                '---------------SMS Misr Exception While Sending SMS ----------', exc_info=True)
            _logger.info(
                "---------------SMS Misr Exception While Sending SMS -----%r---------", e)
            return {}
    return {}


def get_sms_status_for_sms_misr(param):
    if not param:
        return {}
    if param.get("sms_misr_balance_status_url") and param.get("sms_misr_sms_id") \
            and param.get("sms_misr_username") and param.get("sms_misr_password"):
        try:
            # Message sms_id for which the details have to be retrieved
            headers = {
                'content-type': 'application/x-www-form-urlencoded',
                # 'charset': 'utf-8'
            }
            data = {
                "username": param.get("sms_misr_username"),
                "password": param.get("sms_misr_password"),
                "request": "status",
                "SMSID": param.get("sms_misr_sms_id")
            }

            response = requests.post("%s?%s" % (param.get("sms_misr_balance_status_url"), urllib.parse.urlencode(data, doseq=True))
                                     , headers=headers
                                     )
            status = json.loads(response.content.decode('utf-8'))
            return status
        except HTTPError as e:
            logging.info(
                '---------------SMS Misr HTTPError----------------------', exc_info=True)
            _logger.info(
                "---------------SMS Misr HTTPError For SMS History----%r---------", e)
            return {}
        except Exception as e:
            logging.info(
                '---------------SMS Misr Exception While Sending SMS ----------', exc_info=True)
            _logger.info(
                "---------------SMS Misr Exception For SMS History-----%r---------", e)
            return {}
    return {}


class SmsSms(models.Model):
    """SMS sending using SMS Misr Gateway."""

    _inherit = "sms.sms"
    _name = "sms.sms"
    _description = "SMS Misr"

    @api.multi
    def send_sms_via_gateway(self, body_sms, mob_no, from_mob=None, sms_gateway=None):
        self.ensure_one()
        gateway_id = sms_gateway if sms_gateway else super(SmsSms, self).send_sms_via_gateway(
            body_sms, mob_no, from_mob=from_mob, sms_gateway=sms_gateway)
        if gateway_id:
            if gateway_id.gateway == 'sms_misr':
                sms_misr_balance_status_url = sms_gateway.balance_status_url
                sms_misr_username = sms_gateway.username
                sms_misr_password = sms_gateway.password
                sms_misr_sender = sms_gateway.sender
                sms_misr_sms_language = sms_gateway.language
                if mob_no:
                    for element in mob_no:
                        for mobi_no in element.split(','):
                            response = send_sms_using_sms_misr(
                                body_sms, mobi_no, language=sms_misr_sms_language, delay_until=None, sms_gateway=gateway_id)
                            for key in response.keys():
                                if key == mobi_no:
                                    sms_report_obj = self.env["sms.report"].create(
                                        {'to': mobi_no, 'msg': body_sms, 'sms_sms_id': self.id, "auto_delete": self.auto_delete, 'sms_gateway_config_id': gateway_id.id})
                                    if response[mobi_no].get('SMSID'):
                                        sms_sid = response[mobi_no].get('SMSID')
                                        # Get SMS status
                                        msg_status = response[mobi_no].get('code')
                                        if msg_status == '1901':
                                            sms_report_obj.write({'state': 'sent', 'sms_misr_balance_status_url': sms_misr_balance_status_url,
                                                                  'sms_misr_sms_id': sms_sid, 'sms_misr_sender': sms_misr_sender,
                                                                  'sms_misr_username': sms_misr_username, 'sms_misr_password': sms_misr_password})
                                        else:
                                            sms_report_obj.write({'state': 'failed', 'sms_misr_balance_status_url': sms_misr_balance_status_url,
                                                                  'sms_misr_sms_id': sms_sid, 'sms_misr_sender': sms_misr_sender,
                                                                  'sms_misr_username': sms_misr_username, 'sms_misr_password': sms_misr_password,
                                                                  'sms_misr_response_msg': SMS_MISR_RESPONSE_FOR_SMS_MAP.get(msg_status)})
                                    else:
                                        sms_report_obj.write(
                                            {'state': 'undelivered', 'sms_misr_response_msg': SMS_MISR_RESPONSE_FOR_SMS_MAP.get(msg_status)})
                                else:
                                    self.write({'state': 'error'})
                else:
                    self.write({'state': 'error'})
            else:
                gateway_id = super(SmsSms, self).send_sms_via_gateway(
                    body_sms, mob_no, from_mob=from_mob, sms_gateway=sms_gateway)
        else:
            _logger.info(
                "----------------------------- SMS Gateway not found -------------------------")
        return gateway_id


class SmsReport(models.Model):
    """SMS report."""

    _inherit = "sms.report"

    sms_misr_balance_status_url = fields.Char(string="Balance and Status URL")
    sms_misr_sms_id = fields.Char("SMS Misr SMS ID")
    sms_misr_sender = fields.Char("SMS Misr Sender")
    sms_misr_username = fields.Char("SMS Misr Username")
    sms_misr_password = fields.Char("SMS Misr Password")
    sms_misr_response_msg = fields.Char("SMS Misr Response Message")
    '''
    param.get("sms_misr_balance_status_url") and param.get("sms_misr_sms_id") \
            and param.get("sms_misr_username") and param.get("sms_misr_password"):
    '''

    @api.model
    def cron_function_for_sms(self):
        _logger.info(
            "************** Cron Function For SMS Misr ***********************")
        all_sms_report = self.search([('state', 'in', ('sent', 'new'))])
        for sms in all_sms_report:
            sms_sms_obj = sms.sms_sms_id
            if sms.sms_misr_balance_status_url and sms.sms_misr_sms_id and sms.sms_misr_username and sms.sms_misr_password:
                msg_status = get_sms_status_for_sms_misr(
                    {'sms_misr_balance_status_url': sms.sms_misr_balance_status_url, 'sms_misr_sms_id': sms.sms_misr_sms_id,
                     'sms_misr_username': sms.sms_misr_username, 'sms_misr_password': sms.sms_misr_password})
                if msg_status.get('code') == '6000' and any(key == 'Sent' for key in msg_status.keys()):
                    if sms.auto_delete:
                        sms.unlink()
                        if sms_sms_obj.auto_delete and not sms_sms_obj.sms_report_ids:
                            sms_sms_obj.unlink()
                    else:
                        sms.write(
                            {'state': 'delivered', "status_hit_count": sms.status_hit_count + 1})
                else:
                    sms.write(
                        {'state': 'sent', "status_hit_count": sms.status_hit_count + 1})
        super(SmsReport, self).cron_function_for_sms()
        return True

    @api.multi
    def send_sms_via_gateway(self, body_sms, mob_no, from_mob=None, sms_gateway=None):
        self.ensure_one()
        gateway_id = sms_gateway if sms_gateway else super(SmsReport, self).send_sms_via_gateway(
            body_sms, mob_no, from_mob=from_mob, sms_gateway=sms_gateway)
        if gateway_id:
            if gateway_id.gateway == 'sms_misr':
                sms_misr_balance_status_url = sms_gateway.balance_status_url
                sms_misr_username = sms_gateway.username
                sms_misr_password = sms_gateway.password
                sms_misr_sender = sms_gateway.sender
                sms_misr_sms_language = sms_gateway.language
                if mob_no:
                    for element in mob_no:
                        count = 1
                        for mobi_no in element.split(','):
                            if count == 1:
                                self.to = mobi_no
                                rec = self
                            else:
                                rec = self.create(
                                    {'to': mobi_no, 'msg': body_sms, "auto_delete": self.auto_delete, 'sms_gateway_config_id': gateway_id.id})
                            response = send_sms_using_sms_misr(
                                body_sms, mob_no, language=sms_misr_sms_language, delay_until=None, sms_gateway=gateway_id)
                            for key in response.keys():
                                if key == mobi_no:
                                    if response[mobi_no].get('SMSID'):
                                        sms_sid = response[mobi_no].get('SMSID')
                                        # Get SMS status
                                        # msg_status = get_sms_status_for_sms_misr(
                                        #       {'sms_misr_balance_status_url': sms.sms_misr_balance_status_url, 'sms_misr_sms_id': sms.sms_misr_sms_id,
                                        #       'sms_misr_username': sms.sms_misr_username, 'sms_misr_password': sms.sms_misr_password})
                                        msg_status = response[mobi_no].get('code')
                                        if msg_status == '1901':
                                            rec.write({'state': 'sent',
                                                                  'sms_misr_balance_status_url': sms_misr_balance_status_url,
                                                                  'sms_misr_sms_id': sms_sid,
                                                                  'sms_misr_sender': sms_misr_sender,
                                                                  'sms_misr_username': sms_misr_username,
                                                                  'sms_misr_password': sms_misr_password})
                                        else:
                                            rec.write({'state': 'failed',
                                                                  'sms_misr_balance_status_url': sms_misr_balance_status_url,
                                                                  'sms_misr_sms_id': sms_sid,
                                                                  'sms_misr_sender': sms_misr_sender,
                                                                  'sms_misr_username': sms_misr_username,
                                                                  'sms_misr_password': sms_misr_password,
                                                                  'sms_misr_response_msg': SMS_MISR_RESPONSE_FOR_SMS_MAP.get(
                                                                      msg_status)})
                            count += 1
                else:
                    self.write({'state': 'sent'})
            else:
                gateway_id = super(SmsReport, self).send_sms_via_gateway(
                    body_sms, mob_no, from_mob=from_mob, sms_gateway=sms_gateway)
        return gateway_id
