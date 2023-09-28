# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

import logging
import os
import requests
import urllib3
import urllib.parse
import uuid
import suds
import xmltodict

from datetime import datetime, timedelta
from collections import OrderedDict

from suds.client import Client
from suds.plugin import MessagePlugin
from suds.sax.element import Element

from socket import timeout

from suds.sax.text import Raw

SUDS_VERSION = suds.__version__

from odoo import fields, _

_logger = logging.getLogger(__name__)
# uncomment to enable logging of SOAP requests and responses
# logging.getLogger('suds.transport').setLevel(logging.DEBUG)

KHALES_TIMOUT = 30  # timeout in second
KHALES_TIMOUT_RETRY = 3  # Retry x time to call provider when timeout
KHALES_ERROR_MAP = {
    '1': _('Request processed successfully, but fetch limit reached. Some records may not have been fetched'),
    '1102': _('Invalid Sender Code'),
    '1103': _('Invalid Receiver Code'),
    '1104': _('Invalid Message Code'),
    '1105': _('Sender Not Active'),
    '1106': _('Repeated RqUID'),
    '1199': _('General Error'),
    '8001': _('XML. Schema Validation Failed'),
    '8002': _('Invalid Sender Code'),
    '8003': _('Invalid Receiver Code'),
    '8004': _('Invalid Message Code'),
    '8005': _('Repeated RqUID'),
    '8006': _('Invalid Bank Id'),
    '8007': _('Invalid Branch Code'),
    '8008': _('Invalid Access Channel Code'),
    '8009': _('Invalid Customer Id’s Official ID Type'),
    '8010': _('Invalid Proxy Customer Id’s Official ID'),
    '8011': _('Biller ID is Mandatory, When Providing the Bill Number'),
    '8012': _('Invalid Biller Id'),
    '8013': _('Neither Billing Account nor Customer ID Specified In The Query'),
    '8014': _('Invalid Service Type Or Not Mapped To Biller'),
    '8015': _('Start Date is Greater Than The End Date'),
    '8016': _('Either Start or End date Is Mandatory In Case of DateRange Element Is Available'),
    '8017': _('The Max Number of Bills Limitation Reached'),
    '8018': _('No Valid Fulfillment Entity Settlement Account To Be Used For Payment Settlement'),
    '8019': _('Sender Not Active'),
    '8020': _('Bank Not Active'),
    '8090': _('Biller Enquiry service temporary not available'),
    '8091': _('Biller not support enquiry by customer id'),
    '8092': _('Biller not support enquiry by account number'),
    '8093': _('Biller not support enquiry by bill number'),
    '8094': _('Bill Exists, but can’t be paid'),
    '8095': _('Invalid Response Received From Online Biller, or Biller Unable to Process The Request'),
    '8096': _('No Response Received From Biller Online Enquiry, Try Later.'),
    '8097': _('No Matched Customer Found'),
    '8098': _('No Bill Found For The Mentioned Customer'),
    '8099': _('Bill Not Found'),
    '1107': _('Invalid EPayBillRecID'),
    '1108': _('Bill Not Found'),
    '1109': _('Bill Can Not Be Paid'),
    '1110': _('Invalid Payment Amounts'),
    '1111': _('No Commission Configured (for all or some of the payment currencies)'),
    '1112': _('The payments legnth is not valid'),
    '1113': _('Repeated Sequence'),
    '1114': _('PayAmt Curcode Not Matched With Original Amount Due Master'),
    '1115': _('For Range Payment Mode, Payment Amount Should Be Greater Than or Equal To The Minimum Amount'),
    '1116': _(
        'For Range Payment Mode, and Maximum Amount Not Equal To Zero, Payment Amount Should Be Less Than or Equal Maximum Amount'),
    '1117': _(
        'For Installment Payment Mode, Payment Amount Should Be Multiple of The Installment Amount or Equal To The Amount Due'),
    '1118': _('Missing Exact Payment Currency Amount'),
    '1119': _('PayAmt’s Sequence Not Matched With An Existing Bill’s Currency Amount'),
    '1120': _('Invalid Bank Id'),
    '9001': _('Invalid Sender Code'),
    '9002': _('Invalid Receiver Code'),
    '9003': _('Invalid Message Code'),
    '9004': _('Repeated RqUID'),
    '9005': _('Invalid Proxy Customer ID’s Official ID Type'),
    '9006': _('Unable to Match Payment With Existing Bill'),
    '9007': _('Repeated PmtId'),
    '9008': _('Invalid Cust Id’s Official Id Type'),
    '9050': _('Transaction not found'),
    '8999': _('General Error'),
    '9009': _('PayAmt’s Sequence Not Matched With An Existing Bill’s Currency Amount'),
    '9010': _('Missing Exact Payment Currency Amount'),
    '9011': _('PayAmt Can’t Be Zero'),
    '9012': _('For Range Payment Mode, Payment Amount Should Be Greater Than or Equal To The Minimum Amount'),
    '9013': _(
        'For Range Payment Mode, and Maximum Amount Not Equal To Zero, Payment Amount Should Be Less Than or Equal Maximum Amount'),
    '9014': _(
        'For Installment Payment Mode, Payment Amount Should Be Multiple of The Installment Amount or Equal To The Amount Due'),
    '9015': _('PayAmt Curcode Not Matched With Original Amount Due Master'),
    '9016': _('Not Valid Fees Amount'),
    '9017': _('Not Valid Fees Currency'),
    '9018': _('Invalid PrcDt, It Must be Grater Than or Equal The Current Business Date'),
    '9019': _('Invalid Bank Id'),
    '9020': _('Invalid Branch Code'),
    '9021': _('Invalid Access Channel Code'),
    '9022': _('Invalid PmtMethod Code'),
    '9023': _('Invalid Check Digit Value'),
    '9024': _('Invalid Service Type Code'),
    '9025': _('Invalid PmtRefInfo'),
    '9026': _('No Valid Bank Settlement Accounts'),
    '9027': _('Bill Status Does Not Allow Payment'),
    '9028': _('Bill In Hold State, Waiting For Biller Update'),
    '9029': _('Bill Had Expired, or Not Yet Valid For Payment'),
    '9030': _('The payments legnth is not valid'),
    '9031': _('Repeated Sequence'),
    '9032': _('Invalid Pmt Id Type Code'),
    '9033': _('Invalid Bill Number'),
    '9034': _('Invalid Billing Account'),
    '9035': _('Invalid Biller Id'),
    '9036': _('Invalid Message Code'),
    '9037': _('Bill already Paid'),
    '9038': _('Fractions is not allowed'),
    '9039': _('Invalid Payment Sequence'),
    '9040': _('The Customer Payment Name Is Required'),
}


class LogPlugin(MessagePlugin):
    """ Small plugin for suds that catches out/ingoing XML requests and logs them"""

    def __init__(self, debug_logger):
        self.debug_logger = debug_logger

    def sending(self, context):
        self.debug_logger(context.envelope, 'khales_request')

    def received(self, context):
        self.debug_logger(context.reply, 'khales_response')


'''
class FixRequestNamespacePlug(MessagePlugin):
    def __init__(self, root):
        self.root = root

    def marshalled(self, context):
        context.envelope = context.envelope.prune()
'''


class KHALESRequest():
    def __init__(self, debug_logger, endurl, env,
                 sender, receiver,
                 # version, originatorCode, terminalId, deliveryMethod,                           # msgCode: BRSINQRQ, RBINQRQ, RFINQRQ, RPADVRQ and CNLPMTRQ
                 # profileCode=None,                                                                                  # msgCode: BillerInqRq
                 bankId=None,  # msgCode: RBINQRQ, RPADVRQ and CNLPMTRQ
                 # acctId=None, acctType=None, acctKey=None, secureAcctKey=None, acctCur=None, posSerialNumber=None   # msgCode: PmtAddRq
                 accessChannel=None,  # msgCode: RBINQRQ, RPADVRQ and CNLPMTRQ
                 acctCur=None,
                 khales_channel=None  # kahles provider channel object
                 ):
        self.debug_logger = debug_logger
        # Production and Testing url
        self.endurl = endurl
        self.env = env

        # Basic detail require to authenticate
        self.sender = sender  # sender: 0023                               ==> Per Channel
        self.receiver = receiver  # receiver: EPAY                             ==> Per Channel
        # self.version = version                       # version: V1.0
        # self.originatorCode = originatorCode         # originatorCode: SmartPay2
        # self.terminalId = terminalId                 # terminalId: 104667                         ==> Per Channel
        # self.deliveryMethod = deliveryMethod         # DeliveryMethod: MOB                        ==> Per Channel
        # if profileCode:
        # self.profileCode = profileCode           # ProfileCode: 22013                         ==> Per Channel
        # if acctId:
        # self.acctId = acctId                     # acctId: 104667                             ==> Per Channel
        if bankId:
            self.bankId = bankId  # bankId: 1023                               ==> Per Channel
        # if acctType:
        # self.acctType = acctType                 # acctType: SDA                             ==> Per Channel
        # if acctKey:
        # self.acctKey = acctKey                   # acctKey: 1234                             ==> Per Channel
        # if secureAcctKey:
        # self.secureAcctKey = secureAcctKey       # secureAcctKey: gdyb21LQTcIANtvYMT7QVQ==   ==> Per Channel
        if acctCur:
            self.acctCur = acctCur.name  # acctCur: EGP                              ==> Per Channel
        # self.posSerialNumber = posSerialNumber       # posSerialNumber: 332-491-1222             ==> Per Channel
        if accessChannel:
            self.accessChannel = accessChannel  # accessChannel: POS                        ==> Per Channel

        self.wsdl = '../api/BillPaymentService.wsdl'
        self.khales_channel = khales_channel
        _logger.info("Set Khales channels: {}".format(self.khales_channel))

    @staticmethod
    def _add_security_header(token, client, namespace='ns2'):
        ssn_name = (namespace, 'http://namespaces/Authorization')
        value = "Bearer {}".format(token)
        header_token = Element('Authorization', ns=ssn_name).setText(value)
        client.set_options(soapheaders=header_token)
        _logger.info("After Add Authorization Client {}".format(client))

    '''
        def _add_security_header(self, client, namspace):
            # # set the detail which require to authenticate

            # security_ns = ('tns', 'http://www.khales-eg.com/ebpp/IFXMessages/')
            # security = Element('UPSSecurity', ns=security_ns)

            # username_token = Element('UsernameToken', ns=security_ns)
            # username = Element('Username', ns=security_ns).setText(self.username)
            # password = Element('Password', ns=security_ns).setText(self.password)
            # username_token.append(username)
            # username_token.append(password)

            # service_token = Element('ServiceAccessToken', ns=security_ns)
            # license = Element('AccessLicenseNumber', ns=security_ns).setText(self.access_number)
            # service_token.append(license)

            # security.append(username_token)
            # security.append(service_token)

            # client.set_options(soapheaders=security)

            self.SignonProfileType = self.client.factory.create('{}:SignonProfileType'.format(namespace))
            self.SignonProfileType.Sender = self.sender
            self.SignonProfileType.Receiver = self.receiver
            self.SignonProfileType.MsgCode = self.msgCode
            self.SignonProfileType.Version = self.version
        '''

    # def _generate_access_token(self):
    #     if not self.khales_channel:
    #         _logger.info("Not set khales channel object.")
    #         return {}
    #
    #     _logger.info("Generating access token")
    #     url = self.khales_channel.khales_url_access_token
    #     grant_type = self.khales_channel.khales_client_grant_type
    #     client_secret = self.khales_channel.khales_client_secret
    #     client_id = self.khales_channel.khales_client_id
    #     client_secret = urllib.parse.quote(client_secret, safe='!')
    #     payload = 'grant_type={}&client_secret={}&client_id={}'.format(grant_type, client_secret, client_id)
    #
    #     headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    #     urllib3.disable_warnings()
    #     _logger.info('---->> Payload {}'.format(payload))
    #
    #     try:
    #         response = requests.post(url, headers=headers, data=payload, verify=False)
    #         token = response.json()
    #         _logger.info("Successfully generation access token {}".format(token))
    #         return response.json()
    #     except Exception as e:
    #         _logger.info('Exception while generating access token: {}'.format(e))
    #         return {}

    def _set_client(self, wsdl
                    # , api, root
                    ):
        wsdl_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), wsdl)
        # _logger.info("wsdl             >>>>>>>>>>>>>>>>>>>>> " + wsdl)
        # _logger.info("wsdl_path        >>>>>>>>>>>>>>>>>>>>> " + wsdl_path)
        # _logger.info("wsdl_path.lstrip >>>>>>>>>>>>>>>>>>>>> " + 'file:///%s' % wsdl_path.lstrip('/'))
        # _logger.info("endurl           >>>>>>>>>>>>>>>>>>>>> " + self.endurl)
        client = Client('file:///%s' % wsdl_path.lstrip('/'),
                        timeout=KHALES_TIMOUT,
                        # plugins=[FixRequestNamespacePlug(root), LogPlugin(self.debug_logger)]
                        plugins=[LogPlugin(self.debug_logger)]
                        )

        # access_token = self.khales_channel.acquirer_id. \
        #     with_context(default_provider_channel=self.khales_channel).khales_generate_access_token()
        # if access_token is False:
        #     _logger.info('Cannot acquire access token, service not available')
        #     raise Exception('Cannot acquire access token, service not available')
        # _logger.info("Set access_token in security_header")

        # self._add_security_header(access_token, client)

        # self._add_security_header(client)
        client.set_options(location='%s'
                                    # '%s'
                                    % (self.endurl
                                       # , api
                                       ))
        # _logger.info("client           >>>>>>>>>>>>>>>>>>>>> " + str(client))
        return client

    def get_translated_message(self, msg):
        is_translated = False
        translated_msg = self.env['ir.translation'].sudo().search([
            ('type', '=', 'code'),
            ('name', '=', 'addons/tm_khales_gateway/models/khales_request.py'),
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
        msg, is_translated = self.get_translated_message(KHALES_ERROR_MAP.get(error_code))
        result['error_code'] = str(error_code)
        result['error_message'] = msg
        if not result['error_message']:
            msg, is_translated = self.get_translated_message(description)
            if is_translated:
                result['error_message'] = msg
            else:
                result['error_message_to_be_translated'] = msg
        return result

    def _buildRequest(self, client, msgCode, languagePref, namespace, posSerialNumber=None,  # suppressEcho,
                      # pmtType=None, billTypeCode=None, billingAcct=None, extraBillingAcctKeys=None,              # msgCode: BillInqRq, PmtAddRq
                      # amt=None, curCode=None, pmtMethod=None, notifyMobile=None,                                 # msgCode: PmtAddRq
                      # billRefNumber=None,                                                                        # msgCode: PmtAddRq & pmtType: POST
                      # billerId=None,                                                                             # msgCode: PmtAddRq & pmtType: PREP
                      billingAcct=None, billerId=None,  # msgCode: RBINQRQ, RPADVRQ, CNLPMTRQ
                      serviceType=None, additionInfo=None,  # msgCode: RBINQRQ
                      ePayBillRecID=None, payAmts=None,  # msgCode: RFINQRQ, RPADVRQ, CNLPMTRQ
                      pmtId=None, pmtIdType=None, feesAmts=None, billNumber=None, pmtMethod=None, pmtRefInfo=None,
                      # msgCode: RPADVRQ, CNLPMTRQ
                      cancelReason=None  # msgCode: CNLPMTRQ
                      ):

        '''
        signonRqType = client.factory.create('{}:SignonRqType'.format(namespace))
        signonRqType.ClientDt = datetime.now()
        signonRqType.LanguagePref = languagePref  # 'ar-eg' or 'en-gb'

        signonProfileType = client.factory.create('{}:SignonProfileType'.format(namespace))
        signonProfileType.Sender = self.sender     # ("%Configuration Value will be provided by Khales%")
        signonProfileType.Receiver = self.receiver # ("%Configuration Value will be provided by Khales%")
        signonProfileType.MsgCode = msgCode        # BRSINQRQ, RBINQRQ, RFINQRQ, RPADVRQ or CNLPMTRQ
        signonRqType.SignonProfile = signonProfileType

        bankSvcRqType = client.factory.create('{}:BankSvcRqType'.format(namespace))
        bankSvcRqType.RqUID = str(uuid.uuid1().time_low)

        # if msgCode == "BRSINQRQ":
            # billerInqRqType = client.factory.create('{}:BillerInqRqType'.format(namespace))
            # billerInqRqType.DeliveryMethod = self.deliveryMethod
            # billerInqRqType.ReturnLogos = True
            # billerInqRqType.ReturnBillingFreqCycles = True
            # billerInqRqType.ReturnPaymentRanges = True
            # bankSvcRqType.BillerInqRq = billerInqRqType

        if msgCode == "RBINQRQ":
            billInqRqType = client.factory.create('{}:BillInqRqType'.format(namespace))
            billInqRqType.BankId = self.bankId
            billInqRqType.AccessChannel = self.accessChannel
            accountIdType = client.factory.create('{}:AccountIdType'.format(namespace))
            accountIdType.BillingAcct = billingAcct
            accountIdType.BillerId = billerId
            billInqRqType.AccountId = accountIdType
            billInqRqType.ServiceType = serviceType
            if additionInfo:
                additionInfoType = client.factory.create('{}:AdditionInfoType'.format(namespace))
                additionInfoList = []
                for values in additionInfo:
                    valuesType = client.factory.create('{}:ValuesType'.format(namespace))
                    valuesType.Key = values.get("Key")
                    valuesType.Value = values.get("Value")
                    additionInfoList.append(valuesType)
                additionInfoType.Values = additionInfoList
                billInqRqType.AdditionInfo = additionInfoType
            bankSvcRqType.BillInqRq = billInqRqType

        if msgCode == 'RFINQRQ':
            feeInqRqType = client.factory.create('{}:FeeInqRqType'.format(namespace))
            feeInqRqType.EPayBillRecID = ePayBillRecID
            payAmtType = client.factory.create('{}:PayAmtType'.format(namespace))
            payAmtType.Sequence = "1"
            payAmtType.Amt = pmtAmt
            payAmtType.CurCode = curCode # 818
            feeInqRqType.PayAmt = payAmtType
            bankSvcRqType.FeeInqRq = feeInqRqType

        if msgCode == "RPADVRQ" or msgCode == "CNLPMTRQ":
            if msgCode == "RPADVRQ":
                pmtAdviceRqType = client.factory.create('{}:PmtAdviceRqType'.format(namespace))
                pmtAdviceRqType.EPayBillRecID = ePayBillRecID

            if msgCode == "CNLPMTRQ":
                cancelPmtRqType = client.factory.create('{}:CancelPmtRqType'.format(namespace))
                cancelPmtRqType.EPayBillRecID = ePayBillRecID
                cancelPmtRqType.CancelReason = cancelReason

            pmtRecType = client.factory.create('{}:PmtRecType'.format(namespace))

            pmtTransIdType = client.factory.create('{}:PmtTransIdType'.format(namespace))
            pmtTransIdType.PmtId = pmtId
            pmtTransIdType.PmtIdType = pmtIdType # EPTN, BLRPTN or BNKPTN
            pmtRecType.PmtTransId = pmtTransIdType

            pmtInfoType = client.factory.create('{}:PmtInfoType'.format(namespace))
            payAmtType = client.factory.create('{}:PayAmtType'.format(namespace))
            payAmtType.Sequence = "1"
            payAmtType.Amt = pmtAmt
            payAmtType.CurCode = curCode # 818
            pmtInfoType.PayAmt = payAmtType
            feesAmtType = client.factory.create('{}:FeesAmtType'.format(namespace))
            feesAmtType.Amt = feesAmt
            feesAmtType.CurCode = curCode # 818
            pmtInfoType.FeesAmt = feesAmtType
            pmtInfoType.PrcDt = fields.Datetime.now()
            pmtInfoType.BillNumber = billNumber
            accountIdType = client.factory.create('{}:AccountIdType'.format(namespace))
            accountIdType.BillingAcct = billingAcct
            accountIdType.BillerId = billerId
            pmtInfoType.AccountId = accountIdType
            pmtInfoType.BankId = self.bankId
            pmtInfoType.AccessChannel = self.accessChannel
            pmtInfoType.PmtMethod = pmtMethod # CASH, CCARD, EFT, ACTDEB
            pmtInfoType.PmtRefInfo = pmtRefInfo
            pmtRecType.PmtInfo = pmtInfoType

            if msgCode == "RPADVRQ":
                pmtAdviceRqType.PmtRec = pmtRecType
                bankSvcRqType.PmtAdviceRq = pmtAdviceRqType
            if msgCode == "CNLPMTRQ":
                cancelPmtRqType.PmtRec = pmtRecType
                bankSvcRqType.CancelPmtRq = cancelPmtRqType

        EFBPS = client.factory.create('{}:EFBPS'.format(namespace))
        EFBPS.SignonRq = signonRqType
        EFBPS.BankSvcRq = bankSvcRqType

        # khalesType = client.factory.create('{}:KHALESType'.format(namespace))
        # khalesType.Request = requestType

        return EFBPS # khalesType
        '''
        if payAmts and isinstance(payAmts, OrderedDict):
            payAmts = [payAmts]
        posSerialNumber = posSerialNumber or '%s%s' % (self.bankId, self.sender)
        xml_message = '''<![CDATA[<EFBPS><SignonRq><ClientDt>''' + str(
            (datetime.now() + timedelta(hours=2)).isoformat()) + '''</ClientDt><LanguagePref>''' + str(
            languagePref) + '''</LanguagePref><SignonProfile><Sender>''' + self.sender + '''</Sender><Receiver>''' + self.receiver + '''</Receiver><MsgCode>''' + str(
            msgCode) + '''</MsgCode></SignonProfile></SignonRq><BankSvcRq><RqUID>''' + '%s-%s' % (posSerialNumber, (
                datetime.now() + timedelta(hours=2)).strftime(
            '%Y%m%d%H%M%S')) + '''</RqUID>'''  # str(uuid.uuid1().time_low)

        if msgCode == "RBINQRQ":
            xml_message += '''<BillInqRq><BankId>''' + self.bankId + '''</BankId><AccessChannel>''' + self.accessChannel + '''</AccessChannel><AccountId>'''
            if billingAcct:
                xml_message += '''<BillingAcct>''' + str(billingAcct) + '''</BillingAcct>'''
            if billerId:
                xml_message += '''<BillerId>''' + str(billerId) + '''</BillerId>'''
            xml_message += '''</AccountId>'''
            if serviceType:
                xml_message += '''<ServiceType>''' + str(serviceType) + '''</ServiceType>'''

            if additionInfo:
                xml_message += '''<AdditionInfo>'''
                for values in additionInfo:
                    xml_message += '''<Values>'''
                    if values.get("Key"):
                        xml_message += '''<Key>''' + str(values.get("Key")) + '''</Key>'''
                    if values.get("Value"):
                        xml_message += '''<Value>''' + str(values.get("Value")) + '''</Value>'''
                    xml_message += '''</Values>'''
                xml_message += '''</AdditionInfo>'''

            xml_message += '''</BillInqRq>'''

        if msgCode == 'RFINQRQ':
            xml_message += '''<FeeInqRq>'''
            if ePayBillRecID:
                xml_message += '''<EPayBillRecID>''' + str(ePayBillRecID) + '''</EPayBillRecID>'''
            for payAmt in payAmts:
                xml_message += '''<PayAmt>'''
                if payAmt.get("Sequence"):
                    xml_message += '''<Sequence>''' + str(payAmt.get("Sequence")) + '''</Sequence>'''
                if payAmt.get("AmtDue"):
                    xml_message += '''<Amt>''' + str(payAmt.get("AmtDue")) + '''</Amt>'''
                if payAmt.get("CurCode"):
                    xml_message += '''<CurCode>''' + str(payAmt.get("CurCode")) + '''</CurCode>'''
                xml_message += '''</PayAmt>'''
            xml_message += '''</FeeInqRq>'''

        if msgCode == "RPADVRQ" or msgCode == "CNLPMTRQ":
            if msgCode == "RPADVRQ":
                xml_message += '''<PmtAdviceRq>'''
                if ePayBillRecID:
                    xml_message += '''<EPayBillRecID>''' + str(ePayBillRecID) + '''</EPayBillRecID>'''

            if msgCode == "CNLPMTRQ":
                xml_message += '''<CancelPmtRq>'''
                if ePayBillRecID:
                    xml_message += '''<EPayBillRecID>''' + str(ePayBillRecID) + '''</EPayBillRecID>'''

            # xml_message += '''<PmtRec><PmtTransId><PmtId>''' + pmtId + '''</PmtId><PmtIdType>''' + pmtIdType + '''</PmtIdType></PmtTransId><PmtInfo><PayAmt><Sequence>1</Sequence><Amt>''' + pmtAmt + '''</Amt><CurCode>''' + curCode + '''</CurCode></PayAmt><FeesAmt><Amt>''' + feesAmt + '''</Amt><CurCode>''' + curCode + '''</CurCode></FeesAmt><PrcDt>''' + str((fields.Datetime.now() + timedelta(hours=2)).isoformat()) + '''</PrcDt><BillNumber>''' + billNumber + '''</BillNumber><AccountId><BillingAcct>''' + billingAcct + '''</BillingAcct><BillerId>''' + billerId + '''</BillerId></AccountId><BankId>''' + self.bankId + '''</BankId><AccessChannel>''' + self.accessChannel + '''</AccessChannel><PmtMethod>''' + pmtMethod + '''</PmtMethod><PmtRefInfo>''' + pmtRefInfo + '''</PmtRefInfo></PmtInfo></PmtRec>'''
            xml_message += '''<PmtRec><PmtTransId>'''
            if pmtId:
                xml_message += '''<PmtId>''' + str(pmtId) + '''</PmtId>'''
            if pmtIdType:
                xml_message += '''<PmtIdType>''' + str(pmtIdType) + '''</PmtIdType>'''
            xml_message += '''</PmtTransId><PmtInfo>'''
            for payAmt in payAmts:
                xml_message += '''<PayAmt>'''
                if payAmt.get("Sequence"):
                    xml_message += '''<Sequence>''' + str(payAmt.get("Sequence")) + '''</Sequence>'''
                if payAmt.get("AmtDue"):
                    xml_message += '''<Amt>''' + str(payAmt.get("AmtDue")) + '''</Amt>'''
                if payAmt.get("CurCode"):
                    xml_message += '''<CurCode>''' + str(payAmt.get("CurCode")) + '''</CurCode>'''
                xml_message += '''</PayAmt>'''
            for feesAmt in feesAmts:
                xml_message += '''<FeesAmt>'''
                if feesAmt.get("Amt"):
                    xml_message += '''<Amt>''' + str(feesAmt.get("Amt")) + '''</Amt>'''
                if feesAmt.get("CurCode"):
                    xml_message += '''<CurCode>''' + str(feesAmt.get("CurCode")) + '''</CurCode>'''
                xml_message += '''</FeesAmt>'''
            xml_message += '''<PrcDt>''' + str(fields.Datetime.now()).replace(' ', 'T') + '''</PrcDt>'''
            if billNumber:
                xml_message += '''<BillNumber>''' + str(billNumber) + '''</BillNumber>'''
            xml_message += '''<AccountId>'''
            if billingAcct:
                xml_message += '''<BillingAcct>''' + str(billingAcct) + '''</BillingAcct>'''
            if billerId:
                xml_message += '''<BillerId>''' + str(billerId) + '''</BillerId>'''
            xml_message += '''</AccountId>'''
            xml_message += '''<BankId>''' + self.bankId + '''</BankId><AccessChannel>''' + self.accessChannel + '''</AccessChannel>'''
            if pmtMethod:
                xml_message += '''<PmtMethod>''' + str(pmtMethod) + '''</PmtMethod>'''
            if pmtRefInfo:
                xml_message += '''<PmtRefInfo>''' + str(pmtRefInfo) + '''</PmtRefInfo>'''
            if msgCode == "RPADVRQ":
                if additionInfo:
                    xml_message += '''<AdditionInfo><Values>'''
                    for values in additionInfo:
                        if values.get("Key"):
                            xml_message += '''<Key>''' + str(values.get("Key")) + '''</Key>'''
                        if values.get("Value"):
                            xml_message += '''<Value>''' + str(values.get("Value")) + '''</Value>'''
                    xml_message += '''</Values></AdditionInfo>'''
            xml_message += '''</PmtInfo></PmtRec>'''

            if msgCode == "RPADVRQ":
                xml_message += '''<SourceAddressDetails>'''
                xml_message += '''<TerminalId>''' + str(posSerialNumber) + '''</TerminalId>'''
                xml_message += '''<GovernorateCode>''' + '1' + '''</GovernorateCode>'''
                xml_message += '''</SourceAddressDetails></PmtAdviceRq>'''

            if msgCode == "CNLPMTRQ":
                if cancelReason:
                    xml_message += '''<CancelReason>''' + str(cancelReason) + '''</CancelReason>'''
                xml_message += '''</CancelPmtRq>'''

        xml_message += '''</BankSvcRq></EFBPS>]]>'''

        # _logger.info("EFBPS xml_message: " + xml_message)

        request_1 = client.factory.create('{}:Request'.format(namespace))
        request_1.message = Raw(xml_message)
        request_1.senderID = self.sender  # ("%Configuration Value will be provided by Khales%")
        request_1.signature = '?'
        return request_1

    '''
    def _buildResponse(khalesType):
        responseType = khalesType.Response

        signonRsType = responseType.SignonRs
        _logger.info("Client Date: "+ signonRsType.ClientDt)
        _logger.info("Customer Language: "+ signonRsType.CustLangPref)
        _logger.info("Server Language: "+ signonRsType.Language)
        _logger.info("Server Date: "+ signonRsType.ServerDt)

        signonProfileType = signonRsType.SignonProfile
        _logger.info("Message Code: "+ signonProfileType.MsgCode)
        _logger.info("Reciever: "+ signonProfileType.Receiver)
        _logger.info("Sender: "+ signonProfileType.Sender)
        _logger.info("Version: "+ signonProfileType.Version)
        if signonProfileType.MsgCode == "BillerInqRq" or signonProfileType.MsgCode == "BillInqRq":
            presSvcRsType= responseType.PresSvcRs
            statusType = presSvcRsType.Status
            msgRqHdrType = presSvcRsType.MsgRqHdr
        elif signonProfileType.MsgCode == "PmtAddRq":
            paySvcRsType= responseType.PaySvcRs
            statusType = paySvcRsType.Status
            msgRqHdrType = paySvcRsType.MsgRqHdr

        _logger.info("Status Code: "+ statusType.StatusCode)
        _logger.info("Status Desc: "+ statusType.StatusDesc)
        _logger.info("Status Severity: "+ statusType.Severity)

        if msgRqHdrType:
            customPropertyTypes= msgRqHdrType.CustomProperties.CustomProperty
            if customPropertyTypes:
                for customPropertyType in customPropertyTypes:
                    _logger.info("Customer Property Key: "+ customPropertyType.Key)
                    _logger.info("Customer Property Value: "+ customPropertyType.Value)

        if signonProfileType.MsgCode == "BillerInqRq":
            billerInqRsType = presSvcRsType.BillerInqRs
            _logger.info("Biller Payment Type: "+ billerInqRsType.PmtType)
            _logger.info("Biller Delivery Method: "+ billerInqRsType.DeliveryMethod)
            _logger.info("Biller Service Type: "+ billerInqRsType.ServiceType)

            billerRecTypes = billerInqRsType.BillerRec
            if billerRecTypes:
                for billerRecType in billerRecTypes:
                    _logger.info(" ====================================== Biller Data Begin "+ billerRecType.BillerId +" =========================================")
                    _logger.info("Biller ID: "+ billerRecType.BillerId)
                    _logger.info("Biller Name: "+ billerRecType.BillerName)
                    _logger.info("Biller Name Language: "+ billerRecType.BillerNameLang)
                    _logger.info("Biller Status: "+ billerRecType.BillerStatus)

                    billerInfoTypes = billerRecType.BillerInfo
                    if billerInfoTypes:
                        for billerInfoType in billerInfoTypes:
                            _logger.info("Biller Info Type: " + billerInfoType)
                            _logger.info("Bill Type Account Label: "+ billerInfoType.BillTypeAcctLabel)
                            _logger.info("Bill Type Code: "+ billerInfoType.BillTypeCode)
                            _logger.info("Bill Type Status: "+ billerInfoType.BillTypeStatus)
                            _logger.info("Extra Info: "+ billerInfoType.ExtraInfo)
                            _logger.info("Biller Service Name: "+ billerInfoType.Name)
                            _logger.info("Biller Service Name Language: "+ billerInfoType.NameLang)
                            _logger.info("Biller Payment Type: "+ billerInfoType.PmtType)
                            _logger.info("Bill Type Code: "+ billerInfoType.BillTypeCode)
                            _logger.info("Service Type: "+ billerInfoType.ServiceType)
                            _logger.info("Type: "+ billerInfoType.Type)
                            _logger.info("Receipt Footer: "+ billerInfoType.ReceiptFooter)
                            _logger.info("Receipt Footer Language: "+ billerInfoType.ReceiptFooterLang)
                            _logger.info("Receipt Header: "+ billerInfoType.ReceiptHeader)
                            _logger.info("Receipt Header Language: "+ billerInfoType.ReceiptHeaderLang)

                            _logger.info("Service Name: "+ billerInfoType.ServiceName)
                            _logger.info("Expiry Date: "+ billerInfoType.ExpiryDate)
                            _logger.info("Start Date: "+ billerInfoType.StartDate)

                            paymentRangeTypes =  billerInfoType.PaymentRanges.PaymentRangeType
                            if paymentRangeTypes:
                                for paymentRangeType in paymentRangeTypes:
                                    _logger.info("Payment Lower Amount: "+ paymentRangeType.Lower.Amt)
                                    _logger.info("Payment Lower Currency Code: "+ paymentRangeType.Lower.CurCode)
                                    _logger.info("Payment Upper Amount: "+ paymentRangeType.Upper.Amt)
                                    _logger.info("Payment Upper Currency Code: "+ paymentRangeType.Upper.CurCode)

                            tierTypes = billerInfoType.Fees.Tier
                            if tierTypes:
                                for tierType in tierTypes:
                                    _logger.info("Fees Expiry Date: "+tierType.ExpiryDate)
                                    _logger.info("Fees Start Date: "+tierType.StartDate)
                                    _logger.info("Fees Fixed Amount Currency Code: "+tierType.FixedAmt.CurCode)
                                    _logger.info("Fees Fixed Amount: "+tierType.FixedAmt.Amt)
                                    _logger.info("Fees Lower Amount: "+tierType.LowerAmt)
                                    _logger.info("Fees Percent: "+tierType.Percent)
                                    _logger.info("Fees Upper Amount: "+tierType.UpperAmt)

                    _logger.info(" ====================================== Biller Data End "+ billerRecType.BillerId +" =========================================")

        if signonProfileType.MsgCode == "BillInqRq":
            billInqRsType = presSvcRsType.BillInqRs
            if billInqRsType:
                _logger.info("Payment Type: "+ billInqRsType.PmtType)
                _logger.info("Delivery Method: "+ billInqRsType.DeliveryMethod)
                _logger.info("Service Type: "+ billInqRsType.ServiceType)

                billRecTypes = billInqRsType.BillRec
                if billRecTypes:
                    for billRecType in billRecTypes:
                        _logger.info(" ====================================== Bill Data Begin " + billRecType.BillerId + " =========================================")
                        _logger.info("Biller Id: "+ billRecType.BillerId)
                        _logger.info("Billing Account: "+ billRecType.BillingAcct)
                        _logger.info("Bill Number: "+ billRecType.BillNumber)
                        _logger.info("Bill Ref Number: "+ billRecType.BillRefNumber)
                        _logger.info("Bill Status: "+ billRecType.BillStatus)
                        _logger.info("Bill Type Code: "+ billRecType.BillTypeCode)

                        billInfoTypes=billRecType.BillInfo
                        _logger.info("Bill Category: "+ billInfoTypes.BillCategory)
                        _logger.info("Bill Due Date: "+ billInfoTypes.DueDt)
                        _logger.info("Bill Issue Date: "+ billInfoTypes.IssueDt)
                        _logger.info("Bill Expiry Date: "+ billInfoTypes.ExpDt)
                        _logger.info("Extra Bill Info: "+ billInfoTypes.ExtraBillInfo)

                        billSummAmtTypes = billInfoTypes.BillSummAmt
                        if billSummAmtTypes:
                            for billSummAmtType in billSummAmtTypes:
                                _logger.info("Bill Sum Amount Code: "+ billSummAmtType.BillSummAmtCode)
                                _logger.info("Bill Amount Curency Code: "+ billSummAmtType.CurAmt.CurCode)
                                _logger.info("Bill Amount: "+ billSummAmtType.CurAmt.Amt)

                        paymentRangeTypes= billInfoTypes.PaymentRange
                        if paymentRangeTypes:
                            for paymentRangeType in paymentRangeTypes:
                                _logger.info("Range Lower Amount: "+ paymentRangeType.Lower.Amt)
                                _logger.info("Range Lower Amount Currency: "+ paymentRangeType.Lower.CurCode)
                                _logger.info("Range Upper Amount: "+ paymentRangeType.Upper.Amt)
                                _logger.info("Range Upper Amount Currency: "+ paymentRangeType.Upper.CurCode)

                        _logger.info(" ====================================== Bill Data End " + billRecType.BillerId + " =========================================")

        if signonProfileType.MsgCode == "PmtAddRq":
            pmtAddRsType= responseType.PaySvcRs.PmtAddRs

            custIdTypes = pmtAddRsType.CustId

            if custIdTypes:
                for custIdType in custIdTypes:
                    _logger.info("Official ID: "+ custIdType.OfficialId)
                    _logger.info("Official ID Type: "+ custIdType.OfficialIdType)

            pmtInfoValTypes = pmtAddRsType.PmtInfoVal
            if pmtInfoValTypes:
                for pmtInfoValType in pmtInfoValTypes:
                    pmtInfoType = pmtInfoValType.PmtInfo
                    _logger.info("Biller ID: "+ pmtInfoType.BillerId)
                    _logger.info("Billing Account: "+ pmtInfoType.BillingAcct)
                    _logger.info("Bill Number: "+ pmtInfoType.BillNumber)
                    _logger.info("Bill Ref Number: "+ pmtInfoType.BillRefNumber)
                    _logger.info("Bill Type Code: "+ pmtInfoType.BillTypeCode)
                    _logger.info("Delivery Method: "+ pmtInfoType.DeliveryMethod)
                    _logger.info("Extra Bill Info: "+ pmtInfoType.ExtraBillInfo)
                    _logger.info("Issue Date: "+ pmtInfoType.IssueDt)
                    _logger.info("Is Notify Mobile: "+ pmtInfoType.NotifyMobile)
                    _logger.info("Payment Description: "+ pmtInfoType.PmtDesc)
                    _logger.info("Payment Method: "+ pmtInfoType.PmtMethod)
                    _logger.info("Payment Processing Date: "+ pmtInfoType.PrcDt)
                    _logger.info("Amount Currency Code: "+ pmtInfoType.CurAmt.CurCode)
                    _logger.info("Amount: "+ pmtInfoType.CurAmt.Amt)

                    acctKeyTypes = pmtInfoType.ExtraBillingAcctKeys.ExtraBillingAcctKey
                    if acctKeyTypes:
                        for acctKeyType in acctKeyTypes:
                            _logger.info("Extra Billing Account Key: "+ acctKeyType.Key)
                            _logger.info("Extra Billing Account Value: "+ acctKeyType.Value)

                    feesAmtType = pmtInfoType.FeesAmt
                    _logger.info("Fees Currency Code: "+ feesAmtType.CurCode)
                    _logger.info("Fees Amount: "+ feesAmtType.Amt)

                    pmtTransIdTypes= pmtInfoType.PmtTransId
                    if pmtTransIdTypes:
                        for pmtTransIdType in pmtTransIdTypes:
                            _logger.info("Payment Transaction Creation Date: "+ pmtTransIdType.CreatedDt)
                            _logger.info("Payment ID: "+ pmtTransIdType.PmtId)
                            _logger.info("Payment ID Type: "+ pmtTransIdType.PmtIdType)
    '''

    def get_biller_details(self, languagePref):
        try:
            client = self._set_client(self.wsdl)
        except Exception as e:
            _logger.error("KH [get_biller_details] Exception ERROR: " + str(e))
            return self.get_error_message('-2', 'KH Exception Found:\n%s' % e)


        '''
            client, msgCode, languagePref, namespace, # suppressEcho,
            # pmtType, billTypeCode, billingAcct, extraBillingAcctKeys,                                  # msgCode: BillInqRq, PmtAddRq
            # amt, curCode, pmtMethod, notifyMobile,                                                     # msgCode: PmtAddRq
            # billRefNumber,                                                                             # msgCode: PmtAddRq & pmtType: POST
            # billerId,                                                                                  # msgCode: PmtAddRq & pmtType: PREP
            billingAcct=None, billerId=None                                                              # msgCode: RBINQRQ, RPADVRQ, CNLPMTRQ
            serviceType=None, additionInfo=None,                                                         # msgCode: RBINQRQ
            ePayBillRecID=None, payAmts=None,                                                            # msgCode: RFINQRQ, RPADVRQ, CNLPMTRQ
            pmtId=None, pmtIdType=None, feesAmts=None, billNumber=None, pmtMethod=None, pmtRefInfo=None, # msgCode: RPADVRQ, CNLPMTRQ
            cancelReason = None                                                                          # msgCode: CNLPMTRQ
        '''
        namespace = 'ns2'
        EFBPS = self._buildRequest(client=client, msgCode="BRSINQRQ", languagePref=languagePref, namespace=namespace)
        # _logger.info("EFBPS Request: " + str(EFBPS))

        try:
            # Get All of billers data and associated bill types for a specific channel
            # _logger.info("Before Calling Khales Biller Details")
            khalesResponse = client.service.getBillers(EFBPS)
            # _logger.info("After Calling Khales Biller Details")
            # _logger.info("BRSINQRQ EFBPS Response: " + str(khalesResponse))

            response_message_dict = xmltodict.parse(khalesResponse.message)
            status_code = response_message_dict['EFBPS']['BankSvcRs']['Status']['StatusCode']
            short_desc = response_message_dict['EFBPS']['BankSvcRs']['Status']['ShortDesc']

            # Check if process is not success then return reason for that
            if status_code != '0':
                _logger.error("KH [get_biller_details] Response ERROR: [" + status_code + "]: " + short_desc)
                return self.get_error_message(status_code, short_desc)

            # _logger.info("Before Calling BRSINQRQ _buildResponse")
            # self._buildResponse(khalesResponse)
            # _logger.info("After Calling BRSINQRQ _buildResponse")

            result = {}
            # result['billerRecTypes'] = khalesResponse.BankSvcRs.BillerInqRs.BillerRec
            result['serviceGroupTypes'] = response_message_dict['EFBPS']['BankSvcRs']['BillerInqRs'][
                'ServiceGroup']  # khalesResponse.BankSvcRs.GetBillersRs.ServiceGroup
            # _logger.info("Khales Biller Details Result: " + str(result))

            return result

        except suds.WebFault as e:
            # childAtPath behaviour is changing at version 0.6
            prefix = ''
            if SUDS_VERSION >= "0.6":
                prefix = '/Envelope/Body/Fault'
            _logger.error("KH [get_biller_details] WebFault ERROR: " + str(e))
            return self.get_error_message(
                e.document.childAtPath(prefix + '/faultcode').getText(),
                e.document.childAtPath(prefix + '/faultstring').getText())
        except timeout as e:
            _logger.error("KH [get_biller_details] Timeout ERROR: " + str(e))
            return self.get_error_message('0', 'KH Server timeout:\n%s' % e)
        except IOError as e:
            _logger.error("KH [get_biller_details] IO ERROR: " + str(e))
            return self.get_error_message('-1', 'KH Server Not Found:\n%s' % e)
        except Exception as e:
            _logger.error("KH [get_biller_details] Exception ERROR: " + str(e))
            return self.get_error_message('-2', 'KH Exception Found:\n%s' % e)

    def get_bill_details(self, languagePref, posSerialNumber,
                         serviceType, billerId, billingAcct, additionInfo=None, requestNumber=None):
        try:
            client = self._set_client(self.wsdl)
        except Exception as e:
            _logger.error("KH [get_biller_details] Exception ERROR: " + str(e))
            return self.get_error_message('-2', 'KH Exception Found:\n%s' % e)

        '''
            client, msgCode, languagePref, namespace, # suppressEcho,
            # pmtType, billTypeCode, billingAcct, extraBillingAcctKeys,                                  # msgCode: BillInqRq, PmtAddRq
            # amt, curCode, pmtMethod, notifyMobile,                                                     # msgCode: PmtAddRq
            # billRefNumber,                                                                             # msgCode: PmtAddRq & pmtType: POST
            # billerId,                                                                                  # msgCode: PmtAddRq & pmtType: PREP
            billingAcct=None, billerId=None                                                              # msgCode: RBINQRQ, RPADVRQ, CNLPMTRQ
            serviceType=None, additionInfo=None,                                                         # msgCode: RBINQRQ
            ePayBillRecID=None, payAmts=None,                                                            # msgCode: RFINQRQ, RPADVRQ, CNLPMTRQ
            pmtId=None, pmtIdType=None, feesAmts=None, billNumber=None, pmtMethod=None, pmtRefInfo=None, # msgCode: RPADVRQ, CNLPMTRQ
            cancelReason = None                                                                          # msgCode: CNLPMTRQ
        '''
        namespace = 'ns2'
        EFBPS = self._buildRequest(client=client, msgCode="RBINQRQ", languagePref=languagePref, namespace=namespace,
                                   posSerialNumber=posSerialNumber, billingAcct=billingAcct, billerId=billerId,
                                   serviceType=serviceType, additionInfo=additionInfo)
        # _logger.info("EFBPS Request: " + str(EFBPS))

        try:
            # Get All of bill data
            # _logger.info("Before Calling Khales Bill Details")
            khalesResponse = client.service.enquireBills(EFBPS)
            # _logger.info("After Calling Khales Bill Details")
            # _logger.info("RBINQRQ EFBPS Response: " + str(khalesResponse))

            response_message_dict = xmltodict.parse(khalesResponse.message)
            status_code = response_message_dict['EFBPS']['BankSvcRs']['Status']['StatusCode']
            short_desc = response_message_dict['EFBPS']['BankSvcRs']['Status']['ShortDesc']

            # Check if process is not success then return reason for that
            if status_code != '0':
                _logger.error("KH [get_bill_details] Response ERROR: [" + status_code + "]: " + short_desc)
                return self.get_error_message(status_code, short_desc)

            # _logger.info("Before Calling RBINQRQ _buildResponse")
            # self._buildResponse(khalesResponse)
            # _logger.info("After Calling RBINQRQ _buildResponse")

            result = {}
            result['billRecType'] = response_message_dict['EFBPS']['BankSvcRs']['BillInqRs']['BillRec']  # [0]
            # _logger.info("Khales Bill Details Result: " + str(result))

            return result

        except suds.WebFault as e:
            # childAtPath behaviour is changing at version 0.6
            prefix = ''
            if SUDS_VERSION >= "0.6":
                prefix = '/Envelope/Body/Fault'
            _logger.error("KH [get_bill_details] WebFault ERROR: %s - %s" % (requestNumber or 'None', str(e)))
            return self.get_error_message(
                e.document.childAtPath(prefix + '/faultcode').getText(),
                e.document.childAtPath(prefix + '/faultstring').getText())
        except timeout as e:
            _logger.error("KH [get_bill_details] Timeout ERROR: %s - %s" % (requestNumber or 'None', str(e)))
            return self.get_error_message('0', 'KH Server timeout:\n%s' % e)
        except IOError as e:
            _logger.error("KH [get_bill_details] IO ERROR: %s - %s" % (requestNumber or 'None', str(e)))
            return self.get_error_message('-1', 'KH Server Not Found:\n%s' % e)
        except Exception as e:
            _logger.error("KH [get_bill_details] Exception ERROR: %s - %s" % (requestNumber or 'None', str(e)))
            return self.get_error_message('-2', 'KH Exception Found:\n%s' % e)

    def get_fees(self, languagePref, posSerialNumber,
                 ePayBillRecID, payAmts, requestNumber=None):
        try:
            client = self._set_client(self.wsdl)
        except Exception as e:
            _logger.error("KH [get_biller_details] Exception ERROR: " + str(e))
            return self.get_error_message('-2', 'KH Exception Found:\n%s' % e)

        '''
            client, msgCode, languagePref, namespace, # suppressEcho,
            # pmtType, billTypeCode, billingAcct, extraBillingAcctKeys,                                  # msgCode: BillInqRq, PmtAddRq
            # amt, curCode, pmtMethod, notifyMobile,                                                     # msgCode: PmtAddRq
            # billRefNumber,                                                                             # msgCode: PmtAddRq & pmtType: POST
            # billerId,                                                                                  # msgCode: PmtAddRq & pmtType: PREP
            billingAcct=None, billerId=None                                                              # msgCode: RBINQRQ, RPADVRQ, CNLPMTRQ
            serviceType=None, additionInfo=None,                                                         # msgCode: RBINQRQ
            ePayBillRecID=None, payAmts=None,                                                            # msgCode: RFINQRQ, RPADVRQ, CNLPMTRQ
            pmtId=None, pmtIdType=None, feesAmts=None, billNumber=None, pmtMethod=None, pmtRefInfo=None, # msgCode: RPADVRQ, CNLPMTRQ
            cancelReason = None                                                                          # msgCode: CNLPMTRQ
        '''
        namespace = 'ns2'
        EFBPS = self._buildRequest(client=client, msgCode="RFINQRQ", languagePref=languagePref, namespace=namespace,
                                   posSerialNumber=posSerialNumber, ePayBillRecID=ePayBillRecID, payAmts=payAmts)
        # _logger.info("EFBPS Request: " + str(EFBPS))

        try:
            # Get Fees
            # _logger.info("Before Calling Khales Fees Details")
            khalesResponse = client.service.calculateCommission(EFBPS)
            # _logger.info("After Calling Khales Fees Details")
            # _logger.info("RFINQRQ EFBPS Response: " + str(khalesResponse))

            response_message_dict = xmltodict.parse(khalesResponse.message)
            status_code = response_message_dict['EFBPS']['BankSvcRs']['Status']['StatusCode']
            short_desc = response_message_dict['EFBPS']['BankSvcRs']['Status']['ShortDesc']

            # Check if process is not success then return reason for that
            if status_code != '0':
                _logger.error("KH [get_fees] Response ERROR: [" + status_code + "]: " + short_desc)
                return self.get_error_message(status_code, short_desc)

            # _logger.info("Before Calling RFINQRQ _buildResponse")
            # self._buildResponse(khalesResponse)
            # _logger.info("After Calling RFINQRQ _buildResponse")

            result = {}
            result['feeInqRsType'] = response_message_dict['EFBPS']['BankSvcRs']['FeeInqRs']
            # _logger.info("Khales Fees Details Result: " + str(result))

            return result

        except suds.WebFault as e:
            # childAtPath behaviour is changing at version 0.6
            prefix = ''
            if SUDS_VERSION >= "0.6":
                prefix = '/Envelope/Body/Fault'
            _logger.error("KH [get_fees] WebFault ERROR: %s - %s" % (requestNumber or 'None', str(e)))
            return self.get_error_message(
                e.document.childAtPath(prefix + '/faultcode').getText(),
                e.document.childAtPath(prefix + '/faultstring').getText())
        except timeout as e:
            _logger.error("KH [get_fees] Timeout ERROR: %s - %s" % (requestNumber or 'None', str(e)))
            return self.get_error_message('0', 'KH Server timeout:\n%s' % e)
        except IOError as e:
            _logger.error("KH [get_fees] IO ERROR: %s - %s" % (requestNumber or 'None', str(e)))
            return self.get_error_message('-1', 'KH Server Not Found:\n%s' % e)
        except Exception as e:
            _logger.error("KH [get_fees] Exception ERROR: %s - %s" % (requestNumber or 'None', str(e)))
            return self.get_error_message('-2', 'KH Exception Found:\n%s' % e)

    def pay_bill(self, languagePref, posSerialNumber,
                 billingAcct, billerId, ePayBillRecID,
                 payAmts, pmtId, pmtIdType, feesAmts,
                 billNumber, pmtMethod, pmtRefInfo, additionInfo=None, requestNumber=None,
                 isAllowCancel=True, isAllowRetry=True, TIMOUT_RETRY=0):
        try:
            client = self._set_client(self.wsdl)
        except Exception as e:
            _logger.error("KH [get_biller_details] Exception ERROR: " + str(e))
            return self.get_error_message('-2', 'KH Exception Found:\n%s' % e)

        '''
            client, msgCode, languagePref, namespace, # suppressEcho,
            # pmtType, billTypeCode, billingAcct, extraBillingAcctKeys,                                  # msgCode: BillInqRq, PmtAddRq
            # amt, curCode, pmtMethod, notifyMobile,                                                     # msgCode: PmtAddRq
            # billRefNumber,                                                                             # msgCode: PmtAddRq & pmtType: POST
            # billerId,                                                                                  # msgCode: PmtAddRq & pmtType: PREP
            billingAcct=None, billerId=None                                                              # msgCode: RBINQRQ, RPADVRQ, CNLPMTRQ
            serviceType=None, additionInfo=None,                                                         # msgCode: RBINQRQ
            ePayBillRecID=None, payAmts=None,                                                            # msgCode: RFINQRQ, RPADVRQ, CNLPMTRQ
            pmtId=None, pmtIdType=None, feesAmts=None, billNumber=None, pmtMethod=None, pmtRefInfo=None, # msgCode: RPADVRQ, CNLPMTRQ
            cancelReason = None                                                                          # msgCode: CNLPMTRQ
        '''
        namespace = 'ns2'
        EFBPS = self._buildRequest(client=client, msgCode="RPADVRQ", languagePref=languagePref, namespace=namespace,
                                   posSerialNumber=posSerialNumber, billingAcct=billingAcct, additionInfo=additionInfo,
                                   billerId=billerId,
                                   ePayBillRecID=ePayBillRecID, payAmts=payAmts, pmtId=pmtId, pmtIdType=pmtIdType,
                                   feesAmts=feesAmts, billNumber=billNumber, pmtMethod=pmtMethod, pmtRefInfo=pmtRefInfo)
        # _logger.info("EFBPS Request: " + str(EFBPS))

        retry = TIMOUT_RETRY
        while retry < KHALES_TIMOUT_RETRY:
            try:
                # Pay Bill
                # _logger.info("Before Calling Khales Pay Bill")
                khalesResponse = client.service.confirmPayments(EFBPS)
                # _logger.info("After Calling Khales Pay Bill")
                # _logger.info("RPADVRQ EFBPS Response: " + str(khalesResponse))
                retry = KHALES_TIMOUT_RETRY

                response_message_dict = xmltodict.parse(khalesResponse.message)
                status_code = response_message_dict['EFBPS']['BankSvcRs']['Status'][
                    'StatusCode']  # ['PmtAdviceRs']['PmtRecAdviceStatus']
                short_desc = response_message_dict['EFBPS']['BankSvcRs']['Status']['ShortDesc']

                # Check if process is not success then return reason for that
                if status_code != '0':
                    _logger.error("KH [pay_bill] Response ERROR: [" + status_code + "]: " + short_desc)
                    return self.get_error_message(status_code, short_desc)

                # _logger.info("Before Calling RPADVRQ _buildResponse")
                # self._buildResponse(khalesResponse)
                # _logger.info("After Calling RPADVRQ _buildResponse")

                result = {}
                # result['pmtInfoValType'] =  khalesResponse.Response.PaySvcRs.PmtAddRs.PmtInfoVal[0]
                result['pmtAdviceRsType'] = response_message_dict['EFBPS']['BankSvcRs']['PmtAdviceRs']
                # _logger.info("Khales Pay Bill Result: " + str(result))

                return result

            except suds.WebFault as e:
                # childAtPath behaviour is changing at version 0.6
                # retry = KHALES_TIMOUT_RETRY
                prefix = ''
                if SUDS_VERSION >= "0.6":
                    prefix = '/Envelope/Body/Fault'
                _logger.error("KH [pay_bill] WebFault ERROR: %s - %s" % (requestNumber or 'None', str(e)))
                return self.get_error_message(
                    e.document.childAtPath(prefix + '/faultcode').getText(),
                    e.document.childAtPath(prefix + '/faultstring').getText())
            except timeout as e:
                if not isAllowRetry:
                    retry = KHALES_TIMOUT_RETRY
                else:
                    retry += 1
                if retry < KHALES_TIMOUT_RETRY:
                    _logger.info("Timeout Retry Payment: %s - %s" % (retry, ePayBillRecID))
                    client = self._set_client(self.wsdl)
                    namespace = 'ns2'
                    EFBPS = self._buildRequest(client=client, msgCode="RPADVRQ", languagePref=languagePref,
                                               namespace=namespace, posSerialNumber=posSerialNumber,
                                               billingAcct=billingAcct,
                                               billerId=billerId, ePayBillRecID=ePayBillRecID, payAmts=payAmts,
                                               pmtId=pmtId,
                                               pmtIdType=pmtIdType, feesAmts=feesAmts, billNumber=billNumber,
                                               pmtMethod=pmtMethod, pmtRefInfo=pmtRefInfo)
                if retry == KHALES_TIMOUT_RETRY:
                    _logger.error("KH [pay_bill] Timeout ERROR: %s - %s" % (requestNumber or 'None', str(e)))
                    if isAllowCancel:
                        result_payment = self.cancel_payment(languagePref, billingAcct, billerId, ePayBillRecID,
                                                             payAmts, pmtId, pmtIdType, feesAmts,
                                                             billNumber, pmtMethod, pmtRefInfo, '001', requestNumber,
                                                             TIMOUT_RETRY=KHALES_TIMOUT_RETRY - 2)
                        if result_payment.get('cancelPmtRsType'):  # Cancel Success
                            return self.get_error_message('CANCEL_SUCCESS', 'KH Server timeout:\n%s' % e)
                    return self.get_error_message('0', 'KH Server timeout:\n%s' % e)
            except IOError as e:
                if not isAllowRetry:
                    retry = KHALES_TIMOUT_RETRY
                else:
                    retry += 1
                if retry < KHALES_TIMOUT_RETRY:
                    _logger.info("IOError Retry Payment: %s - %s" % (retry, ePayBillRecID))
                    client = self._set_client(self.wsdl)
                    namespace = 'ns2'
                    EFBPS = self._buildRequest(client=client, msgCode="RPADVRQ", languagePref=languagePref,
                                               namespace=namespace, posSerialNumber=posSerialNumber,
                                               billingAcct=billingAcct,
                                               billerId=billerId, ePayBillRecID=ePayBillRecID, payAmts=payAmts,
                                               pmtId=pmtId,
                                               pmtIdType=pmtIdType, feesAmts=feesAmts, billNumber=billNumber,
                                               pmtMethod=pmtMethod, pmtRefInfo=pmtRefInfo)
                if retry == KHALES_TIMOUT_RETRY:
                    _logger.error("KH [pay_bill] IO ERROR: %s - %s" % (requestNumber or 'None', str(e)))
                    if isAllowCancel:
                        result_payment = self.cancel_payment(languagePref, billingAcct, billerId, ePayBillRecID,
                                                             payAmts, pmtId, pmtIdType, feesAmts,
                                                             billNumber, pmtMethod, pmtRefInfo, '001', requestNumber,
                                                             TIMOUT_RETRY=KHALES_TIMOUT_RETRY - 2)
                        if result_payment.get('cancelPmtRsType'):  # Cancel Success
                            return self.get_error_message('CANCEL_SUCCESS', 'KH Server Not Found:\n%s' % e)
                    return self.get_error_message('-1', 'KH Server Not Found:\n%s' % e)
            except Exception as e:
                '''
                _logger.error("KH [pay_bill] Exception ERROR: %s - %s" % (requestNumber or 'None', str(e)))
                return self.get_error_message('-2', 'KH Exception Found:\n%s' % e)
                '''
                if not isAllowRetry:
                    retry = KHALES_TIMOUT_RETRY
                else:
                    retry += 1
                if retry < KHALES_TIMOUT_RETRY:
                    _logger.info("Exception Retry Payment: %s - %s" % (retry, ePayBillRecID))
                    client = self._set_client(self.wsdl)
                    namespace = 'ns2'
                    EFBPS = self._buildRequest(client=client, msgCode="RPADVRQ", languagePref=languagePref,
                                               namespace=namespace, posSerialNumber=posSerialNumber,
                                               billingAcct=billingAcct,
                                               billerId=billerId, ePayBillRecID=ePayBillRecID, payAmts=payAmts,
                                               pmtId=pmtId,
                                               pmtIdType=pmtIdType, feesAmts=feesAmts, billNumber=billNumber,
                                               pmtMethod=pmtMethod, pmtRefInfo=pmtRefInfo)
                if retry == KHALES_TIMOUT_RETRY:
                    _logger.error("KH [pay_bill] Exception ERROR: %s - %s" % (requestNumber or 'None', str(e)))
                    if isAllowCancel:
                        result_payment = self.cancel_payment(languagePref, billingAcct, billerId, ePayBillRecID,
                                                             payAmts, pmtId, pmtIdType, feesAmts,
                                                             billNumber, pmtMethod, pmtRefInfo, '001', requestNumber,
                                                             TIMOUT_RETRY=KHALES_TIMOUT_RETRY - 2)
                        if result_payment.get('cancelPmtRsType'):  # Cancel Success
                            return self.get_error_message('CANCEL_SUCCESS', 'KH Server Not Found:\n%s' % e)
                    return self.get_error_message('-2', 'KH Exception Found:\n%s' % e)

    def _simulate_pay_bill_response(self, billingAcct, billerId, ePayBillRecID, payAmts, pmtId, pmtIdType, feesAmts,
                                    billNumber, pmtMethod, pmtRefInfo):
        '''
        {
          "count": 19,
          "data": {
            "request_number": "2208065072115",
            "request_datetime": "2022-08-21T17:08:52.419708",
            "provider": "khales",
            "provider_response": "",
            "extra_fees_amount": 0,
            "billingAcct": "GT-7C37CA8558CB31010E0E0E",
            "billRefNumber": "5569822",
            "billerId": 99950,
            "pmtType": "BNKPTN",
            "trans_amount": "101",
            "curCode": "818",
            "pmtMethod": "CARD",
            "ePayBillRecID": "RBINQRQ-220821-256289572086-GT-99950",
            "pmtId": "2208065072115",
            "feesAmt": "2.85",
            "pmtRefInfo": "7C37CA8558CB31010E0E0E-5569822-220821050836",
            "payAmts": [
              {
                "Sequence": "1",
                "AmtDue": "101",
                "CurCode": "818"
              }
            ],
            "feesAmts": [
              {
                "Amt": "2.85",
                "CurCode": "818"
              }
            ],
            "message": "Pay Service Bill request was submit successfully with amount 103.85 EGP. Your Machine Wallet Balance is 1646.0912 EGP"
          }
        }

        {
          "PmtRecAdviceStatus": {
            "PmtTransId": {
              "PmtId": "202299001862281952",
              "PmtIdType": "EPTN"
            },
            "SettlDt": "2022-08-22T00:00:00"
          },
          "billingAcct": "2646555",
          "billRefNumber": "20220821171437",
          "billerId": 55554,
          "pmtType": "BNKPTN",
          "trans_amount": "2000.00",
          "curCode": "818",
          "pmtMethod": "CARD",
          "ePayBillRecID": "33c4bb76-c6db-4384-8c94-a69085e9b6a8",
          "pmtId": "202299001862281952",
          "feesAmt": "18.00",
          "pmtRefInfo": "4194598",
          "payAmts": [
            {
              "Sequence": "1",
              "AmtDue": "2000.00",
              "CurCode": "818"
            }
          ],
          "feesAmts": [
            {
              "Amt": "18.00",
              "CurCode": "818"
            }
          ]
        }
        '''
        now = datetime.now()
        trans_amount = 0.0
        if payAmts and isinstance(payAmts, OrderedDict):
            payAmts = [payAmts]
        for payAmt in payAmts:
            if payAmt.get("AmtDue"):
                trans_amount += float(payAmt.get("AmtDue"))
        fees_amt = 0.0
        if feesAmts and isinstance(feesAmts, OrderedDict):
            feesAmts = [feesAmts]
        for feesAmt in feesAmts:
            if feesAmt.get("Amt"):
                fees_amt += float(feesAmt.get("Amt"))
        result = {
            "PmtRecAdviceStatus": {
                "PmtTransId": {
                    "PmtId": "%s" % pmtId,
                    "PmtIdType": "EPTN"
                },
                "SettlDt": "%s" % str(now).replace(' ', 'T')
            },
            "billingAcct": "%s" % billingAcct,
            "billRefNumber": "%s" % billNumber,
            "billerId": "%s" % billerId,
            "pmtType": "%s" % pmtIdType,
            "trans_amount": "%s" % trans_amount,
            "curCode": "818",
            "pmtMethod": "%s" % pmtMethod,
            "ePayBillRecID": "%s" % ePayBillRecID,
            "pmtId": "%s" % pmtId,
            "feesAmt": "%s" % fees_amt,
            "pmtRefInfo": "%s" % pmtRefInfo,
            "payAmts": payAmts,
            "feesAmts": feesAmts,
            "timeout": True
        }
        return result

    def cancel_payment(self, languagePref, posSerialNumber,
                       billingAcct, billerId, ePayBillRecID,
                       payAmts, pmtId, pmtIdType, feesAmts,
                       billNumber, pmtMethod, pmtRefInfo, cancelReason, requestNumber=None, TIMOUT_RETRY=0):
        try:
            client = self._set_client(self.wsdl)
        except Exception as e:
            _logger.error("KH [get_biller_details] Exception ERROR: " + str(e))
            return self.get_error_message('-2', 'KH Exception Found:\n%s' % e)

        '''
            client, msgCode, languagePref, namespace, # suppressEcho,
            # pmtType, billTypeCode, billingAcct, extraBillingAcctKeys,                                  # msgCode: BillInqRq, PmtAddRq
            # amt, curCode, pmtMethod, notifyMobile,                                                     # msgCode: PmtAddRq
            # billRefNumber,                                                                             # msgCode: PmtAddRq & pmtType: POST
            # billerId,                                                                                  # msgCode: PmtAddRq & pmtType: PREP
            billingAcct=None, billerId=None                                                              # msgCode: RBINQRQ, RPADVRQ, CNLPMTRQ
            serviceType=None, additionInfo=None,                                                         # msgCode: RBINQRQ
            ePayBillRecID=None, payAmts=None,                                                            # msgCode: RFINQRQ, RPADVRQ, CNLPMTRQ
            pmtId=None, pmtIdType=None, feesAmts=None, billNumber=None, pmtMethod=None, pmtRefInfo=None, # msgCode: RPADVRQ, CNLPMTRQ
            cancelReason = None                                                                          # msgCode: CNLPMTRQ
        '''
        namespace = 'ns2'
        EFBPS = self._buildRequest(client=client, msgCode="CNLPMTRQ", languagePref=languagePref, namespace=namespace,
                                   posSerialNumber=posSerialNumber, billingAcct=billingAcct, billerId=billerId,
                                   ePayBillRecID=ePayBillRecID, payAmts=payAmts, pmtId=pmtId, pmtIdType=pmtIdType,
                                   feesAmts=feesAmts, billNumber=billNumber, pmtMethod=pmtMethod,
                                   pmtRefInfo=pmtRefInfo, cancelReason=cancelReason)
        # _logger.info("EFBPS Request: " + str(EFBPS))

        retry = TIMOUT_RETRY
        while retry < KHALES_TIMOUT_RETRY:
            try:
                # Cancel Payment
                # _logger.info("Before Calling Khales Cancel Payment")
                khalesResponse = client.service.CancelPmt(EFBPS)
                # _logger.info("After Calling Khales Cancel Payment")
                # _logger.info("CNLPMTRQ EFBPS Response: " + str(khalesResponse))
                retry = KHALES_TIMOUT_RETRY

                response_message_dict = xmltodict.parse(khalesResponse.message)
                status_code = response_message_dict['EFBPS']['BankSvcRs']['Status']['StatusCode']
                short_desc = response_message_dict['EFBPS']['BankSvcRs']['Status']['ShortDesc']

                # Check if process is not success then return reason for that
                if status_code != '0':
                    _logger.error("KH [cancel_payment] Response ERROR: [" + status_code + "]: " + short_desc)
                    return self.get_error_message(status_code, short_desc)

                # _logger.info("Before Calling CNLPMTRQ _buildResponse")
                # self._buildResponse(khalesResponse)
                # _logger.info("After Calling CNLPMTRQ _buildResponse")

                result = {}
                result['cancelPmtRsType'] = response_message_dict['EFBPS']['BankSvcRs']  # ['PaySvcRs']['CancelPmtRs']
                # _logger.info("Khales Cancel Payment Result: " + str(result))

                return result

            except suds.WebFault as e:
                # childAtPath behaviour is changing at version 0.6
                prefix = ''
                if SUDS_VERSION >= "0.6":
                    prefix = '/Envelope/Body/Fault'
                _logger.error("KH [cancel_payment] WebFault ERROR: %s - %s" % (requestNumber or 'None', str(e)))
                return self.get_error_message(
                    e.document.childAtPath(prefix + '/faultcode').getText(),
                    e.document.childAtPath(prefix + '/faultstring').getText())
            except timeout as e:
                retry += 1
                if retry < KHALES_TIMOUT_RETRY:
                    _logger.info("Timeout Retry Cancel Payment: %s - %s" % (retry, ePayBillRecID))
                    client = self._set_client(self.wsdl)
                    namespace = 'ns2'
                    EFBPS = self._buildRequest(client=client, msgCode="CNLPMTRQ", languagePref=languagePref,
                                               namespace=namespace, posSerialNumber=posSerialNumber,
                                               billingAcct=billingAcct, billerId=billerId, ePayBillRecID=ePayBillRecID,
                                               payAmts=payAmts, pmtId=pmtId, pmtIdType=pmtIdType,
                                               feesAmts=feesAmts, billNumber=billNumber, pmtMethod=pmtMethod,
                                               pmtRefInfo=pmtRefInfo, cancelReason=cancelReason)
                if retry == KHALES_TIMOUT_RETRY:
                    _logger.error("KH [cancel_payment] Timeout ERROR: %s - %s" % (requestNumber or 'None', str(e)))
                    return self.get_error_message('0', 'KH Server timeout:\n%s' % e)
            except IOError as e:
                retry += 1
                if retry < KHALES_TIMOUT_RETRY:
                    _logger.info("IOError Retry Cancel Payment: %s - %s" % (retry, ePayBillRecID))
                    client = self._set_client(self.wsdl)
                    namespace = 'ns2'
                    EFBPS = self._buildRequest(client=client, msgCode="CNLPMTRQ", languagePref=languagePref,
                                               namespace=namespace, posSerialNumber=posSerialNumber,
                                               billingAcct=billingAcct, billerId=billerId, ePayBillRecID=ePayBillRecID,
                                               payAmts=payAmts, pmtId=pmtId, pmtIdType=pmtIdType,
                                               feesAmts=feesAmts, billNumber=billNumber, pmtMethod=pmtMethod,
                                               pmtRefInfo=pmtRefInfo, cancelReason=cancelReason)
                if retry == KHALES_TIMOUT_RETRY:
                    _logger.error("KH [cancel_payment] IO ERROR: %s - %s" % (requestNumber or 'None', str(e)))
                    return self.get_error_message('-1', 'KH Server Not Found:\n%s' % e)
            except Exception as e:
                '''
                _logger.error("KH [cancel_payment] Exception ERROR: %s - %s" % (requestNumber or 'None', str(e)))
                return self.get_error_message('-2', 'KH Exception Found:\n%s' % e)
                '''
                retry += 1
                if retry < KHALES_TIMOUT_RETRY:
                    _logger.info("Exception Retry Cancel Payment: %s - %s" % (retry, ePayBillRecID))
                    client = self._set_client(self.wsdl)
                    namespace = 'ns2'
                    EFBPS = self._buildRequest(client=client, msgCode="CNLPMTRQ", languagePref=languagePref,
                                               namespace=namespace, posSerialNumber=posSerialNumber,
                                               billingAcct=billingAcct, billerId=billerId, ePayBillRecID=ePayBillRecID,
                                               payAmts=payAmts, pmtId=pmtId, pmtIdType=pmtIdType,
                                               feesAmts=feesAmts, billNumber=billNumber, pmtMethod=pmtMethod,
                                               pmtRefInfo=pmtRefInfo, cancelReason=cancelReason)
                if retry == KHALES_TIMOUT_RETRY:
                    _logger.error("KH [cancel_payment] Exception ERROR: %s - %s" % (requestNumber or 'None', str(e)))
                    return self.get_error_message('-2', 'KH Exception Found:\n%s' % e)
