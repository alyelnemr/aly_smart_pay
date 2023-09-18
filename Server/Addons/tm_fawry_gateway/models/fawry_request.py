# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.

import logging
import os
from datetime import datetime
import uuid
import re
import time

import suds
from suds.client import Client
from suds.plugin import MessagePlugin
from socket import timeout

from odoo import _

SUDS_VERSION = suds.__version__


_logger = logging.getLogger(__name__)
# uncomment to enable logging of SOAP requests and responses
# logging.getLogger('suds.transport').setLevel(logging.DEBUG)

FAWRY_TIMOUT = 60 # timeout in second
FAWRY_TIMOUT_RETRY = 3 # Retry x time to call provider when timeout
FAWRY_ERROR_MAP = {
    '1': _("Failed to log received Data."),
    '2': _("No Log Storage Configured."),
    '3': _("Configured Log Storage is not Accessible."),
    '4': _("Unknown Message Type."),
    '5': _("Failed to Transform Message."),
    '6': _("Sender is not authorized."),
    '7': _("Message Not Valid."),
    '8': _("Function Not Available."),
    '9': _("Unsupported Service."),
    '10': _("Unsupported Message."),
    '11': _("Unsupported Function."),
    '12': _("Required Element Not Included."),
    '13': _("Duplicate <RqUID>."),
    '14': _("Field not found."),
    '15': _("Message type not exists."),
    '16': _("Missing elements."),
    '17': _("Wrong element data type."),
    '18': _("Element Amount Value Out of Range."),
    '19': _("Element location is not valid."),
    '20': _("Sign in to destination failed."),
    '21': _("Biller Timeout"),
    '23': _("Asynchronous Request Does Not Match Original Request"),
    '24': _("DateTime Too Far In Future"),
    '25': _("General Data Error"),
    '26': _("General Error"),
    '27': _("Invalid  Biller Id"),
    '28': _("Invalid DateTime - Single date or Low of Range"),
    '29': _("Invalid DateTime Range"),
    '30': _("Invalid Enum Value"),
    '31': _("Message Authentication Error"),
    '32': _("None of Selection Criteria Supported"),
    '33': _("Request Denied"),
    '34': _("Service not Enabled"),
    '35': _("The <Cursor> returned within <RecCtrlIn> is invalid or has expired"),
    '36': _("Usage Limit Exceeded"),
    '37': _("Message version is not valid or not supported."),
    '39': _("Invalid Bill Type Code"),
    '40': _("Invalid Transaction State"),
    '41': _("Biller is unauthorized or In-Active"),
    '42': _("Bank is unauthorized or In-Active"),
    '51': _("EBPP Switch Timeout "),
    '61': _("EBPP Gateway Timeout"),
    '11001': _("Failed to Retrieve Billers\ Operators List"),
    '12002': _("In-Active Customer Account"),
    '12006': _("Bill account is not available at biller repository."),
    '12007': _("Biller request customer to contact the biller offices."),
    '12008': _("Failed to retrieve bill information due to system error."),
    '12009': _("Billing account does not allow the payment through this channel."),
    '12010': _("Failed to fetch payment rules due to some system error."),
    '12011': _("Invalid Billing Account Number."),
    '12012': _("Failed to get payment business rules for this bill type."),
    '12013': _("Invalid Bill Number."),
    '21001': _("Bill Account Number Strucure Error"),
    '21002': _("Biller Is Not authorized or In-Active."),
    '21003': _("Bank Is Not authorized or In-Active."),
    '21004': _("Payment Amount validation Error"),
    '21005': _("Connection Time Out or Biller unreachable"),
    '21006': _("Bill Validation Failed"),
    '21007': _("You are not authorized to access this service"),
    '21008': _("Gateway Connection time out"),
    '21009': _("Bill not allowed for payment. Previous bills should be paid."),
    '21010': _("Payment Amount Exceeds Due Payment amount."),
    '21011': _("Payment Amount is less than Due Payment amount."),
    '21012': _("Bill not available for payment."),
    '21013': _("Invalid Billing Account."),
    '21014': _("Invalid Bill Number."),
    '21015': _("Bill not allowed for payment. Previous bills should be paid."),
    '21016': _("Payment Amount Exceeds Due Payment amount."),
    '21017': _("Payment Amount is less than Due Payment amount."),
    '21018': _("Bill not available for payment."),
    '21019': _("Fawry Payment Amount Exceeds Due Payment amount."),
    '21020': _("Fawry Payment Amount is less than Due Payment amount."),
    '21021': _("duplicate payment transaction."),
    '21090': _("Vehicle License Renewal Fees should be paid first"),
    '21092': _("The customer did not confirm the transaction yet"),
    '21132': _("Expired Payment Retry."),
    '22001': _("Payment Not Valid."),
    '22002': _("Biller is unauthorized or in-active."),
    '22003': _("Bank is unauthorized or in-active."),
    '22004': _("Payment Amount validation Error"),
    '22005': _("Invalid Channel Type Code."),
    '22006': _("Payment is already advised."),
    '22007': _("Mismatch in payment & Advice Amounts."),
    '22008': _("Gateway Connection time out"),
    '22009': _("Payment Advice Request Failed"),
    '22010': _("Invalid Billing Account."),
    '22011': _("Invalid Bill Number."),
    '24002': _("Transaction will be delayed."),
    '24003': _("Payment Rejected From Biller"),
    '24004': _("Payment Reversal Rejected by Biller"),
    '24005': _("No Response From Biller"),
    '31001': _("Source Account Invalid"),
    '31002': _("Source Account Not Eligible For Transaction"),
    '31004': _("Insufficient Funds."),
    '31005': _("Collection Account Invalid."),
    '31006': _("Daily Limit Exceeded"),
    '32201': _("Message Accepted for Asynchronous Processing."),
    '22012': _("Failed to Process Payment. General Error."),
    '23001': _("Invalid transaction."),
    '23002': _("Tranaction already Confirmed."),
    '23101': _("Payment Advice In Progress ."),
    '32001': _("Reverse Request Does Not Match Original Debit Request."),
    '32002': _("Reverse Request is for invalid Debit transaction."),
    '32003': _("Failed to reverse payment."),
    '32004': _("Invalid Source Account (From account)."),
    '32005': _("Invalid Collection Account (To account)."),
    '32006': _("Reverse Payment request declined."),
    '33101': _("No Transactions Exists for Requested Date."),
    '33001': _("FAWRY EBPP Cut off request received for Reconciliation Date with Payment Totals Log already sent."),
    '34001': _("Wrong Reconciliation Date."),
    '34002': _("Totals Already Received."),
    '35101': _("No Transactions exists"),
    '35001': _("Wrong Reconciliation date requested"),
    '35002': _("Waiting to Send Payment Totals Log"),
    '35003': _("Received Bill Type Totals not belongs to the current reconciliation date."),
    '36001': _("Wrong Reconciliation Date"),
    '36002': _("Details are not for the targeted Bill Type"),
    '36003': _("Details Already Received"),
    '37001': _("Failed to Transfer Reconciled Bill amounts"),
    '37002': _("Wrong reconciliation date requested"),
    '37003': _("Waiting to Send Payment Totals Log"),
    '37004': _("Received Bill Type Totals not belongs to the current reconciliation date."),
    '41001': _("Wrong Reconciliation Date"),
    '38001': _("Wrong Settlement Date"),
    '38101': _("Settlement Report Already Received"),
}

class LogPlugin(MessagePlugin):
    """ Small plugin for suds that catches out/ingoing XML requests and logs them"""
    def __init__(self, debug_logger):
        self.debug_logger = debug_logger

    def sending(self, context):
        self.debug_logger(context.envelope, 'fawry_request')

    def received(self, context):
        '''
        answer = context.reply
        answerDecoded = answer.decode()
        xmlMessage = re.search(r'(<soapenv\:Envelope.*)\r', answerDecoded)
        replyFinal = xmlMessage.group(1) + '\n'
        replyFinalDecoded = replyFinal.encode()
        context.reply = replyFinalDecoded
        '''
        self.debug_logger(context.reply, 'fawry_response')

'''
class FixRequestNamespacePlug(MessagePlugin):
    def __init__(self, root):
        self.root = root

    def marshalled(self, context):
        context.envelope = context.envelope.prune()
'''

class FAWRYRequest():
    def __init__(self, debug_logger, endurl, env,
                 sender, receiver, version, originatorCode, terminalId, deliveryMethod,                             # msgCode: BillerInqRq, BillInqRq, PmtAddRq and PmtReversal
                 profileCode=None,                                                                                  # msgCode: BillerInqRq
                 bankId=None,                                                                                       # msgCode: BillInqRq, PmtAddRq and PmtReversal
                 acctId=None, acctType=None, acctKey=None, secureAcctKey=None, acctCur=None, posSerialNumber=None   # msgCode: PmtAddRq and PmtReversal
                 ):
        self.debug_logger = debug_logger
        # Production and Testing url
        self.endurl = endurl
        self.env = env

        # Basic detail require to authenticate
        self.sender = sender                            # sender: SmartPay2_MOB                      ==> Per Channel
        self.receiver = receiver                        # receiver: SmartPay2
        self.version = version                          # version: V1.0
        self.originatorCode = originatorCode            # originatorCode: SmartPay2
        self.terminalId = terminalId                    # terminalId: 104667                         ==> Per Channel
        self.deliveryMethod = deliveryMethod            # DeliveryMethod: MOB                        ==> Per Channel
        self.profileCode = profileCode                  # ProfileCode: 22013                         ==> Per Channel
        if acctId:
            self.acctId = acctId                        # acctId: 104667                             ==> Per Channel
        if bankId:
            self.bankId = bankId                        # bankId: SmartPay2
        if acctType:
            self.acctType = acctType                    # acctType: SDA                             ==> Per Channel
        if acctKey:
            self.acctKey = acctKey                      # acctKey: 1234                             ==> Per Channel
        if secureAcctKey:
            self.secureAcctKey = secureAcctKey          # secureAcctKey: gdyb21LQTcIANtvYMT7QVQ==   ==> Per Channel
        if acctCur:
            self.acctCur = acctCur.name                 # acctCur: EGP                              ==> Per Channel
        self.posSerialNumber = posSerialNumber          # posSerialNumber: 332-491-1222             ==> Per Channel

        self.wsdl = '../api/ApplicationBusinessFacadeService.wsdl'

    '''
        def _add_security_header(self, client, namspace):
            # # set the detail which require to authenticate

            # security_ns = ('tns', 'http://www.fawry-eg.com/ebpp/IFXMessages/')
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

    def _set_client(self, wsdl
                    # , api, root
                    ):
        wsdl_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), wsdl)
        # _logger.info("wsdl             >>>>>>>>>>>>>>>>>>>>> " + wsdl)
        # _logger.info("wsdl_path        >>>>>>>>>>>>>>>>>>>>> " + wsdl_path)
        # _logger.info("wsdl_path.lstrip >>>>>>>>>>>>>>>>>>>>> " + 'file:///%s' % wsdl_path.lstrip('/'))
        # _logger.info("endurl           >>>>>>>>>>>>>>>>>>>>> " + self.endurl)
        client = Client('file:///%s' % wsdl_path.lstrip('/'),
                        timeout=FAWRY_TIMOUT,
                        # plugins=[FixRequestNamespacePlug(root), LogPlugin(self.debug_logger)]
                        plugins=[LogPlugin(self.debug_logger)]
                        )
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
            ('name', '=', 'addons/tm_fawry_gateway/models/fawry_request.py'),
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
        msg, is_translated = self.get_translated_message(FAWRY_ERROR_MAP.get(str(error_code)))
        result['error_code'] = str(error_code)
        result['error_message'] = msg
        if not result['error_message']:
            msg, is_translated = self.get_translated_message(description)
            if is_translated:
                result['error_message'] = msg
            else:
                result['error_message_to_be_translated'] = msg
        return result

    def _buildRequest(self, client, msgCode, custLangPref, suppressEcho, namespace,
                      pmtType=None, billTypeCode=None, billingAcct=None, extraBillingAcctKeys=None,        # msgCode: BillInqRq, PmtAddRq and PmtReversal
                      amt=None, curCode=None, pmtMethod=None, notifyMobile=None, clientTerminalSeqId=None, # msgCode: PmtAddRq and PmtReversal
                      billRefNumber=None,                                                                  # msgCode: PmtAddRq & pmtType: POST and PmtReversal
                      billerId=None,                                                                       # msgCode: PmtAddRq & pmtType: PREP and PmtReversal
                      pmtTransIds=None,                                                                    # msgCode: PmtAddCorrRq
                      customProperties=None,
                      isRetry=None
                      ): # BillInqRq: IsRetry, IncOpenAmt => False, BillerId, PmtType => PREP
                         # PmtAddRq: IsRetry, billerId, pmtType
        '''
        # FAWRY JAVA Example Code
        FAWRYType fawryType = new FAWRYType();

		SignonRqType signonRqType = new SignonRqType();
        GregorianCalendar gcal = new GregorianCalendar();
        XMLGregorianCalendar xgcal = DatatypeFactory.newInstance().newXMLGregorianCalendar(gcal);
		signonRqType.setClientDt(xgcal);
		signonRqType.setCustLangPref("en-gb");
		signonRqType.setSuppressEcho(true);
		'''
        signonRqType = client.factory.create('{}:SignonRqType'.format(namespace))
        signonRqType.ClientDt = datetime.now()
        if msgCode != "PmtReversal":
            signonRqType.CustLangPref = custLangPref  # 'ar-eg' or 'en-gb'
            signonRqType.SuppressEcho = suppressEcho  # False

        '''
        # FAWRY JAVA Example Code
		SignonProfileType signonProfileType = new SignonProfileType();

		signonProfileType.setMsgCode("PmtAddRq"); /* SignonRq*/ // BillerInqRq, BillInqRq or PmtAddRq
		signonProfileType.setReceiver("%Configuration Value will be provided by Fawry%");
		signonProfileType.setVersion("V1.0");
		signonProfileType.setSender("%Configuration Value will be provided by Fawry%");
		signonRqType.setSignonProfile(signonProfileType); /* SignonRq*/
		'''
        signonProfileType = client.factory.create('{}:SignonProfileType'.format(namespace))
        signonProfileType.Sender = self.sender     # ("%Configuration Value will be provided by Fawry%")
        signonProfileType.Receiver = self.receiver # ("%Configuration Value will be provided by Fawry%")
        signonProfileType.MsgCode = "PmtAddRq" if msgCode == "PmtReversal" else msgCode # BillerInqRq, BillInqRq, PmtAddRq or PmtReversal
        signonProfileType.Version = self.version
        signonRqType.SignonProfile = signonProfileType

        msgRqHdrType = client.factory.create('{}:MsgRqHdrType'.format(namespace))
        networkTrnInfoType = client.factory.create('{}:NetworkTrnInfoType'.format(namespace))
        networkTrnInfoType.OriginatorCode = self.originatorCode  # ("%Configuration Value will be provided by Fawry%")
        networkTrnInfoType.TerminalId = self.terminalId          # ("%Configuration Value will be provided by Fawry%")
        msgRqHdrType.NetworkTrnInfo = networkTrnInfoType
        if msgCode in ("PmtAddRq", "PmtReversal") and clientTerminalSeqId:
            msgRqHdrType.ClientTerminalSeqId = clientTerminalSeqId

        if msgCode == "BillInqRq" and customProperties:
            customPropertiesType = client.factory.create('{}:CustomPropertiesType'.format(namespace))
            customPropertiesList = []
            for customProperty in customProperties:
                customPropertyType = client.factory.create('{}:CustomPropertyType'.format(namespace))
                customPropertyType.Key = customProperty.get("Key")
                customPropertyType.Value = customProperty.get("Value")
                customPropertiesList.append(customPropertyType)
            customPropertiesType.CustomProperty = customPropertiesList
            msgRqHdrType.CustomProperties = customPropertiesType

        '''
        # FAWRY JAVA Example Code
		// BillerInqRq, BillInqRq
			PresSvcRqType presSvcRqType = new PresSvcRqType();
			presSvcRqType.setRqUID(java.util.UUID.randomUUID().toString());

			// BillerInqRq
				//presSvcRqType.setAsyncRqUID(java.util.UUID.randomUUID().toString());
				BillerInqRqType billerInqRqType = new BillerInqRqType();
				billerInqRqType.setDeliveryMethod("INT");
				billerInqRqType.setReturnLogos(true);
				billerInqRqType.setReturnBillingFreqCycles(true);
				billerInqRqType.setReturnPaymentRanges(true);
				presSvcRqType.setBillerInqRq(billerInqRqType);

			// BillInqRq
				BillInqRqType billInqRqType = new BillInqRqType();
				billInqRqType.setPmtType("POST");
				billInqRqType.setDeliveryMethod("INT");
				billInqRqType.setBillTypeCode(155L);
				presSvcRqType.setBillInqRq(billInqRqType);
		'''
        if msgCode in ("BillerInqRq", "BillInqRq"):
            presSvcRqType = client.factory.create('{}:PresSvcRqType'.format(namespace))
            presSvcRqType.RqUID = str(uuid.uuid1())
            presSvcRqType.MsgRqHdr = msgRqHdrType

            if msgCode == "BillerInqRq":
                billerInqRqType = client.factory.create('{}:BillerInqRqType'.format(namespace))
                billerInqRqType.DeliveryMethod = self.deliveryMethod
                billerInqRqType.ReturnLogos = True
                billerInqRqType.ReturnBillingFreqCycles = True
                billerInqRqType.ReturnPaymentRanges = True
                presSvcRqType.BillerInqRq = billerInqRqType

            if msgCode == "BillInqRq":
                billInqRqType = client.factory.create('{}:BillInqRqType'.format(namespace))
                if pmtType:
                    billInqRqType.PmtType = pmtType # POST, PREP or VOCH
                billInqRqType.DeliveryMethod = self.deliveryMethod
                billInqRqType.BillTypeCode = billTypeCode
                if extraBillingAcctKeys:
                    extraBillingAcctKeysType = client.factory.create('{}:ExtraBillingAcctKeysType'.format(namespace))
                    extraBillingAcctKeysList = []
                    for extraBillingAcctKey in extraBillingAcctKeys:
                        extraBillingAcctKeyType = client.factory.create('{}:ExtraBillingAcctKeyType'.format(namespace))
                        extraBillingAcctKeyType.Key = extraBillingAcctKey.get("Key")
                        extraBillingAcctKeyType.Value = extraBillingAcctKey.get("Value")
                        extraBillingAcctKeysList.append(extraBillingAcctKeyType)
                    extraBillingAcctKeysType.ExtraBillingAcctKey = extraBillingAcctKeysList
                    billInqRqType.ExtraBillingAcctKeys = extraBillingAcctKeysType
                billInqRqType.BankId = self.bankId
                billInqRqType.BillingAcct = billingAcct  # 01200000200
                billInqRqType.IncOpenAmt = True
                presSvcRqType.BillInqRq = billInqRqType

        '''
        # FAWRY JAVA Example Code
		// PmtAddRq
			PaySvcRqType paySvcRqType = new PaySvcRqType();
			paySvcRqType.setRqUID(java.util.UUID.randomUUID().toString());  /* PaySvcRq */
			paySvcRqType.setAsyncRqUID("a74419c9-02cf-4104-b2ea-5f3b757036e1");  /* Received in BillInqRs */

			MsgRqHdrType msgRqHdrType = new MsgRqHdrType();
			NetworkTrnInfoType networkTrnInfoType = new NetworkTrnInfoType();

			networkTrnInfoType.setOriginatorCode("%Configuration Value will be provided by Fawry%");
			msgRqHdrType.setNetworkTrnInfo(networkTrnInfoType);

			PmtAddRqType pmtAddRqType = new PmtAddRqType();
			PmtInfoType pmtInfoType = new PmtInfoType(); /* PmtAddRq */

			// PmtAddRq -- Post Paid
				pmtInfoType.setBillingAcct("01200000200");
				pmtInfoType.setBillRefNumber("f16e2fa1-2611-42fc-80aa-4b12e84c6b96");  /* Received in BillInqRs */

			// PmtAddRq -- Pre Paid
				pmtInfoType.setBillerId("1");
				pmtInfoType.setBillingAcct("01000000200");//01012341254
				pmtInfoType.setPmtType(PmtTypeEnum.PREP);

			pmtInfoType.setBillTypeCode(111L);
			pmtInfoType.setDeliveryMethod("INT");

			CurAmtType curAmtType = new CurAmtType();
			curAmtType.setAmt(new BigDecimal(100));
			curAmtType.setCurCode("EGP");

			pmtInfoType.setCurAmt(curAmtType);

			pmtInfoType.setProfileCode("165");
			pmtInfoType.setBankId("%Configuration Value will be provided by Fawry%");

			DepAcctIdFromType depAcctIdFromType = new DepAcctIdFromType();
			depAcctIdFromType.setAcctId("101755");
			depAcctIdFromType.setAcctCur("EGP");

			pmtInfoType.setDepAccIdFrom(depAcctIdFromType);
			pmtInfoType.setPmtMethod(("CASH"));

			pmtAddRqType.getPmtInfo().add(pmtInfoType);

			paySvcRqType.setPmtAddRq(pmtAddRqType);
			paySvcRqType.setMsgRqHdr(msgRqHdrType);

			XMLGregorianCalendar xgcal2 = DatatypeFactory.newInstance().newXMLGregorianCalendar(gcal);
			pmtInfoType.setPrcDt(xgcal2);
		'''
        if msgCode in ("PmtAddRq", "PmtAddCorrRq", "PmtReversal"):
            paySvcRqType = client.factory.create('{}:PaySvcRqType'.format(namespace))
            paySvcRqType.RqUID = str(uuid.uuid1())
            paySvcRqType.AsyncRqUID = str(uuid.uuid1()) # FYI: Received in BillInqRs

            if self.posSerialNumber and msgCode != "PmtReversal":
                customPropertiesType = client.factory.create('{}:CustomPropertiesType'.format(namespace))
                customPropertiesList = []
                customPropertyType = client.factory.create('{}:CustomPropertyType'.format(namespace))
                customPropertyType.Key = 'PosSerialNumber'
                customPropertyType.Value = self.posSerialNumber
                customPropertiesList.append(customPropertyType)
                customPropertiesType.CustomProperty = customPropertiesList
                msgRqHdrType.CustomProperties = customPropertiesType

            paySvcRqType.MsgRqHdr = msgRqHdrType

            pmtAddRqType = client.factory.create('{}:PmtAddRqType'.format(namespace))
            pmtInfoType = client.factory.create('{}:PmtInfoType'.format(namespace))

            pmtInfoType.BillingAcct = billingAcct  # 01200000200
            if extraBillingAcctKeys:
                extraBillingAcctKeysType = client.factory.create('{}:ExtraBillingAcctKeysType'.format(namespace))
                extraBillingAcctKeysList = []
                for extraBillingAcctKey in extraBillingAcctKeys:
                    extraBillingAcctKeyType = client.factory.create('{}:ExtraBillingAcctKeyType'.format(namespace))
                    extraBillingAcctKeyType.Key = extraBillingAcctKey.get("Key")
                    extraBillingAcctKeyType.Value = extraBillingAcctKey.get("Value")
                    extraBillingAcctKeysList.append(extraBillingAcctKeyType)
                extraBillingAcctKeysType.ExtraBillingAcctKey = extraBillingAcctKeysList
                pmtInfoType.ExtraBillingAcctKeys = extraBillingAcctKeysType

            if notifyMobile:
                pmtInfoType.NotifyMobile = notifyMobile

            if pmtType == "POST" or billRefNumber:
                pmtInfoType.BillRefNumber = billRefNumber # Received in BillInqRs
            elif pmtType == "PREP":
                if billerId:
                    pmtInfoType.BillerId = billerId
            if pmtType: # in ('POST', 'PREP')
                pmtInfoType.PmtType = pmtType;

            pmtInfoType.BillTypeCode =  billTypeCode # 111L
            pmtInfoType.DeliveryMethod = self.deliveryMethod

            curAmtType = client.factory.create('{}:CurAmtType'.format(namespace))
            curAmtType.Amt = amt         # new BigDecimal(100)
            curAmtType.CurCode = curCode # "EGP"

            pmtInfoType.CurAmt = curAmtType
            pmtInfoType.BankId = self.bankId           # ("%Configuration Value will be provided by Fawry%")

            depAcctIdFromType = client.factory.create('{}:DepAcctIdFromType'.format(namespace))
            depAcctIdFromType.AcctId = self.acctId     # "101755"
            depAcctIdFromType.AcctType = self.acctType # "SDA"
            depAcctIdFromType.AcctKey = self.acctKey   # "1234"
            depAcctIdFromType.AcctCur = self.acctCur   # "EGP"

            pmtInfoType.DepAccIdFrom = depAcctIdFromType
            pmtInfoType.PmtMethod = pmtMethod # "CASH"
            pmtInfoType.PrcDt = datetime.now()
            if self.profileCode and msgCode == "BillInqRq": # Updated by Saeed
                pmtInfoType.ProfileCode = self.profileCode
            if msgCode == "PmtAddCorrRq" and pmtTransIds and len(pmtTransIds) > 0:
                pmtTransIdsList = []
                for pmtTransId in reversed(pmtTransIds): # Use reversed because the original Transaction is the last record in list
                    pmtTransIdType = client.factory.create('{}:PmtTransIdType'.format(namespace))
                    pmtTransIdType.PmtId = pmtTransId.get('PmtId')
                    pmtTransIdType.PmtIdType = pmtTransId.get('PmtIdType')
                    pmtTransIdType.CreatedDt = pmtTransId.get('CreatedDt')
                    pmtTransIdsList.append(pmtTransIdType)
                pmtInfoType.PmtTransId = pmtTransIdsList
            if msgCode == "PmtReversal":
                '''
                <PmtRevInfo>
                   <PmtStatus>
                      <PmtStatusCode>PmtReversal</PmtStatusCode>
                   </PmtStatus>
                </PmtRevInfo>
                '''
                pmtRevInfoType = client.factory.create('{}:PmtRevInfoType'.format(namespace))
                pmtStatusType = client.factory.create('{}:PmtStatusType'.format(namespace))
                pmtStatusType.PmtStatusCode = msgCode
                pmtRevInfoType.PmtStatus = pmtStatusType
                pmtInfoType.PmtRevInfo = pmtRevInfoType

            pmtAddRqType.PmtInfo = pmtInfoType

            paySvcRqType.PmtAddRq = pmtAddRqType

        '''
        # FAWRY JAVA Example Code
		RequestType requestType = new RequestType();
		requestType.setSignonRq(signonRqType);

		// BillerInqRq, BillInqRq
			requestType.setPresSvcRq(presSvcRqType);
		// PmtAddRq
			requestType.setPaySvcRq(paySvcRqType);

		fawryType.setRequest(requestType);

		return fawryType;
        '''
        requestType = client.factory.create('{}:RequestType'.format(namespace))
        requestType.SignonRq = signonRqType
        if isRetry:
            requestType.IsRetry = isRetry

        if msgCode in ("BillerInqRq", "BillInqRq"):
            requestType.PresSvcRq = presSvcRqType
        elif msgCode in ("PmtAddRq", "PmtAddCorrRq", "PmtReversal"):
            requestType.PaySvcRq = paySvcRqType

        fawryType = client.factory.create('{}:FAWRYType'.format(namespace))
        fawryType.Request = requestType

        return fawryType

    def _buildResponse(fawryType):
        '''
        # FAWRY JAVA Example Code
        SignonRsType  signonRsType= fawryType.getResponse().getSignonRs();
		System.out.println("Client Date: "+ signonRsType.getClientDt());
		System.out.println("Customer Language: "+ signonRsType.getCustLangPref());
		System.out.println("Server Language: "+ signonRsType.getLanguage());
		System.out.println("Server Date: "+ signonRsType.getServerDt());

		SignonProfileType signonProfileType=signonRsType.getSignonProfile();
		System.out.println("Message Code: "+ signonProfileType.getMsgCode());
		System.out.println("Reciever: "+ signonProfileType.getReceiver());
		System.out.println("Sender: "+ signonProfileType.getSender());
		System.out.println("Version: "+ signonProfileType.getVersion());

		ResponseType responseType = fawryType.getResponse();
		// BillerInqRq, BillInqRq
			PresSvcRsType presSvcRsType= responseType.getPresSvcRs();
			StatusType statusType = presSvcRsType.getStatus();
			MsgRqHdrType msgRqHdrType = presSvcRsType.getMsgRqHdr();
		// PmtAddRq
			PaySvcRsType paySvcRsType= responseType.getPaySvcRs();
			StatusType statusType = paySvcRsType.getStatus();
			MsgRqHdrType msgRqHdrType = paySvcRsType.getMsgRqHdr();
		System.out.println("Status Code: "+ statusType.getStatusCode());
		System.out.println("Status Desc: "+ statusType.getStatusDesc());
		System.out.println("Status Severity: "+ statusType.getSeverity());

		if(msgRqHdrType!=null)
		{
			List<CustomPropertyType> customPropertyTypes= msgRqHdrType.getCustomProperties().getCustomProperty();
			if(customPropertyTypes!=null)
			{
				for(CustomPropertyType customPropertyType: customPropertyTypes)
				{
					System.out.println("Customer Property Key: "+ customPropertyType.getKey());
					System.out.println("Customer Property Value: "+ customPropertyType.getValue());
				}
			}
		}

		// BillerInqRq
		BillerInqRsType billerInqRsType = presSvcRsType.getBillerInqRs();
		System.out.println("Biller Payment Type: "+ billerInqRsType.getPmtType());
		System.out.println("Biller Delivery Method: "+ billerInqRsType.getDeliveryMethod());
		System.out.println("Biller Service Type: "+ billerInqRsType.getServiceType());

		List<BillerRecType> billerRecTypes =billerInqRsType.getBillerRec();
		if(billerRecTypes!=null)
		{
			for(BillerRecType billerRecType:billerRecTypes)
			{
				System.out.println(" ====================================== Biller Data Begin "+ billerRecType.getBillerId() +" =========================================");
				System.out.println("Biller ID: "+ billerRecType.getBillerId());
				System.out.println("Biller Name: "+ billerRecType.getBillerName());
				System.out.println("Biller Name Language: "+ billerRecType.getBillerNameLang());
				System.out.println("Biller Status: "+ billerRecType.getBillerStatus());

				List<BillerInfoType> billerInfoTypes = billerRecType.getBillerInfo();
				if(billerInfoTypes!=null)
				{
					for(BillerInfoType billerInfoType :billerInfoTypes)
					{
						System.out.println("Bill Type Account Label: "+ billerInfoType.getBillTypeAcctLabel());
						System.out.println("Bill Type Code: "+ billerInfoType.getBillTypeCode());
						System.out.println("Bill Type Status: "+ billerInfoType.getBillTypeStatus());
						System.out.println("Extra Info: "+ billerInfoType.getExtraInfo());
						System.out.println("Biller Service Name: "+ billerInfoType.getName());
						System.out.println("Biller Service Name Language: "+ billerInfoType.getNameLang());
						System.out.println("Biller Payment Type: "+ billerInfoType.getPmtType());
						System.out.println("Bill Type Code: "+ billerInfoType.getBillTypeCode());
						System.out.println("Service Type: "+ billerInfoType.getServiceType());
						System.out.println("Type: "+ billerInfoType.getType());
						System.out.println("Receipt Footer: "+ billerInfoType.getReceiptFooter());
						System.out.println("Receipt Footer Language: "+ billerInfoType.getReceiptFooterLang());
						System.out.println("Receipt Header: "+ billerInfoType.getReceiptHeader());
						System.out.println("Receipt Header Language: "+ billerInfoType.getReceiptHeaderLang());

						System.out.println("Service Name: "+ billerInfoType.getServiceName());
						System.out.println("Expiry Date: "+ billerInfoType.getExpiryDate());
						System.out.println("Start Date: "+ billerInfoType.getStartDate());

						List<PaymentRangeType> paymentRangeTypes =  billerInfoType.getPaymentRanges().getPaymentRangeType();
						if(paymentRangeTypes!=null)
						{
							for(PaymentRangeType paymentRangeType :paymentRangeTypes)
							{
								System.out.println("Payment Lower Amount: "+ paymentRangeType.getLower().getAmt());
								System.out.println("Payment Lower Currency Code: "+ paymentRangeType.getLower().getCurCode());
								System.out.println("Payment Upper Amount: "+ paymentRangeType.getUpper().getAmt());
								System.out.println("Payment Upper Currency Code: "+ paymentRangeType.getUpper().getCurCode());
							}
						}

						List<TierType> tierTypes = billerInfoType.getFees().getTier();

						if(tierTypes!=null)
						for(TierType tierType : tierTypes)
						{
							System.out.println("Fees Expiry Date: "+tierType.getExpiryDate());
							System.out.println("Fees Start Date: "+tierType.getStartDate());
							System.out.println("Fees Fixed Amount Currency Code: "+tierType.getFixedAmt().getCurCode());
							System.out.println("Fees Fixed Amount: "+tierType.getFixedAmt().getAmt());
							System.out.println("Fees Lower Amount: "+tierType.getLowerAmt());
							System.out.println("Fees Percent: "+tierType.getPercent());
							System.out.println("Fees Upper Amount: "+tierType.getUpperAmt());
						}
					}
				}
				System.out.println(" ====================================== Biller Data End "+ billerRecType.getBillerId() +" =========================================");
			}
		}

		// BillInqRq
		BillInqRsType billInqRsType = presSvcRsType.getBillInqRs();
		if(billInqRsType!=null)
		{
			System.out.println("Payment Type: "+ billInqRsType.getPmtType());
			System.out.println("Delivery Method: "+ billInqRsType.getDeliveryMethod());
			System.out.println("Service Type: "+ billInqRsType.getServiceType());


			List<BillRecType> billRecTypes = billInqRsType.getBillRec();
			if(billRecTypes!=null)
			{
				for(BillRecType billRecType: billRecTypes)
				{
					System.out.println("Biller Id: "+ billRecType.getBillerId());
					System.out.println("Billing Account: "+ billRecType.getBillingAcct());
					System.out.println("Bill Number: "+ billRecType.getBillNumber());
					System.out.println("Bill Ref Number: "+ billRecType.getBillRefNumber());
					System.out.println("Bill Status: "+ billRecType.getBillStatus());
					System.out.println("Bill Type Code: "+ billRecType.getBillTypeCode());

					BillInfoType billInfoTypes=billRecType.getBillInfo();
					System.out.println("Bill Category: "+ billInfoTypes.getBillCategory());
					System.out.println("Bill Due Date: "+ billInfoTypes.getDueDt());
					System.out.println("Bill Issue Date: "+ billInfoTypes.getIssueDt());
					System.out.println("Bill Expiry Date: "+ billInfoTypes.getExpDt());
					System.out.println("Extra Bill Info: "+ billInfoTypes.getExtraBillInfo());

					List<BillSummAmtType> billSummAmtTypes = billInfoTypes.getBillSummAmt();
					if(billSummAmtTypes!=null)
					for(BillSummAmtType billSummAmtType:billSummAmtTypes)
					{
						System.out.println("Bill Sum Amount Code: "+ billSummAmtType.getBillSummAmtCode());
						System.out.println("Bill Amount Curency Code: "+ billSummAmtType.getCurAmt().getCurCode());
						System.out.println("Bill Amount: "+ billSummAmtType.getCurAmt().getAmt());
					}

					List<PaymentRangeType> paymentRangeTypes= billInfoTypes.getPaymentRange();
					if(paymentRangeTypes!=null)
					for(PaymentRangeType paymentRangeType:paymentRangeTypes)
					{
						System.out.println("Range Lower Amount: "+ paymentRangeType.getLower().getAmt());
						System.out.println("Range Lower Amount Currency: "+ paymentRangeType.getLower().getCurCode());
						System.out.println("Range Upper Amount: "+ paymentRangeType.getUpper().getAmt());
						System.out.println("Range Upper Amount Currency: "+ paymentRangeType.getUpper().getCurCode());
					}
				}
			}
		}

		// PmtAddRq
			PmtAddRsType pmtAddRsType= fawryType.getResponse().getPaySvcRs().getPmtAddRs();

			List<CustIdType> custIdTypes = pmtAddRsType.getCustId();
			if(custIdTypes!=null)
				for(CustIdType custIdType:custIdTypes)
				{
					System.out.println("Official ID: "+ custIdType.getOfficialId());
					System.out.println("Official ID Type: "+ custIdType.getOfficialIdType());
				}

			List<PmtInfoValType> pmtInfoValTypes = pmtAddRsType.getPmtInfoVal();
			if(pmtInfoValTypes!=null)
			{
				for(PmtInfoValType pmtInfoValType: pmtInfoValTypes)
				{
					PmtInfoType pmtInfoType = pmtInfoValType.getPmtInfo();
					System.out.println("Biller ID: "+ pmtInfoType.getBillerId());
					System.out.println("Billing Account: "+ pmtInfoType.getBillingAcct());
					System.out.println("Bill Number: "+ pmtInfoType.getBillNumber());
					System.out.println("Bill Ref Number: "+ pmtInfoType.getBillRefNumber());
					System.out.println("Bill Type Code: "+ pmtInfoType.getBillTypeCode());
					System.out.println("Delivery Method: "+ pmtInfoType.getDeliveryMethod());
					System.out.println("Extra Bill Info: "+ pmtInfoType.getExtraBillInfo());
					System.out.println("Issue Date: "+ pmtInfoType.getIssueDt());
					System.out.println("Is Notify Mobile: "+ pmtInfoType.getNotifyMobile());
					System.out.println("Payment Description: "+ pmtInfoType.getPmtDesc());
					System.out.println("Payment Method: "+ pmtInfoType.getPmtMethod());
					System.out.println("Payment Processing Date: "+ pmtInfoType.getPrcDt());
					System.out.println("Amount Currency Code: "+ pmtInfoType.getCurAmt().getCurCode());
					System.out.println("Amount: "+ pmtInfoType.getCurAmt().getAmt());

					 List<ExtraBillingAcctKeyType> acctKeyTypes = pmtInfoType.getExtraBillingAcctKeys().getExtraBillingAcctKey();
					 if(acctKeyTypes!=null)
					  for(ExtraBillingAcctKeyType acctKeyType: acctKeyTypes){
						 System.out.println("Extra Billing Account Key: "+ acctKeyType.getKey());
						 System.out.println("Extra Billing Account Value: "+ acctKeyType.getValue());
					 }

					 FeesAmtType feesAmtType = pmtInfoType.getFeesAmt();
					 System.out.println("Fees Currency Code: "+ feesAmtType.getCurCode());
					 System.out.println("Fees Amount: "+ feesAmtType.getAmt());

					List<PmtTransIdType> pmtTransIdTypes= pmtInfoType.getPmtTransId();
					if(pmtTransIdTypes!=null)
						  for(PmtTransIdType pmtTransIdType: pmtTransIdTypes){
							 System.out.println("Payment Transaction Creation Date: "+ pmtTransIdType.getCreatedDt());
							 System.out.println("Payment ID: "+ pmtTransIdType.getPmtId());
							 System.out.println("Payment ID Type: "+ pmtTransIdType.getPmtIdType());
						 }
				}
			}
        '''
        responseType = fawryType.Response

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

    def get_biller_details(self, custLangPref, suppressEcho):
        client = self._set_client(self.wsdl)

        '''
            client, msgCode, custLangPref, suppressEcho, namespace,
            pmtType, billTypeCode, billingAcct, extraBillingAcctKeys,     # msgCode: BillInqRq, PmtAddRq
            amt, curCode, pmtMethod, notifyMobile,                        # msgCode: PmtAddRq
            billRefNumber,                                                # msgCode: PmtAddRq & pmtType: POST
            billerId,                                                     # msgCode: PmtAddRq & pmtType: PREP
        '''
        namespace = 'ns1'
        fawryType = self._buildRequest(client=client, msgCode="BillerInqRq", custLangPref=custLangPref,
                                       suppressEcho=suppressEcho, namespace=namespace) # PmtType (POST/PREP), ServiceType, ProfileCode
        # _logger.info("FawryType Request: " + str(fawryType))

        try:
            # Get All of billers data and associated bill types for a specific channel
            # _logger.info("Before Calling BillerInqRq Fawry Service")
            fawryResponse = client.service.process(fawryType)
            # _logger.info("After Calling BillerInqRq Fawry Service")
            # _logger.info("BillerInqRq FawryType Response: " + str(fawryResponse))

            # Check if process is not success then return reason for that
            if fawryResponse.Response.PresSvcRs.Status.StatusCode != 200:
                _logger.error("FW [get_biller_details] Response ERROR: [" +
                              str(fawryResponse.Response.PresSvcRs.Status.StatusCode) + "]: " +
                              fawryResponse.Response.PresSvcRs.Status.StatusDesc)
                return self.get_error_message(fawryResponse.Response.PresSvcRs.Status.StatusCode,
                                              fawryResponse.Response.PresSvcRs.Status.StatusDesc)

            # _logger.info("Before Calling BillerInqRq _buildResponse")
            # self._buildResponse(fawryResponse)
            # _logger.info("After Calling BillerInqRq _buildResponse")

            result = {}
            result['billerRecTypes'] = fawryResponse.Response.PresSvcRs.BillerInqRs.BillerRec
            # _logger.info("Fawry Biller Details Result: " + str(result))

            return result

        except suds.WebFault as e:
            # childAtPath behaviour is changing at version 0.6
            prefix = ''
            if SUDS_VERSION >= "0.6":
                prefix = '/Envelope/Body/Fault'
            _logger.error("FW [get_biller_details] WebFault ERROR: " + str(e))
            return self.get_error_message(
                e.document.childAtPath(prefix + '/faultcode').getText(),
                e.document.childAtPath(prefix + '/faultstring').getText())
        except timeout as e:
            _logger.error("FW [get_biller_details] Timeout ERROR: " + str(e))
            return self.get_error_message('0', 'FW Server timeout:\n%s' % e)
        except IOError as e:
            _logger.error("FW [get_biller_details] IO ERROR: " + str(e))
            return self.get_error_message('-1', 'FW Server Not Found:\n%s' % e)
        except Exception as e:
            _logger.error("FW [get_biller_details] Exception ERROR: " + str(e))
            return self.get_error_message('-2', 'FW Exception Found:\n%s' % e)

    def get_bill_details(self, custLangPref, suppressEcho,
                         # pmtType,
                         billTypeCode, billingAcct, extraBillingAcctKeys=None,
                         customProperties=None, requestNumber=None):
        client = self._set_client(self.wsdl)

        '''
            client, msgCode, custLangPref, suppressEcho, namespace,
            pmtType, billTypeCode, billingAcct, extraBillingAcctKeys,     # msgCode: BillInqRq, PmtAddRq
            amt, curCode, pmtMethod, notifyMobile,                        # msgCode: PmtAddRq
            billRefNumber,                                                # msgCode: PmtAddRq & pmtType: POST
            billerId,                                                     # msgCode: PmtAddRq & pmtType: PREP
        '''
        namespace = 'ns1'
        fawryType = self._buildRequest(client=client, msgCode="BillInqRq", custLangPref=custLangPref, suppressEcho=suppressEcho, namespace=namespace,
                                       # pmtType=pmtType,
                                       billTypeCode=billTypeCode, billingAcct=billingAcct, extraBillingAcctKeys=extraBillingAcctKeys,
                                       customProperties=customProperties) # IsRetry, IncOpenAmt => False, BillerId, PmtType => PREP
        # _logger.info("FawryType Request: " + str(fawryType))

        try:
            # Get All of bill data
            # _logger.info("Before Calling BillInqRq Fawry Service")
            fawryResponse = client.service.process(fawryType)
            # _logger.info("After Calling BillInqRq Fawry Service")
            # _logger.info("BillInqRq FawryType Response: " + str(fawryResponse))

            # Check if process is not success then return reason for that
            if fawryResponse.Response.PresSvcRs.Status.StatusCode != 200:
                _logger.error("FW [get_bill_details] Response ERROR: [" +
                              str(fawryResponse.Response.PresSvcRs.Status.StatusCode) + "]: " +
                              fawryResponse.Response.PresSvcRs.Status.StatusDesc)
                return self.get_error_message(fawryResponse.Response.PresSvcRs.Status.StatusCode,
                                              fawryResponse.Response.PresSvcRs.Status.StatusDesc)

            # _logger.info("Before Calling BillInqRq _buildResponse")
            # self._buildResponse(fawryResponse)
            # _logger.info("After Calling BillerInqRq _buildResponse")

            result = {}
            result['billRecType'] = fawryResponse.Response.PresSvcRs.BillInqRs.BillRec[0]
            # _logger.info("Fawry Bill Details Result: " + str(result))

            return result

        except suds.WebFault as e:
            # childAtPath behaviour is changing at version 0.6
            prefix = ''
            if SUDS_VERSION >= "0.6":
                prefix = '/Envelope/Body/Fault'
            _logger.error("FW [get_bill_details] WebFault ERROR: %s - %s" % (requestNumber or 'None', str(e)))
            return self.get_error_message(
                e.document.childAtPath(prefix + '/faultcode').getText(),
                e.document.childAtPath(prefix + '/faultstring').getText())
        except timeout as e:
            _logger.error("FW [get_bill_details] Timeout ERROR: %s - %s" % (requestNumber or 'None', str(e)))
            return self.get_error_message('0', 'FW Server timeout:\n%s' % e)
        except IOError as e:
            _logger.error("FW [get_bill_details] IO ERROR: %s - %s" % (requestNumber or 'None', str(e)))
            return self.get_error_message('-1', 'FW Server Not Found:\n%s' % e)
        except Exception as e:
            _logger.error("FW [get_bill_details] Exception ERROR: %s - %s" % (requestNumber or 'None', str(e)))
            return self.get_error_message('-2', 'FW Exception Found:\n%s' % e)

    def pay_bill(self, custLangPref,
                 suppressEcho, billTypeCode,
                 billingAcct, extraBillingAcctKeys,
                 amt, curCode, pmtMethod,
                 notifyMobile, billRefNumber,
                 billerId, pmtType, clientTerminalSeqId=None, requestNumber=None,
                 isAllowCancel=True, isAllowRetry=True, TIMOUT_RETRY=0):
        client = self._set_client(self.wsdl)

        '''
            client, msgCode, custLangPref, suppressEcho, namespace,
            pmtType, billTypeCode, billingAcct, extraBillingAcctKeys,     # msgCode: BillInqRq, PmtAddRq
            amt, curCode, pmtMethod, notifyMobile,                        # msgCode: PmtAddRq
            billRefNumber,                                                # msgCode: PmtAddRq & pmtType: POST
            billerId,                                                     # msgCode: PmtAddRq & pmtType: PREP
        '''
        namespace = 'ns1'
        fawryType = self._buildRequest(client=client, msgCode="PmtAddRq", custLangPref=custLangPref, suppressEcho=suppressEcho, namespace=namespace,
                                       # pmtType=pmtType,
                                       billTypeCode=billTypeCode, billingAcct=billingAcct, extraBillingAcctKeys=extraBillingAcctKeys,
                                       amt=amt, curCode=curCode, pmtMethod=pmtMethod, notifyMobile=notifyMobile,
                                       billRefNumber=billRefNumber, clientTerminalSeqId=clientTerminalSeqId
                                       # billerId=billerId
                                       ) # IsRetry, BillerId, PmtType
        # _logger.info("FawryType Request: " + str(fawryType))

        retry = TIMOUT_RETRY
        while retry < FAWRY_TIMOUT_RETRY:
            try:
                # Pay Bill
                # _logger.info("Before Calling Fawry Pay Bill")
                fawryResponse = client.service.process(fawryType)
                # _logger.info("After Calling Fawry Pay Bill")
                # _logger.info("PmtAddRq FawryType Response: " + str(fawryResponse))
                retry = FAWRY_TIMOUT_RETRY

                # Check if process is not success then return reason for that
                if fawryResponse.Response.PaySvcRs.Status.StatusCode not in (200, 22090): # 200 ==> Success, 22090 Pending from provider
                    _logger.error("FW [pay_bill] Response ERROR: [" +
                                  str(fawryResponse.Response.PaySvcRs.Status.StatusCode) + "]: " +
                                  fawryResponse.Response.PaySvcRs.Status.StatusDesc)
                    return self.get_error_message(fawryResponse.Response.PaySvcRs.Status.StatusCode,
                                                  fawryResponse.Response.PaySvcRs.Status.StatusDesc)

                # _logger.info("Before Calling PmtAddRq _buildResponse")
                # self._buildResponse(fawryResponse)
                # _logger.info("After Calling PmtAddRq _buildResponse")

                result = {}
                result['pmtInfoValType'] = fawryResponse.Response.PaySvcRs.PmtAddRs.PmtInfoVal[0]
                result['msgRqHdrType'] = fawryResponse.Response.PaySvcRs.MsgRqHdr # for get customProperties
                if fawryResponse.Response.PaySvcRs.Status.StatusCode == 22090: # Pending from provider
                    result['pending'] = True
                # _logger.info("Fawry Pay Bill Result: " + str(result))

                return result

            except suds.WebFault as e:
                # childAtPath behaviour is changing at version 0.6
                prefix = ''
                if SUDS_VERSION >= "0.6":
                    prefix = '/Envelope/Body/Fault'
                _logger.error("FW [pay_bill] WebFault ERROR: %s - %s" % (requestNumber or 'None', str(e)))
                return self.get_error_message(
                    e.document.childAtPath(prefix + '/faultcode').getText(),
                    e.document.childAtPath(prefix + '/faultstring').getText())
            except timeout as e:
                if not isAllowRetry:
                    retry = FAWRY_TIMOUT_RETRY
                else:
                    retry += 1
                if retry < FAWRY_TIMOUT_RETRY:
                    _logger.info("Timeout Retry Payment: %s - %s" %(retry, billRefNumber))
                    client = self._set_client(self.wsdl)
                    namespace = 'ns1'
                    fawryType = self._buildRequest(client=client, msgCode="PmtAddRq", custLangPref=custLangPref,
                                                   suppressEcho=suppressEcho, namespace=namespace,
                                                   # pmtType=pmtType,
                                                   billTypeCode=billTypeCode, billingAcct=billingAcct,
                                                   extraBillingAcctKeys=extraBillingAcctKeys,
                                                   amt=amt, curCode=curCode, pmtMethod=pmtMethod,
                                                   notifyMobile=notifyMobile,
                                                   billRefNumber=billRefNumber, clientTerminalSeqId=clientTerminalSeqId,
                                                   # billerId=billerId
                                                   isRetry=True
                                                   )  # IsRetry, BillerId, PmtType
                if retry == FAWRY_TIMOUT_RETRY:
                    _logger.error("FW [pay_bill] Timeout ERROR: %s - %s" % (requestNumber or 'None', str(e)))
                    if isAllowCancel:
                        result_payment = self.reverse_bill(custLangPref, suppressEcho, billTypeCode, billingAcct,
                                                           extraBillingAcctKeys, amt, curCode, pmtMethod, notifyMobile,
                                                           billRefNumber, billerId, pmtType, clientTerminalSeqId,
                                                           requestNumber, TIMOUT_RETRY=FAWRY_TIMOUT_RETRY-2)
                        if result_payment.get('pmtInfoValType'): # Cancel Success
                            return self.get_error_message('CANCEL_SUCCESS', 'FW Server timeout:\n%s' % e)
                    return self.get_error_message('0', 'FW Server timeout:\n%s' % e)
            except IOError as e:
                if not isAllowRetry:
                    retry = FAWRY_TIMOUT_RETRY
                else:
                    retry += 1
                if retry < FAWRY_TIMOUT_RETRY:
                    _logger.info("IOError Retry Payment: %s - %s" % (retry, billRefNumber))
                    client = self._set_client(self.wsdl)
                    namespace = 'ns1'
                    fawryType = self._buildRequest(client=client, msgCode="PmtAddRq", custLangPref=custLangPref,
                                                   suppressEcho=suppressEcho, namespace=namespace,
                                                   # pmtType=pmtType,
                                                   billTypeCode=billTypeCode, billingAcct=billingAcct,
                                                   extraBillingAcctKeys=extraBillingAcctKeys,
                                                   amt=amt, curCode=curCode, pmtMethod=pmtMethod,
                                                   notifyMobile=notifyMobile,
                                                   billRefNumber=billRefNumber, clientTerminalSeqId=clientTerminalSeqId,
                                                   # billerId=billerId
                                                   isRetry=True
                                                   )  # IsRetry, BillerId, PmtType
                if retry == FAWRY_TIMOUT_RETRY:
                    _logger.error("FW [pay_bill] IO ERROR: %s - %s" % (requestNumber or 'None', str(e)))
                    if isAllowCancel:
                        result_payment = self.reverse_bill(custLangPref, suppressEcho, billTypeCode, billingAcct,
                                                           extraBillingAcctKeys, amt, curCode, pmtMethod, notifyMobile,
                                                           billRefNumber, billerId, pmtType, clientTerminalSeqId,
                                                           requestNumber, TIMOUT_RETRY=FAWRY_TIMOUT_RETRY-2)
                        if result_payment.get('pmtInfoValType'): # Cancel Success
                            return self.get_error_message('CANCEL_SUCCESS', 'FW Server Not Found:\n%s' % e)
                    return self.get_error_message('-1', 'FW Server Not Found:\n%s' % e)
            except Exception as e:
                _logger.error("FW [pay_bill] Exception ERROR: %s - %s" % (requestNumber or 'None', str(e)))
                return self.get_error_message('-2', 'FW Exception Found:\n%s' % e)

    def _simulate_pay_bill_response(self, bankId, acctId, acctType, acctCur, profileCode, billTypeCode,
                                    billingAcct, amt, curCode, pmtMethod, billRefNumber, requestNumber=None):
        '''
        {
          "count": 7,
          "data": {
            "request_number": "2208064772016",
            "request_datetime": "2022-08-20T18:24:39.356243",
            "provider": "fawry",
            "provider_response": "",
            "extra_fees_amount": 0,
            "message": "Pay Service Bill request was submit successfully with amount 50.0 EGP. Your Machine Wallet Balance is 2233.05 EGP"
          }
        }

        {
          "status": {
            "StatusCode": 200,
            "Severity": "Info",
            "StatusDesc": "Success."
          },
          "PmtTransId": [
            {
              "PmtId": "cd16f0a0-860b-440d-88da-cb10c2c9f6e5",
              "PmtIdType": "FPTN",
              "CreatedDt": "2022-08-21 16:50:30.066000"
            },
            {
              "PmtId": "d22b7e88-a292-478f-9c8f-dd2652d289af",
              "PmtIdType": "BNKPTN",
              "CreatedDt": "2022-08-21 16:50:27.068000"
            },
            {
              "PmtId": "7600583903",
              "PmtIdType": "BNKDTN",
              "CreatedDt": "2022-08-21 16:50:27.238000"
            },
            {
              "PmtId": "7137992675",
              "PmtIdType": "FCRN",
              "CreatedDt": "2022-08-21 16:50:27.068000"
            }
          ],
          "PmtInfo": {
            "CorrelationUID": "d22b7e88-a292-478f-9c8f-dd2652d289af",
            "BillingAcct": "0502854883",
            "BillRefNumber": "f7c48614-0564-40cb-9773-301aab2d0186",
            "BillTypeCode": 114,
            "BankId": "SMARTPAY",
            "DeliveryMethod": "INT",
            "CurAmt": {
              "Amt": 78.25,
              "CurCode": "EGP"
            },
            "FeesAmt": {
              "Amt": 3,
              "CurCode": "EGP"
            },
            "DepAccIdFrom": {
              "AcctId": "3113334",
              "AcctType": "SDA",
              "AcctCur": "EGP",
              "Balance": {
                "Balance": 391955.44,
                "CurCode": "EGP"
              }
            },
            "PmtMethod": "Cash",
            "PrcDt": "2022-08-21",
            "ProfileCode": "426"
          }
        }
        '''
        result = {}
        result['msgRqHdrType'] = {}
        result['timeout'] = True

        now = datetime.now()
        today = now.date()
        result['pmtInfoValType'] = {
            "status": {
                "StatusCode": 200,
                "Severity": "Info",
                "StatusDesc": "Success."
            },
            "PmtTransId": [
                {
                    "PmtId": "%s" % requestNumber or "REQUEST_NUMBER",
                    "PmtIdType": "FPTN",
                    "CreatedDt": "%s" % now
                },
                {
                    "PmtId": "%s" % requestNumber or "REQUEST_NUMBER",
                    "PmtIdType": "BNKPTN",
                    "CreatedDt": "%s" % now
                },
                {
                    "PmtId": "%s" % requestNumber or "REQUEST_NUMBER",
                    "PmtIdType": "BNKDTN",
                    "CreatedDt": "%s" % now
                },
                {
                    "PmtId": "%s" % requestNumber or "REQUEST_NUMBER",
                    "PmtIdType": "FCRN",
                    "CreatedDt": "%s" % now
                }
            ],
            "PmtInfo": {
                "CorrelationUID": "%s" % requestNumber or "REQUEST_NUMBER",
                "BillingAcct": "%s" % billingAcct,
                "BillRefNumber": "%s" % billRefNumber,
                "BillTypeCode": int(billTypeCode),
                "BankId": "%s" % bankId,
                "DeliveryMethod": "INT",
                "CurAmt": {
                    "Amt": amt,
                    "CurCode": "%s" % curCode
                },
                "FeesAmt": {
                    "Amt": 0,
                    "CurCode": "%s" % curCode
                },
                "DepAccIdFrom": {
                    "AcctId": "%s" % acctId,
                    "AcctType": "%s" % acctType,
                    "AcctCur": "%s" % acctCur,
                    "Balance": {
                        "Balance": 0,
                        "CurCode": "%s" % acctCur
                    }
                },
                "PmtMethod": "%s" % pmtMethod,
                "PrcDt": "%s" % today,
                "ProfileCode": "%s" % profileCode
            }
        }
        return result

    def correlation_bill(self, custLangPref,
                         suppressEcho, billTypeCode,
                         billingAcct, # extraBillingAcctKeys,
                         amt, curCode, pmtMethod,
                         # notifyMobile, billRefNumber,
                         # billerId, pmtType,
                         pmtTransIds, requestNumber=None, TIMOUT_RETRY=0):
        client = self._set_client(self.wsdl)

        '''
            client, msgCode, custLangPref, suppressEcho, namespace,
            pmtType, billTypeCode, billingAcct, extraBillingAcctKeys,     # msgCode: BillInqRq, PmtAddRq
            amt, curCode, pmtMethod, notifyMobile,                        # msgCode: PmtAddRq
            billRefNumber,                                                # msgCode: PmtAddRq & pmtType: POST
            billerId,                                                     # msgCode: PmtAddRq & pmtType: PREP
        '''
        namespace = 'ns1'
        fawryType = self._buildRequest(client=client, msgCode="PmtAddCorrRq", custLangPref=custLangPref, suppressEcho=suppressEcho, namespace=namespace,
                                       # pmtType=pmtType,
                                       billTypeCode=billTypeCode, billingAcct=billingAcct, # extraBillingAcctKeys=extraBillingAcctKeys,
                                       amt=amt, curCode=curCode, pmtMethod=pmtMethod, # notifyMobile=notifyMobile,
                                       # billRefNumber=billRefNumber,
                                       # billerId=billerId,
                                       pmtTransIds=pmtTransIds
                                       ) # IsRetry, BillerId, PmtType
        # _logger.info("FawryType Request: " + str(fawryType))

        retry = TIMOUT_RETRY
        while retry < FAWRY_TIMOUT_RETRY:
            try:
                # Pay Bill
                # _logger.info("Before Calling Fawry Pay Bill")
                fawryResponse = client.service.process(fawryType)
                # _logger.info("After Calling Fawry Pay Bill")
                # _logger.info("PmtAddRq FawryType Response: " + str(fawryResponse))
                retry = FAWRY_TIMOUT_RETRY

                # Check if process is not success then return reason for that
                if fawryResponse.Response.PaySvcRs.Status.StatusCode not in (200, 22090):  # 200 ==> Success, 22090 Pending from provider
                    _logger.error("FW [correlation_bill] Response ERROR: [" +
                                  str(fawryResponse.Response.PaySvcRs.Status.StatusCode) + "]: " +
                                  fawryResponse.Response.PaySvcRs.Status.StatusDesc)
                    return self.get_error_message(fawryResponse.Response.PaySvcRs.Status.StatusCode,
                                                  fawryResponse.Response.PaySvcRs.Status.StatusDesc)

                # _logger.info("Before Calling PmtAddRq _buildResponse")
                # self._buildResponse(fawryResponse)
                # _logger.info("After Calling PmtAddRq _buildResponse")

                result = {}
                result['pmtInfoValType'] = fawryResponse.Response.PaySvcRs.PmtAddRs.PmtInfoVal[0]
                if fawryResponse.Response.PaySvcRs.Status.StatusCode == 22090: # Pending from provider
                    result['pending'] = True
                # _logger.info("Fawry Pay Bill Result: " + str(result))

                return result

            except suds.WebFault as e:
                # childAtPath behaviour is changing at version 0.6
                prefix = ''
                if SUDS_VERSION >= "0.6":
                    prefix = '/Envelope/Body/Fault'
                _logger.error("FW [correlation_bill] WebFault ERROR: %s - %s" % (requestNumber or 'None', str(e)))
                return self.get_error_message(
                    e.document.childAtPath(prefix + '/faultcode').getText(),
                    e.document.childAtPath(prefix + '/faultstring').getText())
            except timeout as e:
                retry += 1
                if retry < FAWRY_TIMOUT_RETRY:
                    _logger.info("Timeout Retry Correlation: %s - %s" % (retry, billingAcct))
                    client = self._set_client(self.wsdl)
                    namespace = 'ns1'
                    fawryType = self._buildRequest(client=client, msgCode="PmtAddCorrRq", custLangPref=custLangPref,
                                                   suppressEcho=suppressEcho, namespace=namespace,
                                                   # pmtType=pmtType,
                                                   billTypeCode=billTypeCode, billingAcct=billingAcct,
                                                   # extraBillingAcctKeys=extraBillingAcctKeys,
                                                   amt=amt, curCode=curCode, pmtMethod=pmtMethod,
                                                   # notifyMobile=notifyMobile,
                                                   # billRefNumber=billRefNumber,
                                                   # billerId=billerId,
                                                   pmtTransIds=pmtTransIds
                                                   )  # IsRetry, BillerId, PmtType
                if retry == FAWRY_TIMOUT_RETRY:
                    _logger.error("FW [correlation_bill] Timeout ERROR: %s - %s" % (requestNumber or 'None', str(e)))
                    return self.get_error_message('0', 'FW Server timeout:\n%s' % e)
            except IOError as e:
                retry += 1
                if retry < FAWRY_TIMOUT_RETRY:
                    _logger.info("IOError Retry Correlation: %s - %s" % (retry, billingAcct))
                    client = self._set_client(self.wsdl)
                    namespace = 'ns1'
                    fawryType = self._buildRequest(client=client, msgCode="PmtAddCorrRq", custLangPref=custLangPref,
                                                   suppressEcho=suppressEcho, namespace=namespace,
                                                   # pmtType=pmtType,
                                                   billTypeCode=billTypeCode, billingAcct=billingAcct,
                                                   # extraBillingAcctKeys=extraBillingAcctKeys,
                                                   amt=amt, curCode=curCode, pmtMethod=pmtMethod,
                                                   # notifyMobile=notifyMobile,
                                                   # billRefNumber=billRefNumber,
                                                   # billerId=billerId,
                                                   pmtTransIds=pmtTransIds
                                                   )  # IsRetry, BillerId, PmtType
                if retry == FAWRY_TIMOUT_RETRY:
                    _logger.error("FW [correlation_bill] IO ERROR: %s - %s" % (requestNumber or 'None', str(e)))
                    return self.get_error_message('-1', 'FW Server Not Found:\n%s' % e)
            except Exception as e:
                _logger.error("FW [correlation_bill] Exception ERROR: %s - %s" % (requestNumber or 'None', str(e)))
                return self.get_error_message('-2', 'FW Exception Found:\n%s' % e)

    def reverse_bill(self, custLangPref,
                     suppressEcho, billTypeCode,
                     billingAcct, extraBillingAcctKeys,
                     amt, curCode, pmtMethod,
                     notifyMobile, billRefNumber,
                     billerId, pmtType, clientTerminalSeqId, requestNumber=None, TIMOUT_RETRY=0):
        client = self._set_client(self.wsdl)

        '''
            client, msgCode, custLangPref, suppressEcho, namespace,
            pmtType, billTypeCode, billingAcct, extraBillingAcctKeys,     # msgCode: BillInqRq, PmtAddRq and PmtReversal
            amt, curCode, pmtMethod, notifyMobile,                        # msgCode: PmtAddRq and PmtReversal
            billRefNumber,                                                # msgCode: PmtAddRq & pmtType: POST and PmtReversal
            billerId,                                                     # msgCode: PmtAddRq & pmtType: PREP and PmtReversal
        '''
        namespace = 'ns1'
        fawryType = self._buildRequest(client=client, msgCode="PmtReversal", custLangPref=custLangPref, suppressEcho=suppressEcho, namespace=namespace,
                                       pmtType=pmtType,
                                       billTypeCode=billTypeCode, billingAcct=billingAcct, extraBillingAcctKeys=extraBillingAcctKeys,
                                       amt=amt, curCode=curCode, pmtMethod=pmtMethod, notifyMobile=notifyMobile,
                                       billRefNumber=billRefNumber, clientTerminalSeqId=clientTerminalSeqId
                                       # billerId=billerId
                                       ) # IsRetry, BillerId, PmtType
        # _logger.info("FawryType Request: " + str(fawryType))

        retry = TIMOUT_RETRY
        while retry < FAWRY_TIMOUT_RETRY:
            try:
                # Pay Bill
                # _logger.info("Before Calling Fawry Pay Bill")
                fawryResponse = client.service.process(fawryType)
                # _logger.info("After Calling Fawry Pay Bill")
                # _logger.info("PmtAddRq FawryType Response: " + str(fawryResponse))
                retry = FAWRY_TIMOUT_RETRY

                # Check if process is not success then return reason for that
                if fawryResponse.Response.PaySvcRs.Status.StatusCode != 200:
                    _logger.error("FW [reverse_bill] Response ERROR: [" +
                                  str(fawryResponse.Response.PaySvcRs.Status.StatusCode) + "]: " +
                                  fawryResponse.Response.PaySvcRs.Status.StatusDesc)
                    return self.get_error_message(fawryResponse.Response.PaySvcRs.Status.StatusCode,
                                                  fawryResponse.Response.PaySvcRs.Status.StatusDesc)

                # _logger.info("Before Calling PmtAddRq _buildResponse")
                # self._buildResponse(fawryResponse)
                # _logger.info("After Calling PmtAddRq _buildResponse")

                result = {}
                result['pmtInfoValType'] = fawryResponse.Response.PaySvcRs.PmtAddRs.PmtInfoVal[0]
                # _logger.info("Fawry Pay Bill Result: " + str(result))

                return result

            except suds.WebFault as e:
                # childAtPath behaviour is changing at version 0.6
                prefix = ''
                if SUDS_VERSION >= "0.6":
                    prefix = '/Envelope/Body/Fault'
                _logger.error("FW [reverse_bill] WebFault ERROR: %s - %s" % (requestNumber or 'None', str(e)))
                return self.get_error_message(
                    e.document.childAtPath(prefix + '/faultcode').getText(),
                    e.document.childAtPath(prefix + '/faultstring').getText())
            except timeout as e:
                retry += 1
                if retry < FAWRY_TIMOUT_RETRY:
                    _logger.info("Timeout Retry Reverse Payment: %s - %s" % (retry, billRefNumber))
                    client = self._set_client(self.wsdl)
                    namespace = 'ns1'
                    fawryType = self._buildRequest(client=client, msgCode="PmtReversal", custLangPref=custLangPref,
                                                   suppressEcho=suppressEcho, namespace=namespace,
                                                   pmtType=pmtType,
                                                   billTypeCode=billTypeCode, billingAcct=billingAcct,
                                                   extraBillingAcctKeys=extraBillingAcctKeys,
                                                   amt=amt, curCode=curCode, pmtMethod=pmtMethod, notifyMobile=notifyMobile,
                                                   billRefNumber=billRefNumber, clientTerminalSeqId=clientTerminalSeqId
                                                   # billerId=billerId
                                                   )  # IsRetry, BillerId, PmtType
                if retry == FAWRY_TIMOUT_RETRY:
                    _logger.error("FW [reverse_bill] Timeout ERROR: %s - %s" % (requestNumber or 'None', str(e)))
                    return self.get_error_message('0', 'FW Server timeout:\n%s' % e)
            except IOError as e:
                retry += 1
                if retry < FAWRY_TIMOUT_RETRY:
                    _logger.info("IOError Retry Reverse Payment: %s - %s" % (retry, billRefNumber))
                    client = self._set_client(self.wsdl)
                    namespace = 'ns1'
                    fawryType = self._buildRequest(client=client, msgCode="PmtReversal", custLangPref=custLangPref,
                                                   suppressEcho=suppressEcho, namespace=namespace,
                                                   pmtType=pmtType,
                                                   billTypeCode=billTypeCode, billingAcct=billingAcct,
                                                   extraBillingAcctKeys=extraBillingAcctKeys,
                                                   amt=amt, curCode=curCode, pmtMethod=pmtMethod,
                                                   notifyMobile=notifyMobile,
                                                   billRefNumber=billRefNumber, clientTerminalSeqId=clientTerminalSeqId
                                                   # billerId=billerId
                                                   )  # IsRetry, BillerId, PmtType
                if retry == FAWRY_TIMOUT_RETRY:
                    _logger.error("FW [reverse_bill] IO Error: %s - %s" % (requestNumber or 'None', str(e)))
                    return self.get_error_message('-1', 'FW Server Not Found:\n%s' % e)
            except Exception as e:
                _logger.error("FW [reverse_bill] Exception Error: %s - %s" % (requestNumber or 'None', str(e)))
                #return self.get_error_message('-2', 'FW Exception Found:\n%s' % e)
                retry += 1
                if retry < FAWRY_TIMOUT_RETRY:
                    time.sleep(60)
                    _logger.info("Http error Retry Reverse Payment: %s - %s" % (retry, billRefNumber))
                    client = self._set_client(self.wsdl)
                    namespace = 'ns1'
                    fawryType = self._buildRequest(client=client, msgCode="PmtReversal", custLangPref=custLangPref,
                                                   suppressEcho=suppressEcho, namespace=namespace,
                                                   pmtType=pmtType,
                                                   billTypeCode=billTypeCode, billingAcct=billingAcct,
                                                   extraBillingAcctKeys=extraBillingAcctKeys,
                                                   amt=amt, curCode=curCode, pmtMethod=pmtMethod,
                                                   notifyMobile=notifyMobile,
                                                   billRefNumber=billRefNumber, clientTerminalSeqId=clientTerminalSeqId
                                                   # billerId=billerId
                                                   )  # IsRetry, BillerId, PmtType
                if retry == FAWRY_TIMOUT_RETRY:
                    _logger.error("FW [reverse_bill] http Error: %s - %s" % (requestNumber or 'None', str(e)))
                    return self.get_error_message('-2', 'FW Exception Found:\n%s' % e)
