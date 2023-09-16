import json
import ast
import logging
import math
from datetime import date
from datetime import datetime as date_time, timedelta
from psycopg2 import IntegrityError
from Crypto.Cipher import DES3
import base64
from collections import OrderedDict
import requests

from odoo import http, fields, _
from odoo.exceptions import UserError, ValidationError, AccessDenied, AccessError
from odoo.addons.restful.common import (
    extract_arguments,
    invalid_response,
    valid_response,
    default,
)
from odoo.addons.website_form.controllers.main import WebsiteForm
from odoo.addons.tm_base_gateway.common import (
    suds_to_json,
)

from odoo.http import request
from odoo.addons.smartpay_api.controllers.main import APIController as SmartAPIController
from odoo.addons.smartpay_api_extend.tools.validate_machine import validate_machine
from odoo.addons.smartpay_multi_devices.tools.validate_token import validate_token

_REQUEST_TYPES_IDS = ['general_inquiry', 'recharge_wallet', 'service_bill_inquiry', 'pay_service_bill', 'pay_invoice',
                      'wallet_invitation']
SECRET_KEY = base64.b64decode('MfG6sLDTQIaS8QgOnkBS2THxurCw00CG')
UNPAD = lambda s: s[0:-s[-1]]

_logger = logging.getLogger(__name__)


class RequestApiTempTags(SmartAPIController.RequestApiTemp):

    @validate_token
    @http.route('/api/get_sevice_categories', type="http", auth="none", methods=["POST"], csrf=False)
    def get_sevice_categories(self, **payload):
        _logger.info("@@@@@@@@@@@@@@@@@@@ Calling Get Sevice Category API")
        domain, fields, offset, limit, order = extract_arguments(payload)
        domain += [("parent_id", "=", request.env.ref("tm_base_gateway.product_category_services").id),
                   ("product_count", "!=", 0)]
        # if not any(item[0] == 'tag_ids' for item in domain):
        for item in domain:
            if item[0] == 'tag_ids':
                domain.pop(domain.index(item))
                break
        access_token = request.httprequest.headers.get("access_token")
        _token = request.env['api.access_token'].sudo()
        device = _token.search([
            ('active', '=', True),
            ("token", "=", access_token),
            ("user_id", "=", request.env.user.id),
        ], limit=1).filtered(lambda d: d.user_id.active)
        _logger.info("Get Device related to user, device {}, machine_serial {}".format(device, device.machine_serial))
        # user = request.env['res.users'].sudo().search([('id', '=', request.env.user.id)], limit=1)
        if device.allowed_product_tag_ids:
            domain += [('tag_ids', 'in', device.allowed_product_tag_ids.ids)]
        else:
            domain += [('tag_ids', 'in', (0))]

        lang = payload.get("lang", "en_US")
        ir_translation_sudo = request.env['ir.translation'].sudo()
        product_category_sudo = request.env['product.category'].sudo()
        '''
        service_categories = product_category_sudo.search_read(domain=domain,
                                                                 fields=fields,
                                                                 offset=offset,
                                                                 limit=limit,
                                                                 order=order,
                                                                 )
        '''
        service_categories = product_category_sudo.search(domain, offset=offset, limit=limit, order=order)
        categories = []
        if service_categories:
            for service_category in service_categories:
                category = {
                    "id": service_category.id,
                    # "image": service_category.image_medium and service_category.image_medium.decode('ascii') or False,
                    # "name": service_category.name
                }

                if service_category.image_medium:
                    category.update({"image": "/web/image?model=%s&field=image_medium&id=%s" % (
                        "product.category", service_category.id)})

                '''
                ir_translation_ids = ir_translation_sudo.search_read(
                    domain=[("name", "=", "product.category,name"), ("res_id", "=", service_category.id)],
                    fields=["lang", "source", "value"], order="res_id")
                if ir_translation_ids:
                    category_trans = []
                    for ir_translation in ir_translation_ids:
                        category_trans.append({
                            "lang": ir_translation["lang"],
                            "name": ir_translation["value"]
                        })
                    category.update({"name_translate": category_trans})
                '''

                if lang == "en_US":
                    category.update({"name": service_category.name})
                else:
                    ir_translation_id = ir_translation_sudo.search(
                        [("name", "=", "product.category,name"), ("res_id", "=", service_category.id),
                         ("lang", "=", lang)],
                        limit=1)
                    if ir_translation_id:
                        category.update({"name": ir_translation_id.value})

                categories.append(category)

        return valid_response(categories)
        # return invalid_response("service_categories_not_found",  _("Could not get Service Categories"), 400)

    @validate_token
    @http.route('/api/get_sevice_billers', type="http", auth="none", methods=["POST"], csrf=False)
    def get_sevice_billers(self, **payload):
        _logger.info("@@@@@@@@@@@@@@@@@@@ Calling Get Sevice Biller API")
        domain, fields, offset, limit, order = extract_arguments(payload)
        domain += [("product_count", "!=", 0)]
        # if not any(item[0] == 'tag_ids' for item in domain):
        for item in domain:
            if item[0] == 'tag_ids':
                domain.pop(domain.index(item))
                break
        # user = request.env['res.users'].sudo().search([('id', '=', request.env.user.id)], limit=1)
        access_token = request.httprequest.headers.get("access_token")
        _token = request.env['api.access_token'].sudo()
        device = _token.search([
            ('active', '=', True),
            ("token", "=", access_token),
            ("user_id", "=", request.env.user.id),
        ], limit=1).filtered(lambda d: d.user_id.active)
        _logger.info("Get Device related to user, device {}, machine_serial {}".format(device, device.machine_serial))

        if device.allowed_product_tag_ids:
            domain += [('tag_ids', 'in', device.allowed_product_tag_ids.ids)]
        else:
            domain += [('tag_ids', 'in', (0))]

        lang = payload.get("lang", "en_US")
        ir_translation_sudo = request.env['ir.translation'].sudo()
        product_category_sudo = request.env['product.category'].sudo()
        '''
        service_billers = product_category_sudo.search_read(domain=domain,
                                                                 fields=fields,
                                                                 offset=offset,
                                                                 limit=limit,
                                                                 order=order,
                                                                 )
        '''
        service_billers = product_category_sudo.search(domain, offset=offset, limit=limit, order=order)
        billers = []
        if service_billers:
            for service_biller in service_billers:
                biller = {
                    "id": service_biller.id,
                    "categ_id": service_biller.parent_id.id,
                    "categ_name": service_biller.parent_id.name,
                    # "image": service_biller.image_medium and service_biller.image_medium.decode('ascii') or False,
                    # "name": service_biller.name
                }

                if service_biller.image_medium:
                    biller.update({"image": "/web/image?model=%s&field=image_medium&id=%s" % (
                        "product.category", service_biller.id)})

                '''
                ir_translation_ids = ir_translation_sudo.search_read(
                    domain=[("name", "=", "product.category,name"), ("res_id", "=", service_biller.id)],
                    fields=["lang", "source", "value"], order="res_id")
                if ir_translation_ids:
                    biller_trans = []
                    for ir_translation in ir_translation_ids:
                        biller_trans.append({
                            "lang": ir_translation["lang"],
                            "name": ir_translation["value"]
                        })
                    biller.update({"name_translate": biller_trans})
                '''

                if lang == "en_US":
                    biller.update({"name": service_biller.name})
                else:
                    ir_translation_id = ir_translation_sudo.search(
                        [("name", "=", "product.category,name"), ("res_id", "=", service_biller.id),
                         ("lang", "=", lang)],
                        limit=1)
                    if ir_translation_id:
                        biller.update({"name": ir_translation_id.value})

                billers.append(biller)

        return valid_response(billers)
        # return invalid_response("service_billers_not_found", _("Could not get Service Billers"), 400)

    @validate_token
    @http.route('/api/get_sevices', type="http", auth="none", methods=["POST"], csrf=False)
    def get_sevices(self, **payload):
        _logger.info("@@@@@@@@@@@@@@@@@@@ Calling Get Sevices API")
        domain, fields, offset, limit, order = extract_arguments(payload)
        # if not any(item[0] == 'tag_ids' for item in domain):
        for item in domain:
            if item[0] == 'tag_ids':
                domain.pop(domain.index(item))
                break
        # user = request.env['res.users'].sudo().search([('id', '=', request.env.user.id)], limit=1)
        access_token = request.httprequest.headers.get("access_token")
        _token = request.env['api.access_token'].sudo()
        device = _token.search([
            ('active', '=', True),
            ("token", "=", access_token),
            ("user_id", "=", request.env.user.id),
        ], limit=1).filtered(lambda d: d.user_id.active)
        _logger.info("Get Device related to user, device {}, machine_serial {}".format(device, device.machine_serial))

        if device.allowed_product_tag_ids:
            domain += [('tag_ids', 'in', device.allowed_product_tag_ids.ids)]
        else:
            domain += [('tag_ids', 'in', (0))]

        lang = payload.get("lang", "en_US")
        biller_info_sudo = request.env['product.supplierinfo'].sudo()
        ir_translation_sudo = request.env['ir.translation'].sudo()
        product_template_sudo = request.env['product.template'].sudo()
        '''
        service_ids = product_template_sudo.search_read(domain=domain,
                                                                 fields=fields,
                                                                 offset=offset,
                                                                 limit=limit,
                                                                 order=order,
                                                                 )
        '''
        service_ids = product_template_sudo.search(domain, offset=offset, limit=limit, order=order)
        services = []
        if service_ids:
            for service_id in service_ids:
                service = {
                    "id": service_id.product_variant_id.id,
                    "categ_id": service_id.categ_id.id,
                    "categ_name": service_id.categ_id.name,
                    # "image": service_id.image_medium and service_id.image_medium.decode('ascii') or False,
                    # "name": service_id.name
                }

                if service_id.image_medium:
                    service.update(
                        {"image": "/web/image?model=%s&field=image_medium&id=%s" % ("product.template", service_id.id)})

                '''
                ir_translation_ids = ir_translation_sudo.search_read(
                    domain=[("name", "=", "product.template,name"), ("res_id", "=", service_id.id)],
                    fields=["lang", "source", "value"], order="res_id")
                if ir_translation_ids:
                    service_trans = []
                    for ir_translation in ir_translation_ids:
                        service_trans.append({
                            "lang": ir_translation["lang"],
                            "name": ir_translation["value"]
                        })
                    service.update({"name_translate": service_trans})
                '''

                biller_info_id = biller_info_sudo.search(
                    [("product_tmpl_id.type", "=", "service"),
                     ("product_tmpl_id.id", "=", service_id.id)],
                    limit=1)

                if lang == "en_US":
                    service.update({"name": service_id.name})

                    if biller_info_id:
                        biller_info_dict = json.loads(
                            biller_info_id.biller_info.replace("'", '"').replace('True', 'true').replace('False',
                                                                                                         'false'),
                            strict=False)
                        if biller_info_dict.get('ServiceTypeLogo'):
                            biller_info_dict.pop('ServiceTypeLogo')
                        if biller_info_dict.get('BillTypeLogo'):
                            biller_info_dict.pop('BillTypeLogo')
                        service.update({"biller_info": json.dumps(biller_info_dict, default=default)})
                else:
                    ir_translation_id = ir_translation_sudo.search(
                        [("name", "=", "product.template,name"), ("res_id", "=", service_id.id),
                         ("lang", "=", lang)],
                        limit=1)
                    if ir_translation_id:
                        service.update({"name": ir_translation_id.value})

                    ir_translation_id = ir_translation_sudo.search(
                        [("name", "=", "product.supplierinfo,biller_info"), ("res_id", "=", biller_info_id.id),
                         ("lang", "=", lang)],
                        limit=1)
                    if ir_translation_id:
                        biller_info_dict = json.loads(
                            ir_translation_id.value.replace("'", '"').replace('True', 'true').replace('False', 'false'),
                            strict=False)
                        if biller_info_dict.get('ServiceTypeLogo'):
                            biller_info_dict.pop('ServiceTypeLogo')
                        if biller_info_dict.get('BillTypeLogo'):
                            biller_info_dict.pop('BillTypeLogo')
                        service.update({"biller_info": json.dumps(biller_info_dict, default=default)})

                services.append(service)

        return valid_response(services)
        # return invalid_response("services_not_found", _("Could not get Services"), 400)

    @validate_token
    @http.route('/api/get_all_sevices', type="http", auth="none", methods=["POST"], csrf=False)
    def get_all_sevices(self, **payload):
        _logger.info("@@@@@@@@@@@@@@@@@@@ Calling Get All Sevices API")
        domain, fields, offset, limit, order = extract_arguments(payload)
        domain += [("parent_id", "=", request.env.ref("tm_base_gateway.product_category_services").id),
                   ("product_count", "!=", 0)]
        # if not any(item[0] == 'tag_ids' for item in domain):
        for item in domain:
            if item[0] == 'tag_ids':
                domain.pop(domain.index(item))
                break
        # user = request.env['res.users'].sudo().search([('id', '=', request.env.user.id)], limit=1)
        access_token = request.httprequest.headers.get("access_token")
        _token = request.env['api.access_token'].sudo()
        device = _token.search([
            ('active', '=', True),
            ("token", "=", access_token),
            ("user_id", "=", request.env.user.id),
        ], limit=1).filtered(lambda d: d.user_id.active)
        _logger.info("Get Device related to user, device {}, machine_serial {}".format(device, device.machine_serial))

        if device.allowed_product_tag_ids:
            domain += [('tag_ids', 'in', device.allowed_product_tag_ids.ids)]
        else:
            domain += [('tag_ids', 'in', (0))]

        lang = payload.get("lang", "en_US")
        ir_translation_sudo = request.env['ir.translation'].sudo()
        product_category_sudo = request.env['product.category'].sudo()

        service_categories = product_category_sudo.search(domain, offset=offset, limit=limit, order=order)
        categories = []
        for service_category in service_categories:
            category = {
                "id": service_category.id
            }

            if service_category.image_medium:
                category.update({"image": "/web/image?model=%s&field=image_medium&id=%s" % (
                    "product.category", service_category.id)})

            if lang == "en_US":
                category.update({"name": service_category.name})
            else:
                ir_translation_id = ir_translation_sudo.search(
                    [("name", "=", "product.category,name"), ("res_id", "=", service_category.id),
                     ("lang", "=", lang)],
                    limit=1)
                if ir_translation_id:
                    category.update({"name": ir_translation_id.value})

            # Get billers
            _logger.info("@@@@@@@@@@@@@@@@@@@ Get Billers")
            domain, fields, offset, limit, order = extract_arguments(payload)
            domain += [("parent_id.id", "=", service_category.id), ("product_count", "!=", 0)]

            service_billers = product_category_sudo.search(domain, offset=offset, limit=limit, order=order)
            billers = []
            for service_biller in service_billers:
                biller = {
                    "id": service_biller.id,
                    "categ_id": service_biller.parent_id.id,
                    "categ_name": service_biller.parent_id.name
                }

                if service_biller.image_medium:
                    biller.update({"image": "/web/image?model=%s&field=image_medium&id=%s" % (
                        "product.category", service_biller.id)})

                if lang == "en_US":
                    biller.update({"name": service_biller.name})
                else:
                    ir_translation_id = ir_translation_sudo.search(
                        [("name", "=", "product.category,name"), ("res_id", "=", service_biller.id),
                         ("lang", "=", lang)],
                        limit=1)
                    if ir_translation_id:
                        biller.update({"name": ir_translation_id.value})

                # Get Services
                _logger.info("@@@@@@@@@@@@@@@@@@@ Get Sevices")
                domain, fields, offset, limit, order = extract_arguments(payload)
                domain += [("type", "=", "service"), ("categ_id.id", "=", service_biller.id)]

                biller_info_sudo = request.env['product.supplierinfo'].sudo()
                product_template_sudo = request.env['product.template'].sudo()

                service_ids = product_template_sudo.search(domain, offset=offset, limit=limit, order=order)
                services = []
                for service_id in service_ids:
                    service = {
                        "id": service_id.product_variant_id.id,
                        "categ_id": service_id.categ_id.id,
                        "categ_name": service_id.categ_id.name
                    }

                    if service_id.image_medium:
                        service.update({"image": "/web/image?model=%s&field=image_medium&id=%s" % (
                            "product.template", service_id.id)})

                    biller_info_id = biller_info_sudo.search(
                        [("product_tmpl_id.type", "=", "service"),
                         ("product_tmpl_id.id", "=", service_id.id)],
                        limit=1)

                    if lang == "en_US":
                        service.update({"name": service_id.name})

                        if biller_info_id:
                            biller_info_dict = json.loads(
                                biller_info_id.biller_info.replace("'", '"').replace('True', 'true').replace('False',
                                                                                                             'false'),
                                strict=False)
                            if biller_info_dict.get('ServiceTypeLogo'):
                                biller_info_dict.pop('ServiceTypeLogo')
                            if biller_info_dict.get('BillTypeLogo'):
                                biller_info_dict.pop('BillTypeLogo')
                            service.update({"biller_info": json.dumps(biller_info_dict, default=default)})
                    else:
                        ir_translation_id = ir_translation_sudo.search(
                            [("name", "=", "product.template,name"), ("res_id", "=", service_id.id),
                             ("lang", "=", lang)],
                            limit=1)
                        if ir_translation_id:
                            service.update({"name": ir_translation_id.value})

                        ir_translation_id = ir_translation_sudo.search(
                            [("name", "=", "product.supplierinfo,biller_info"),
                             ("res_id", "=", biller_info_id.id),
                             ("lang", "=", lang)],
                            limit=1)
                        if ir_translation_id:
                            biller_info_dict = json.loads(
                                ir_translation_id.value.replace("'", '"').replace('True', 'true').replace('False',
                                                                                                          'false'),
                                strict=False)
                            if biller_info_dict.get('ServiceTypeLogo'):
                                biller_info_dict.pop('ServiceTypeLogo')
                            if biller_info_dict.get('BillTypeLogo'):
                                biller_info_dict.pop('BillTypeLogo')
                            service.update({"biller_info": json.dumps(biller_info_dict, default=default)})

                    services.append(service)

                biller.update({"services": services})
                billers.append(biller)

            category.update({"billers": billers})
            categories.append(category)

        return valid_response(categories)
        # return invalid_response("service_categories_not_found",  _("Could not get Service Categories"), 400)
