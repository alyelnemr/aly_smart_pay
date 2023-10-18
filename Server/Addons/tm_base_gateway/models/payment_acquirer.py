# -*- coding: utf-8 -*-
# This module and its content is copyright of Tamayozsoft.
# - © Tamayozsoft 2020. All rights reserved.
import logging
import requests
from datetime import datetime as date_time, timedelta

from odoo import api, fields, models
from odoo.exceptions import ValidationError

_logger = logging.getLogger(__name__)


class AcquirerBase(models.Model):
    _inherit = 'payment.acquirer'

    sevice_provider = fields.Boolean('Sevice Provider', default=False)
    related_partner = fields.Many2one('res.partner', 'Partner', domain=[('supplier', '=', True)])
    debug_logging = fields.Boolean('Debug logging', help="Log requests in order to ease debugging")
    active = fields.Boolean('Active', default=True,
                            help="If unchecked, it will allow you to hide the provider without removing it.")

    server_url = fields.Char("Provider Server URL", readonly=True)
    server_state = fields.Selection(string="Provider Server Status",
                                    selection=[('offline', "Offline"), ('online', "Online")])
    online_time = fields.Datetime('Server Online On')
    offline_time = fields.Datetime('Server Offline On')

    # offline_reason = fields.Text('Server Offline Reason')

    def toggle_debug(self):
        for c in self:
            c.debug_logging = not c.debug_logging

    def health_check_providers_servers(self):
        for service_provider in self.env['payment.acquirer'].sudo().search([('sevice_provider', '=', True)]):
            url = service_provider.server_url
            _logger.info(" >>>>>>>>>>>>>>>>>>>>>>>>>> %s" % service_provider.name)
            _logger.info(" >>>>>>>>>>>>>>>>>>>>>>>>>> %s" % url)
            if url:
                try:
                    res = requests.get(url,  # params={'d': '404', 's': '128'},
                                       timeout=5)
                    '''
                    _logger.info(" >>>>>>>>>>>>>>>>>>>>>>>>>> %s - %s" % (res.status_code, requests.codes.ok))
                    if res.status_code != requests.codes.ok:
                        if not service_provider.server_state or service_provider.server_state == 'online':
                            service_provider.server_state = 'offline'
                            service_provider.offline_time = date_time.now()
                        _logger.info(" >>>>>>>>>>>>>>>>>>>>>>>>>> Offline")
                    else:
                        if not service_provider.server_state or service_provider.server_state == 'offline':
                            service_provider.server_state = 'online'
                            service_provider.online_time = date_time.now()
                        _logger.info(" >>>>>>>>>>>>>>>>>>>>>>>>>> Online")
                    '''
                    if res.status_code and (
                            not service_provider.server_state or service_provider.server_state == 'offline'):
                        service_provider.server_state = 'online'
                        service_provider.online_time = date_time.now()
                    _logger.info(" >>>>>>>>>>>>>>>>>>>>>>>>>> Online")
                except requests.exceptions.ConnectionError as e:
                    if not service_provider.server_state or service_provider.server_state == 'online':
                        service_provider.server_state = 'offline'
                        service_provider.offline_time = date_time.now()
                    _logger.info(" >>>>>>>>>>>>>>>>>>>>>>>>>> ConnectionError")
                except requests.exceptions.Timeout as e:
                    if not service_provider.server_state or service_provider.server_state == 'online':
                        service_provider.server_state = 'offline'
                        service_provider.offline_time = date_time.now()
                    _logger.info(" >>>>>>>>>>>>>>>>>>>>>>>>>> Timeout")
                except Exception as e:
                    if not service_provider.server_state or service_provider.server_state == 'online':
                        service_provider.server_state = 'offline'
                        service_provider.offline_time = date_time.now()
                    _logger.info(" >>>>>>>>>>>>>>>>>>>>>>>>>> Exception")

    def get_manager_mail(self):
        email_list = ''
        manager_id = self.env['ir.model.data'].get_object_reference('smartpay_operations',
                                                                    'group_smartpay_operations_manager')[1]
        for each_user in self.env['res.groups'].sudo().browse(manager_id).users:
            email_list += str(each_user.partner_id.email or (each_user.email if "@" in each_user.email else '')) + ','
        return email_list

    def notify_providers_servers_down(self, raise_error=False):
        try:
            for service_provider in self.env['payment.acquirer'].sudo().search(
                    [('sevice_provider', '=', True), ('server_state', '=', 'offline')]).filtered(
                lambda p: p.offline_time and p.online_time and p.offline_time > p.online_time and p.offline_time <= date_time.now() - timedelta(
                    minutes=10)):
                template_id = self.env.ref('tm_base_gateway.email_template_for_providers_servers_down')
                if template_id:
                    template_id.send_mail(service_provider.id, force_send=True)
        except Exception as e:
            _logger.info(" >>>>>>>>>>>>>>>>>>>>>>>>>> Exception (%s)" % e)
            if raise_error:
                raise e


class AcquirerChannel(models.Model):
    _name = 'payment.acquirer.channel'
    _order = "sequence"

    name = fields.Char('Chennel Name', required=True, groups='base.group_user')
    type = fields.Selection(
        [('internet', 'Internet'), ('machine', 'Machine'), ('mobile', 'Mobile'), ('other', 'Other')],
        string='Chennel Type', default='internet',
        required=True, groups='base.group_user')
    acquirer_id = fields.Many2one('payment.acquirer', 'Payment Acquirer', ondelete='cascade', readonly=True)
    sequence = fields.Integer('Sequence',
                              help="Gives the sequence order when displaying a list of payment acquirer channels.",
                              default=1)
    company_id = fields.Many2one('res.company', readonly=True, default=lambda self: self.env.user.company_id.id)

    @api.multi
    def _check_required_if_provider(self):
        """ If the field has 'required_if_provider="<provider>"' attribute, then it
        required if record.acquirer_id.provider is <provider>. """
        empty_field = []
        for channel in self:
            for k, f in channel._fields.items():
                if getattr(f, 'required_if_provider', None) == channel.acquirer_id.provider and not channel[k]:
                    empty_field.append(self.env['ir.model.fields'].search(
                        [('name', '=', k), ('model', '=', channel._name)]).field_description)
        if empty_field:
            raise ValidationError((', ').join(empty_field))
        return True

    _constraints = [
        (_check_required_if_provider, 'Required fields not filled', []),
    ]
