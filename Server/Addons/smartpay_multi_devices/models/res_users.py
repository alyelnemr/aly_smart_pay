import logging

from odoo.http import request
from odoo.exceptions import UserError, AccessDenied
from odoo import fields, models, api, _, SUPERUSER_ID
from odoo.addons.restful.common import invalid_response, valid_response

_logger = logging.getLogger(__name__)


class ResUsers(models.Model):
    _inherit = 'res.users'

    count_devices = fields.Integer('N.Devices', compute="_compute_count_devices")

    @api.depends('token_ids')
    def _compute_count_devices(self):
        for user in self:
            user.count_devices = len(user.token_ids)

    @api.model
    def _get_login_order(self):
        return self._order

    # Business methods
    @classmethod
    def _login(cls, db, login, password):
        if not password:
            raise AccessDenied()
        ip = request.httprequest.environ['REMOTE_ADDR'] if request else 'n/a'
        try:
            with cls.pool.cursor() as cr:
                self = api.Environment(cr, SUPERUSER_ID, {})[cls._name]
                with self._assert_can_auth():
                    _logger.info('Checking authentication for db:%s login:%s password:%s from %s', db, login, password,
                                 ip)
                    # _logger.info('self %s, has attr %s', self, hasattr(self, '_get_login_order'))
                    user = self.search(self._get_login_domain(login), order=self._get_login_order(), limit=1)
                    if not user:
                        raise AccessDenied()
                    user = user.sudo(user.id)
                    # _logger.info('Checking authentication for device or user')
                    # _logger.info('context {}'.format(request.context))
                    ctx = dict(request.context)
                    auth_type = ctx.get('auth_type')
                    machine_serial = ctx.get('machine_serial')
                    if auth_type == 'device' and machine_serial:
                        #  _logger.info('Device Authentication')
                        # check no devices.
                        if not user.token_ids:
                            raise AccessDenied()
                        device = user.token_ids.filtered(lambda u: u.machine_serial == machine_serial)
                        if not device:
                            device_without_machine_serial = user.token_ids. \
                                filtered(lambda u: u.machine_serial is False)
                            device_without_machine_serial = device_without_machine_serial and \
                                                            device_without_machine_serial[0]
                            if not device_without_machine_serial:
                                info = "authentication failed"
                                error = 'authentication failed on device with this machine serial {}'.format(
                                    machine_serial)
                                _logger.info('{}'.format(error))
                                return invalid_response(info, error, 403)
                            device_without_machine_serial.write({'machine_serial': machine_serial})
                            device_without_machine_serial._check_credentials_device(password)
                        else:
                            device._check_credentials_device(password)
                    else:
                        _logger.info('User Authentication')
                        user._check_credentials(password)
                        user._update_last_login()
        except AccessDenied:
            _logger.info("Login failed for db:%s login:%s from %s", db, login, ip)
            raise

        _logger.info("Login successful for db:%s login:%s from %s", db, login, ip)

        return user.id

    def get_linked_device(self, machine_serial):
        """Returns the device linked to current user and
            associated with the given machine"""
        assert machine_serial
        return self.env['api.access_token']. \
            search(self._get_device_domain(machine_serial), limit=1)

    def _get_device_domain(self, machine_serial):
        return [('user_id', '=', self.id), ('machine_serial', '=', machine_serial)]

    def _create_device(self):
        """Creates a new device for current user
        @rtype: api.access_token object.
        @return param: Api.access_token object.
        """
        self.ensure_one()
        return self.env['api.access_token']. \
            with_context(login_related_user=self.id).create({})

    def _migrate_info_to_devices(self):
        """Get the related fields form user and update related devices."""
        self.ensure_one()
        try:
            devices = self.token_ids or self._create_device()
            device = devices.filtered(lambda d: not (d.machine_serial and d.password))
            device = device and device[0]
            if not device:
                return
            self.env.cr.execute(
                f""" 
                     update api_access_token 
                     set password = ( select password from res_users where id = {self.id} ),
                     machine_serial = '{self.machine_serial}',
                     commission = {self.commission} ,
                     device_status = 'confirmed'
                     where id = {device.id} 
               """)
            vals = {
                'allowed_product_tag_ids': [(4, allow_id) for allow_id in self.allowed_product_tag_ids.ids],
            }
            device.write(vals)
        except Exception as e:
            raise UserError(_('Error {}'.format(e)))
        return True

    @api.model
    def migrate_info_to_devices(self):
        """Migrate info to devices"""
        users = self.search([('machine_serial', '!=', False)])
        for user in users:
            user._migrate_info_to_devices()

    # Action methods

    def action_open_devices(self):
        """Smart button for open devices related to user"""
        self.ensure_one()
        action = self.env.ref('smartpay_multi_devices.api_access_token_act_window').read()[0]
        action['context'] = {'default_user_id': self.id}
        action['domain'] = [('user_id', 'in', self.ids)]
        action['name'] = 'Other Devices'
        return action

    def add_device(self):
        """Add a device to user"""
        self.ensure_one()
        return {
            'type': 'ir.actions.act_window',
            'name': _('New Device'),
            'res_model': 'api.access_token',
            'view_type': 'form',
            'view_mode': 'form',
            'view_id': self.env.ref("smartpay_multi_devices.api_access_token_form_view").id,
            'target': 'current',
            'context': {'login_related_user': self.id}
        }

    @api.multi
    def write(self, vals):
        if "active" in vals and not vals.get("active"):
            for user in self:
                user.token_ids.write({"active": False})
        res = super(ResUsers, self).write(vals)
        return res
