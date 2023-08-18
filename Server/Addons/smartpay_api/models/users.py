import logging

from odoo import api, fields, models,_
from odoo.exceptions import ValidationError

_logger = logging.getLogger(__name__)

class Users(models.Model):
    _inherit = "res.users"

    machine_serial = fields.Char(string="Machine Serial", copy=False)
    allowed_product_tag_ids = fields.Many2many('product.tags', string='Allowed Services Tags')
    commission = fields.Boolean(string="Commission", copy=False, default=False)
    transfer_to_salesperson = fields.Boolean(string="Allow Transfer to Salesperson", copy=False, default=False)

    @api.one
    @api.constrains('machine_serial')
    def _check_unique_constraint(self):
        record = self.search([('machine_serial', '=ilike', self.machine_serial), ('id', '!=', self.id)])
        if record:
            raise ValidationError(_('Another user with the same machine exists!'))

    @api.onchange('machine_serial')
    def _onchange_machine_serial(self):
        if self.machine_serial:
            self.commission = True

    @api.model
    def create(self, vals):
        res = super(Users, self).create(vals)
        if res.machine_serial:
            res.machine_serial = res.machine_serial.rstrip().lstrip()
        return res

    @api.multi
    def write(self, vals):
        if 'machine_serial' in vals:
            vals['machine_serial'] = vals['machine_serial'].rstrip().lstrip()
        return super(Users, self).write(vals)
