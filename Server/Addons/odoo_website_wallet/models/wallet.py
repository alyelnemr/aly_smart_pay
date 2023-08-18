# -*- coding: utf-8 -*-
# Part of BrowseInfo. See LICENSE file for full copyright and licensing details.

from odoo import fields, models, api, _
from odoo.exceptions import UserError
from odoo import SUPERUSER_ID


class res_partner(models.Model):
    _inherit = 'res.partner'

    wallet_balance = fields.Float('Wallet Balance')

class sale_order(models.Model):
    _inherit = 'sale.order'

    wallet_used = fields.Float('Wallet Amount Used')
    wallet_transaction_id = fields.Many2one('website.wallet.transaction', 'Wallet Transaction')
    
        
class website_wallet_transaction(models.Model):
    _name='website.wallet.transaction'
    _order = 'id desc'
    
    #============================================== mail send ===========================================
    
    @api.multi 
    def wallet_transaction_email_send(self):
        context = self._context
        active_ids = context.get('active_ids')
        super_user = self.env['res.users'].browse(SUPERUSER_ID)
        
        if self.wallet_type == 'credit':
            template_id = self.env['ir.model.data'].get_object_reference('odoo_website_wallet', 'email_template_wallet_transaction_credit')[1]
        else:
            template_id = self.env['ir.model.data'].get_object_reference('odoo_website_wallet', 'email_template_wallet_transaction_debit')[1]
        email_template_obj = self.env['mail.template'].browse(template_id)
        values = email_template_obj.generate_email(self.id)
        values['email_from'] = super_user.email
        values['email_to'] = self.partner_id.email
        values['res_id'] = self.id
        mail_mail_obj = self.env['mail.mail']
        msg_id = mail_mail_obj.create(values)
        if msg_id:
            mail_mail_obj.send([msg_id])
        
        
        '''for a_id in active_ids:
            account_invoice_brw = self.env['account.invoice'].browse(a_id)
            for partner in account_invoice_brw.partner_id:
                partner_email = partner.email
                if not partner_email:
                    raise UserError(_('%s customer has no email id please enter email address')
                            % (account_invoice_brw.partner_id.name)) 
                else:
                    template_id = self.env['ir.model.data'].get_object_reference(
                                                                      'account', 
                                                                      'email_template_edi_invoice')[1]
                    email_template_obj = self.env['mail.template'].browse(template_id)
                    if template_id:
                        values = email_template_obj.generate_email(a_id, fields=None)
                        #values['email_from'] = super_user.email
                        values['email_to'] = partner.email
                        values['res_id'] = a_id
                        ir_attachment_obj = self.env['ir.attachment']
                        vals = {
                                'name' : account_invoice_brw.number or "Draft",
                                'type' : 'binary',
                                'datas' : values['attachments'][0][1],
                                'res_id' : a_id,
                                'res_model' : 'account.invoice',
                                'datas_fname' : account_invoice_brw.number or "Draft",
                        }
                        attachment_id = ir_attachment_obj.create(vals)
                        # Set boolean field true after mass invoice email sent
                        account_invoice_brw.write({
                                                    'is_invoice_sent' : True
                                                 })
                        mail_mail_obj = self.env['mail.mail']
                        msg_id = mail_mail_obj.create(values)
                        msg_id.attachment_ids=[(6,0,[attachment_id.id])]
                        if msg_id:
                            mail_mail_obj.send([msg_id])'''
                                                     
        return True
    
    #====================================================================================================


    @api.model
    def create(self, vals):
        vals['name'] = self.env['ir.sequence'].next_by_code('website.wallet.transaction') or 'New'
        res = super(website_wallet_transaction, self).create(vals)
        return res

        
        
    name = fields.Char('Name')
    wallet_type = fields.Selection([
        ('credit', 'Credit'),
        ('debit', 'Debit')
        ], string='Type', default='credit')
    partner_id = fields.Many2one('res.partner', 'Customer')
    sale_order_id = fields.Many2one('sale.order', 'Sale Order')
    #wallet_id = fields.Many2one('res.partner', 'Wallet')
    reference = fields.Selection([
        ('manual', 'Manual'),
        ('sale_order', 'Sale Order')
        ], string='Reference', default='manual')
    amount = fields.Char('Amount')
    currency_id = fields.Many2one('res.currency', 'Currency')
    status = fields.Selection([
        ('draft', 'Draft'),
        ('done', 'Done')
        ], string='Status', readonly=True, default='draft')


class Website(models.Model):
    _inherit = 'website'
        
    def get_wallet_balance(self):   
        res_ids=self.env['res.partner'].sudo().search([("id", "=", self.env.user.partner_id.id)])
        return res_ids  
            

# vim:expandtab:smartindent:tabstop=4:softtabstop=4:shiftwidth=4:    
