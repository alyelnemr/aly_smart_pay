
//console.log("custom js caleedddddddddddddddddddddddddddddddddd")
odoo.define('odoo_website_wallet.odoo_website_wallet', function(require) {
    "use strict";
    var core = require('web.core');
    var _t = core._t;

    var ajax = require('web.ajax');
    $(document).ready(function() {
	    var oe_website_sale = this;
		
		var $wallet = $("#website_wallet");
		//$('.oe_website_sale form button.btn-primary').attr('disabled', true);
		$wallet.click(function () {
			//check if checkbox is checked
			if ($(this).is(':checked')) {
			    var wallet = $(this).is(':checked');
				//$('.oe_website_sale form button.btn-primary').removeAttr('disabled'); //enable button
				
				ajax.jsonRpc('/shop/payment/wallet', 'call', {
					'wallet': wallet,
				}).then(function (wallet) {
					location.reload();
				});
    
        
				
			} else {
				//Do Nothing
			}
		});
		
        
        
    });
});;
