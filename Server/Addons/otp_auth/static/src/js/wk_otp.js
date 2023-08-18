/* Copyright (c) 2016-Present Webkul Software Pvt. Ltd. (<https://webkul.com/>) */
/* See LICENSE file for full copyright and licensing details. */
odoo.define('otp_auth.wk_otp', function (require) {
    "use strict";

    var sAnimations = require('website.content.snippets.animation');
    var core = require('web.core');
    var _t = core._t;
    var ajax = require('web.ajax');

    sAnimations.registry.Wk_OtpAuth = sAnimations.Class.extend({
        selector: '.oe_signup_form,.oe_reset_password_form',
        read_events: {
            'click .wk_send'            : '_clickSendOtp',
            'click .wk_resend'          : '_clickResendOtp',
            'keyup input#otp'           : '_changeOtp',
        },
        
        /**
         * @constructor
         */
        init: function () {
            this._super.apply(this, arguments);
            this.ValidUser = 0;
        },

        /**
        * @override
        */
        start: function () {
            var def = this._super.apply(this, arguments);
            
            if ($('#otpcounter').get(0)) {
                $("#otpcounter").html("<a class='btn btn-link pull-left wk_send' href='#'>Send OTP</a>");
                $(":submit").attr("disabled", true);
                $("#otp").css("display","none");
                $( ".oe_signup_form" ).wrapInner( "<div class='fluid-container' id='wk_container'></div>");
            }

            return def
        },

        /**
        * @private
        */
        _validateEmail: function (emailId) {
            var mailRegex = /^([\w-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([\w-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)$/;
            return mailRegex.test(emailId);        
        },

        /**
        * @private
        */
        _getInterval: function (otpTimeLimit) {
            var countDown = otpTimeLimit;
            var x = setInterval(function() {
                countDown = countDown - 1;
                $("#otpcounter").html("OTP will expire in " + countDown + " seconds.");            
                if (countDown < 0) {
                    clearInterval(x);
                    $("#otpcounter").html("<a class='btn btn-link pull-right wk_resend position-absolute' href='#'>Resend OTP</a>");
                    $("#otpcounter").append('<span>Otp is expire.Please Click on resend button</span>');
                    $(":submit").attr("disabled", true);
                }
            }, 1000);
        },

        /**
        * @private
        */
        _generateOtp: function (ValidUser) {
            var self = this;
            var $selector = $(this.selector);
            var email = $selector.find('#login').val();
            var mobile = $selector.find('#mobile').val();
            var userName = $selector.find('#name').val();
            var country_id = $selector.find('#country_id').val();
            $selector.find("div#wk_loader").addClass('show');
            $selector.find('#wk_error').remove();
            $selector.find('.alert.alert-danger').remove();

            ajax.jsonRpc("/generate/otp", 'call', {'email':email, 'userName':userName, 'mobile':mobile, 'country':country_id,'validUser':ValidUser})
            .then(function (data) {
                if (data[0] == 1) {
                    $selector.find("div#wk_loader").removeClass('show');
                    $selector.find('.wk_send').remove();
                    self._getInterval(data[2]);
                    $selector.find("#wkotp").after("<p id='wk_error' class='alert alert-success'>" +data[1] + "</p>");
                    $selector.find("#otp").css("display","");
                    $selector.find('#otp').after($('#otpcounter'));
                } else {
                    $selector.find("div#wk_loader").removeClass('show');
                    $selector.find('#wk_error').remove();
                    $selector.find(".field-confirm_password").after("<p id='wk_error' class='alert alert-danger'>" +data[1] + "</p>");
                }
            });
        },

        /**
        * @private
        * @param {Event} ev
        */
       _clickSendOtp: function (ev) {
            if($(ev.currentTarget).closest('form').hasClass('oe_reset_password_form')){
                this.ValidUser = 1;
            }
            var email = $(this.selector).find('#login').val();
            if (email) {
                if(this._validateEmail(email)) {
                    this._generateOtp(this.ValidUser);
                } else {
                    $(this.selector).find('#wk_error').remove();
                    $(this.selector).find(".field-confirm_password").after("<p id='wk_error' class='alert alert-danger'>Please enter a valid email address.</p>");
                }
            } else {
                $(this.selector).find('#wk_error').remove();
                $(this.selector).find(".field-confirm_password").after("<p id='wk_error' class='alert alert-danger'>Please enter an email address.</p>");
            }
        },

        /**
        * @private
        * @param {Event} ev
        */
       _clickResendOtp: function (ev) {
            $(this.selector).find(".wkcheck").remove();
            this._generateOtp(this.ValidUser);
        },

        /**
        * @private
        * @param {keyup event} ev
        */
        _changeOtp: function (ev) {
            if(!$('.wk_resend').get(0)){
                if ($(ev.currentTarget).val().length == 6) {
                    var otp = $(ev.currentTarget).val();
                    ajax.jsonRpc("/verify/otp", 'call', {'otp':otp})
                        .then(function (data) {
                            if (data) {
                                $('#otp').after("<i class='fa fa-check-circle wkcheck' aria-hidden='true'></i>");
                                $(".wkcheck").css("color","#3c763d");
                                $('#wkotp').removeClass("form-group has-error");
                                $('#wkotp').addClass("form-group has-success");
                                $(":submit").removeAttr("disabled", false).find('.fa-refresh').addClass('d-none');
                            } else {
                                $(this.selector).find(":submit").attr("disabled", true);
                                $('#otp').after("<i class='fa fa-times-circle wkcheck' aria-hidden='true'></i>");
                                $('#wkotp').removeClass("form-group has-success");
                                $(".wkcheck").css("color","#a94442");
                                $('#wkotp').addClass("form-group has-error");
                            }
                        });
                } else {
                    $(this.selector).find(":submit").attr("disabled", true);
                    $(".wkcheck").remove();
                    $('#wkotp').removeClass("form-group has-success");
                    $('#wkotp').removeClass("form-group has-error");
                    $('#wkotp').addClass("form-group");
                }
            }
        },

    });
});