/* Copyright (c) 2016-Present Webkul Software Pvt. Ltd. (<https://webkul.com/>) */
/* See LICENSE file for full copyright and licensing details. */
odoo.define('otp_auth.wk_otp_login', function (require) {
    "use strict";
    
    var ajax = require('web.ajax');
    var sAnimations = require('website.content.snippets.animation');
    var core = require('web.core');
    var _t = core._t;

    sAnimations.registry.Wk_OtpAuthLogin = sAnimations.Class.extend({
        selector: '.oe_login_form',
        read_events: {
            'click .wk_next_btn'                    : '_clickNextbtn',
            'click .wk_login_resend'                : '_clickResend',
            'change input:radio[name="radio-otp"]'  : '_changeRadiobtn',
            'keyup input.wkpassword'                : '_EnterOtp',
        },

        /*
        * @override
        */
        willStart: function () {
            var self = this;
            var def = this._super.apply(this, arguments);         
            if ($('#otplogincounter').get(0)) {
                $(":submit").hide()
                $(":submit").attr("disabled", true)
                $(".field-password").hide();
                $( ".oe_login_form" ).wrapInner( "<div class='container' id='wk_container'></div>");
                // $("#password").addClass('wkpassword');
            }
            return def;
        },

        /**
        * @private
        */
        _getLoginInterval:function(otpTimeLimit){
            var countDown = otpTimeLimit;
            var x = setInterval(function() {
                countDown = countDown - 1;
                $("#otplogincounter").html("OTP will expire in " + countDown + " seconds.");
                if (countDown < 0) {
                    clearInterval(x);
                    $('#wk_error').remove();
                    $("#otplogincounter").html("<a class='btn btn-link pull-right wk_login_resend' href='#'>Resend OTP</a>");
                    $(":submit").attr("disabled", true);
                }
            }, 1000);
        },

        /**
        * @private
        */
        _generateLoginOtp:function(){
           var self = this;
            var mobile = $('#mobile').val();
            var email = $('#login').val();
            var otp_type = $('.otp_type').val();
            $("div#wk_loader").addClass('show');
            $(".field-password").show();
            $(".field-password>label").text('Enter Otp');
            $("#password").attr('placeholder', 'Enter OTP').addClass('wkpassword');;
            if (otp_type == '4') {
                $("#password").attr("type", "text");
            }
       
            ajax.jsonRpc("/send/otp", 'call', {'email':email, "loginOTP":'loginOTP', 'mobile':mobile})
            .then(function (data) {
                if (data) {
                    if (data.email) {
                        if (data.email.status == 1) {
                            $("div#wk_loader").removeClass('show');
                            $('#wk_error').remove();
                            self._getLoginInterval(data.email.otp_time);
                            $(":submit").show();
                            // $(":submit").removeAttr("disabled")
                            $(".wk_next_btn").hide();
                            $(".field-otp-option").css("display","none");
                            $(".field-password").after("<p id='wk_error' class='alert alert-success'>" +data.email.message + "</p>");
                        } else {
                            $("div#wk_loader").removeClass('show');
                            $('#wk_error').remove();
                            $(".field-otp-option").after("<p id='wk_error' class='alert alert-danger'>" +data.email.message + "</p>");
                        }
                    }
                    if (data.mobile) {
                        if (data.mobile.status == 1) {
                            // if (data.email) {
                                // if (data.email.status != 1) {
                                    $("div#wk_loader").removeClass('show');
                                    // $('#wk_error').remove();
                                    self._getLoginInterval(data.mobile.otp_time);
                                    // $(".field-password").show();
                                    // $(".field-password>label").text('Enter Otp');
                                    // $("#password").attr('placeholder', 'Enter OTP').addClass('wkpassword');
                                    // if (otp_type == '4') {
                                    //     $("#password").attr("type", "text");
                                    // }
                                    $(":submit").show();
                                    $(".wk_next_btn").hide();
                                    $(".field-otp-option").css("display","none");
                                // }
                            // }
                            $(".field-password").after("<p id='wk_error' class='alert alert-success'>" +data.mobile.message + "</p>");
                        } 
                        else {
                            // if (data.email) {
                            //     if (data.email.status != 1) {
                                    $("div#wk_loader").removeClass('show');
                                    $('#wk_error').remove();
                                // }
                                $(".field-otp-option").after("<p id='wk_error' class='alert alert-danger'>" +data.mobile.message + "</p>");
                                // $(".field-otp-option").after("<p  class='alert alert-danger'>" +data.email.message + "</p>");
                            // }
                        }
                    }
                }
            });
        },
        
        /**
        * @private
        * @param {KeyboardEvent} ev
        */
        _EnterOtp:function(ev){
            if(!$('.wk_login_resend').get(0)){
                if ($(ev.currentTarget).val().length == 6) {
                    var otp = $(ev.currentTarget).val();
                    ajax.jsonRpc("/verify/otp", 'call', {'otp':otp})
                        .then(function (data) {
                            if (data) {
                                $(":submit").removeAttr("disabled", false);
                            } else {
                                $(this.selector).find(":submit").attr("disabled", true);
                            }
                        });
                } else {
                    $(this.selector).find(":submit").attr("disabled", true);
                }
            }
        },

        /**
        * @private
        * @param {Event} ev
        */
        _clickResend: function (ev) {
            this._generateLoginOtp();
        },

        /**
        * @private
        * @param {Event} ev
        */
        _changeRadiobtn: function (ev) {
            if ($(ev.currentTarget).val() == 'radiotp') {
                $('label[for=password], input#password').text("OTP");
            } else if ($(ev.currentTarget).val() == 'radiopwd') {
                $('label[for=password], input#password').text("Password");
            }
        },

        /**
        * @private
        * @param {Event} ev
        */
        _clickNextbtn: function (ev) {
            if ($(".field-otp-option").css("display") == 'none') {
                $(".field-login").hide();
                $(".field-otp-option").css("display","");
            } else {
                var radioVal = $('input[name=radio-otp]:checked').val();
                if (radioVal == 'radiotp') {
                    this._generateLoginOtp();
                } else if (radioVal == 'radiopwd') {
                    $(".field-password").show();
                    $("#password").attr('placeholder', 'Enter Password');
                    $(":submit").attr("disabled", false).show();
                    $(".wk_next_btn").hide();
                    $(".field-otp-option").css("display","none");
                }
            }
        },
    });
});