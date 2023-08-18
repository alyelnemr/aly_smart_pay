/* Copyright (c) 2016-Present Webkul Software Pvt. Ltd. (<https://webkul.com/>) */
/* See LICENSE file for full copyright and licensing details. */
odoo.define('otp_sms_auth.wk_otp', function (require) {
    "use strict";

    var ajax = require('web.ajax');
    var sAnimations = require('website.content.snippets.animation');
    var core = require('web.core');
    var _t = core._t;
    
    sAnimations.registry.Wk_OtpAuthSMSLogin = sAnimations.Class.extend({
        selector: '.oe_login_form,.oe_adv_login_form',
        read_events: {
            'click .wk_next_btn'                        : '_clickAuthSmsNextbtn',
            // 'click .wk_login_resend'                    : '_clickAuthSmsResend',
            'change  input:radio[name="radio-login"]'   : '_changeRadiobtnlogin',
            'click .wk_send'                            : '_clickAuthSmsSend',
        },

        /*
        * @override
        */
        willStart: function () {
            var self = this;
            var def = this._super.apply(this, arguments);         
            if (!$(this).find('#wkmobile label[for=mobile], input#mobile').text()) {
                $('label[for=mobile], input#mobile').hide();
            }
            return def;
        },

        /**
        * @private
        */
        _generateSMSLoginOtp:function(){
            var self = this;
            var mobile = $('#mobile').val();
            var otp_type = $('.otp_type').val();
            $("div#wk_loader").addClass('show');
            var loginType = $('input:radio[name="radio-login"]:checked').val();
            if (loginType == 'radiomobile') {
                ajax.jsonRpc("/send/sms/otp", 'call', {'mobile':mobile})
                    .then(function (data) {
                        if (data[0] == 1) {
                            $("div#wk_loader").removeClass('show');
                            $('#wk_error').remove();
                            if (data[3]) {
                                $('label[for=login], input#login').val(data[3]);
                            }
                            self._getSMSLoginInterval(data[2]);
                            $(".field-password").show();
                            $("#passwogenerateSMSSignUpOtprd").attr('placeholder', 'Enter OTP');
                            if (otp_type == '4') {
                                $("#password").attr("type", "text");
                            }
                            $(".field-password").after("<p id='wk_error' class='alert alert-success'>" +data[1] + "</p>");
                            $(":submit").show();
                            $(".wk_next_btn").hide();
                            $(".field-otp-option").css("display","none");
                        } else {
                            $("div#wk_loader").removeClass('show');
                            $('#wk_error').remove();
                            $(".field-otp-option").after("<p id='wk_error' class='alert alert-danger'>" +data[1] + "</p>");
                        }
                    }).fail(function (error){
                        console.log(error)
                    });
            } else {
                $("div#wk_loader").removeClass('show');
            }
        },

        /**
        * @private
        */
        _getUserEmail:function(){
            var mobile = $('#mobile').val();
            var login = $('#login').val();
            $("div#wk_loader").addClass('show');
            var loginType = $('input:radio[name="radio-login"]:checked').val();
            if (loginType) {
                ajax.jsonRpc("/get/user/email", 'call', {'mobile':mobile, 'login':login})
                .then(function (data) {
                    if (data.status == 1) {
                        $("div#wk_loader").removeClass('show');
                        $('#wk_error').remove();
                        if (mobile) {
                            $('label[for=login], input#login').val(data.login);
                        } else {
                            $('label[for=mobile], input#mobile').val(data.mobile);
                        }
                        $(".field-password").show();
                        $(":submit").show();
                        $(".wk_next_btn").hide();
                        $(".field-otp-option").css("display","none");
                    } else {
                        $("div#wk_loader").removeClass('show');
                        $('#wk_error').remove();
                        $(".field-otp-option").after("<p id='wk_error' class='alert alert-danger'>" +data.message + "</p>");
                    }
                }).fail(function (error){
                    console.log(error)
                });
            }        
        },

        /**
        * @private
        */
        _getUserData:function(){
            var mobile = $('#mobile').val();
            var login = $('#login').val();
            var loginType = $('input:radio[name="radio-login"]:checked').val();
            if (loginType) {
                ajax.jsonRpc("/get/user/email", 'call', {'mobile':mobile, 'login':login})
                    .then(function (data) {
                        if (data.status == 1) {
                            if (mobile) {
                                $('label[for=login], input#login').val(data.login);
                            } else {
                                $('label[for=mobile], input#mobile').val(data.mobile);
                            }
                        }
                        else {
                            $("div#wk_loader").removeClass('show');
                            $('#wk_error').remove();
                            $(".field-otp-option").after("<p id='wk_error' class='alert alert-danger'>" +data.message + "</p>");
                            
                        }
                    }).fail(function (error){
                        console.log(error)
                    });
            }
        },

        /**
        * @private
        */
        _getSMSLoginInterval:function(){
            var countDown = otpTimeLimit;
            var x = setInterval(function() {
                countDown = countDown - 1;
                $("#otplogincounter").html("OTP will expire in " + countDown + " seconds.");
                if (countDown < 0) {
                    clearInterval(x);
                    $('#wk_error').remove();
                    $("#otplogincounter").html("<a class='btn btn-link pull-right wk_login_resend' href='#'>Resend OTP</a>");
                }
            }, 1000);
        },

        /**
        * @private
        * @param {KeyboardEvent} ev
        */
        _changeRadiobtnlogin:function(ev){
            if ($(ev.currentTarget).val() == 'radioemail') {
                $('label[for=login], input#login').show();
                $('label[for=mobile], input#mobile').hide();
            } else if ($(ev.currentTarget).val() == 'radiomobile') {
                $('label[for=mobile], input#mobile').show();
                $('label[for=login], input#login').hide().prop('required',false);
            }
        },

        /**
        * @private
        * @param {KeyboardEvent} ev
        */
        _clickAuthSmsNextbtn:function(ev){
            $(".field-login-option").hide();
            $(".field-mobile").hide();
            $('.alert.alert-danger').remove();
            var radioVal = $('input[name=radio-otp]:checked').val();
            if ($("#smsotp").css("display") == 'none') {
                $('#smsotp').show();
                this._getUserData();
            } else {
                if (radioVal == 'radiopwd') {
                    this._getUserEmail();
                }
                if (radioVal == 'radiotp') {
                    console.log('--------testing-------------')
                    this._getUserEmail();
                    // this._generateSMSLoginOtp();
                } else {
                    if ($('label[for=mobile], input#mobile').css('display') == 'none') {
                        $('label[for=mobile], input#mobile').val('');
                    } else {
                        if ($('label[for=login], input#login').css('display')) {
                            $('label[for=login], input#login').val('');
                        }
                    }
                }
            }
        },

        /**
        * @private
        * @param {KeyboardEvent} ev
        */
        _clickAuthSmsResend:function(ev){
            this._generateSMSLoginOtp();
        },

        /**
        * @private
        * @param {KeyboardEvent} ev
        */
        _clickAuthSmsSend:function(ev){
            var mobile = $('#mobile').val();
            if (!mobile) {
                alert(mobile+"Please enter a mobile n");
                $('#wk_error').remove();
                $(".field-confirm_password").after("<p id='wk_error' class='alert alert-danger'>Please enter a mobile no.</p>");
            }
        },

    });
});
