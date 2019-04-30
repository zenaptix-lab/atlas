/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


//Define indexOf for IE
if (!Array.prototype.indexOf) {
    Array.prototype.indexOf = function (obj, start) {
        for (var i = (start || 0); i < this.length; i++) {
            if (this[i] == obj) {
                return i;
            }
        }
        return -1;
    };
}

if (!String.prototype.startsWith) {
    String.prototype.startsWith = function (str, matchStr) {
        return str.lastIndexOf(matchStr, 0) === 0
    }
}

function doLogin() {

    var userName = $('#username').val().trim();
    var passwd = $('#password').val().trim();

    if (userName === '' || passwd === '') {
        $('#errorBox').show();
        $('#signInLoading').hide();
        $('#signIn').removeAttr('disabled');
        $('#errorBox .errorMsg').text("The username or password you entered is blank..");
        return false;
    }

    var baseUrl = getBaseUrl();
    if (baseUrl.lastIndexOf('/') != (baseUrl.length - 1)) {
        if (baseUrl) {
            baseUrl = baseUrl + '/';
        } else {
            baseUrl = '/';
        }
    }
    // var url = baseUrl + 'http://localhost:8080/auth/realms/master/protocol/openid-connect/token';
    var url = 'http://localhost:8080/auth/realms/master/protocol/openid-connect/token';

    var tokenInfo = {
        username: userName,
        password: passwd,
        client_id: "atlas",
        grant_type: "password"
    };

    function getLoginToken(callback) {
        $.ajax({
            data: tokenInfo,
            url: url,
            type: 'POST',
            dataType: 'json',
            async: false,
            timeout: 10000,
            contentType: "application/x-www-form-urlencoded"
            ,
            success: function (data) {
                console.log("**************************************************************************************");
                callback(data);
                console.log(JSON.parse(data));
                if (location.hash.length > 2)
                    window.location.replace('index.html' + location.hash);
                else
                    window.location.replace('index.html');
            },
            error: function (jqXHR, textStatus, err) {
                console.log("######################################ERROR##############################################111");
                // console.log(JSON.parse(jqXHR.responseText));
                console.log(textStatus);
                console.log("Error " + err.toString());
                console.log(jqXHR.type);
                console.log(jqXHR);

                $('#signIn').removeAttr('disabled');
                $('#signInLoading').css("visibility", "hidden");

                if (jqXHR.status && jqXHR.status == 412) {
                    $('#errorBox').hide();
                    $('#errorBoxUnsynced').show();
                } else {
                    try {
                        var resp = JSON.parse(jqXHR.responseText);
                        console.log("resp", resp);
                        if (resp.msgDesc.startsWith("Username not found") || resp.msgDesc.startsWith("Wrong password")) {
                            $('#errorBox .errorMsg').text("Invalid User credentials. Please try again.");
                        } else if (resp.msgDesc.startsWith("User role credentials is not set properly")) {
                            $('#errorBox .errorMsg').text("User role or credentials is not set properly");
                        } else {
                            $('#errorBox .errorMsg').text("Error while authentication");
                        }
                    } catch (err) {
                        $('#errorBox .errorMsg').text("Something went wrong1");
                    }
                    $('#errorBox').show();
                    $('#errorBoxUnsynced').hide();
                }
            }
        });
    }

    var token = getLoginToken(function (data) {
        return JSON.parse(data)
    });
    console.log("TOKEN : " + token);
    return token;
}

function getBaseUrl() {
    if (!window.location.origin) {
        window.location.origin = window.location.protocol + "//" + window.location.hostname + (window.location.port ? ':' + window.location.port : '');
    }
    return window.location.origin + window.location.pathname.substring(window.location.pathname
        .indexOf('/', 2) + 1, 0);
}

$(function () {
    // register handlers
    if (!('placeholder' in HTMLInputElement.prototype)) {
        $("#username , #password").placeholder();
    }
    $('#signIn').on('click', function () {
        $('#signIn').attr('disabled', true);
        $('#signInLoading').css("visibility", "visible");
        var userToken = doLogin();
        console.log("userToken: " + userToken);
        return false;
    });
    $('#loginForm').each(function () {
        $('input').keypress(function (e) {
            // Enter pressed?
            if (e.which == 10 || e.which == 13) {
                var userToken_1 = doLogin();
                console.log("userToken_1 : " + userToken_1)
            }
        });
    });

    $('#loginForm  li[class^=control-group] > input').on('change', function (e) {
        if (e.target.value === '') {
            $(e.target).parent().addClass('error');
        } else {
            $(e.target).parent().removeClass('error');
        }
    });
});