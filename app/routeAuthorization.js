/* load required modules */
var basicAuth = require('basic-auth');
var crypto = require("axolotl-crypto"); // docs: https://github.com/joebandenburg/libaxolotl-javascript/blob/master/doc/crypto.md
var base64 = require('base64-arraybuffer');

/* load db models */
var Users = require('./models/user');

/* Constants */
var constants = require('./constants');

/* helper functions */
var helper = require('./helperFunctions');

// auth
module.exports.initialAuth = function (req, res, next) {
    /* Parse auth credentials */
    var credentials = basicAuth(req);
    if(!credentials) {
        console.log("Authentication Failed - No basic_auth");
        return unauthorized(res, 'badly formed credentials');
    }
    var names = credentials.name.split(constants.NAME_DELIMITER);
    if (names.length != 2 || !names[0] || !names[1]) {
        console.log("Authentication Failed - Badly Formed basic_auth name");
        return unauthorized(res, 'badly formed credentials');
    }
    var identityKey = names[0];
    var deviceId = names[1];
    var pass = credentials.pass.split(constants.NAME_DELIMITER);
    if (pass.length != 2) {
        console.log("Authentication Failed - Badly Formed basic_auth pass");
        return unauthorized(res, 'badly formed credentials');
    }
    var authDate = Number(pass[0]);
    var authSig = pass[1];

    /* Qurey DB. Continue iff idKey & did combo DNE */
    Users.findOne({identityKey : identityKey},
        function(err, dbUser) {
            if ((!dbUser && !helper.userContainsDeviceId(dbUser, deviceId) ) && !err) {
                /* Verify date freshness */
                var timeAuthDate = new Date(authDate);
                var timeNow = new Date();
                var difference = timeNow - timeAuthDate;
                var pubkey = base64.decode(identityKey);
                var dataToSign = base64.decode(String(authDate));
                var signature = base64.decode(authSig);
                var verified = crypto.verifySignature(pubkey,
                                             dataToSign,
                                             signature);
                if (difference < (constants.AUTH_CHALLENGE_TIME_TO_LIVE * 1000) && difference > (constants.AUTH_CHALLENGE_TIME_TO_LIVE * 1000 * -1)) { //if auth is fresh
                    /* Verify signature on date */
                    var verified = crypto.verifySignature(pubkey, dataToSign, signature);
                    /* return apropriate response */
                    if (verified) { // signature on date verified
                        return next();
                    } else { // signature on date !verified
                        console.log("Authentication Failed - Bad signature");
                        return unauthorized(res, 'signature');
                    }
                } else { //else, auth is stale
                    console.log("Authentication Failed - Stale date");
                    return unauthorized(res, 'time');
                }
            } else { // identityKey + did combo existed in DB
                console.log("Authentication Failed - idkey/did exist in DB");
                return unauthorized(res, 'registered');
            }
        });
};

module.exports.standardAuth = function (req, res, next) {
    /* get basic_auth fields from request */
    var user = basicAuth(req);
    if(!user) {
        console.log("Authentication Failed - No basic_auth");
        return unauthorized(res, 'badly formed credentials');
    }
    if (user && user.name && user.pass) {   // if username & password in basic_auth)
        /* Parse auth credentials */
        var credentials = basicAuth(req);
        var names = credentials.name.split(constants.NAME_DELIMITER);
        if (names.length != 2) {
            console.log("Authentication Failed - Badly Formed basic_auth name");
            return unauthorized(res, 'badly formed credentials');
        }
        var identityKey = names[0];
        var deviceId = names[1];
        var pass = credentials.pass.split(constants.NAME_DELIMITER);
        if (names.length != 2) {
            console.log("Authentication Failed - Badly Formed basic_auth pass");
            return unauthorized(res, 'badly formed credentials');
        }
        var authDate = Number(pass[0]);
        var authSig = base64.decode(pass[1]);

        /* Only continue if identityKey & did exist is Users db */
        Users.findOne({identityKey : identityKey},
            function(err, dbUser) {
                if (dbUser && helper.userContainsDeviceId(dbUser, deviceId) && !err) { //if identityKey & did exist is Users db
                    if (dbUser.revoked == true) { //if idkey has been revoked
                        console.log("FOUR");
                        return unauthorized(res, 'revoked');
                    }
                    /* Verify date freshness */
                    var timeAuthDate = new Date(authDate);
                    var timeNow = new Date();
                    var difference = timeNow - timeAuthDate
                    if (difference < (constants.AUTH_CHALLENGE_TIME_TO_LIVE * 1000) && difference > (constants.AUTH_CHALLENGE_TIME_TO_LIVE * 1000 * -1)) { //if auth is fresh
                        /* Verify signature on date */
                        var verified = crypto.verifySignature(base64.decode(identityKey), base64.decode(String(authDate)), authSig);
                        /* return apropriate response */
                        if (verified) {
                            return next();
                        } else {
                            console.log("Authentication Failed - Bad signature");
                            return unauthorized(res, 'signature');
                        }
                    } else { //else, auth is stale
                        console.log("Authentication Failed - Stale date");
                        return unauthorized(res, 'time');
                    }
                } else { //identityKey & did !exist is Users db
                    console.log("Authentication Failed - idkey/did DNE in DB");
                    return unauthorized(res, 'not registered');
                }
            }
        );
    } else { //if no basic_auth credentials
        console.log("Authentication Failed - No basic_auth");
        return unauthorized(res, 'badly formed credentials');
    }
};

/* Helper Functions */
/* Helper function to deny access */
var unauthorized = function (res, error) {
    res.set('WWW-Authenticate', 'Basic realm=Authorization Required');
    res.status(401);
    switch (error) {
        case 'signature': //unauthorized (bad signature)
            return res.send('signature');
            break;
        case 'not registered': //Not Found (identityKey/did DNE in database)
            return res.send('not registered');
            break;
        case 'time': //conflict (invalid time stamp)
            var serverTime = String((new Date()).getTime());
            res.set('Server-Time', serverTime);
            return res.send('time');
            break;
        case 'revoked': //gone (key revoked)
            return res.send('revoked');
            break;
        case 'registered': //Unprocessable Entity (identityKey/did already exist in database)
            return res.send('registered');
            break;
        case 'badly formed credentials':
            return res.send('badly formed credentials');
            break;
        default:
            return res.send();
            break;
    }
};
