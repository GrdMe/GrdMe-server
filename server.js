// server.js

'use strict'

// set up ========================
    var express  = require('express');
    var app      = express();                               // create our app w/ express
    var mongoose = require('mongoose');                     // mongoose for mongodb
    var morgan   = require('morgan');                       // log requests to the console (express4)
    var bodyParser = require('body-parser');                // pull information from HTML POST (express4)
    var methodOverride = require('method-override');        // simulate DELETE and PUT (express4)
    var basicAuth = require('basic-auth');
    var protoBuf = require('protobufjs');
    var crypto = require("axolotl-crypto"); // docs: https://github.com/joebandenburg/libaxolotl-javascript/blob/master/doc/crypto.md
    var rateLimit = require('express-rate-limit'); // docs: https://www.npmjs.com/package/express-rate-limit
    var base64 = require('base64-arraybuffer');

    /*****************************
    **** FOR TESTING PURPOSES ****
    *****************************/
    /**/ var request = require("request");
    /**/ var axolotl = require("axolotl");
    /**/ var store = {
    /**/     getLocalIdentityKeyPair : function() {},
    /**/     getLocalRegistrationId : function() {},
    /**/     getLocalSignedPreKeyPair : function(signedPreKeyId) {},
    /**/     getLocalPreKeyPair: function(preKeyId) {}
    /**/ };
    /**/ var axol = axolotl(store);
    /*************************
    ** END TESTING INCLUDES **
    *************************/

    // configuration =================
    var limiter = rateLimit({/* config */});

    app.use(express.static(__dirname + '/public'));                 // set the static files location /public/img will be /img for users
    app.use(morgan('dev'));                                         // log every request to the console
    app.use(bodyParser.urlencoded({'extended':'true'}));            // parse application/x-www-form-urlencoded
    app.use(bodyParser.json());                                     // parse application/json
    app.use(bodyParser.json({ type: 'application/vnd.api+json' })); // parse application/vnd.api+json as json
    app.use(methodOverride());
    app.use(limiter);

    // database ================================================================
    mongoose.connect('mongodb://localhost/grdmeUsers');
    var db = mongoose.connection;
    db.on('error', console.error.bind(console, 'connection error:'));
    db.once('open', function (callback) {
        console.log("connection to mongo database successful.");
    });

    var userSchema = mongoose.Schema({
        identityKey: String,
        devices: [{deviceId: String,
                   lastResortKey: {keyId: String,
                                   publicKey: String,
                                   identityKey: String,
                                   deviceId: String},
                    keys: [{keyId: String,
                            publicKey: String,
                            identityKey: String,
                            deviceId: String}]
                 }]
    });

    var AUTH_CHALLENGE_TIME_TO_LIVE = 60; //seconds

    var Users = mongoose.model('Users', userSchema);

    // routes ======================================================================
    // auth
    /* Constants */
    var NAME_DELIMITER = "|";

    /* Helper function to deny access */
    var unauthorized = function (res) {
        res.set('WWW-Authenticate', 'Basic realm=Authorization Required');
        return res.sendStatus(401);
    };

    /* Helper function to determin if deviceId exists under IdentityKey */
    var userContainsDeviceId = function(user, did) {
        for (var i = 0; i < user.devices.length; i++) {
            if (user.devices[i].deviceId == did)
                return true;
        }
        return false;
    };

    var initialAuth = function (req, res, next) {
        /* Parse auth credentials */
        var credentials = basicAuth(req);
        var names = credentials.name.split(NAME_DELIMITER);
        if (names.length != 2) {
            console.log("Authentication Failed - Badly Formed basic_auth");
            return unauthorized(res);
        }
        var identityKey = names[0];
        var deviceId = names[1];
        var pass = credentials.pass.split(NAME_DELIMITER);
        if (pass.length != 2) {
            console.log("Authentication Failed - Badly Formed basic_auth");
            return unauthorized(res);
        }
        var authDate = Number(pass[0]);
        var authSig = pass[1];
        /* Qurey DB. Continue iff idKey & did combo DNE */
        Users.findOne({identityKey : identityKey},
            function(err, dbUser) {
                if ((!dbUser || !userContainsDeviceId(dbUser, deviceId) ) && !err) {
                    /* Verify date freshness */
                    var timeAuthDate = new Date(authDate);
                    var timeNow = new Date();
                    var difference = timeNow - timeAuthDate;
                    var pubkey = base64.decode(identityKey);
                    var dataToSign = base64.decode(authDate);
                    var signature = base64.decode(authSig);
                    var verified = crypto.verifySignature(pubkey,
                                                 dataToSign,
                                                 signature);
                    if (difference < (AUTH_CHALLENGE_TIME_TO_LIVE * 1000) && difference > 0) { //if auth is fresh
                        /* Verify signature on date */
                        var verified = crypto.verifySignature(pubkey, dataToSign, signature);
                        /* return apropriate response */
                        if (verified) { // signature on date verified
                            return next();
                        } else { // signature on date !verified
                            console.log("Authentication Failed - Bad signature");
                            return unauthorized(res);
                        }
                    } else { //else, auth is stale
                        console.log("Authentication Failed - Stale date");
                        return unauthorized(res);
                    }
                } else { // identityKey + did combo existed in DB
                    console.log("Authentication Failed - idkey/did exist in DB");
                    return unauthorized(res);
                }
            });
    };

    var auth = function (req, res, next) {
        /* get basic_auth fields from request */
        var user = basicAuth(req);

        if (user && user.name && user.pass) {   // if username & password in basic_auth)
            /* Parse auth credentials */
            var credentials = basicAuth(req);
            var names = credentials.name.split(NAME_DELIMITER);
            if (names.length != 2) {
                console.log("Authentication Failed - Badly Formed basic_auth");
                return unauthorized(res);
            }
            var identityKey = names[0];
            var deviceId = names[1];
            var pass = credentials.pass.split(NAME_DELIMITER);
            if (names.length != 2) {
                console.log("Authentication Failed - Badly Formed basic_auth");
                return unauthorized(res);
            }
            var authDate = Number(pass[0]);
            var authSig = base64.decode(pass[1]);

            /* Only continue if identityKey & did exist is Users db */
            Users.findOne({identityKey : identityKey},
                function(err, dbUser) {
                    if (dbUser && userContainsDeviceId(dbUser, deviceId) && !err) { //if identityKey & did exist is Users db
                        /* Verify date freshness */
                        var timeAuthDate = new Date(authDate);
                        var timeNow = new Date();
                        var difference = timeNow - timeAuthDate
                        if (difference < (AUTH_CHALLENGE_TIME_TO_LIVE * 1000) && difference > 0) { //if auth is fresh
                            /* Verify signature on date */
                            var verified = crypto.verifySignature(base64.decode(identityKey), base64.decode(authDate), authSig);
                            /* return apropriate response */
                            if (verified) {
                                return next();
                            } else {
                                console.log("Authentication Failed - Bad signature");
                                return unauthorized(res);
                            }
                        } else { //else, auth is stale
                            console.log("Authentication Failed - Stale date");
                            return unauthorized(res);
                        }
                    } else { //identityKey & did !exist is Users db
                        console.log("Authentication Failed - idkey/did DNE in DB");
                        return unauthorized(res);
                    }
                }
            );
        } else { //if no basic_auth credentials
            console.log("Authentication Failed - No basic_auth");
            return unauthorized(res);
        }
    };


    // api =========================================================================

    //Register prekeys
    app.post('/v1/key/initial', initialAuth, function(req, res) {
        /* get basic_auth fields from request */
        console.log("1");
        var user = basicAuth(req);
        var names = user.name.split(NAME_DELIMITER);
        if (names.length != 2) {
            return res.sendStatus(401);
        }
        var identityKey = names[0];
        var deviceId = names[1];
        /* Create DB Entry. New user and/or new device w/ prekeys */
        console.log("2");
        Users.create({
            identityKey: identityKey,
            devices : [
                {deviceId : deviceId}
            ]
/*            devices: [{deviceId: deviceId,
                       lastResortKey: {keyId: String,
                                       publicKey: String,
                                       identityKey: String,
                                       deviceId: String},
                        keys: [{keyId: String,
                                publicKey: String,
                                identityKey: String,
                                deviceId: String}]
                     }]*/
        }, function(err, user) {
            console.log("3");
            if (user && !err) {
                return res.sendStatus(200);
            } else {
                return res.sendStatus(500);
            }
        });

        //var lastResortKey = req.body.lastResortKey;
        //var prekeys = req.body.preKeys;
    });

    //Register prekeys
    app.post('/v1/key/update', auth, function(req, res) {
        console.log("ACCESS GRANTED!!!!");
        //var lastResortKey = req.body.body.lastResortKey;
        //var prekeys = req.body.body.keys;
        return res.sendStatus(200);
    });

    //getting a recipients prekeys based on idkey and device key
    app.get('/v1/key/', auth, function(req, res) {
        var signature = req.body.signature;
        var bodyToVerify = req.body.body;

        var identityKey = req.body.body.identityKey;
        var deviceIdKey = req.body.body.deviceIdKey;

    });

    //submitting a message
    app.post('/v1/messages/', basicAuth, function(req, res) {
        var signature = req.body.signature;
        var bodyToVerify = req.body.body;

        for (var i=0; i<req.body.body.messages.length; i++) {
            var message = req.body.body.messages[i].body;

            for (var j=0; j<req.body.body.headers.length; j++) {
                var deviceIdKey = req.body.body.headers.deviceIdKey;
                var messageHeader = req.body.body.headers.messageHeader;
            }
        }
    });

    //test axolotl
    app.get('/test/authsig', function(req, res) {
        console.log(Number(new Date()));
        return res.sendStatus(200);
    });
    app.get('/test/freshness/:time', function(req, res) {
        console.log(req.params.time);
        var reqTime = new Date(Number(req.params.time));
        var now = new Date();
        console.log(reqTime);
        console.log(now);
        console.log("-------------");

        console.log(String(reqTime));
        console.log(Math.abs(now - reqTime));
        console.log(Boolean(now - reqTime < (AUTH_CHALLENGE_TIME_TO_LIVE * 1000)));
        return res.sendStatus(200);
    });
    app.get('/test/axolotl', function(req, res) {
        var result;
        axol.generateIdentityKeyPair().then(function(idKeyPair) { // Generate our identity key
            axol.generateRegistrationId().then(function(registrationId) { // Generate our registration id
                axol.generateLastResortPreKey().then(function(lastResortKey) { // Generate our last restore pre-key to send to the server
                    axol.generatePreKeys(0, 100).then(function(preKeys) { // Generate the first set of our pre-keys to send to the server
                        console.log("Type of Key: "+typeof(idKeyPair.public));
                        result = {
                            identityKeyPair : idKeyPair,
                            reqistrationId : registrationId,
                            lastResortKey : lastResortKey,
                            preKeys: preKeys
                        };

                        var basicAuthUserName = base64.encode(idKeyPair.public);
                        basicAuthUserName = basicAuthUserName.concat(NAME_DELIMITER);
                        basicAuthUserName = basicAuthUserName.concat(registrationId);
                        var now = new Date();
                        var basicAuthPassword = String(now.getTime());
                        basicAuthPassword = basicAuthPassword.concat(NAME_DELIMITER);
                        var signature = base64.encode(crypto.sign(idKeyPair.private, base64.decode(now.getTime())));
                        basicAuthPassword = basicAuthPassword.concat(signature);

                        console.log("Basic_Auth User Name: " + basicAuthUserName);
                        console.log("Basic_Auth Passwors: "+ basicAuthPassword);

                        // var pubkey = base64.decode(base64.encode(idKeyPair.public));
                        // var dataToSign = base64.decode(now.getTime());
                        // var signature = base64.decode(signature);
                        // var verified = crypto.verifySignature(pubkey,
                        //                              dataToSign,
                        //                              signature);
                        // console.log("Signature verifiable?: "+verified);

                        /* Make Request to register user */
                    //     var postData = {
                    //       name: 'test',
                    //       value: 'test'
                    //     };
                    //     var url = 'http://'+basicAuthUserName+':'+''+'@localhost:8080/v1/key/initial/';
                    //     var options = {
                    //       method: 'post',
                    //       //body: postData,
                    //       //json: true,
                    //       url: url
                    //     };
                    //     request(options, function (err, res, body) {
                    //       if (err) {
                    //         console.log("Error in making request to /v1/key/initial: ");
                    //         console.log(err);
                    //         console.log("SATATUS CODE OF RESPONSE: "+statusCode);
                    //         return res.json(result);
                    //       }
                    //       var headers = res.headers;
                    //       var statusCode = res.statusCode;
                    //       console.log("SATATUS CODE OF RESPONSE: "+statusCode);
                    //       return res.json(result);
                    //   });

                        return res.json(result);
                    });
                });
            });
        });

        // axol.generateSignedPreKey(identityKeyPair, 1).then(function(result) { // Generate our first signed pre-key to send to the server
        //     console.log("signed pre key: "+result);
        // });
    });


    // application -------------------------------------------------------------


    app.get('/', function (req, res) {
        res.send('Hello World!');
    });

    // listen (start app with node server.js) ======================================
    app.listen(8080, function () {
        console.log('Grd Me sever listening at http://11.12.13.14:8080');
    });
