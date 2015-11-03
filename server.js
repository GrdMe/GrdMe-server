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
    var bcrypt = require('bcrypt');
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

    var AUTH_CHALLENGE_TIME_TO_LIVE = 30; //seconds
    var authSchema = mongoose.Schema({
        nonce : Buffer, //will be stored as ArrayBuffer that is generated on server
        identityKeyCatDid  : String, //will be base64 that comes via httprequest <identityKey>|<deviceId>
        identityKey : String,
        timestamp : { type: Date, expires: AUTH_CHALLENGE_TIME_TO_LIVE, default: Date.now }
    });

    var Users = mongoose.model('Users', userSchema);
    var AuthChallenges = mongoose.model('AuthChallenges', authSchema);

    // routes ======================================================================
    // auth
    /* Constants */
    var NAME_DELIMITER = "|";
    var NONCE_BYTE_LENGTH = 32; //256 bits

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
        /* get basic_auth fields from request */
        var user = basicAuth(req);
        var names = user.name.split(NAME_DELIMITER);
        if (names.length != 2) {
            return unauthorized(res);
        }
        var identityKey = names[0];
        var deviceId = names[1];
        /* Qurey DB. Continue iff idKey & did combo DNE */
        Users.findOne({identityKey : identityKey},
            function(err, dbUser) {
                if ((!dbUser || !userContainsDeviceId(dbUser, deviceId) ) && !err) {
                    return next();
                } else {
                    return unauthorized(res);
                }
            });
    };

    var auth = function (req, res, next) {
        /* Helper function. Converts node Buffer to JS ArrayBuffer */
        function toArrayBuffer(buffer) {
            var ab = new ArrayBuffer(buffer.length);
            var view = new Uint8Array(ab);
            for (var i = 0; i < buffer.length; ++i) {
                view[i] = buffer[i];
            }
            return ab;
        };

        /* get basic_auth fields from request */
        var user = basicAuth(req); //!!this is somehow asynchronous

        /* Proceed depending on presence/absence of basic_auth fields */
        if (user && user.name && !user.pass) {   // if username & no password in basic_auth
            /* Initial connection to server requires <identityKey>|<deviceId> in
             * the username field of http basic_auth and empty password field.
             * Server generates nonce, and temporarily saves it in relation to the
             * identityKey & deviceId. Server responds with 401 (unauthorized) header
             * and the nonce in the body.
            */
            var names = user.name.split(NAME_DELIMITER);
            if (names.length != 2) {
                return unauthorized(res);
            }
            var identityKey = names[0];
            var deviceId = names[1];

            /* Only continue if identityKey & did exist is Users db*/
            Users.findOne({identityKey : identityKey},
                function(err, dbUser) {
                    if (dbUser && userContainsDeviceId(dbUser, deviceId) && !err) { //if identityKey & did exist is Users db
                        /* generate nonce */
                        var nonce = crypto.randomBytes(NONCE_BYTE_LENGTH); //of type ArrayBuffer
                        console.log("Type of Nonce: " + typeof(nonce));
                        /* insert nonce into database */
                        AuthChallenges.create({
                            "nonce" : nonce,
                            "identityKeyCatDid" : user.name,
                            "identityKey" : identityKey,
                            "timestamp" : Date.now
                        }, function(err, authChallenge) {
                            if (err)
                                res.send(err);
                            if (authChallenge) {
                                /* Respond to client with nonce */
                                return res.status(401).send({"nonce": nonce});
                            } else {
                                return unauthorized(res);
                            }
                        });
                    } else { //identityKey & did !exist is Users db
                        return unauthorized(res);
                    }
                }
            );

        } else if (user && user.name && user.pass) {   // if username & password in basic_auth)
            /* Second connection to server requires <identityKey>|<deviceId> in
             * the username field of http basic_auth and signature(nonce) in the
             * password field.
             * Server verifies signature of nonce by requesting the nonce from
             * the authChallenges db collection. If signature is verified, access
             * is granted; else, 401
            */

            /* Query db for authChallenge */
            AuthChallenges.findOne({identityKey : user.name},
                function(err, authChallenge) {
                    /* Note - even though docs in the AuthChallenges collection
                     * time out automaticly, Mogodb's data expiration task only
                     * runs once per minuite, so checking the timestamp here
                     * is still necessary.
                    */
                    if (authChallenge
                        && date.now - authChallenge.timestamp < (AUTH_CHALLENGE_TIME_TO_LIVE * 1000) //convert sec to milliseconds
                        && !err) { //if authChallenge not timed out
                        /* convert signature to ArrayBuffer */
                        var signatureArrayBuffer = base64.decode(user.pass);
                        /* verify signature */
                        var verified = crypto.verifySignature(authChallenge.identityKey, authChallenge.nonce, signatureArrayBuffer);
                        /* return apropriate response */
                        if (verified) {
                            return next();
                        } else {
                            return unauthorized(res);
                        }

                    } else { //identityKey & did !exist is Users db
                        return unauthorized(res);
                    }
                }
            );
        } else { //if no basic_auth credentials
            return unauthorized(res);
        }
    };


    // api =========================================================================

    //Register prekeys
    app.post('/v1/key/initial'/*, initialAuth*/, function(req, res) {
        /* get basic_auth fields from request */
        console.log("1");
        var user = basicAuth(req);
        var names = user.name.split(NAME_DELIMITER);
        if (names.length != 2) {
            return res.status(400);
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
            if(err) {
                return res.send(err);
            } else if (user) {
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
        var lastResortKey = req.body.body.lastResortKey;
        var prekeys = req.body.body.keys;
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
                        console.log("Basic_Auth User Name: " + basicAuthUserName);

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
