// server.js


// set up ========================
    var express  = require('express');
    var app      = express();                               // create our app w/ express
    var mongoose = require('mongoose');                     // mongoose for mongodb
    var morgan   = require('morgan');                       // log requests to the console (express4)
    var bodyParser = require('body-parser');                // pull information from HTML POST (express4)
    var methodOverride = require('method-override');        // simulate DELETE and PUT (express4)
    //var nano = require('nano')('http://localhost:5984');  //connect with local database
    var basicAuth = require('basic-auth');
    var bcrypt = require('bcrypt');
    var protoBuf = require('protobufjs');
    var crypto = require("axolotl-crypto");
    // docs: https://github.com/joebandenburg/libaxolotl-javascript/blob/master/doc/crypto.md
    var rateLimit = require('express-rate-limit');
    // docs: https://www.npmjs.com/package/express-rate-limit

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
        password: String, // !!!!no longer needed
        pushId: String, // !!!!no longer needed
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
        // should be able to query for and compare Binary/buffer values
        nonce : Buffer, //will be stored as ArrayBuffer that is generated on server
        identityKeyCatDid  : String, //will be base64 that comes via httprequest <identityKey>|<deviceId>
        idnetityKey : String,
        timestamp : { type: Date, expires: AUTH_CHALLENGE_TIME_TO_LIVE, default: Date.now }
    })

    var Users = mongoose.model('Users', userSchema);
    var AuthChallenges = mongoose.model('AuthChallenges', authSchema);

    // routes ======================================================================
    // auth
    /* Constants */
    var NAME_DELIMITER = "|";
    var NONCE_BYTE_LENGTH = 32; //256 bits

    var auth = function (req, res, next) {
        /* function to deny access */
        function unauthorized(res) {
        	res.set('WWW-Authenticate', 'Basic realm=Authorization Required');
            return res.sendStatus(401);
        };

        /* Helper function to determin if deviceId exists under IdentityKey */
        function userContainsDeviceId(user, did) {
            for (var i = 0; i < array.length; i++) {
                if (user.devices[i].deviceId == did)
                    return true;
            }
            return false;
        }

        /* Helper function. Converts node Buffer to JS ArrayBuffer */
        function toArrayBuffer(buffer) {
            var ab = new ArrayBuffer(buffer.length);
            var view = new Uint8Array(ab);
            for (var i = 0; i < buffer.length; ++i) {
                view[i] = buffer[i];
            }
            return ab;
        }

        /* get basic_auth fields from request */
        var user = basicAuth(req);

        /* Proceed depending on presence/absence of basic_auth fields */
        if (!user || (!user.name && !user.pass)) {      // if no username and no password in basic_auth
            return unauthorized(res);

        } else if (user && user.name && !user.pass) {   // if username & no password in basic_auth
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
                            "timestamp" : Date.now;
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
                        var signatureBuffer = new Buffer(user.pass, 'base64');
                        var signatureArrayBuffer = toArrayBuffer(signatureBuffer);
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
        }
    };


    // api =========================================================================
    // // Register
    // app.post('/v1/accounts/register/', function(req, res) {
    //     if (!req.body.signature ||
    //         !req.body.body ||
    //         !req.body.body.identityKey ||
    //         !req.body.body.password) {
    //             res.sendStatus(415);
    //         }
    //
    //     var signature = req.body.signature;
    //     var bodyToVerify = req.body.body;
    //
    //     /* !!!! verify body with signature here !!!! */
    //
    //     var identityKeyToRegister = req.body.body.identityKey;
    //     var passwordToRegister;
    //     bcrypt.hash(req.body.body.password, 8, function(err, hash) {
    //         if (err) {
    //             res.send(err);
    //         } else {
    //             passwordToRegister = hash;
    //             Users.create({
    //                 identityKey : identityKeyToRegister,
    //                 password: passwordToRegister
    //             }, function(err, user) {
    //                 if (err)
    //                     res.send(err);
    //                 if (user) {
    //                     //res.sendStatus(200);
    //                     res.json(user);
    //                 }
    //             });
    //         }
    //     });
    //
    // });

    // // Register a gcm id
    // app.put('/v1/accounts/push/', auth, function(req, res) {
    //     if (!req.body ||
    //         !req.body.pushRegistrationId) {
    //             res.sendStatus(415);
    //             return;
    //         }
    //
    //     var pushRegistrationId = req.body.pushRegistrationId;
    //     var user = basicAuth(req);
    //
    //     Users.update({identityKey : user.name},{
    //         pushID : pushRegistrationId
    //     }, function(err, dbUser) {
    //             if (err)
    //                 res.send(err);
    //
    //             res.sendStatus(200);
    //         }
    //     );
    //
    // });

    //Register prekeys
    app.post('/v1/key/initial', auth, function(req, res) {
        var signature = req.body.signature;
        var bodyToVerify = req.body.body;

        var lastResortKey = req.body.body.lastResortKey;
        var prekeys = req.body.body.keys;
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


    // application -------------------------------------------------------------


    app.get('/', function (req, res) {
        res.send('Hello World!');
    });

    // listen (start app with node server.js) ======================================
    app.listen(8080, function () {
        console.log('Grd Me sever listening at http://11.12.13.14:8080');
    });
