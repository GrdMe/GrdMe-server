// app/routes.js

/* Constants */
var NAME_DELIMITER = "|";
var AUTH_CHALLENGE_TIME_TO_LIVE = 120; //seconds

/* load required modules */
var basicAuth = require('basic-auth');
var protoBuf = require('protobufjs');
var crypto = require("axolotl-crypto"); // docs: https://github.com/joebandenburg/libaxolotl-javascript/blob/master/doc/crypto.md
var base64 = require('base64-arraybuffer');

/* load db models */
var Users = require('./models/user');
var MessageQueue = require('./models/messageQueue');

/* Load protobuf helper methods */
var pbhelper = require('../protobuf/protobufHelperFunctions')

//expose the routs to app with module.exports
module.exports = function(app) {

    // auth
    var initialAuth = function (req, res, next) {
        /* Parse auth credentials */
        var credentials = basicAuth(req);
        if(!credentials) {
            console.log("Authentication Failed - No basic_auth");
            return unauthorized(res, 'badly formed credentials');
        }
        var names = credentials.name.split(NAME_DELIMITER);
        if (names.length != 2 || !names[0] || !names[1]) {
            console.log("Authentication Failed - Badly Formed basic_auth name");
            return unauthorized(res, 'badly formed credentials');
        }
        var identityKey = names[0];
        var deviceId = names[1];
        var pass = credentials.pass.split(NAME_DELIMITER);
        if (pass.length != 2) {
            console.log("Authentication Failed - Badly Formed basic_auth pass");
            return unauthorized(res, 'badly formed credentials');
        }
        var authDate = Number(pass[0]);
        var authSig = pass[1];
        /* Qurey DB. Continue iff idKey & did combo DNE */
        Users.findOne({identityKey : identityKey},
            function(err, dbUser) {
                if ((!dbUser && !userContainsDeviceId(dbUser, deviceId) ) && !err) {
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
                    if (difference < (AUTH_CHALLENGE_TIME_TO_LIVE * 1000) && difference > 0) { //if auth is fresh
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

    var auth = function (req, res, next) {
        /* get basic_auth fields from request */
        var user = basicAuth(req);
        if(!user) {
            console.log("Authentication Failed - No basic_auth");
            return unauthorized(res, 'badly formed credentials');
        }
        if (user && user.name && user.pass) {   // if username & password in basic_auth)
            /* Parse auth credentials */
            var credentials = basicAuth(req);
            var names = credentials.name.split(NAME_DELIMITER);
            if (names.length != 2) {
                console.log("Authentication Failed - Badly Formed basic_auth name");
                return unauthorized(res, 'badly formed credentials');
            }
            var identityKey = names[0];
            var deviceId = names[1];
            var pass = credentials.pass.split(NAME_DELIMITER);
            if (names.length != 2) {
                console.log("Authentication Failed - Badly Formed basic_auth pass");
                return unauthorized(res, 'badly formed credentials');
            }
            var authDate = Number(pass[0]);
            var authSig = base64.decode(pass[1]);

            /* Only continue if identityKey & did exist is Users db */
            Users.findOne({identityKey : identityKey},
                function(err, dbUser) {
                    if (dbUser && userContainsDeviceId(dbUser, deviceId) && !err) { //if identityKey & did exist is Users db
                        if (dbUser.revoked == true) { //if idkey has been revoked
                            return unauthorized(res, 'revoked');
                        }
                        /* Verify date freshness */
                        var timeAuthDate = new Date(authDate);
                        var timeNow = new Date();
                        var difference = timeNow - timeAuthDate
                        if (difference < (AUTH_CHALLENGE_TIME_TO_LIVE * 1000) && difference > 0) { //if auth is fresh
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


    // api =========================================================================

    //Register prekeys
    app.post('/api/v1/key/initial', initialAuth, function(req, res) {
        /* get basic_auth fields from request */
        var user = basicAuth(req);
        if (!user) {
            return res.sendStatus(401);
        }
        var names = user.name.split(NAME_DELIMITER);
        if (names.length != 2) {
            return res.sendStatus(401);
        }
        var identityKey = names[0];
        var deviceId = names[1];

        /* Get protobuf payload */
        var payload = req.body;

        var builder = protoBuf.loadProtoFile("protobuf/keys.proto"); //appears to automaticly search from root of project
        var Protoprekeys = builder.build("protoprekeys");
        var Prekeys = Protoprekeys.Prekeys;
        var Prekey = Protoprekeys.Prekey;
        var KeyPair = Protoprekeys.KeyPair;
        var recievedPrekeys = Prekeys.decode(payload);

        ////console.log("payload: %j", payload);
        ////console.log("recievedPrekeys - decode: %j", recievedPrekeys);

        /* Create DB Entry. New user and/or new device w/ prekeys */
        Users.findOne({identityKey : identityKey},
            function(err, dbUser) {
                var prekeysArray = [];
                for (var i=0; i<recievedPrekeys.prekeys.length; i++) {
                    prekeysArray.push({
                        keyId : Number(recievedPrekeys.prekeys[i].id),
                        key : JSON.stringify(recievedPrekeys.prekeys[i])//.toBuffer()
                    });
                }
                if (!err && !dbUser) { //if identityKey DNE in DB
                    //create new document in db
                    //console.log("RECIEVEDPREKEYS (DECODED): %j", recievedPrekeys.prekeys[0]);
                    /////console.log("RECIEVEDPREKEYS (ENCODED): %j", recievedPrekeys.prekeys[1].toBuffer());
                    /////console.log("RECIEVEDPREKEYS (ENCODED)type of: ", typeof(recievedPrekeys.prekeys[1].toBuffer()));
                    ////console.log("RECIEVED PREKEYS: "+ typeof(recievedPrekeys.prekeys[1]));
                    /* create devices object */
                    var devicesObject = {numberOfDevices : 1};
                    devicesObject[deviceId] = {
                                                 deviceId : deviceId,
                                                 lastResortKey :  {
                                                                   keyId : Number(recievedPrekeys.lastResortKey.id),
                                                                   key : JSON.stringify(recievedPrekeys.lastResortKey)
                                                                  },
                                                 prekeys : prekeysArray //an array of stringified Prekey protobuf messages
                                                }
                    Users.create({
                        identityKey : identityKey,
                        revoked : false,
                        devices : devicesObject
                    }, function(err, user) {
                        if (user && !err) {
                            ////console.log("NEW USER: %j", user);
                            success(user, identityKey, deviceId, function(status) {
                                return res.sendStatus(status);
                            });
                        } else {
                            console.log("500 1");
                            console.log(err);
                            return res.sendStatus(500);
                        }
                    });
                } else { // else, error
                    console.log("500 2");
                    return res.sendStatus(500);
                }
            });
    });

    app.post('/api/v1/key/addDevice', /*<another auth scheme>,*/ function(req, res) {
        //to be implemented in the future
        return res.sendStatus(403);
    });

    //Register prekeys
    app.post('/api/v1/key/update', auth, function(req, res) {
        /* get basic_auth fields from request */
        var user = basicAuth(req);
        if (!user) {
            return res.sendStatus(401);
        }
        var names = user.name.split(NAME_DELIMITER);
        if (names.length != 2) {
            return res.sendStatus(401);
        }
        var identityKey = names[0];
        var deviceId = names[1];

        /* Get protobuf payload */
        var payload = req.body;

        var builder = protoBuf.loadProtoFile("protobuf/keys.proto"); //appears to automaticly search from root of project
        var Protoprekeys = builder.build("protoprekeys");
        var Prekeys = Protoprekeys.Prekeys;
        var Prekey = Protoprekeys.Prekey;
        var KeyPair = Protoprekeys.KeyPair;
        var recievedPrekeys = Prekeys.decode(payload);

        /* Create DB Entry. New user and/or new device w/ prekeys */
        Users.findOne({identityKey : identityKey},
            function(err, dbUser) {
                var prekeysArray = [];
                if(!err && dbUser) { //if identityKey exists
                    for (var i=0; i<recievedPrekeys.prekeys.length; i++) {
                        dbUser.devices[deviceId].prekeys.push({
                            keyId : Number(recievedPrekeys.prekeys[i].id),
                            key : JSON.stringify(recievedPrekeys.prekeys[i])//.toBuffer()
                        });
                    }

                    //add new keys to dbUser's device
                    Users.update({_id : dbUser._id}, {devices : dbUser.devices}, function(err) {
                    //dbUser.save(function(err) {
                        if (err) {
                            console.log(err);
                            return res.sendStatus(500);
                        } else {
                            success(dbUser, identityKey, deviceId, function(status) {
                                return res.sendStatus(status);
                            });
                        }
                    });
                } else { // else, error
                    return res.sendStatus(500);
                }
            });
    });

    //getting a recipients prekeys based on idkey
    app.get('/api/v1/key/', auth, function(req, res) {
        /* get basic_auth fields from request */
        var user = basicAuth(req);
        if (!user) {
            return res.sendStatus(401);
        }
        var names = user.name.split(NAME_DELIMITER);
        if (names.length != 2) {
            return res.sendStatus(401);
        }
        var authIdentityKey = names[0];
        var authDeviceId = names[1];

        var identityKey = req.body.identityKey;
        /* Create DB Entry. New user and/or new device w/ prekeys */
        Users.findOne({identityKey : identityKey},
            function(err, dbUser) {
                if (!err && dbUser) {
                    if (dbUser.revoked == true){ //if identityKey has been revoked
                        return send.Status(410);
                    }
                    var builder = protoBuf.loadProtoFile("protobuf/keys.proto"); //appears to automaticly search from root of project
                    var Protoprekeys = builder.build("protoprekeys");
                    var Prekeys = Protoprekeys.Prekeys;
                    var Prekey = Protoprekeys.Prekey;
                    var KeyPair = Protoprekeys.KeyPair;

                    var prekeysArray = [];
                    for (var key in dbUser.devices) {
                        if(key != 'numberOfDevices') {
                            if (dbUser.devices[key].prekeys.length > 0) { // if there is a prekey left, fetch it
                                console.log("NUMBER OF PREKEYS BEFORE SHIFT: "+dbUser.devices[key].prekeys.length);
                                var prekey = dbUser.devices[key].prekeys.shift();
                                /////console.log("PREKEY FROM MONGOOSE: %j", prekey);
                                //console.log("PREKEY.key FROM MONGOOSE: %j", JSON.parse(prekey.key));
                                console.log("NUMBER OF PREKEYS AFTER SHIFT: "+dbUser.devices[key].prekeys.length);
                                prekeysArray.push(JSON.parse(prekey.key)); //is in form of Prekey protobuf object in buffer form
                            } else { //if no prekey left, fetch last resort key
                                prekeysArray.push(JSON.parse(dbUser.devices[key].lastResortKey.key));
                            }
                        }
                    }
                    Users.update({_id : dbUser._id}, {devices : dbUser.devices}, function(err) {
                    //dbUser.save(function(err) {
                        if (err) {
                            return res.sendStatus(500);
                        } else {
                            /////console.log("PREKEYS AFTER DECODE: %j", prekeysArray);
                            //var protoPrekeys = new Prekeys(null, prekeysArray);
                            //protoPrekeys['prekeys'][0] = prekeysArray[0];
                            //console.log("NEW CONSTRUCTION RESULT: %j", protoPrekeys);
                            var protoPrekeys = pbhelper.constructKeysProtobuf(null, prekeysArray);
                            console.log("PROTOPREKEYS: %j", protoPrekeys.prekeys[0]);

                            res.set('Content-Type', 'application/octet-stream');
                            success(null, authIdentityKey, authDeviceId, function(status) {
                                return res.status(status).send(protoPrekeys.toBuffer()).end();
                            });
                        }
                    });

                } else if (!dbUser && !err) { //if identityKey not in db
                    return res.sendStatus(404);
                } else { // if error
                    return res.sendStatus(500);
                }
            }
        );
    });

    //submitting a message
        //**consider implementing checks for revoked recipient, stale device recipient, and mismatched idkey/did recipients
    app.post('/api/v1/message/', auth, function(req, res) {
        /* get basic_auth fields from request */
        var user = basicAuth(req);
        if (!user) {
            return res.sendStatus(401);
        }
        var names = user.name.split(NAME_DELIMITER);
        if (names.length != 2) {
            return res.sendStatus(401);
        }
        var identityKey = names[0];
        var deviceId = names[1];

        for (var i=0; i<req.body.messages.length; i++) {
            var messageBody = req.body.messages[i].body; //in form of protobuf
            for (var j=0; j<req.body.messages[i].headers.length; j++) {
                var recipient = req.body.messages[i].headers[j].recipient.split(NAME_DELIMITER);
                var recipientIdKey = recipient[0];
                var recipientDid = recipient[1];
                var messageHeader = req.body.messages[i].headers[j].messageHeader;

                MessageQueue.create({
                    recipientIdKey : recipientIdKey,
                    recipientDid : recipientDid,
                    messageHeader : messageHeader,
                    messageBody : messageBody
                }, function(err, message) {
                    if (err || !message) { //if error putting messsage in queue
                        console.log(err);
                        return res.sendStatus(500);
                    } else if (i >= req.body.messages.length) {
                        //console.log("STATUS : "+success(null, identityKey, deviceId));
                        success(null, identityKey, deviceId, function(status) {
                            return res.sendStatus(status);
                        });
                    }
                });
            }
        }
    });

    app.delete('/api/v1/key/', auth, function(req, res) {
        /* get basic_auth fields from request */
        var user = basicAuth(req);
        if (!user) {
            return unauthorized(res, 'badly formed credentials');
        }
        var names = user.name.split(NAME_DELIMITER);
        if (names.length != 2) {
            return unauthorized(res, 'badly formed credentials');
        }
        var identityKey = names[0];
        var deviceId = names[1];

        Users.findOne({identityKey : identityKey}, function(err, dbUser) {
            if (err || !dbUser) { //if error or user not found
                return res.sendStatus(500);
            } else {
                delete dbUser.devices[deviceId];
                dbUser.devices.numberOfDevices -= 1;
                if (dbUser.devices.numberOfDevices < 1) {
                    dbUser.revoked = true;
                }
                dbUser.save(function(err) {
                    if (err) {
                        console.log(err);
                        return res.sendStatus(500);
                    } else {
                        return res.sendStatus(200);
                    }
                });
            }
        });
    });

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

    app.get('/test/axolotl/:numPrekeys', function(req, res) {
        var result;
        axol.generateIdentityKeyPair().then(function(idKeyPair) { // Generate our identity key
            axol.generateRegistrationId().then(function(registrationId) { // Generate our registration id
                axol.generateLastResortPreKey().then(function(lastResortKey) { // Generate our last restore pre-key to send to the server
                    axol.generatePreKeys(0, req.params.numPrekeys-1).then(function(preKeys) { // Generate the first set of our pre-keys to send to the server

                        // Generate auth user names
                        var basicAuthUserName = base64.encode(idKeyPair.public);
                        basicAuthUserName = basicAuthUserName.concat(NAME_DELIMITER);
                        var badDidUserName = basicAuthUserName.concat('123456');
                        basicAuthUserName = basicAuthUserName.concat(registrationId);

                        // Generate valid auth password
                        var now = new Date();
                        var basicAuthPassword = String(now.getTime());
                        basicAuthPassword = basicAuthPassword.concat(NAME_DELIMITER);
                        var signature = base64.encode(crypto.sign(idKeyPair.private, base64.decode(String(now.getTime()))));
                        basicAuthPassword = basicAuthPassword.concat(signature);

                        // Generate <timestamp>|<sign(timestamp)> from future
                        var future = (now.getTime() + (2*AUTH_CHALLENGE_TIME_TO_LIVE*1000));
                        var futurePassword = String(future);
                        futurePassword = futurePassword.concat(NAME_DELIMITER);
                        var futureSignature = base64.encode(crypto.sign(idKeyPair.private, base64.decode(String(future))));
                        futurePassword = futurePassword.concat(futureSignature);

                        // Generate bad password <valid timestamp>|<bad signature>
                        var badSignaturePassword = String(now.getTime());
                        badSignaturePassword = badSignaturePassword.concat(NAME_DELIMITER);
                        badSignaturePassword = badSignaturePassword.concat(futureSignature);

                        // Generate <timestamp>|<sign(timestamp)> from past
                        var past = now.getTime() - (AUTH_CHALLENGE_TIME_TO_LIVE*1000);
                        var pastPassword = String(past);
                        pastPassword = pastPassword.concat(NAME_DELIMITER);
                        signature = base64.encode(crypto.sign(idKeyPair.private, base64.decode(String(past))));
                        pastPassword = pastPassword.concat(signature);

                        console.log("Basic_Auth User Name: " + basicAuthUserName);
                        console.log("Basic_Auth Password: "+ basicAuthPassword);
                        console.log("Future Password    : " + futurePassword);
                        console.log("Bad Sig Password   : "+ badSignaturePassword);

                        result = {
                            basicAuthUserName : basicAuthUserName,
                            badDidUserName : badDidUserName,
                            basicAuthPassword : basicAuthPassword,
                            badSignaturePassword : badSignaturePassword,
                            futurePassword : futurePassword,
                            pastPassword : pastPassword,
                            identityKeyPair : idKeyPair,
                            reqistrationId : registrationId,
                            lastResortKey : lastResortKey,
                            preKeys: preKeys
                        };

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

}; //end module.exports

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

var success = function(user, idKey, did, callback) {
    console.log("SUCCESS 0");

    if (user && did) {
        console.log("SUCCESS 2.0");
        if (user.devices[did].prekeys.length > 0) {
            console.log("SUCCESS 2.1");
            return callback(200);
        } else {
            console.log("SUCCESS 2.2");
            return callback(205);
        }

    } else if (!user && idKey && did) {
        console.log("SUCCESS 1.0");
        Users.findOne({identityKey : idKey}, function(err, dbUser) {
            console.log("SUCCESS 1.1");
            if (err || !dbUser) { //if error or user not found
                console.log("SUCCESS 1.11");
                return callback(500);
            } else {
                console.log("SUCCESS 1.2");
                if (dbUser.devices[did].prekeys.length > 0) {
                    console.log("SUCCESS 1.3");
                    return callback(200);
                } else {
                    console.log("SUCCESS 1.4");
                    return callback(205);
                }
            }
        });
    }
    console.log("SUCCESS 3");
};

/* Helper function to determin if deviceId exists under IdentityKey */
var userContainsDeviceId = function(user, did) {
    if (user) {
        if (user.devices[did]) {
            return true;
        }
    }
    return false;
};
