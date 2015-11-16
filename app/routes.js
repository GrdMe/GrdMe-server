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
            return unauthorized(res);
        }
        var names = credentials.name.split(NAME_DELIMITER);
        if (names.length != 2 || !names[0] || !names[1]) {
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
        if(!user) {
            console.log("Authentication Failed - No basic_auth");
            return unauthorized(res);
        }
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
                            var verified = crypto.verifySignature(base64.decode(identityKey), base64.decode(String(authDate)), authSig);
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
    app.post('/api/v1/key/initial', initialAuth, function(req, res) {
        /* get basic_auth fields from request */
        console.log("IN THE REAL ROUTE");
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
        // console.log("TYPE OF HOPEBUF: "+typeof(hopebuf));
        // console.log("HB: %j", hopebuf);

        //var payload = buffertools.concat.apply(null, payload);
        //console.log("PAYLOAD1: %j", payload);
        var builder = protoBuf.loadProtoFile("protobuf/keys.proto"); //appears to automaticly search from root of project
        var Protoprekeys = builder.build("protoprekeys");
        var Prekeys = Protoprekeys.Prekeys;
        var Prekey = Protoprekeys.Prekey;
        var Keypair = Protoprekeys.Keypair;
        var recievedPrekeys = Prekeys.decode(payload);
        //recievedPrekeys.lastResortKey = Prekey.decode(recievedPrekeys.lastResortKey);
        //console.log("PAYLOAD2: %j", payload);
        //console.log("recievedPrekeys: "+recievedPrekeys);
        console.log("recievedLRK: "+typeof(recievedPrekeys.lastResortKey.keypair.public));
        //console.log("recievedLRK: %j", recievedPrekeys);

        //return res.sendStatus(200);
        // rest of code here
        /* Create DB Entry. New user and/or new device w/ prekeys */
        Users.findOne({identityKey : identityKey},
            function(err, dbUser) {
                console.log("dbUSer: "+dbUser);
                var prekeysArray = [];
                for (var i=0; i<recievedPrekeys.prekeys.length; i++) {
                    prekeysArray.push({
                        keyId : Number(recievedPrekeys.prekeys[i].id),
                        key : recievedPrekeys.prekeys[i].toBuffer()
                    });
                }
                if(!err && dbUser) { //if identityKey exists
                    //add new device & keys to dbUser

                } else if (!err && !dbUser) { //if identityKey DNE in DB
                    //create new document in db
                    Users.create({
                        identityKey : identityKey,
                        devices : [{
                            deviceId : deviceId,
                            lastresortKey :  {
                                keyId : Number(recievedPrekeys.lastResortKey.id),
                                key : recievedPrekeys.lastResortKey.toBuffer()
                            },
                            prekeys : prekeysArray
                        }]
                    }, function(err, user) {
                        if (user && !err) {
                            return res.sendStatus(200);
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

    //Register prekeys
    app.post('/api/v1/key/update', auth, function(req, res) {
        console.log("ACCESS GRANTED!!!!");
        //var lastResortKey = req.body.body.lastResortKey;
        //var prekeys = req.body.body.keys;
        return res.sendStatus(200);
    });

    //getting a recipients prekeys based on idkey and device key
    app.get('/api/v1/key/', auth, function(req, res) {
        var signature = req.body.signature;
        var bodyToVerify = req.body.body;

        var identityKey = req.body.body.identityKey;
        var deviceIdKey = req.body.body.deviceIdKey;

    });

    //submitting a message
    app.post('/api/v1/message/', auth, function(req, res) {
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

    app.get('/test/axolotl', function(req, res) {
        var result;
        axol.generateIdentityKeyPair().then(function(idKeyPair) { // Generate our identity key
            axol.generateRegistrationId().then(function(registrationId) { // Generate our registration id
                axol.generateLastResortPreKey().then(function(lastResortKey) { // Generate our last restore pre-key to send to the server
                    axol.generatePreKeys(0, 100).then(function(preKeys) { // Generate the first set of our pre-keys to send to the server

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

    app.get('/test/demo', function(req, res) {
        /* Make Request to create user & credentials */
        var result = "";
        /**********************
        **  Make request to  **
        **   /test/axolotl   **
        **********************/
        result = result.concat("GENERATING USER AND AUTH CREDENTIALS FOR DEMO:\n");
        result = result.concat(" - Expected: No auth, 200 returned, credentials & prekeys returned in body\n");
        result = result.concat("    Making request to /test/axolotl ...\n");
        var postData = {};
        var url = 'http://localhost:8080/test/axolotl';
        var options = {
          method: 'get',
          //body: postData,
          //json: true,
          url: url
        };
        request(options, function (err, response, body) {
          if (err) {
            console.log("Error in making request to /test/axolotl: ");
            console.log(err);
            return;
          }
          var headers = response.headers;
          var statusCode = response.statusCode;
          var axolotlJson = JSON.parse(body);
          var basicAuthUserName = axolotlJson.basicAuthUserName;
          var basicAuthPassword = axolotlJson.basicAuthPassword;
          result = result.concat("    Returned status: " +statusCode+ "\n");
          result = result.concat("    basic_auth username: "+basicAuthUserName +"\n");
          result = result.concat("    basic_auth password: "+basicAuthPassword +"\n");


          /**********************
          **  Make request to  **
          **  /v1/key/update  **
          **********************/
          result = result.concat("\n");
          result = result.concat("USING AUTH CREDENTIALS TO ACCESS PROTECTED PAGE\n");
          result = result.concat(" - Expected: Access DENIED, 401 returned implies user/device HAVE NOT BEEN registered\n");
          result = result.concat("    Making request to /v1/key/update ...\n");
          var postData = {};
          var url = 'http://localhost:8080/v1/key/update';
          var options = {
            method: 'post',
            //body: postData,
            //json: true,
            url: url,
            auth: {
                user: basicAuthUserName,
                password: basicAuthPassword
            }
          };
          request(options, function (err2, response2, body2) {
            if (err2) {
              console.log("Error in making request to /v1/key/initial: ");
              console.log(err2);
              return;
            }
            var headers = response2.headers;
            var statusCode = response2.statusCode;
            result = result.concat("    Returned status: " +statusCode+ "\n");

            /**********************
            **  Make request to  **
            **  /v1/key/initial  **
            **********************/
            result = result.concat("\n");
            result = result.concat("USING AUTH CREDENTIALS TO MAKE INITIAL PREKEY UPLOAD\n");
            result = result.concat(" - Expected: Access granted, 200 returned implies user/device/prekeys registered\n");
            result = result.concat("    Making request to /v1/key/initial ...\n");
            var postData = {};
            var url = 'http://localhost:8080/v1/key/initial';
            var options = {
              method: 'post',
              //body: postData,
              //json: true,
              url: url,
              auth: {
                  user: basicAuthUserName,
                  password: basicAuthPassword
              }
            };
            request(options, function (err2, response2, body2) {
              if (err2) {
                console.log("Error in making request to /v1/key/initial: ");
                console.log(err2);
                return;
              }
              var headers = response2.headers;
              var statusCode = response2.statusCode;
              //var axolotlJson = JSON.parse(body2);

              //var basicAuthUserName = axolotlJson.basicAuthUserName;
              //var basicAuthPassword = axolotlJson.basicAuthPassword;
              result = result.concat("    Returned status: " +statusCode+ "\n");
              //result = result.concat("    basic_auth username: "+basicAuthUserName +"\n");
              //result = result.concat("    basic_auth password: "+basicAuthPassword +"\n");

              /**********************
              **  Make request to  **
              **  /v1/key/initial  **
              **********************/
              result = result.concat("\n");
              result = result.concat("ATTEMPTING TO MAKE INITIAL PREKEY UPLOAD AGAIN\n");
              result = result.concat(" - Expected: Access denied, 401 returned implies idKey/did combo already exists in DB\n");
              result = result.concat("    Making request to /v1/key/initial ...\n");
              var postData = {};
              var url = 'http://localhost:8080/v1/key/initial';
              var options = {
                method: 'post',
                //body: postData,
                //json: true,
                url: url,
                auth: {
                    user: basicAuthUserName,
                    password: basicAuthPassword
                }
              };
              request(options, function (err2, response2, body2) {
                if (err2) {
                  console.log("Error in making request to /v1/key/initial: ");
                  console.log(err2);
                  return;
                }
                var headers = response2.headers;
                var statusCode = response2.statusCode;
                //var axolotlJson = JSON.parse(body2);

                //var basicAuthUserName = axolotlJson.basicAuthUserName;
                //var basicAuthPassword = axolotlJson.basicAuthPassword;
                result = result.concat("    Returned status: " +statusCode+ "\n");
                //result = result.concat("    basic_auth username: "+basicAuthUserName +"\n");
                //result = result.concat("    basic_auth password: "+basicAuthPassword +"\n");

                /**********************
                **  Make request to  **
                **  /v1/key/update  **
                **********************/
                result = result.concat("\n");
                result = result.concat("USING AUTH CREDENTIALS TO ACCESS PROTECTED PAGE AGAIN\n");
                result = result.concat(" - Expected: Access granted, 200 returned implies user/device HAVE been registered in DB\n");
                result = result.concat("    Making request to /v1/key/update ...\n");
                var postData = {};
                var url = 'http://localhost:8080/v1/key/update';
                var options = {
                  method: 'post',
                  //body: postData,
                  //json: true,
                  url: url,
                  auth: {
                      user: basicAuthUserName,
                      password: basicAuthPassword
                  }
                };
                request(options, function (err2, response2, body2) {
                  if (err2) {
                    console.log("Error in making request to /v1/key/initial: ");
                    console.log(err2);
                    return;
                  }
                  var headers = response2.headers;
                  var statusCode = response2.statusCode;
                  result = result.concat("    Returned status: " +statusCode+ "\n");


                  return res.send(result);
              });
            });
          });
        });
      });
    });



    // application -------------------------------------------------------------


    app.get('/', function (req, res) {

        res.send('Hello World!');
    });

}; //end module.exports

/* Helper Functions */
/* Helper function to deny access */
var unauthorized = function (res) {
    var timeJson = {time: (new Date()).getTime()};
    //res.set('WWW-Authenticate', 'Basic realm=Authorization Required');
    return res.status(401).json(timeJson);
};

/* Helper function to determin if deviceId exists under IdentityKey */
var userContainsDeviceId = function(user, did) {
    for (var i = 0; i < user.devices.length; i++) {
        if (user.devices[i].deviceId == did)
            return true;
    }
    return false;
};
