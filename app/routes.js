// app/routes.js

/* Constants */
var constants = require('./constants');

/* load required modules */
var basicAuth = require('basic-auth');
var crypto = require("axolotl-crypto"); // docs: https://github.com/joebandenburg/libaxolotl-javascript/blob/master/doc/crypto.md
var base64 = require('base64-arraybuffer');

/* load authorization functions */
var auth = require('./routeAuthorization');

/* load db models */
var Users = require('./models/user');
var MessageQueue = require('./models/messageQueue');

/* load helper functions */
var helper = require('./helperFunctions');

//expose the routs to app with module.exports
module.exports = function(app) {

    // api =========================================================================

    //Register prekeys
    app.post('/api/v1/key/initial', auth.initialAuth, function(req, res) {
        /* get basic_auth fields from request */
        var user = basicAuth(req);
        if (!user) {
            return res.sendStatus(401);
        }
        var names = user.name.split(constants.NAME_DELIMITER);
        if (names.length != 2) {
            return res.sendStatus(401);
        }
        var identityKey = names[0];
        var deviceId = names[1];

        /* Get protobuf payload */
        var payload = req.body;
        //check composition of payload & return 415

        /* Create DB Entry. New user and/or new device w/ prekeys */
        Users.findOne({identityKey : identityKey},
            function(err, dbUser) {
                if (!err && !dbUser) { //if identityKey DNE in DB
                    /* create devices object */
                    var devicesObject = {numberOfDevices : 1};
                    devicesObject[deviceId] = {
                                                 deviceId : deviceId,
                                                 lastResortKey :  payload.lastResortKey,
                                                 prekeys : payload.prekeys //an array of prekeys with the keys base64 encoded
                                              }
                    /* create new entry in DB */
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
    app.post('/api/v1/key/update', auth.standardAuth, function(req, res) {
        /* get basic_auth fields from request */
        var user = basicAuth(req);
        if (!user) {
            return res.sendStatus(401);
        }
        var names = user.name.split(constants.NAME_DELIMITER);
        if (names.length != 2) {
            return res.sendStatus(401);
        }
        var identityKey = names[0];
        var deviceId = names[1];

        /* Get protobuf payload */
        var payload = req.body;
        //check composition of payload & return 415

        /* Query DB for user to be updated */
        Users.findOne({identityKey : identityKey},
            function(err, dbUser) {
                if(!err && dbUser) { //if identityKey exists
                    /* add prekeys to device */
                    for (var i=0; i<payload.prekeys.length; i++) {
                        dbUser.devices[deviceId].prekeys.push(payload.prekeys[i]);
                    }
                    /* update device's lastResortKey */
                    if (payload.lastResortKey) {
                        dbUser.devices[deviceId].lastResortKey = payload.lastResortKey;
                    }

                    //save new keys to dbUser's device
                    Users.update({_id : dbUser._id}, {devices : dbUser.devices}, function(err) {
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
    app.get('/api/v1/key/', auth.standardAuth, function(req, res) {
        /* get basic_auth fields from request */
        var user = basicAuth(req);
        if (!user) {
            return res.sendStatus(401);
        }
        var names = user.name.split(constants.NAME_DELIMITER);
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

                    var responseBody = new Object();
                    for (var key in dbUser.devices) {
                        if(key != 'numberOfDevices') {
                            if (dbUser.devices[key].prekeys.length > 0) { // if there is a prekey left, fetch it
                                //console.log("NUMBER OF PREKEYS BEFORE SHIFT: "+dbUser.devices[key].prekeys.length);
                                var prekey = dbUser.devices[key].prekeys.shift();
                                responseBody[key] = prekey;
                            } else { //if no prekey left, fetch last resort key
                                responseBody[key] = dbUser.devices[key].lastResortKey;
                            }
                        }
                    }
                    Users.update({_id : dbUser._id}, {devices : dbUser.devices}, function(err) {
                    //dbUser.save(function(err) {
                        if (err) {
                            return res.sendStatus(500);
                        } else {
                            res.set('Content-Type', 'application/json');
                            success(null, authIdentityKey, authDeviceId, function(status) {
                                return res.status(status).send(responseBody).end();
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
    app.post('/api/v1/message/', auth.standardAuth, function(req, res) {
        /* get basic_auth fields from request */
        var user = basicAuth(req);
        if (!user) {
            return res.sendStatus(401);
        }
        var names = user.name.split(constants.NAME_DELIMITER);
        if (names.length != 2) {
            return res.sendStatus(401);
        }
        var identityKey = names[0];
        var deviceId = names[1];

        var responseBody = {
            messagesQueued : 0,
            keysNotFound : [],
            revokedKeys : [],
            missingDevices : []
        };

        /* calculate number of iterations necessary */
        var numIterationsCompleted = 0;
        var numIterationsRequired = 0;
        for (var i=0; i<req.body.messages.length; i++) {
            numIterationsRequired += req.body.messages[i].headers.length;
        }

        /* iterate through messages */
        for (var i=0; i<req.body.messages.length; i++) {
            var messageBody = req.body.messages[i].body;
            /* iterate through headers (recipients) for each message */
            for (var j=0; j<req.body.messages[i].headers.length; j++) {
                var recipient = req.body.messages[i].headers[j].recipient.split(constants.NAME_DELIMITER);
                var messageHeader = req.body.messages[i].headers[j].messageHeader;
                var recipientIdKey = recipient[0];
                var recipientDid = recipient[1];
                /* check if valid recipientIdKey */
                Users.findOne({identityKey : recipientIdKey}, function(err, recipientUser) {
                    if (err) { //if error
                        console.log(err);
                        return res.sendStatus(500);
                    } else if (!recipientUser) { //if recipientIdKey DNE in DB
                        responseBody.keysNotFound.push(req.body.messages[i].headers[j].recipient);
                        if(++numIterationsCompleted == numIterationsRequired) {
                            success(null, identityKey, deviceId, function(status) {
                                return res.status(status).send(messageBody);
                            });
                        }
                    } else if (recipientUser.revoked) { //if recipientIdKey is revoked
                        responseBody.revokedKeys.push(req.body.messages[i].headers[j].recipient);
                        if(++numIterationsCompleted == numIterationsRequired) {
                            success(null, identityKey, deviceId, function(status) {
                                return res.status(status).send(messageBody);
                            });
                        }
                    } else if (!helper.userContainsDeviceId(recipientUser, deviceId)) { //if device does not belong to identityKey
                        responseBody.missingDevices.push(req.body.messages[i].headers[j].recipient);
                        if(++numIterationsCompleted == numIterationsRequired) {
                            success(null, identityKey, deviceId, function(status) {
                                return res.status(status).send(messageBody);
                            });
                        }
                    } else {
                        /* else, queue message */
                        MessageQueue.create({
                            recipientIdKey : recipientIdKey,
                            recipientDid : recipientDid,
                            messageHeader : messageHeader,
                            messageBody : messageBody
                        }, function(err, message) {
                            if (err || !message) { //if error putting messsage in queue
                                console.log(err);
                                return res.sendStatus(500);
                            } else {
                                responseBody.messagesQueued += 1;
                                /* push message to recipient */
                                var pushMessageBody = {
                                    id: message._id,
                                    header: message.messageHeader,
                                    body: message.messageBody
                                }
                                var recipientUn = message.recipientIdKey+constants.NAME_DELIMITER+recipientDid;
                                require('../push/socket').emitMessage(recipientUn, pushMessageBody);
                                if(++numIterationsCompleted == numIterationsRequired) {
                                    success(null, identityKey, deviceId, function(status) {
                                        return res.status(status).send(messageBody);
                                    });
                                }
                            }
                        });//end of enqueue message
                    }
                });//end of findone recipient user
            } //end of inner for loop
        } //end of outer for loop
    });

    //delete a device
    app.delete('/api/v1/key/', auth.standardAuth, function(req, res) {
        /* get basic_auth fields from request */
        var user = basicAuth(req);
        if (!user) {
            return unauthorized(res, 'badly formed credentials');
        }
        var names = user.name.split(constants.NAME_DELIMITER);
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
                Users.update({_id : dbUser._id}, {devices : dbUser.devices, revoked : dbUser.revoked}, function(err) {
                //dbUser.save(function(err) {
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


    // application -------------------------------------------------------------


    app.get('/', function (req, res) {
        res.send('Hello World!');
    });

}; //end module.exports


/* helper functions */
/* helper function to determine whether to send 200 or 205 on success */
var success = function(user, idKey, did, callback) {
    if (user && did) {
        if (user.devices[did].prekeys.length > 0) {
            return callback(200);
        } else {
            return callback(205);
        }

    } else if (!user && idKey && did) {
        Users.findOne({identityKey : idKey}, function(err, dbUser) {
            if (err || !dbUser) { //if error or user not found
                return callback(500);
            } else {
                if (dbUser.devices[did].prekeys.length > 0) {
                    return callback(200);
                } else {
                    return callback(205);
                }
            }
        });
    }
};
