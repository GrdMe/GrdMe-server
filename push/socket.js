var socketio     = require('socket.io');
var base64       = require('base64-arraybuffer');
var crypto       = require("axolotl-crypto");
var MessageQueue = require('../app/models/messageQueue');
var Users        = require('../app/models/user');

/* constants */
var constants = require('../app/constants');

/* helper functions */
var helper = require('../app/helperFunctions');

//keep track of connected clients
//object keyed by identityKey|deviceId
//session specific mapping of socket.id to identityKey|deviceId
var clients = new Object();
exports.clients = clients;

var io;

module.exports.emitMessage = function(userName, message) {
    var socketId = clients[userName];
    if(socketId) {
        io.to(socketId).emit('message', message);
    }

}

module.exports.listen = function(server) {
    io = socketio.listen(server);

    io.sockets.on('connection', function(socket) {

        socket.on('authentication', function(data) {
            authorize(data.username, data.password, function(errObject)  { //if socket authorized
                if(errObject) {
                    socket.emit('not authorized', errObject);
                } else {
                    socket.emit('authorized', null);
                    //create mapping in clients object
                    clients[data.username] = socket.id;
                    //get queued messages from DB
                    var names = data.username.split(constants.NAME_DELIMITER);
                    var identityKey = names[0];
                    var deviceId = names[1];

                    MessageQueue.find({recipientIdKey : identityKey,
                                       recipientDid : deviceId}, function(err, docs){
                        if (err) console.log(err);
                        for (var i=0; i<docs.length; i++) {
                            //construct message
                            var message = {
                                id : docs[i]._id,
                                header : docs[i].messageHeader,
                                body : docs[i].messageBody
                            };
                            //push message
                            socket.emit('message', message);
                        }
                    });
                }
            });
        });

        socket.on('recieved', function (data) {
            MessageQueue.remove({_id : data.messageId}, function(err){
                if (err) console.log(err);
            });
        });

        socket.on('disconnect', function (data) {
            for (var key in clients) {
                if (clients.key == socket.id) {
                    delete clients[key];
                    break;
                }
            }
        });
    });
}

var authorize = function(username, password, callback) {
    /* parse credentials */
    var names       = username.split(constants.NAME_DELIMITER);
    var identityKey = names[0];
    var deviceId    = names[1];
    var pass        = password.split(constants.NAME_DELIMITER);
    var authDate    = Number(pass[0]);
    var authSig     = pass[1];

    /* verify presence of credentials */
    if(!username || !password || !names || names.length != 2 || !identityKey || !deviceId || !pass || pass.length != 2 || !authDate || !authSig) {
        console.log('Socket Auth Failed: malformed credentials');
        return callback({message:'badly formed credentials'});
    }

    /* varify credentials */
    Users.findOne({identityKey : identityKey},
        function(err, dbUser) {
            if (dbUser && userContainsDeviceId(dbUser, deviceId) && !err) {
                if (dbUser.revoked == true) { //if idkey has been revoked
                    console.log("Socket Auth Failed: - Revoked");
                    return callback({message:'revoked'});
                }
                /* Verify date freshness */
                var timeAuthDate = new Date(authDate);
                var timeNow = new Date();
                var difference = timeNow - timeAuthDate;
                var pubkey = base64.decode(identityKey);
                var dataToSign = helper.str2ab(String(authDate));
                var signature = base64.decode(authSig);
                var verified = crypto.verifySignature(pubkey,
                                                      dataToSign,
                                                      signature);
                if (difference < (constants.AUTH_CHALLENGE_TIME_TO_LIVE * 1000) && difference > (constants.AUTH_CHALLENGE_TIME_TO_LIVE * 1000 * -1)) { //if auth is fresh
                    /* Verify signature on date */
                    var verified = crypto.verifySignature(pubkey, dataToSign, signature);
                    /* return apropriate response */
                    if (verified) { // signature on date verified
                        return callback(null);
                    } else { // signature on date !verified
                        console.log("Socket Auth Failed: - Bad signature");
                        //return unauthorized(res, 'signature');
                        return callback({message:'signature'});
                    }
                } else { //else, auth is stale
                    console.log("Socket Auth Failed: - Stale date");
                    //return unauthorized(res, 'time');
                    var serverTime = String((new Date()).getTime());
                    return callback({message:'time', serverTime:serverTime});
                }
            } else { // identityKey + did combo existed in DB
                console.log("Socket Auth Failed: - idkey/did !exist in DB");
                //return unauthorized(res, 'registered');
                return callback({message:'not registered'});
            }
        });

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
