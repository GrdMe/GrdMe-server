var socketio = require('socket.io');
var MessageQueue = require('../app/models/messageQueue');

var NAME_DELIMITER = '|';

//keep track of connected clients
//object keyed by identityKey|deviceId
//session specific mapping of socket.id to identityKey|deviceId
var clients = new Object();
exports.clients = clients;

module.exports.listen = function(server) {
    var io = socketio.listen(server);

    io.sockets.on('connection', function(socket) {
        //console.log("====Socket Connected!====");
        //console.log(socket.id);
        //socket.emit('message', { hello: 'world' });


        socket.on('authentication', function(data) {
            if (authorize(data.username, data.password)) { //if socket authorized
                //create mapping in clients object
                clients[data.username] = socket.id;
                console.log("custom Id mapped");
                //get queued messages from DB
                var names = data.username.split(NAME_DELIMITER);
                var identityKey = names[0];
                var deviceId = names[1];

                MessageQueue.find({recipientIdKey : identityKey,
                                   recipientDid : deviceId}, function(err, docs){
                    if (err) console.log(err);
                    for (doc in docs) {
                        //construct message
                        var message = new Object();
                        message.id = doc._id;
                        message.header = doc.messageHeader;
                        message.body = doc.messageBody;
                        //push message
                        if(clients[data.customId]) { //if client still connected
                            socket.emit('message', message);
                        }
                    }
                });
            } else { //else, socket not authorized

            }
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

var authorize = function(username, password) {
    /* parse credentials */
    var names = username.split(NAME_DELIMITER);
    var identityKey = names[0];
    var deviceId = names[1];
    var pass = password.split(NAME_DELIMITER);
    var authDate = pass[0];
    var authSig = pass[1];

    /* verify presence of credentials */
    if(!username || !password || !names || names.length != 2 || !identityKey || !deviceId || !pass || pass.length != 2 || !authDate || !authSig) {
        console.log('Socket Auth Failed: malformed credentials');
        return false;
    }

    /* varify credentials */
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
