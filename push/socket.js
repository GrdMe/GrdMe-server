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


        socket.on('storeCustomPushId', function(data) {
            //create mapping in clients object
            clients[data.customId] = socket.id;
            console.log("custom Id mapped");
            //get queued messages from DB
            var names = data.customId.split(NAME_DELIMITER);
            var identityKey = names[0];
            var deviceId = names[1];

            MessageQueue.find({recipientIdKey : identityKey, recipientDid : deviceId}, function(err, docs){
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
