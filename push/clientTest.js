var ioClient = require('socket.io-client');

var socket = ioClient.connect("http://localhost:8080");

socket.on('connect', function (data) {
    socket.emit('storeCustomPushId', { customId:"identityKey|deviceId" });
});

socket.on('message', function(messageData) {
    // vvv do something with messageData here vvv
    console.log(messageData);

    // ^^^ do something with messageData here ^^^
    //confirm reception of message
    socket.emit('recieved', {messageId: messageData.id});
});
