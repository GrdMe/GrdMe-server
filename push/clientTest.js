var ioClient = require('socket.io-client');

// 1: vvv change url to be appropriate vvv
var socket = ioClient.connect("http://localhost:8080");

socket.on('connect', function (data) {
    // 2: vvv Change value of username & password to be appropriate for specific client
    socket.emit('authentication', { username:"identityKey|deviceId", password:"time|sig(time)" });
});

socket.on('message', function(messageData) {
    // 3: vvv do something with messageData here vvv
    console.log(messageData);
    var messageHeader = messageData.header; //same header protobuff that was sent to server
    var messageBody = messageData.body;     //same body protobuff that was sent to server

    // ^^^ do something with messageData here ^^^

    //confirm reception of message
    socket.emit('recieved', {messageId: messageData.id});
});
