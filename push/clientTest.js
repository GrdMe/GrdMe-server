var ioClient = require('socket.io-client');

// 1: vvv change url to be appropriate vvv
var socket = ioClient.connect("http://localhost:8080");

socket.on('connect', function (data) {
    // 2: vvv Change value of username & password to be appropriate for specific client
    socket.emit('authentication', { username:"identityKey|deviceId", password:"time|sig(time)" });
});

socket.on('not authorized', function(data) {
    switch(data.message){
        case 'badly formed credentials':
            //deal with it
            break;
        case 'revoked':
            //deal with it
            break;
        case 'signature':
            //deal with it
            break;
        case 'not registered':
            //deal with it
            break;
        case 'time':
            var serverTime = data.serverTime; //int. unix time
            //deal with it
            break;
    }
});

socket.on('authorized', function(data) {
    //lets you know that socket.emit('authentication'... was successful
});

socket.on('message', function(messageData) {
    //confirm reception of message
    socket.emit('recieved', {messageId: messageData.id});

    var messageHeader = messageData.header; //same header that was sent to server
    var messageBody = messageData.body;     //same body that was sent to server

    // do something with messageData here
    // ...
});
