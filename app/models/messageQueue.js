// app/models/messageQueue.js

var mongoose = require('mongoose');

var messageQueueSchema = mongoose.Schema({
    recipientIdKey : String,
    recipientDid : String,
    messsageHeader : Object,
    messageBody : Object,
});

module.exports = mongoose.model('MessageQueue', messageQueueSchema);
