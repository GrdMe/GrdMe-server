// app/models/messageQueue.js

var mongoose = require('mongoose');

var messageQueueSchema = mongoose.Schema({
    recipientIdKey : String,
    recipientDid : String,
    messageHeader : Object,
    messageBody : Object,
});

module.exports = mongoose.model('MessageQueue', messageQueueSchema);
