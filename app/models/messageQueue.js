// app/models/messageQueue.js

var mongoose = require('mongoose');

var messageQueueSchema = mongoose.Schema({
    recipientIdKey : String,
    recipientDid : String,
    messageHeader : String,
    messageBody : String,
});

module.exports = mongoose.model('MessageQueue', messageQueueSchema);
