// app/models/messageQueue.js

var mongoose = require('mongoose');

var messageQueueSchema = mongoose.Schema({
    recipientIdKey : String,
    recipientDid : String,
    messsageHeader : Buffer,
    messageBody : Buffer,
});

module.exports = mongoose.model('MessageQueue', messageQueueSchema);
