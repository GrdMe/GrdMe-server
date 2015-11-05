// app/models/user.js

var mongoose = require('mongoose');

var userSchema = mongoose.Schema({
    identityKey: String,
    devices: [{deviceId: String,
               lastResortKey: {keyId: String,
                               publicKey: String,
                               identityKey: String,
                               deviceId: String},
                keys: [{keyId: String,
                        publicKey: String,
                        identityKey: String,
                        deviceId: String}]
             }]
});



module.exports = mongoose.model('Users', userSchema);
