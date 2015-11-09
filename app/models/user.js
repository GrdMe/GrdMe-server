// app/models/user.js

var mongoose = require('mongoose');

var userSchema = mongoose.Schema({
    identityKey: String, //base64 encoded pubkey
    identityKeyBuffer: Buffer, //ArrayBuffer of identity Key used to verify sigs
    devices: [{deviceId: Number, //int
               lastResortKey: {keyId: Number, //int
                               publicKey: String, //binary blob?
                               identityKey: String, //base64 encoded pubkey
                               deviceId: String}, //int
                keys: [{keyId: String,
                        publicKey: String,
                        identityKey: String,
                        deviceId: String}]
             }]
});



module.exports = mongoose.model('Users', userSchema);
