// app/models/user.js

var mongoose = require('mongoose');

var userSchema = mongoose.Schema({
    identityKey: String, //base64 encoded pubkey
    revoked: Boolean,
    devices: [{deviceId: Number, //int
               lastResortKey: {keyId: Number, //int
                               key: Object//binary blob?
                           },
                prekeys: [{keyId: Number,
                           key: Object
                    }]
             }]
});



module.exports = mongoose.model('Users', userSchema);
