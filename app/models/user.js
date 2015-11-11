// app/models/user.js

var mongoose = require('mongoose');

var userSchema = mongoose.Schema({
    identityKey: String, //base64 encoded pubkey
    devices: [{deviceId: Number, //int
               lastResortKey: {keyId: Number, //int
                               key: Buffer //binary blob?
                           },
                prekeys: [{keyId: Number,
                           key: Buffer
                    }]
             }]
});



module.exports = mongoose.model('Users', userSchema);
