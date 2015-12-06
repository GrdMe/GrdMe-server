// app/models/user.js

var mongoose = require('mongoose');

var userSchema = mongoose.Schema({
    identityKey: String, //base64 encoded pubkey
    revoked: Boolean,
    devices: Object //device object modeled below
});

/* ** devices object **
{
    numberOfDevices: Number,

    <deviceId> :    {deviceId: Number,
                     lastResortKey: {keyId: Number,
                                     key: Object
                                    },
                     prekeys: [{keyId: Number,
                                key: Object
                              }]
                    }
}
*/
module.exports = mongoose.model('Users', userSchema);
