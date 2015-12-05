var base64 = require('base64-arraybuffer');

var prekeysObjectConstructor = function(lastResortKey, prekeys) {
    var obj = {
        lastResortKey : base64EncodePrekey(lastResortKey),
        prekeys : []
    };

    for (var i=0; i<prekeys.length; i++) {
        obj.prekeys.push(base64EncodePrekey(prekeys[i]));
    }
    return obj;
};
module.exports.prekeysObjectConstructor = prekeysObjectConstructor;

var base64EncodePrekey = function(prekey) {
    prekey.keyPair.public = base64.encode(prekey.keyPair.public);
    prekey.keyPair.private = base64.encode(prekey.keyPair.private);
    return prekey;
};
module.exports.base64EncodePrekey = base64EncodePrekey;

var base64DecodePrekey = function(prekey) {
    prekey.keyPair.public = base64.decode(prekey.keyPair.public);
    prekey.keyPair.private = base64.decode(prekey.keyPair.private);
    return prekey;
};
module.exports.base64DecodePrekey = base64DecodePrekey;

var ab2str = function(buf) {
  return String.fromCharCode.apply(null, new Int8Array(buf));
};
module.exports.ab2str = ab2str;

var str2ab = function(str) {
  var buf = new ArrayBuffer(str.length*2); // 2 bytes for each char
  var bufView = new Int8Array(buf);
  for (var i=0, strLen=str.length; i<strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
};
module.exports.str2ab = str2ab;

/* Helper function to determin if deviceId exists under IdentityKey */
var userContainsDeviceId = function(user, did) {
    if (user) {
        if (user.devices[did]) {
            return true;
        }
    }
    return false;
};
module.exports.userContainsDeviceId = userContainsDeviceId;
