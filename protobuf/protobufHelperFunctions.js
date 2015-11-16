var protoBuf = require('protobufjs');

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

var constructKeysProtobuf = function (lastResortKey, prekeys){
    var builder = protoBuf.loadProtoFile("protobuf/keys.proto"); //appears to automaticly search from root of project
    var Protoprekeys = builder.build("protoprekeys");
    var Prekeys = Protoprekeys.Prekeys;
    var Prekey = Protoprekeys.Prekey;
    var Keypair = Protoprekeys.Keypair;

    var protoLastResortKey = new Prekey(Number(lastResortKey.id), new Keypair(ab2str(lastResortKey.keyPair.public), ab2str(lastResortKey.keyPair.private)));

    var protoPrekeys = new Prekeys(protoLastResortKey);
    for (var i=0; i<prekeys.length; i++) {
        protoPrekeys['prekeys'][i] = new Prekey(prekeys[i].id, new Keypair(ab2str(prekeys[i].keyPair.public), ab2str(prekeys[i].keyPair.private)));
    }
    return protoPrekeys;
};
module.exports.constructKeysProtobuf = constructKeysProtobuf;
