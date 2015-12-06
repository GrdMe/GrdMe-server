var axolotl = require("axolotl");
var crypto = require("axolotl-crypto");
var store = {
    getLocalIdentityKeyPair : function() {},
    getLocalRegistrationId : function() {},
    getLocalSignedPreKeyPair : function(signedPreKeyId) {},
    getLocalPreKeyPair: function(preKeyId) {}
 };
var axol = axolotl(store);

var base64 = require('base64-arraybuffer');
var helper = require('../app/helperFunctions')

/* Constants */
var constants = require('../app/constants');

module.exports.generate = function(numPrekeys, callback) {
    var result;
    axol.generateIdentityKeyPair().then(function(idKeyPair) { // Generate our identity key
        axol.generateRegistrationId().then(function(registrationId) { // Generate our registration id
            axol.generateLastResortPreKey().then(function(lastResortKey) { // Generate our last restore pre-key to send to the server
                axol.generatePreKeys(0, numPrekeys-1).then(function(preKeys) { // Generate the first set of our pre-keys to send to the server

                    // Generate valid auth username & un w/ bad deviceId
                    var basicAuthUserName = base64.encode(idKeyPair.public);
                    basicAuthUserName = basicAuthUserName.concat(constants.NAME_DELIMITER);
                    var badDidUserName = basicAuthUserName.concat('123456');
                    basicAuthUserName = basicAuthUserName.concat(registrationId);

                    // Generate valid auth password
                    var now = new Date();
                    var basicAuthPassword = String(now.getTime() + (constants.AUTH_CHALLENGE_TIME_TO_LIVE*1000) - 1);
                    var signature = base64.encode(crypto.sign(idKeyPair.private, helper.str2ab(basicAuthPassword)));
                    basicAuthPassword = basicAuthPassword.concat(constants.NAME_DELIMITER);
                    basicAuthPassword = basicAuthPassword.concat(signature);

                    // Generate <timestamp>|<sign(timestamp)> from future
                    var future = (now.getTime() + (2*constants.AUTH_CHALLENGE_TIME_TO_LIVE*1000));
                    var futurePassword = String(future);
                    futurePassword = futurePassword.concat(constants.NAME_DELIMITER);
                    var futureSignature = base64.encode(crypto.sign(idKeyPair.private, helper.str2ab(String(future))));
                    futurePassword = futurePassword.concat(futureSignature);

                    // Generate bad password <valid timestamp>|<bad signature>
                    var badSignaturePassword = String(now.getTime());
                    badSignaturePassword = badSignaturePassword.concat(constants.NAME_DELIMITER);
                    badSignaturePassword = badSignaturePassword.concat(futureSignature);

                    // Generate <timestamp>|<sign(timestamp)> from past
                    var past = now.getTime() - (constants.AUTH_CHALLENGE_TIME_TO_LIVE*1000);
                    var pastPassword = String(past);
                    pastPassword = pastPassword.concat(constants.NAME_DELIMITER);
                    signature = base64.encode(crypto.sign(idKeyPair.private, helper.str2ab(String(past))));
                    pastPassword = pastPassword.concat(signature);

                    //construct response object
                    result = {
                        basicAuthUserName : basicAuthUserName,
                        badDidUserName : badDidUserName,
                        basicAuthPassword : basicAuthPassword,
                        badSignaturePassword : badSignaturePassword,
                        futurePassword : futurePassword,
                        pastPassword : pastPassword,
                        identityKeyPair : idKeyPair,
                        reqistrationId : registrationId,
                        lastResortKey : lastResortKey,
                        preKeys: preKeys
                    };

                    callback(result);
                    return;
                });
            });
        });
    });

}
