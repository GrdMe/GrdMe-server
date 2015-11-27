"use strict"

//process.env.NODE_ENV = 'test';

var request = require('supertest');
var server = require('../server');
var express = require('express');
var protoBuf = require('protobufjs');
var app = server.app;

var database = require('../config/database');
var mongoose = require('mongoose');
mongoose.connect(database.url);
var db = mongoose.connection;
/* load db models */
var Users = require('../app/models/user');
var MessageQueue = require('../app/models/messageQueue');

/* Load protobuf helper methods */
var pbhelper = require('../protobuf/protobufHelperFunctions')

/* Constants */
var NUMBER_PREKEYS_CREATED = 3;

describe("Routes:", function(done) {
    var authUn;
    var authUnBadDid;
    var authPass;
    var authPassBadSig;
    var authPassFuture;
    var authPassPast;
    var prekeys; //array of array buffer prekeys
    var lastResortKey; //singular array buffer prekey
    var protoPrekeys; //sungular protobuf "prekeys" message

    it('Create Credentials & Keys for testing', function(done) {
        request(app)
        .get('/test/axolotl/'+String(NUMBER_PREKEYS_CREATED))
        .end(function(err, res) {
            if (err) {
                throw err;
            }
            authUn = res.body.basicAuthUserName;
            authPass = res.body.basicAuthPassword;
            authUnBadDid = res.body.badDidUserName;
            authPassBadSig = res.body.badSignaturePassword;
            authPassFuture = res.body.futurePassword;
            authPassPast = res.body.pastPassword;
            lastResortKey = res.body.lastResortKey;
            prekeys = res.body.preKeys;
            done();
        });
    });

    it('Create Prekeys protobuf', function(done) {
        protoPrekeys = pbhelper.constructKeysProtobuf(authUn.split("|")[1], lastResortKey, prekeys);
        done();
    });


    describe('Regular Authentication, not registered:', function() {
        describe('Try Valid Credentials:', function() {
            describe('POST /api/v1/key/update/', function() {
                it('should respond with 401, not registered', function(done){
                    request(app)
                    .post('/api/v1/key/update/')
                    .auth(authUn, authPass)
                    .expect(401, 'not registered', done);
                });
            });
            describe('GET /api/v1/key/', function() {
                it('should respond with 401, not registered', function(done){
                    request(app)
                    .get('/api/v1/key/')
                    .auth(authUn, authPass)
                    .expect(401, 'not registered', done);
                });
            });
            describe('POST /api/v1/message/', function() {
                it('should respond with 401, not registered', function(done){
                    request(app)
                    .post('/api/v1/message/')
                    .auth(authUn, authPass)
                    .expect(401, 'not registered', done);
                });
            });
        });//end of 'Valid Credentials'
    });//end of decribe 'Regular Authentication, not registered'

    describe('Initial Authentication, not registered:', function() {
        describe('POST /api/v1/key/initial/', function() {
            describe('Try Invalid Credentials', function() {
                it('Bad Signature: should respond with 401, signature', function(done){
                    request(app)
                    .post('/api/v1/key/initial/')
                    .auth(authUn, authPassBadSig)
                    .set('Content-Type', 'application/octet-stream')
                    .send(protoPrekeys.toBuffer())
                    .expect(401, 'signature', done);
                });
                it('Future Password: should respond with 401, time & time in \'Server-Time\' header', function(done){
                    request(app)
                    .post('/api/v1/key/initial/')
                    .auth(authUn, authPassFuture)
                    .set('Content-Type', 'application/octet-stream')
                    .send(protoPrekeys.toBuffer())
                    .expect('Server-Time', /[0-9]*/)
                    .expect(401, 'time', done);
                });
                it('Past Password: should respond with 401, time & time in \'Server-Time\' header', function(done){
                    request(app)
                    .post('/api/v1/key/initial/')
                    .auth(authUn, authPassPast)
                    .set('Content-Type', 'application/octet-stream')
                    .send(protoPrekeys.toBuffer())
                    .expect('Server-Time', /[0-9]*/)
                    .expect(401, 'time', done);
                });
            });
            describe('Try Valid Credentials:', function() {
                it('should respond with 200', function(done){
                    /////console.log("SENDER-PRE-ENC: %j", protoPrekeys.prekeys[0]);
                    request(app)
                    .post('/api/v1/key/initial/')
                    .auth(authUn, authPass)
                    .set('Content-Type', 'application/octet-stream')
                    .send(protoPrekeys.toBuffer())
                    .expect(200, done);
                });
                it('new user should be in database', function(done){
                    Users.findOne({identityKey : authUn.split("|")[0]}, function(err, dbUser) {
                        expect(dbUser).toBeDefined();
                        done();
                    });
                });
                it('new user should be pupulated appropriately', function(done){
                    Users.findOne({identityKey : authUn.split("|")[0]}, function(err, dbUser) {
                        expect(dbUser.revoked).toBe(false);
                        expect(dbUser.devices.numberOfDevices).toEqual(1);
                        expect(dbUser.devices[authUn.split("|")[1]]).toBeDefined();
                        expect(dbUser.devices[authUn.split("|")[1]].lastResortKey).toBeDefined();
                        expect(dbUser.devices[authUn.split("|")[1]].prekeys.length).toEqual(NUMBER_PREKEYS_CREATED-1);
                        done();
                    });
                });
            });
        });//end of 'Valid Credentials'
    });//end of decribe 'Initial Authentication, not registered'

    describe('Regular Authentication, Registered', function() {
        describe('GET /api/v1/key/', function() {
            describe('Try Invalid Credentials', function() {
                it('Bad Signature: should respond with 401, signature', function(done){
                    request(app)
                    .get('/api/v1/key/')
                    .auth(authUn, authPassBadSig)
                    .set('Content-Type', 'application/json')
                    .send({identityKey : authUn.split("|")[0]})
                    //.parse(binaryParser)
                    .expect(401, 'signature', done);
                });
                it('Future Password: should respond with 401, time & time in \'Server-Time\' header', function(done){
                    request(app)
                    .get('/api/v1/key/')
                    .auth(authUn, authPassFuture)
                    .set('Content-Type', 'application/json')
                    .send({identityKey : authUn.split("|")[0]})
                    //.parse(binaryParser)
                    .expect('Server-Time', /[0-9]*/)
                    .expect(401, 'time', done);
                });
                it('Past Password: should respond with 401, time & time in \'Server-Time\' header', function(done){
                    request(app)
                    .get('/api/v1/key/')
                    .auth(authUn, authPassPast)
                    .set('Content-Type', 'application/json')
                    .send({identityKey : authUn.split("|")[0]})
                    //.parse(binaryParser)
                    .expect('Server-Time', /[0-9]*/)
                    .expect(401, 'time', done);
                });
            });//end of 'Try Invalid Credentials'
            describe('Try Valid Credentials', function() {
                it('should respond with 200 & list of matching prekeys', function(done){
                    request(app)
                    .get('/api/v1/key/')
                    .auth(authUn, authPass)
                    .set('Content-Type', 'application/json')
                    .send({identityKey : authUn.split("|")[0]})
                    .parse(binaryParser)
                    //.expect(200, done);
                    .end(function(err, res) {
                        if(err) {
                            throw err;
                        }
                        expect(res.status).toEqual(200);
                        //get protobuf builder
                        var builder = protoBuf.loadProtoFile("protobuf/keys.proto");
                        var Protoprekeys = builder.build("protoprekeys");
                        var Prekeys = Protoprekeys.Prekeys;
                        var Prekey = Protoprekeys.Prekey;
                        var KeyPair = Protoprekeys.KeyPair;
                        //expect deviceId to match
                        expect(Prekeys.decode(res.body).prekeys[0].deviceId).toEqual(protoPrekeys.prekeys[0].deviceId);
                        //expect key id to match
                        expect(Prekeys.decode(res.body).prekeys[0].id).toEqual(protoPrekeys.prekeys[0].id);
                        var recievedPub = Prekeys.decode(res.body).prekeys[0].keyPair.public;
                        var expectedPub = protoPrekeys.prekeys[0].keyPair.public;
                        //expect public key to match
                        expect(pbhelper.str2ab(recievedPub)).toEqual(pbhelper.str2ab(expectedPub));
                        done();
                    });
                });
            });//end of 'Try Valid Credentials'
            describe ('Consume all prekeys', function() {
                it('should respond with 205', function(done) {
                    request(app)
                    .get('/api/v1/key/')
                    .auth(authUn, authPass)
                    .set('Content-Type', 'application/json')
                    .send({identityKey : authUn.split("|")[0]})
                    .parse(binaryParser)
                    .end(function(err, res) {
                        if (err) {
                            throw err;
                        }
                        expect(res.status).toEqual(205);
                        done();
                    });
                });
                it('device should have no prekeys', function(done){
                    Users.findOne({identityKey : authUn.split("|")[0]}, function(err, dbUser) {
                        expect(dbUser.devices[authUn.split("|")[1]].prekeys.length).toEqual(0);
                        done();
                    });
                });
                it('should respond with 205 & lastResortKey', function(done) {
                    request(app)
                    .get('/api/v1/key/')
                    .auth(authUn, authPass)
                    .set('Content-Type', 'application/json')
                    .send({identityKey : authUn.split("|")[0]})
                    .parse(binaryParser)
                    .end(function(err, res) {
                        if (err) {
                            throw err;
                        }
                        expect(res.status).toEqual(205);
                        //get protobuf builder
                        var builder = protoBuf.loadProtoFile("protobuf/keys.proto");
                        var Protoprekeys = builder.build("protoprekeys");
                        var Prekeys = Protoprekeys.Prekeys;
                        var Prekey = Protoprekeys.Prekey;
                        var KeyPair = Protoprekeys.KeyPair;
                        //expect deviceId to match
                        expect(Prekeys.decode(res.body).prekeys[0].deviceId).toEqual(authUn.split("|")[1]);
                        //expect key id to match
                        expect(Prekeys.decode(res.body).prekeys[0].id).toEqual(lastResortKey.id);
                        var recievedPub = Prekeys.decode(res.body).prekeys[0].keyPair.public;
                        var expectedPub = lastResortKey.keyPair.public;
                        //expect public key to match
                        expect(pbhelper.str2ab(recievedPub)).toEqual(pbhelper.str2ab(expectedPub));
                        done();
                    });
                });
            });//end of 'Consume all prekeys'
        }); //end of 'GET /api/v1/key/'
        describe('POST /api/v1/key/update/', function(){
            describe('Try Invalid Credentials', function() {
                it('Bad Signature: should respond with 401, signature', function(done){
                    request(app)
                    .post('/api/v1/key/update/')
                    .auth(authUn, authPassBadSig)
                    .set('Content-Type', 'application/octet-stream')
                    .send(protoPrekeys.toBuffer())
                    .expect(401, 'signature', done);
                });
                it('Future Password: should respond with 401, time & time in \'Server-Time\' header', function(done){
                    request(app)
                    .post('/api/v1/key/update/')
                    .auth(authUn, authPassFuture)
                    .set('Content-Type', 'application/octet-stream')
                    .send(protoPrekeys.toBuffer())
                    .expect('Server-Time', /[0-9]*/)
                    .expect(401, 'time', done);
                });
                it('Past Password: should respond with 401, time & time in \'Server-Time\' header', function(done){
                    request(app)
                    .post('/api/v1/key/update/')
                    .auth(authUn, authPassPast)
                    .set('Content-Type', 'application/octet-stream')
                    .send(protoPrekeys.toBuffer())
                    .expect('Server-Time', /[0-9]*/)
                    .expect(401, 'time', done);
                });
            });//end of 'Invalid Credentials'
            describe('Try Valid Credentials:', function() {
                it('should respond with 200', function(done){
                    request(app)
                    .post('/api/v1/key/update/')
                    .auth(authUn, authPass)
                    .set('Content-Type', 'application/octet-stream')
                    .send(protoPrekeys.toBuffer())
                    .expect(200, done);
                });
                it('should have 2 prekeys in DB', function(done){
                    Users.findOne({identityKey : authUn.split("|")[0]}, function(err, dbUser) {
                        expect(dbUser.devices[authUn.split("|")[1]].prekeys.length).toEqual(NUMBER_PREKEYS_CREATED-1);
                        done();
                    });
                });
            });//end of 'Valid Credentials'
        }); //end of 'POST /api/v1/key/update'
        describe('POST /api/v1/message/', function(){
            describe('Try Invalid Credentials', function() {
                it('Bad Signature: should respond with 401', function(done){
                    request(app)
                    .post('/api/v1/message/')
                    .auth(authUn, authPassBadSig)
                    .expect(401, 'signature', done);
                });
                it('Future Password: should respond with 401, time & time in \'Server-Time\' header', function(done){
                    request(app)
                    .post('/api/v1/message/')
                    .auth(authUn, authPassFuture)
                    .expect('Server-Time', /[0-9]*/)
                    .expect(401, 'time', done);
                });
                it('Past Password: should respond with 401, time & time in \'Server-Time\' header', function(done){
                    request(app)
                    .post('/api/v1/message/')
                    .auth(authUn, authPassPast)
                    .expect('Server-Time', /[0-9]*/)
                    .expect(401, 'time', done);
                });
            });//end of 'Invalid Credentials'
            describe('Try Valid Credentials:', function() {
                //var messagesJson = {messages: [{headers:[{recipient: authUn, messageHeader: protoPrekeys.toBuffer()}], body: protoPrekeys.toBuffer()}]};
                var beforeCount;
                var numMessages = 1;
                it('get count of messages in queue', function(done) {
                    MessageQueue.count({}, function(err, count){
                        beforeCount = count;
                        done();
                    });
                });
                it('should respond with 200', function(done){
                    request(app)
                    .post('/api/v1/message/')
                    .auth(authUn, authPass)
                    .set('Content-Type', 'application/json')
                    .send({messages: [{headers:[{recipient: authUn, messageHeader: protoPrekeys.toBuffer()}], body: protoPrekeys.toBuffer()}]})
                    .expect(200, done);
                });
                    //var numMessages = messagesJson.messages.length;
                it('MessageQueue model should have '+numMessages+' new entries', function(done){
                    MessageQueue.count({}, function(err, afterCount){
                        expect(afterCount).toEqual(beforeCount+numMessages);
                        done();
                    });
                });

            });//end of 'Valid Credentials'
        }); //end of 'POST /api/v1/message/'

        /*======= Delete device =======*/
        describe('DELETE /api/v1/key/', function(){
            describe('Try Invalid Credentials', function() {
                it('Bad Signature: should respond with 401, signature', function(done){
                    request(app)
                    .delete('/api/v1/key/')
                    .auth(authUn, authPassBadSig)
                    .expect(401, 'signature', done);
                });
                it('Future Password: should respond with 401, time & time in \'Server-Time\' header', function(done){
                    request(app)
                    .delete('/api/v1/key/')
                    .auth(authUn, authPassFuture)
                    .expect('Server-Time', /[0-9]*/)
                    .expect(401, 'time', done);
                });
                it('Past Password: should respond with 401, time & time in \'Server-Time\' header', function(done){
                    request(app)
                    .delete('/api/v1/key/')
                    .auth(authUn, authPassPast)
                    .expect('Server-Time', /[0-9]*/)
                    .expect(401, 'time', done);
                });
            });//end of invalid credentials
            describe('Try Valid Credentials:', function() {
                it('should respond with 200', function(done){
                    request(app)
                    .delete('/api/v1/key/')
                    .auth(authUn, authPass)
                    .expect(200, done);
                });
                it('device should be deleted from database', function(done){
                    Users.findOne({identityKey : authUn.split("|")[0]}, function(err, dbUser) {
                        expect(dbUser.devices[authUn.split("|")[1]]).not.toBeDefined();
                        done();
                    });
                });
                it('identityKey should be revoked in database', function(done){
                    Users.findOne({identityKey : authUn.split("|")[0]}, function(err, dbUser) {
                        expect(dbUser.revoked).toBe(true);
                        done();
                    });
                });
            });//end of 'Valid Credentials'
        }); //end of 'DELETE /api/v1/key/'
    }); //end of 'Regular Authentication, Registered'

    describe('Regular Authentication, Revoked', function() {
        describe('Try Valid Credentials:', function() {
            it('should respond with 401, not registered', function(done){
                request(app)
                .get('/api/v1/key/')
                .auth(authUn, authPass)
                .send({identityKey : authUn.split("|")[0]})
                .expect(401, 'not registered', done);
            });
        });//end of 'Valid Credentials'
    });

    it('Close Server', function(done) {
        server.close();
        done();
    });
});

/* Helper Functions */
function binaryParser(res, callback) {
    res.setEncoding('binary');
    res.data = '';
    res.on('data', function (chunk) {
        res.data += chunk;
    });
    res.on('end', function () {
        callback(null, new Buffer(res.data, 'binary'));
    });
}
