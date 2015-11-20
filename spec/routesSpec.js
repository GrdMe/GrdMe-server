"use strict"

//process.env.NODE_ENV = 'test';

var request = require('supertest');
var server = require('../server');
var express = require('express');
var protoBuf = require('protobufjs');
var app = server.app;

/* Load protobuf helper methods */
var pbhelper = require('../protobuf/protobufHelperFunctions')

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
        .get('/test/axolotl')
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
        protoPrekeys = pbhelper.constructKeysProtobuf(lastResortKey, prekeys);
        ////console.log("PROTOPREKEYS FRPM TEST: %j", protoPrekeys);
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
        describe('Try Invalid Credentials: Bad Signature', function() {
            describe('POST /api/v1/key/initial/', function() {
                it('should respond with 401, signature', function(done){
                    request(app)
                    .post('/api/v1/key/initial/')
                    .auth(authUn, authPassBadSig)
                    .set('Content-Type', 'application/octet-stream')
                    .send(protoPrekeys.toBuffer())
                    .expect(401, 'signature', done);
                });
            });
        });//end of 'Bad Signature'
        describe('Try Invalid Credentials: Future Password', function() {
            describe('POST /api/v1/key/initial/', function() {
                it('should respond with 401, time & time in \'Server-Time\' header', function(done){
                    request(app)
                    .post('/api/v1/key/initial/')
                    .auth(authUn, authPassFuture)
                    .set('Content-Type', 'application/octet-stream')
                    .send(protoPrekeys.toBuffer())
                    .expect('Server-Time', /[0-9]*/)
                    .expect(401, 'time', done);
                });
            });
        });//end of 'Future Password'
        describe('Try Invalid Credentials: Past Password', function() {
            describe('POST /api/v1/key/initial/', function() {
                it('should respond with 401, time & time in \'Server-Time\' header', function(done){
                    request(app)
                    .post('/api/v1/key/initial/')
                    .auth(authUn, authPassPast)
                    .set('Content-Type', 'application/octet-stream')
                    .send(protoPrekeys.toBuffer())
                    .expect('Server-Time', /[0-9]*/)
                    .expect(401, 'time', done);
                });
            });
        });//end of 'Past Password'
        describe('Try Valid Credentials:', function() {
            describe('POST /api/v1/key/initial/', function() {
                it('should respond with 200', function(done){
                    /////console.log("SENDER-PRE-ENC: %j", protoPrekeys.prekeys[0]);
                    request(app)
                    .post('/api/v1/key/initial/')
                    .auth(authUn, authPass)
                    .set('Content-Type', 'application/octet-stream')
                    .send(protoPrekeys.toBuffer())
                    .expect(200, done);
                });
            });
        });//end of 'Valid Credentials'
    });//end of decribe 'Initial Authentication, not registered'

    describe('Regular Authentication, Registered', function() {
        describe('GET /api/v1/key/', function() {
            describe('Try Invalid Credentials: Bad Signature', function() {
                it('should respond with 401, signature', function(done){
                    request(app)
                    .get('/api/v1/key/')
                    .auth(authUn, authPassBadSig)
                    .set('Content-Type', 'application/json')
                    .send({identityKey : authUn.split("|")[0]})
                    //.parse(binaryParser)
                    .expect(401, 'signature', done);
                });
            });//end of 'Try Invalid Credentials: Bad Signature'
            describe('Try Invalid Credentials: Future Password', function() {
                it('should respond with 401, time & time in \'Server-Time\' header', function(done){
                    request(app)
                    .get('/api/v1/key/')
                    .auth(authUn, authPassFuture)
                    .set('Content-Type', 'application/json')
                    .send({identityKey : authUn.split("|")[0]})
                    //.parse(binaryParser)
                    .expect('Server-Time', /[0-9]*/)
                    .expect(401, 'time', done);
                });
            });//end of 'Try Invalid Credentials: Future Password'
            describe('Try Invalid Credentials: Past Password', function() {
                it('should respond with 401, time & time in \'Server-Time\' header', function(done){
                    request(app)
                    .get('/api/v1/key/')
                    .auth(authUn, authPassPast)
                    .set('Content-Type', 'application/json')
                    .send({identityKey : authUn.split("|")[0]})
                    //.parse(binaryParser)
                    .expect('Server-Time', /[0-9]*/)
                    .expect(401, 'time', done);
                });
            });//end of 'Try Invalid Credentials: Past Password'
            describe('Try Valid Credentials', function() {
                it('should respond with 200 & list of prekeys', function(done){
                    request(app)
                    .get('/api/v1/key/')
                    .auth(authUn, authPass)
                    .set('Content-Type', 'application/json')
                    .send({identityKey : authUn.split("|")[0]})
                    .parse(binaryParser)
                    .expect(200, done);
                    // .end(function(err, res) {
                    //     if(err) {
                    //         throw err;
                    //     }
                    //     //console.log("RES.BODY: %j", res.body);
                    //
                    //     expect(res.status).toEqual(200);
                    //
                    //     var builder = protoBuf.loadProtoFile("protobuf/keys.proto"); //appears to automaticly search from root of project
                    //     var Protoprekeys = builder.build("protoprekeys");
                    //     var Prekeys = Protoprekeys.Prekeys;
                    //     var Prekey = Protoprekeys.Prekey;
                    //     var KeyPair = Protoprekeys.KeyPair;
                    //     //console.log("JASMINE RECIEVED: %j", Prekeys.decode(res.body).prekeys[0]);
                    //     //console.log("EXPECTED........: %j", protoPrekeys.prekeys[0])
                    //     expect(Prekeys.decode(res.body).prekeys[0].id).toEqual(protoPrekeys.prekeys[0].id);
                    //     //expect(Prekeys.decode(res.body).prekeys[0].keyPair.public).toEqual( Prekeys.decode(protoPrekeys.toBuffer()).prekeys[0].keyPair.public );
                    //     //res.status.should.equal(401);
                    //
                    //     for (var i=0; i<protoPrekeys.prekeys.length; i++) {
                    //
                    //     }
                    //
                    //     done();
                    // });
                });
            });//end of 'Try Valid Credentials'
        }); //end of 'GET /api/v1/key/'
        describe('POST /api/v1/key/update/', function(){
            describe('Try Invalid Credentials: Bad Signature', function() {
                it('should respond with 401, signature', function(done){
                    request(app)
                    .post('/api/v1/key/update/')
                    .auth(authUn, authPassBadSig)
                    .set('Content-Type', 'application/octet-stream')
                    .send(protoPrekeys.toBuffer())
                    .expect(401, 'signature', done);
                });
            });//end of 'Bad Signature'
            describe('Try Invalid Credentials: Future Password', function() {
                it('should respond with 401, time & time in \'Server-Time\' header', function(done){
                    request(app)
                    .post('/api/v1/key/update/')
                    .auth(authUn, authPassFuture)
                    .set('Content-Type', 'application/octet-stream')
                    .send(protoPrekeys.toBuffer())
                    .expect('Server-Time', /[0-9]*/)
                    .expect(401, 'time', done);
                });
            });//end of 'Future Password'
            describe('Try Invalid Credentials: Past Password', function() {
                it('should respond with 401, time & time in \'Server-Time\' header', function(done){
                    request(app)
                    .post('/api/v1/key/update/')
                    .auth(authUn, authPassPast)
                    .set('Content-Type', 'application/octet-stream')
                    .send(protoPrekeys.toBuffer())
                    .expect('Server-Time', /[0-9]*/)
                    .expect(401, 'time', done);
                });
            });//end of 'Past Password'
            describe('Try Valid Credentials:', function() {
                it('should respond with 200', function(done){
                    request(app)
                    .post('/api/v1/key/update/')
                    .auth(authUn, authPass)
                    .set('Content-Type', 'application/octet-stream')
                    .send(protoPrekeys.toBuffer())
                    .expect(200, done);
                });
            });//end of 'Valid Credentials'
        }); //end of 'POST /api/v1/key/update'
        describe('POST /api/v1/message/', function(){
            describe('Try Invalid Credentials: Bad Signature', function() {
                it('should respond with 401', function(done){
                    request(app)
                    .post('/api/v1/message/')
                    .auth(authUn, authPassBadSig)
                    .expect(401, 'signature', done);
                });
            });//end of 'Bad Signature'
            describe('Try Invalid Credentials: Future Password', function() {
                it('should respond with 401, time & time in \'Server-Time\' header', function(done){
                    request(app)
                    .post('/api/v1/message/')
                    .auth(authUn, authPassFuture)
                    .expect('Server-Time', /[0-9]*/)
                    .expect(401, 'time', done);
                });
            });//end of 'Future Password'
            describe('Try Invalid Credentials: Past Password', function() {
                it('should respond with 401, time & time in \'Server-Time\' header', function(done){
                    request(app)
                    .post('/api/v1/message/')
                    .auth(authUn, authPassPast)
                    .expect('Server-Time', /[0-9]*/)
                    .expect(401, 'time', done);
                });
            });//end of 'Past Password'
            describe('Try Valid Credentials:', function() {
                it('should respond with 200', function(done){
                    request(app)
                    .post('/api/v1/message/')
                    .auth(authUn, authPass)
                    .set('Content-Type', 'application/json')
                    .send({messages: [{headers:[{recipient: authUn, messageHeader: protoPrekeys.toBuffer()}], body: protoPrekeys.toBuffer()}]})
                    .expect(200, done);
                });
            });//end of 'Valid Credentials'
        }); //end of 'POST /api/v1/message/'

        /*======= Delete device =======*/
        describe('DELETE /api/v1/key/', function(){
            describe('Try Invalid Credentials: Bad Signature', function() {
                it('should respond with 401, signature', function(done){
                    request(app)
                    .delete('/api/v1/key/')
                    .auth(authUn, authPassBadSig)
                    .expect(401, 'signature', done);
                });
            });//end of 'Bad Signature'
            describe('Try Invalid Credentials: Future Password', function() {
                it('should respond with 401, time & time in \'Server-Time\' header', function(done){
                    request(app)
                    .delete('/api/v1/key/')
                    .auth(authUn, authPassFuture)
                    .expect('Server-Time', /[0-9]*/)
                    .expect(401, 'time', done);
                });
            });//end of 'Future Password'
            describe('Try Invalid Credentials: Past Password', function() {
                it('should respond with 401, time & time in \'Server-Time\' header', function(done){
                    request(app)
                    .delete('/api/v1/key/')
                    .auth(authUn, authPassPast)
                    .expect('Server-Time', /[0-9]*/)
                    .expect(401, 'time', done);
                });
            });//end of 'Past Password'
            describe('Try Valid Credentials:', function() {
                it('should respond with 200', function(done){
                    request(app)
                    .delete('/api/v1/key/')
                    .auth(authUn, authPass)
                    .expect(200, done);
                });
            });//end of 'Valid Credentials'
        }); //end of 'DELETE /api/v1/key/'
    }); //end of 'Regular Authentication, Registered'

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
