"use strict"

//process.env.NODE_ENV = 'test';

var request = require('supertest');
var server = require('../server');
var express = require('express');
var protoBuf = require('protobufjs');
var app = server.app;

describe("Routes:", function(done) {
    var authUn;
    var authUnBadDid;
    var authPass;
    var authPassBadSig;
    var authPassFuture;
    var authPassPast;
    var prekeys;
    var lastResortKey;
    var protoPrekeys;

    it('Create Credentials & Keys for testing', function(done) {
        //this.timeout(10000);
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
        //experiment with protoBuf
        var builder = protoBuf.loadProtoFile("protobuf/keys.proto"); //appears to automaticly search from root of project
        var Protoprekeys = builder.build("protoprekeys");
        var Prekeys = Protoprekeys.Prekeys;
        var Prekey = Protoprekeys.Prekey;
        var Keypair = Protoprekeys.Keypair;

        var ConstructKeysProtobuf = function (lastResortKey, prekeys){
            var protoLastResortKey = new Prekey(Number(lastResortKey.id), new Keypair(ab2str(lastResortKey.keyPair.public), ab2str(lastResortKey.keyPair.private)));

            var protoPrekeys = new Prekeys(protoLastResortKey);
            for (var i=0; i<prekeys.length; i++) {
                protoPrekeys['prekeys'][i] = new Prekey(prekeys[i].id, new Keypair(ab2str(prekeys[i].keyPair.public), ab2str(prekeys[i].keyPair.private)));
            }
            return protoPrekeys;
        };
        protoPrekeys = ConstructKeysProtobuf(lastResortKey, prekeys);
        done();
    });


    describe('Regular Authentication, not registered:', function() {
        describe('Try Valid Credentials:', function() {
            describe('POST /api/v1/key/update/', function() {
                it('should respond with 401 & time in json body', function(done){
                    request(app)
                    .post('/api/v1/key/update/')
                    .auth(authUn, authPass)
                    .end(function(err, res) {
                        if(err) {
                            throw err;
                        }
                        expect(res.status).toEqual(401);
                        expect(res.body.time).toBeDefined();
                        //res.status.should.equal(401);
                        done();
                    });
                });
            });
            describe('GET /api/v1/key/', function() {
                it('should respond with 401 & time in json body', function(done){
                    request(app)
                    .get('/api/v1/key/')
                    .auth(authUn, authPass)
                    .end(function(err, res) {
                        if(err) {
                            throw err;
                        }
                        expect(res.status).toEqual(401);
                        expect(res.body.time).toBeDefined();
                        //res.status.should.equal(401);
                        done();
                    });
                });
            });
            describe('POST /api/v1/message/', function() {
                it('should respond with 401 & time in json body', function(done){
                    request(app)
                    .post('/api/v1/message/')
                    .auth(authUn, authPass)
                    .end(function(err, res) {
                        if(err) {
                            throw err;
                        }
                        expect(res.status).toEqual(401);
                        expect(res.body.time).toBeDefined();
                        //res.status.should.equal(401);
                        done();
                    });
                });
            });
        });//end of 'Valid Credentials'
    });//end of decribe 'Regular Authentication, not registered'

    describe('Initial Authentication, not registered:', function() {
        describe('Try Invalid Credentials: Bad Signature', function() {
            describe('POST /api/v1/key/initial/', function() {
                it('should respond with 401 & time in json body', function(done){
                    request(app)
                    .post('/api/v1/key/initial/')
                    .auth(authUn, authPassBadSig)
                    .set('Content-Type', 'application/octet-stream')
                    .send(protoPrekeys.toBuffer())
                    .end(function(err, res) {
                        if(err) {
                            throw err;
                        }
                        expect(res.status).toEqual(401);
                        expect(res.body.time).toBeDefined();
                        //res.status.should.equal(401);
                        done();
                    });
                });
            });
        });//end of 'Bad Signature'
        describe('Try Invalid Credentials: Future Password', function() {
            describe('POST /api/v1/key/initial/', function() {
                it('should respond with 401 & time in json body', function(done){
                    request(app)
                    .post('/api/v1/key/initial/')
                    .auth(authUn, authPassFuture)
                    .set('Content-Type', 'application/octet-stream')
                    .send(protoPrekeys.toBuffer())
                    .end(function(err, res) {
                        if(err) {
                            throw err;
                        }
                        expect(res.status).toEqual(401);
                        expect(res.body.time).toBeDefined();
                        //res.status.should.equal(401);
                        done();
                    });
                });
            });
        });//end of 'Future Password'
        describe('Try Invalid Credentials: Past Password', function() {
            describe('POST /api/v1/key/initial/', function() {
                it('should respond with 401 & time in json body', function(done){
                    request(app)
                    .post('/api/v1/key/initial/')
                    .auth(authUn, authPassPast)
                    .set('Content-Type', 'application/octet-stream')
                    .send(protoPrekeys.toBuffer())
                    .end(function(err, res) {
                        if(err) {
                            throw err;
                        }
                        expect(res.status).toEqual(401);
                        expect(res.body.time).toBeDefined();
                        //res.status.should.equal(401);
                        done();
                    });
                });
            });
        });//end of 'Past Password'
        describe('Try Valid Credentials:', function() {
            describe('POST /api/v1/key/initial/', function() {
                it('should respond with 200', function(done){
                    request(app)
                    .post('/api/v1/key/initial/')
                    .auth(authUn, authPass)
                    .set('Content-Type', 'application/octet-stream')
                    .send(protoPrekeys.toBuffer())
                    .end(function(err, res) {
                        if(err) {
                            throw err;
                        }
                        expect(res.status).toEqual(200);
                        //res.status.should.equal(401);
                        done();
                    });
                });
            });
        });//end of 'Valid Credentials'
    });//end of decribe 'Initial Authentication, not registered'

    it('Close Server', function(done) {
        server.close();
        done();
    });
});

var ab2str = function(buf) {
  return String.fromCharCode.apply(null, new Int8Array(buf));
};

var str2ab = function(str) {
  var buf = new ArrayBuffer(str.length*2); // 2 bytes for each char
  var bufView = new Int8Array(buf);
  for (var i=0, strLen=str.length; i<strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
};
