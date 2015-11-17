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
    var prekeys;
    var lastResortKey;
    var protoPrekeys;

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
        done();
    });


    describe('Regular Authentication, not registered:', function() {
        describe('Try Valid Credentials:', function() {
            describe('POST /api/v1/key/update/', function() {
                it('should respond with 404', function(done){
                    request(app)
                    .post('/api/v1/key/update/')
                    .auth(authUn, authPass)
                    .end(function(err, res) {
                        if(err) {
                            throw err;
                        }
                        expect(res.status).toEqual(404);
                        //expect(res.body.time).toBeDefined();
                        //res.status.should.equal(401);
                        done();
                    });
                });
            });
            describe('GET /api/v1/key/', function() {
                it('should respond with 404', function(done){
                    request(app)
                    .get('/api/v1/key/')
                    .auth(authUn, authPass)
                    .end(function(err, res) {
                        if(err) {
                            throw err;
                        }
                        expect(res.status).toEqual(404);
                        //expect(res.body.time).toBeDefined();
                        //res.status.should.equal(401);
                        done();
                    });
                });
            });
            describe('POST /api/v1/message/', function() {
                it('should respond with 404', function(done){
                    request(app)
                    .post('/api/v1/message/')
                    .auth(authUn, authPass)
                    .end(function(err, res) {
                        if(err) {
                            throw err;
                        }
                        expect(res.status).toEqual(404);
                        //expect(res.body.time).toBeDefined();
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
                it('should respond with 401', function(done){
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
                        //expect(res.body.time).toBeDefined();
                        //res.status.should.equal(401);
                        done();
                    });
                });
            });
        });//end of 'Bad Signature'
        describe('Try Invalid Credentials: Future Password', function() {
            describe('POST /api/v1/key/initial/', function() {
                it('should respond with 409 & time in json body', function(done){
                    request(app)
                    .post('/api/v1/key/initial/')
                    .auth(authUn, authPassFuture)
                    .set('Content-Type', 'application/octet-stream')
                    .send(protoPrekeys.toBuffer())
                    .end(function(err, res) {
                        if(err) {
                            throw err;
                        }
                        expect(res.status).toEqual(409);
                        expect(res.body.time).toBeDefined();
                        //res.status.should.equal(401);
                        done();
                    });
                });
            });
        });//end of 'Future Password'
        describe('Try Invalid Credentials: Past Password', function() {
            describe('POST /api/v1/key/initial/', function() {
                it('should respond with 409 & time in json body', function(done){
                    request(app)
                    .post('/api/v1/key/initial/')
                    .auth(authUn, authPassPast)
                    .set('Content-Type', 'application/octet-stream')
                    .send(protoPrekeys.toBuffer())
                    .end(function(err, res) {
                        if(err) {
                            throw err;
                        }
                        expect(res.status).toEqual(409);
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
