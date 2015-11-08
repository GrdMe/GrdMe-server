"use strict"

//process.env.NODE_ENV = 'test';

var request = require('supertest');
var server = require('../server');
var express = require('express');
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


    describe('Regular Authentication, not registered:', function() {
        describe('Try Valid Credentials:', function() {
            describe('POST /v1/key/update/', function() {
                it('should respond with 401', function(done){
                    request(app)
                    .post('/v1/key/update/')
                    .auth(authUn, authPass)
                    .end(function(err, res) {
                        if(err) {
                            throw err;
                        }
                        expect(res.status).toEqual(401);
                        //res.status.should.equal(401);
                        done();
                    });
                });
            });
            describe('GET /v1/key/', function() {
                it('should respond with 401', function(done){
                    request(app)
                    .get('/v1/key/')
                    .auth(authUn, authPass)
                    .end(function(err, res) {
                        if(err) {
                            throw err;
                        }
                        expect(res.status).toEqual(401);
                        //res.status.should.equal(401);
                        done();
                    });
                });
            });
            describe('POST /v1/messages/', function() {
                it('should respond with 401', function(done){
                    request(app)
                    .post('/v1/messages/')
                    .auth(authUn, authPass)
                    .end(function(err, res) {
                        if(err) {
                            throw err;
                        }
                        expect(res.status).toEqual(401);
                        //res.status.should.equal(401);
                        done();
                    });
                });
            });
        });//end of 'Valid Credentials'
    });//end of decribe 'Regular Authentication, not registered'

    describe('Initial Authentication, not registered:', function() {
        describe('Try Invalid Credentials: Bad Signature', function() {
            describe('POST /v1/key/initial/', function() {
                it('should respond with 401', function(done){
                    request(app)
                    .post('/v1/key/initial/')
                    .auth(authUn, authPassBadSig)
                    .end(function(err, res) {
                        if(err) {
                            throw err;
                        }
                        expect(res.status).toEqual(401);
                        //res.status.should.equal(401);
                        done();
                    });
                });
            });
        });//end of 'Bad Signature'
        describe('Try Invalid Credentials: Future Password', function() {
            describe('POST /v1/key/initial/', function() {
                it('should respond with 401', function(done){
                    request(app)
                    .post('/v1/key/initial/')
                    .auth(authUn, authPassFuture)
                    .end(function(err, res) {
                        if(err) {
                            throw err;
                        }
                        expect(res.status).toEqual(401);
                        //res.status.should.equal(401);
                        done();
                    });
                });
            });
        });//end of 'Future Password'
        describe('Try Invalid Credentials: Past Password', function() {
            describe('POST /v1/key/initial/', function() {
                it('should respond with 401', function(done){
                    request(app)
                    .post('/v1/key/initial/')
                    .auth(authUn, authPassPast)
                    .end(function(err, res) {
                        if(err) {
                            throw err;
                        }
                        expect(res.status).toEqual(401);
                        //res.status.should.equal(401);
                        done();
                    });
                });
            });
        });//end of 'Past Password'
        describe('Try Valid Credentials:', function() {
            describe('POST /v1/key/initial/', function() {
                it('should respond with 200', function(done){
                    request(app)
                    .post('/v1/key/initial/')
                    .auth(authUn, authPass)
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
        app.close();
        done();
    });
});
