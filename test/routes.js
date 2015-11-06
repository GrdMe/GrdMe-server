"use strict"

process.env.NODE_ENV = 'test';

var request = require('supertest');
var app = require('../server').app;

describe("Routes:", function() {
    var authUn;
    var authUnBadDid;
    var authPass;
    var authPassBadSig;
    var authPassFuture;
    var authPassPast;
    var prekeys;
    var lastResortKey;

    before(function(done) {
        this.timeout(10000);
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
            this.timeout(10000);
            describe('POST /v1/key/update/', function() {
                it('should respond with 401', function(done){
                    request(app)
                    .post('/v1/key/update/')
                    .auth(authUn, authPass)
                    .end(function(err, res) {
                        if(err) {
                            throw err;
                        }
                        res.status.should.equal(401);
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
                        res.status.should.equal(401);
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
                        res.status.should.equal(401);
                        done();
                    });
                });
            });
        });//end of 'Valid Credentials'
        



    });//end of decribe 'Regular Authentication, not registered'
});
