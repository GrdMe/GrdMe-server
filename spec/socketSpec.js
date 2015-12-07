"use strict"

var request = require('supertest');
var server = require('../server');
var express = require('express');
var app = server.app;

/* database setup */
var database = require('../config/database');
var mongoose = require('mongoose');
mongoose.connect(database.url);
var db = mongoose.connection;

/* load db models */
var Users = require('../app/models/user');
var MessageQueue = require('../app/models/messageQueue');

/* socket.io */
var ioClient = require('socket.io-client');
var options ={
  transports: ['websocket'],
  'force new connection': true
};

/* Load helper methods */
var helper = require('../app/helperFunctions');
var axolotlTest = require('./axolotlTestGenerator');
var constants = require('../app/constants');

/* Constants */
var NUMBER_PREKEYS_CREATED = 3;

/* auth variables */
var authUn;
var authUnBadDid;
var authPass;
var authPassBadSig;
var authPassFuture;
var authPassPast;
var prekeys; //array of array buffer prekeys
var lastResortKey; //singular array buffer prekey
var prekeysObj;


describe("socketSpec.js", function(){
    it('Create Credentials & Keys for testing', function(done) {
        axolotlTest.generate(NUMBER_PREKEYS_CREATED, function(data){
            authUn         = data.basicAuthUserName;
            authPass       = data.basicAuthPassword;
            authUnBadDid   = data.badDidUserName;
            authPassBadSig = data.badSignaturePassword;
            authPassFuture = data.futurePassword;
            authPassPast   = data.pastPassword;
            lastResortKey  = data.lastResortKey;
            prekeys        = data.preKeys;
            prekeysObj     = helper.prekeysObjectConstructor(lastResortKey, prekeys);
            done();
        });
    });



    describe("User not registered:", function(){
        describe('Try Valid Credentials:', function() {
            it('should connect & return not registered', function(done){
                var socket = ioClient.connect("http://localhost:8080", options);
                socket.once('connect', function(data){
                    socket.emit('authentication', { username:authUn, password:authPass });
                    socket.once('not authorized', function(data) {
                        expect(data.message).toBe('not registered');
                        socket.disconnect();
                        done();
                    });
                });
            });
        });
    });

    describe("User registered:", function(){
        it('register user', function(done){
            request(app)
            .post('/api/v1/key/initial/')
            .auth(authUn, authPass)
            .set('Content-Type', 'application/json')
            .send(prekeysObj)
            .expect(200, done);
        });

        describe("Make initial connection to server:", function(){
            describe('Try Invalid Credentials', function() {
                it('Bad Signature: should respond with not authorized, signature', function(done){
                    var socket = ioClient.connect("http://localhost:8080", options);
                    socket.once('connect', function(data){
                        socket.emit('authentication', { username:authUn, password:authPassBadSig });
                        socket.once('not authorized', function(data) {
                            expect(data.message).toBe('signature');
                            socket.disconnect();
                            done();
                        });
                    });
                });
                it('Future Password: should respond with not authorized, time & time in \'serverTime\' key', function(done){
                    var socket = ioClient.connect("http://localhost:8080", options);
                    socket.once('connect', function(data){
                        socket.emit('authentication', { username:authUn, password:authPassFuture });
                        socket.once('not authorized', function(data) {
                            expect(data.message).toBe('time');
                            expect(data.serverTime).toBeDefined();
                            expect(data.serverTime).toMatch(/[0-9]*/);
                            socket.disconnect();
                            done();
                        });
                    });
                });
                it('Past Password: should respond with not authorized, time & time in \'serverTime\' key', function(done){
                    var socket = ioClient.connect("http://localhost:8080", options);
                    socket.once('connect', function(data){
                        socket.emit('authentication', { username:authUn, password:authPassFuture });
                        socket.once('not authorized', function(data) {
                            expect(data.message).toBe('time');
                            expect(data.serverTime).toBeDefined();
                            expect(data.serverTime).toMatch(/[0-9]*/);
                            socket.disconnect();
                            done();
                        });
                    });
                });
            });//end of 'Try Invalid Credentials'
            describe("Try Valid Credentials", function(){
                it('should connect & return authorized', function(done){
                    var socket = ioClient.connect("http://localhost:8080", options);
                    socket.once('connect', function(data){
                        socket.emit('authentication', { username:authUn, password:authPass });
                        socket.once('authorized', function(data) {
                            socket.disconnect();
                            done();
                        });
                    });

                });
            });
        }); // end 'Make initial connection to server'
        describe("Get messages:", function(){
            var messageRequestBody = {messages: [{headers:[{recipient: authUn, messageHeader: "base64 encoded string"},], body: "base64 encoded string"}, {headers:[{recipient: authUn, messageHeader: "base64 encoded string"},], body: "base64 encoded string"}]};
            messageRequestBody = Object(messageRequestBody);
            var numMessages = messageRequestBody.messages.length;
            describe("Get backloged messages on connection", function(){
                it('submit message to server', function(done){
                    request(app)
                    .post('/api/v1/message/')
                    .auth(authUn, authPass)
                    .set('Content-Type', 'application/json')
                    .send({messages: [{headers:[{recipient: authUn, messageHeader: "base64 encoded string"},], body: "base64 encoded string"}, {headers:[{recipient: authUn, messageHeader: "base64 encoded string"},], body: "base64 encoded string"}]})
                    .expect(function(res) {
                        res.body.messagesQueued = numMessages;
                    })
                    .expect(200, done);
                });
                it('should connect & return message(s)', function(done){
                    var numMessagesRecieved = 0;
                    var socket = ioClient.connect("http://localhost:8080", options);
                    socket.once('connect', function(data){
                        socket.emit('authentication', { username:authUn, password:authPass });
                        socket.on('message', function(messageData) {
                            expect(messageData.header).toBeDefined();
                            expect(messageData.body).toBeDefined();
                            expect(messageData.id).toBeDefined();
                            //confirm reception of message
                            socket.emit('recieved', {messageId: messageData.id});
                            numMessagesRecieved++;
                            if(numMessagesRecieved == numMessages) {
                                expect(numMessagesRecieved).toEqual(2);
                                //sleep(1000);
                                socket.disconnect();
                                done();
                            }
                        });
                    });

                });
                it('all messages for recipient should be removed from DB', function(done) {
                    /* sleep to allow server to recieve messages and modify DB */
                    //sleep(2000);
                    /* begin test */
                    MessageQueue.count({recipientIdKey: authUn.split(constants.NAME_DELIMITER)[0],
                                        recipientDid: authUn.split(constants.NAME_DELIMITER)[1]}, function(err, count){
                        expect(count).toEqual(0);
                        done();
                    });
                });
            });
            describe("Get new messages while connected", function(){
                it('should recieve push message imediately after sending when sockets are connected', function(done){
                    //connect to socket
                    var socket = ioClient.connect("http://localhost:8080", options);
                    socket.once('connect', function(data){
                        socket.emit('authentication', { username:authUn, password:authPass });
                        socket.once('authorized', function(data){
                            request(app)
                            .post('/api/v1/message/')
                            .auth(authUn, authPass)
                            .set('Content-Type', 'application/json')
                            .send({messages: [{headers:[{recipient: authUn, messageHeader: "base64 encoded string"},], body: "base64 encoded string"}]})
                            .expect(function(res) {
                                res.body.messagesQueued = numMessages;
                            })
                            .expect(200)
                            .end(function(err, res){
                                if (err) throw err;
                            });
                        });
                        socket.once('message', function(messageData) {
                            //confirm reception of message
                            socket.emit('recieved', {messageId: messageData.id});
                            expect(messageData.header).toBeDefined();
                            expect(messageData.body).toBeDefined();
                            expect(messageData.id).toBeDefined();
                            socket.disconnect();
                            done();
                        });
                    });
                });
                it('all messages for recipient should be removed from DB', function(done) {
                    MessageQueue.count({recipientIdKey: authUn.split(constants.NAME_DELIMITER)[0],
                                        recipientDid: authUn.split(constants.NAME_DELIMITER)[1]}, function(err, count){
                        expect(count).toEqual(0);
                        done();
                    });
                });
            });
        });
    });


});

var sleep = function (milliseconds) {
  var start = new Date().getTime();
  for (var i = 0; i < 1e7; i++) {
    if ((new Date().getTime() - start) > milliseconds){
      break;
    }
  }
}
