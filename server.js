#!/usr/bin/node
// server.js

'use strict'

// set up ======================================================================
    var express        = require('express');
    var app            = express();                         // create our app w/ express
    var mongoose       = require('mongoose');               // mongoose for mongodb
    var morgan         = require('morgan');                 // log requests to the console (express4)
    var bodyParser     = require('body-parser');            // pull information from HTML POST (express4)
    var methodOverride = require('method-override');        // simulate DELETE and PUT (express4)
    var rateLimit      = require('express-rate-limit');     // docs: https://www.npmjs.com/package/express-rate-limit

    // configuration ===========================================================
    var limiter = rateLimit({/* config */});
    //app.use(limiter);
    switch(process.env.NODE_ENV){
        case 'development':
            app.use(morgan('dev'));      // log every request to the console
            break;
        case 'production':
            app.use(morgan('common'));   // log every request to the console
            break;
        default:
            app.use(morgan('dev'));      // log every request to the console
            break;
    }
    app.use(bodyParser.urlencoded({'extended':'true'}));            // parse application/x-www-form-urlencoded
    app.use(bodyParser.json());                                     // parse application/json
    app.use(bodyParser.json({ type: 'application/vnd.api+json' })); // parse application/vnd.api+json as json
    app.use(bodyParser.raw());
    app.use(methodOverride());



    // database ================================================================
    var database = require('./config/database');
    mongoose.connect(database.url);
    var db = mongoose.connection;
    db.on('error', console.error.bind(console, 'connection error:'));
    db.once('open', function (callback) {
        console.log("connection to mongo database successful.");
    });


    // listen ==================================================================
    var server;
    switch(process.env.NODE_ENV){
        case 'development':
            server = app.listen(8080, function() {
                console.log('Grd Me sever listening at port 8080');
            });
            break;
        case 'production':
            var fs          = require('fs');
            var https       = require('https');
            var httpsConfig = require('./config/productionPaths');
            var privateKey  = fs.readFileSync(httpsConfig.privateKeyPath);
            var certificate = fs.readFileSync(httpsConfig.certificatePath);
            var credentials = {key: privateKey, cert: certificate};
            server          = https.createServer(credentials, app);
            server.listen(443, function () {
                console.log('Grd Me sever listening at port 443');
            });
            break;

        default:
            server = app.listen(8080, function() {
                console.log('Grd Me sever listening at port 8080');
            });
            break;
    }

    exports.close = function() {
        server.close();
        mongoose.disconnect();
    };

    exports.app = app;

    // socket.io ===============================================================
    var io = require('./push/socket').listen(server);
    // load the routes
    require('./app/routes')(app);
