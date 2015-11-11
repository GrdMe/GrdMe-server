// server.js

'use strict'

// set up ======================================================================
    var express  = require('express');
    var app      = express();                              // create our app w/ express
    var mongoose = require('mongoose');                     // mongoose for mongodb
    var morgan   = require('morgan');                       // log requests to the console (express4)
    var bodyParser = require('body-parser');                // pull information from HTML POST (express4)
    var methodOverride = require('method-override');        // simulate DELETE and PUT (express4)
    var rateLimit = require('express-rate-limit'); // docs: https://www.npmjs.com/package/express-rate-limit

    // configuration ===========================================================
    var limiter = rateLimit({/* config */});
    //app.use(limiter);
    app.use(express.static(__dirname + '/public'));                 // set the static files location /public/img will be /img for users
    app.use(morgan('dev'));                                         // log every request to the console
    app.use(bodyParser.urlencoded({'extended':'true'}));            // parse application/x-www-form-urlencoded
    app.use(bodyParser.json());                                     // parse application/json
    app.use(bodyParser.json({ type: 'application/vnd.api+json' })); // parse application/vnd.api+json as json
    app.use(bodyParser.raw());
    app.use(methodOverride());

    // load the routes
    require('./app/routes')(app);

    // database ================================================================
    var database = require('./config/database');
    mongoose.connect(database.url);
    var db = mongoose.connection;
    db.on('error', console.error.bind(console, 'connection error:'));
    db.once('open', function (callback) {
        console.log("connection to mongo database successful.");
    });


    // listen ==================================================================
    var server = app.listen(8080, function () {
        console.log('Grd Me sever listening at http://11.12.13.14:8080');
    });

    exports.close = function() {
        server.close();
        mongoose.disconnect();
    };

    exports.app = app;
