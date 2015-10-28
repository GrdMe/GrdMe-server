// server.js


// set up ========================
    var express  = require('express');
    var app      = express();                               // create our app w/ express
    var mongoose = require('mongoose');                     // mongoose for mongodb
    var morgan   = require('morgan');                       // log requests to the console (express4)
    var bodyParser = require('body-parser');                // pull information from HTML POST (express4)
    var methodOverride = require('method-override');        // simulate DELETE and PUT (express4)
    //var nano = require('nano')('http://localhost:5984');    //connect with local database
    var basicAuth = require('basic-auth');
    var bcrypt = require('bcrypt');
    var protoBuf = require('protobufjs');

    // configuration =================

    app.use(express.static(__dirname + '/public'));                 // set the static files location /public/img will be /img for users
    app.use(morgan('dev'));                                         // log every request to the console
    app.use(bodyParser.urlencoded({'extended':'true'}));            // parse application/x-www-form-urlencoded
    app.use(bodyParser.json());                                     // parse application/json
    app.use(bodyParser.json({ type: 'application/vnd.api+json' })); // parse application/vnd.api+json as json
    app.use(methodOverride());

    // database ================================================================
    mongoose.connect('mongodb://localhost/grdmeUsers');
    var db = mongoose.connection;
    db.on('error', console.error.bind(console, 'connection error:'));
    db.once('open', function (callback) {
        console.log("connection to mongo database successful.");
    });

    var userSchema = mongoose.Schema({
        identityKey: String,
        password: String,
        pushId: String,
        devices: [{deviceId: String,
                   lastResortKey: {keyId: String,
                                   publicKey: String,
                                   identityKey: String,
                                   deviceId: String},
                    keys: [{keyId: String,
                            publicKey: String,
                            identityKey: String,
                            deviceId: String}]
                 }]
    });

    var Users = mongoose.model('Users', userSchema);

    // routes ======================================================================
    // auth
    var auth = function (req, res, next) {
      function unauthorized(res) {
        res.set('WWW-Authenticate', 'Basic realm=Authorization Required');
        return res.sendStatus(401);
      };

      var user = basicAuth(req);

      if (!user || !user.name || !user.pass) {
        return unauthorized(res);
      };

      Users.findOne({identityKey : user.name},
          function(err, dbUser) {
              if (err)
                  res.send(err);

              console.log(Object(user));
              console.log(String(dbUser.password));

              if (bcrypt.compareSync(String(user.pass), String(dbUser.password))) {
                      console.log("Authentication Successful");
                      return next();
              } else {
                      return unauthorized(res);
              }


          }
      );
    };


    // api =========================================================================
    // Register
    app.post('/v1/accounts/register/', function(req, res) {
        if (!req.body.signature ||
            !req.body.body ||
            !req.body.body.identityKey ||
            !req.body.body.password) {
                res.sendStatus(415);
            }

        var signature = req.body.signature;
        var bodyToVerify = req.body.body;

        /* !!!! verify body with signature here !!!! */

        var identityKeyToRegister = req.body.body.identityKey;
        var passwordToRegister;
        bcrypt.hash(req.body.body.password, 8, function(err, hash) {
            if (err) {
                res.send(err);
            } else {
                passwordToRegister = hash;
                Users.create({
                    identityKey : identityKeyToRegister,
                    password: passwordToRegister
                }, function(err, user) {
                    if (err)
                        res.send(err);
                    if (user) {
                        //res.sendStatus(200);
                        res.json(user);
                    }
                });
            }
        });

    });

    // Register a gcm id
    app.put('/v1/accounts/push/', auth, function(req, res) {
        if (!req.body ||
            !req.body.pushRegistrationId) {
                res.sendStatus(415);
                return;
            }

        var pushRegistrationId = req.body.pushRegistrationId;
        var user = basicAuth(req);

        Users.update({identityKey : user.name},{
            pushID : pushRegistrationId
        }, function(err, dbUser) {
                if (err)
                    res.send(err);

                res.sendStatus(200);
            }
        );

    });

    //Register prekeys
    app.put('/v1/keys/', auth, function(req, res) {
        var signature = req.body.signature;
        var bodyToVerify = req.body.body;

        var lastResortKey = req.body.body.lastResortKey;
        var prekeys = req.body.body.keys;
    });

    //getting a recipients prekeys based on idkey and device key
    app.get('/v1/keys/', basicAuth, function(req, res) {
        var signature = req.body.signature;
        var bodyToVerify = req.body.body;

        var identityKey = req.body.body.identityKey;
        var deviceIdKey = req.body.body.deviceIdKey;

    });

    //submitting a message
    app.put('/v1/messages/', basicAuth, function(req, res) {
        var signature = req.body.signature;
        var bodyToVerify = req.body.body;

        for (var i=0; i<req.body.body.messages.length; i++) {
            var message = req.body.body.messages[i].body;

            for (var j=0; j<req.body.body.headers.length; j++) {
                var deviceIdKey = req.body.body.headers.deviceIdKey;
                var messageHeader = req.body.body.headers.messageHeader;
            }
        }
    });


    // application -------------------------------------------------------------


    app.get('/', function (req, res) {
        res.send('Hello World!');
    });

    // listen (start app with node server.js) ======================================
    app.listen(8080, function () {
        console.log('Grd Me sever listening at http://11.12.13.14:8080');
    });
