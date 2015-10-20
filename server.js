// server.js


// set up ========================
    var express  = require('express');
    var app      = express();                               // create our app w/ express
    var morgan = require('morgan');             // log requests to the console (express4)
    var bodyParser = require('body-parser');    // pull information from HTML POST (express4)
    var methodOverride = require('method-override'); // simulate DELETE and PUT (express4)
    var nano = require('nano')('http://localhost:5984');

//     //Create a server
// var server = http.createServer(handleRequest);

    // configuration =================


    //mongoose.connect('mongodb://admin:hacknc2015@ec2-54-152-75-255.compute-1.amazonaws.com:27017/dummyDB');     // connect to mongoDB database on modulus.io

    app.use(express.static(__dirname + '/public'));                 // set the static files location /public/img will be /img for users
    app.use(morgan('dev'));                                         // log every request to the console
    app.use(bodyParser.urlencoded({'extended':'true'}));            // parse application/x-www-form-urlencoded
    app.use(bodyParser.json());                                     // parse application/json
    app.use(bodyParser.json({ type: 'application/vnd.api+json' })); // parse application/vnd.api+json as json
    app.use(methodOverride());

    // define models =================
    // var Schema = mongoose.Schema;
    //
    // var Users = mongoose.model('Users', {
    //     name : String,
    //     email : String,
    //     google_id_token: String
    // });


    // routes ======================================================================

    // api ---------------------------------------------------------------------
    // // get all users
    // app.get('/api/users', function(req, res) {
    //
    //     // use mongoose to get all users in the database
    //     Users.find(function(err, users) {
    //
    //         // if there is an error retrieving, send the error. nothing after res.send(err) will execute
    //         if (err)
    //             res.send(err)
    //
    //         res.json(users); // return all users in JSON format
    //     });
    // });
    //
    // //user apis ================================================================
    // // create user and send back all users after creation
    // app.post('/api/users', function(req, res) {
    //
    //     // create a user, information comes from AJAX request from Angular
    //     Users.create({
    //         name : req.body.name,
    //         email: req.body.email,
    //         google_id_token: req.body.google_id_token
    //     }, function(err, user) {
    //         if (err)
    //             res.send(err);
    //
    //         // get and return all the users after you create another
    //         Users.find(function(err, users) {
    //             if (err)
    //                 res.send(err)
    //             res.json(users);
    //         });
    //     });
    //
    // });
    //
    // // delete a user
    // app.delete('/api/users/:user_id', function(req, res) {
    //     Users.remove({
    //         _id : req.params.user_id
    //     }, function(err, users) {
    //         if (err)
    //             res.send(err);
    //
    //         // get and return all the users after you create another
    //         Users.find(function(err, users) {
    //             if (err)
    //                 res.send(err)
    //             res.json(users);
    //         });
    //     });
    // });
    //
    // //courses api ==============================================================
    // // get all courses
    // app.get('/api/courses', function(req, res) {
    //
    //     // use mongoose to get all courses in the database
    //     Courses.find(function(err, courses) {
    //
    //         // if there is an error retrieving, send the error. nothing after res.send(err) will execute
    //         if (err)
    //             res.send(err)
    //
    //         res.json(courses); // return all courses in JSON format
    //     });
    // });
    //
    // //get courses for a single user
    // app.get('/api/courses/user/:user_id', function(req, res) {
    //     Enrolled.find({user_id : req.params.user_id},
    //         {course_id: 1, _id: 0},
    //         function(err, enrolleds) {
    //             if (err)
    //                 res.send(err);
    //
    //                 var ids = enrolleds.map(function(enrolleds) {return enrolleds.course_id});
    //                 //query Courses for every course_id listed in enrolleds.course_id
    //                 Courses.find({_id: {$in: ids}},
    //                             function(err, courses) {
    //                                     if (err || !courses)
    //                                         res.send(err);
    //                                     res.json(courses);
    //                             }
    //                 );
    //                 //res.json(enrolleds); // return all courses in JSON format
    //
    //         }
    //     );
    // });
    //
    // // create course and send back all courses after creation
    // app.post('/api/courses', function(req, res) {
    //
    //     // create a course, information comes from AJAX request from Angular
    //     Courses.create({
    //         name : req.body.name,
    //         in_session : false
    //     }, function(err, course) {
    //         if (err)
    //             res.send(err);
    //
    //         // get and return all the courses after you create another
    //         Courses.find(function(err, courses) {
    //             if (err)
    //                 res.send(err)
    //             res.json(courses);
    //         });
    //     });
    //
    // });
    //
    // // delete a course
    // app.delete('/api/courses/:course_id', function(req, res) {
    //     Courses.remove({
    //         _id : req.params.course_id
    //     }, function(err, courses) {
    //         if (err)
    //             res.send(err);
    //
    //         // get and return all the courses after you create another
    //         Courses.find(function(err, courses) {
    //             if (err)
    //                 res.send(err)
    //             res.json(courses);
    //         });
    //     });
    // });
    //
    // // begin a class
    // app.post('/api/courses/startclass/:course_id', function(req, res) {
    //     var conditions = {_id : req.params.course_id};
    //     var update = {$set : {in_session : true}};
    //     var options = {upsert : true};
    //     Courses.update(conditions, update, options,
    //                 function(err, enrolleds) {
    //                     if (err)
    //                         res.send(err);
    //
    //                     //create new data db object for class set to active
    //                     Data.create({
    //                         course_id : req.body.course_id,
    //                         timestamp : Date.now(),
    //                         active: true,
    //                         data: {
    //                             latest_data : null,
    //                             archived_data : []
    //                             }
    //                     }, function(err, course) {
    //                         if (err)
    //                             res.send(err);
    //
    //                         // get and return all the courses after you create another
    //                         Courses.find(function(err, courses) {
    //                             if (err)
    //                                 res.send(err)
    //                             res.json(courses);
    //                         });
    //                     });
    //
    //                     //res.json(enrolleds);
    //         }
    //     );
    // });
    //
    // // end a class
    // app.post('/api/courses/endclass/:course_id', function(req, res) {
    //     var conditions = {_id : req.params.course_id};
    //     var update = {$set : {in_session : false}};
    //     var options = {upsert : true};
    //     Courses.update(conditions, update, options,
    //                 function(err, enrolleds) {
    //                     if (err)
    //                         res.send(err);
    //
    //                     // archive the active Data instance
    //                     Data.findOne({
    //                             course_id : req.body.course_id,
    //                             active : true},
    //                             function (err, dataEntry) {
    //                                 var dataObject = dataEntry.data;
    //                                 console.log(dataObject);
    //
    //                                 //push dataObject.latest_data onto dataObject.archived_data
    //                                 dataObject.archived_data.push(dataObject.latest_data);
    //                                 //make newDataInstant most recent dataObject
    //                                 dataObject.latest_data = {};
    //
    //                                 //update data in database
    //                                 var conditions = {
    //                                     course_id : req.params.course_id,
    //                                     active : true};
    //                                 var update = {$set : {data : dataObject, active : false}};
    //                                 var options = {upsert : true};
    //                                 Data.update(conditions, update, options,
    //                                             function(err, endData) {
    //                                                 if (err)
    //                                                     res.send(err);
    //
    //                                                 //res.json(enrolleds);
    //                                             }
    //                                 );
    //                         //res.json(enrolleds); // return all courses in JSON format
    //                     });
    //
    //                     res.json(enrolleds);
    //         }
    //     );
    // });
    //
    // //enroll/drop api ==========================================================
    // app.get('/api/enrolled', function(req, res) {
    //
    //     // use mongoose to get all courses in the database
    //     Enrolled.find(function(err, enrolleds) {
    //
    //         // if there is an error retrieving, send the error. nothing after res.send(err) will execute
    //         if (err)
    //             res.send(err)
    //
    //         res.json(enrolleds); // return all courses in JSON format
    //     });
    // });
    //
    // app.post('/api/courses/enroll', function(req, res) {
    //
    //     // create a course, information comes from AJAX request from Angular
    //     Enrolled.create({
    //         user_id : req.body.user_id,
    //         course_id : req.body.course_id,
    //         role_in_course : req.body.role_in_course
    //     }, function(err, enrolled) {
    //         if (err)
    //             res.send(err);
    //
    //         // get and return all the courses after you create another
    //         Enrolled.find(function(err, enrolleds) {
    //             if (err)
    //                 res.send(err)
    //             res.json(enrolleds);
    //         });
    //     });
    //
    // });
    //
    // app.delete('/api/courses/drop/:enrolled_id', function(req, res) {
    //
    //     // create a course, information comes from AJAX request from Angular
    //     Enrolled.remove({
    //         _id : req.params.enrolled_id
    //     }, function(err, enrolleds) {
    //         if (err)
    //             res.send(err);
    //
    //         // get and return all the courses after you create another
    //         Enrolled.find(function(err, enrolleds) {
    //             if (err)
    //                 res.send(err)
    //             res.json(enrolleds);
    //         });
    //     });
    //
    // });
    //
    // //vote api =================================================================
    // app.post('/api/vote', function(req, res) {
    //     console.log('1');
    //     if (req.body.old_vote != req.body.new_vote) {
    //         console.log('2');
    //         // use mongoose to get all courses in the database
    //         Courses.findOne({_id : req.body.course_id},
    //                     function(err, course) {
    //                         console.log('3');
    //                         // if there is an error retrieving, send the error. nothing after res.send(err) will execute
    //                         if (err)
    //                             res.send(err)
    //                         console.log(course);
    //                         console.log(typeof course.in_session);
    //                         if (course.in_session) {
    //                             console.log('4');
    //                             //note for later - check if user id is enrolled in class before continuing
    //                             //update data object
    //                             Data.findOne({
    //                                     course_id : req.body.course_id,
    //                                     active : true},
    //                                     function (err, dataEntry) {
    //                                         console.log('5');
    //                                         var dataObject = dataEntry.data;
    //                                         console.log(dataObject);
    //
    //                                         //create new dataInstantObject
    //                                         console.log(dataObject.latest_data);
    //
    //                                         var newDataInstant;
    //                                         //!!!!this does not evaluate correctly, and latest_data remains null even the second time through
    //                                         if (dataObject.latest_data != null) {
    //                                             newDataInstant = {num_up_votes: dataObject.latest_data.num_up_votes + req.body.new_vote,
    //                                                                 num_down_votes: dataObject.latest_data.num_up_votes - req.body.new_vote,
    //                                                                 timestamp: Date.now()};
    //                                         } else {
    //                                             newDataInstant = {num_up_votes: req.body.new_vote,
    //                                                                 num_down_votes: req.body.new_vote,
    //                                                                 timestamp: Date.now()};
    //                                         }
    //
    //
    //                                         //push dataObject.latest_data onto dataObject.archived_data
    //                                         dataObject.archived_data.push(dataObject.latest_data);
    //                                         //make newDataInstant most recent dataObject
    //                                         dataObject.latest_data = newDataInstant;
    //
    //                                         //update data in database
    //                                         var conditions = {
    //                                             course_id : req.params.course_id,
    //                                             active : true
    //                                         };
    //                                         var update = {$set : {data : dataObject}};
    //                                         var options = {upsert : true};
    //                                         Data.update(conditions, update, options,
    //                                                     function(err, endData) {
    //                                                         console.log('6');
    //                                                         if (err)
    //                                                             res.send(err);
    //
    //                                                         res.json(0);
    //                                                     });
    //                                     });
    //                                 //res.json(enrolleds); // return all courses in JSON format
    //                             } //else invalid change
    //                     });
    //     } //else invalid change
    // });
    //
    // // application -------------------------------------------------------------
    // app.get('/relations', function(req, res) {
    //     res.sendfile('./public/relations.html'); // load the single view file (angular will handle the page changes on the front-end)
    // });
    //
    // app.get('/courses', function(req, res) {
    //     res.sendfile('./public/courses.html'); // load the single view file (angular will handle the page changes on the front-end)
    // });

    app.get('/', function (req, res) {
        res.send('Hello World!');
    });

    // listen (start app with node server.js) ======================================
    app.listen(8080, function () {
        console.log('Example app listening at 8080');
    });
