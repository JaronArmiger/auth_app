require('dotenv').config();

const createError = require('http-errors');
const http = require('http');
const debug = require('debug')('local-library:server');
const express = require('express');
const path = require('path');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const validator = require('express-validator');
const bcrypt = require('bcryptjs');
const User = require('./models/user');

const mongoose = require('mongoose');
const mongoDB = process.env.MONGODB_URI;
mongoose.connect(mongoDB, { useUnifiedTopology: true,
  useNewUrlParser: true });
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'mongo connection error'));

//const signupRouter = require('./routes/sign-up');

const app = express();

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

app.use(session({secret: 'cats', resave: false, saveUninitialized: true }));

passport.use(
  new LocalStrategy((username, password, done) => {
    User.findOne({ username: username }, (err, user) => {
      if (err) {
      	return done(err);
      };
      if (!user) {
      	return done(null, false, { msg: 'Incorrect username' });
      };
      bcrypt.compare(password, user.password, (err, res) => {
        if (res) {
          return done(null, user);
        } else {
          return done(null, false, {msg: "Incorrect password"});
        }
      });
      return done(null, user);
    });
  })
);

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

app.use(function(req, res, next) {
  res.locals.currentUser = req.user;
  next();
});

app.get('/', (req, res) => { 
  res.render('index');
});
app.post('/log-in', passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/'
  })
);
app.get('/log-out', (req, res) => {
  req.logout();
  res.redirect('/');
});

app.get('/sign-up', (req, res) => {
  res.render('sign-up-form');
});
app.post('/sign-up', [
  validator.body('username', 'You gotta enter a username')
     .trim().isLength({ min: 1 }),
  validator.sanitizeBody('username').escape(),
  validator.sanitizeBody('password').escape(),

  (req, res, next) => {
    bcrypt.hash(req.body.password, 10, (err, hashed) => {
        if (err) return next(err);
        const user = new User({
          username: req.body.username,
          password: hashed
        }).save(err => {
          if (err) return next(err);
          res.redirect("/");
        });
    });
  }
]);

app.use(function(req, res, next) {
  next(createError(404));
});

app.use(function(err, req, res, next) {
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  res.status(err.status || 500);
  res.render('error');
});

const server = http.createServer(app);
server.listen(3000);