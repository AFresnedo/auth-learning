var express = require('express');
var passport = require('../config/passportConfig');

var db = require('../models');

var router = express.Router();


router.get('/login', function(req, res) {
  res.render('auth/login');
});

router.post('/login', passport.authenticate('local', {
  successRedirect: '/profile',
  successFlash: 'Logged in.',
  failureRedirect: '/auth/login',
  failureFlash: 'Could not log in.'
}));

router.get('/signup', function(req, res) {
  res.render('auth/signup');
});

router.post('/signup', function(req, res) {
  console.log(req.body);
  // defaults is important in following code, adds the input to db
  db.user.findOrCreate({
    where: { email: req.body.email },
    defaults: req.body
  }).spread(function(user, wasCreated) {
    if (wasCreated) {
      // automatically log user in using local strategy
      passport.authenticate('local', {
        successRedirect: '/profile',
        successFlash: 'Successfully registered!',
        failureRedirect: '/',
        failureFlash: 'Could not log in.'
      })(req, res);
    }
    else {
      // TODO give user already-created message
      req.flash('error', 'Please login');
      res.redirect('/auth/login');
    }
  }).catch(function(err) {
    // req.flash is a new function by flash i assume
    // "what kind of thing is it", "message"
    req.flash('error', err.message);
    res.redirect('/auth/signup');
  });
});

router.get('/logout', function(req, res) {
  req.logout(); // logs out of session
  req.flash('success', 'Successfully logged out!');
  res.redirect('/');
});

// oAUTH routes

// this calls the passport-facebook strategy
router.get('/facebook', passport.authenticate('facebook', {
  scope: ['public_profile', 'email']
}));

// common format for oAuth.../callback/thing
// you're going to "call it with some login info"
// so this is here for facebook to give you a response after facebook checks
// handle response/callback from facebook
router.get('/callback/facebook', passport.authenticate('facebook',
  {
  successRedirect: '/profile',
  successFlash: 'facebook login successful',
  failureRedirect: '/auth/login',
  failureFlash: 'failed to login with facebook'
  }
));

module.exports = passport;

module.exports = router;
