// require env variables (base_url)
require('dotenv').config();
var passport = require('passport');
// passport login methods are called strategies
var passportFacebookStrategy = require('passport-facebook').Strategy;
var passportLocalStrategy = require('passport-local').Strategy;

var db = require('../models');

// provide serialize/deserialize functions (passport + session functionality)
passport.serializeUser(function(user, callback) {
  callback(null, user.id);
});

passport.deserializeUser(function(id, callback) {
  db.user.findById(id).then(function(user) {
    callback(null, user);
  }).catch(function(err) {
    callback(err, null);
  });
});

// login code
passport.use(new passportLocalStrategy({
  // this gets the "thing" to work on
  usernameField: 'email',
  passwordField: 'password'
}, function(email, password, done) {
  // this does the work on the thing
  db.user.findOne({
    where: { email: email }
  }).then(function(foundUser) {
    // !foundUser first because if it's null you can't do password check
    if(!foundUser || !foundUser.isValidPassword(password)) {
      // first arg is err, second is "the thing" in this case null none found
      done(null, null);
    }
    else {
      done(null, foundUser);
    }
  }).catch(function(err) {
    done(err, null);
  })
}));

passport.use(new passportFacebookStrategy({
  clientID: process.env.FB_APP_ID,
  clientSecret: process.env.FB_APP_SECRET,
  callbackURL: process.env.BASE_URL + '/auth/callback/facebook',
  profileFields: ['id', 'email', 'displayName'],
  enableProof: true
}, function(accessToken, refreshToken, profile, done) {
  // see if we have an email address we can use for ident user
  // TODO doesn't this change the user if they change their facebook email?
  var facebookEmail = profile.emails ? profile.emails[0].value : null;

  // see if user exsits in table
  db.user.findOne({
    where: { email: facebookEmail }
  }).then(function(existingUser) {
    if (existingUser && facebookEmail) {
      // this user is a returning user - update facebookId and token
      existingUser.updateAttributes( {
        facebookId: profile.id,
        facebookToken: accessToken
      }).then(function(updatedUser){
        done(null, updatedUser);
      }).catch(done);
    }
    else {
      // person is a new user
      var usernameArr = profile.displayName.split(' ');

      db.user.findOrCreate({
        where: { facebookId: profile.id },
        defaults: {
          facebookToken: accessToken,
          email: facebookEmail,
          firstname: usernameArr[0],
          lastname: usernameArr[usernameArr.length - 1],
          admin: false,
          dob: profile.birthday,
          image: 'http://notarealaddress.barnie'
        }
      }).spread(function(user, wasCreated) {
        if (wasCreated) {
          // expected result
          done(null, user);
        }
        else {
          // user changed email on fb since last login
          user.facebookToken = accessToken;
          user.email = facebookEmail;
          user.save().then(function(updatedUser) {
            done(null, updatedUser).catch(done);
          })
        }
      });
    }
  });
}));

module.exports = passport;
