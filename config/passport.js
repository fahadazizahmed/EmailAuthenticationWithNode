const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const User = require('../models/user');

// it store user cookies maintain session

passport.serializeUser((user, done) => {
    done(null, user.id);
});
// it find the user from that id

passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch(error) {
        done(error, null);
    }
});

//Now User Login Done here

passport.use('local', new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password',
    passReqToCallback: false
}, async (email, password, done) => {
    try {
        // 1) Check if the email already exists
        const user = await User.findOne({ 'email': email });
        if (!user) {
            return done(null, false, { message: 'Unknown User' });
        }

        // 2) Check if the password is correct
        const isValid = User.comparePasswords(password, user.password);
        if (!isValid) {
          return done(null, false, { message: 'Unknown Password' });
        }

        // 3) Check if email has been verified
        if (!user.active) {//here active=true so you need to verify email after email verify  we make database active=true and here is false

            return done(null, false, { message: 'Sorry, you must validate email first' });
        }

       return done(null, user);
    } catch(error) {
        return done(error, false);
    }
}));
