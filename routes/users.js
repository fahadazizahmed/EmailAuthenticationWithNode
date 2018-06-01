const express = require('express');
const router = express.Router();
const Joi = require('joi');
const User = require('../models/user');
const passport = require('passport');
const randomstring = require('randomstring');
const mailer = require('../misc/mailer');


// Validation Schema
const userSchema = Joi.object().keys({
  email: Joi.string().email().required(),
  username: Joi.string().required(),
  password: Joi.string().regex(/^[a-zA-Z0-9]{3,30}$/).required(),
  confirmationPassword: Joi.any().valid(Joi.ref('password')).required()
});

// now we can directly see the http://localhost:5700/users/dashboard although user is not login we need to fix that here

// Authorization Function

const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
//if(req.user){//it  work same as above
    return next();
  } else {
    req.flash('error', 'Sorry, but you must be registered first!');
    res.redirect('/');
  }
};


const isNotAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    req.flash('error', 'Sorry, but you are already logged in!');
    res.redirect('/');
  } else {
    return next();
  }
};

router.get('/register', isNotAuthenticated,function(req, res)//if user is lgin and we hit this url it work so to avoid this we use isnotAutheticate MIDDLE
   {
     res.render('register');
  });

  //user Registration

  router.post('/register',async function(req,res,next)
  {
      try
      {
        // check validation and show flash message
        const result = Joi.validate(req.body,userSchema);//first argument which thing you want to validate second is against which schema
        console.log("result",result);
          if(result.error){
            req.flash('error','Data is not valid.Please try again')
            res.redirect('/users/register')
            return;
          }
    // Here we check if email already exist in database
          const user = await User.findOne({ 'email': result.value.email });//can also req.body.email and find one method find the specific record mean table propert name is email and value we give req.value.email

         if(user){
           req.flash('error','Emai is already Exist')
           res.redirect('/users/register')
           return;
         }


    //Here we hashing the Password
    console.log("password",result.value.password)
    const hash = await User.hashPassword(result.value.password);
    console.log('hash',hash);

    // here we generate secret token
    const secretToken = randomstring.generate();
      console.log('secretToken', secretToken);
      // Save secret token to the DB
    result.value.secretToken = secretToken;
    // Flag account as inactive
    result.value.active = false;




    // Save data to database
    delete result.value.confirmationPassword;
    result.value.password= hash;
    console.log("New value",result.value);
    const newUser = await new User(result.value);
    console.log("New User",newUser);
    await newUser.save();

    // Compose email
      const html = `Hi there,
      <br/>
      Thank you for registering!
      <br/><br/>
      Please verify your email by typing the following token:
      <br/>
      Token: <b>${secretToken}</b>
      <br/>
      On the following page:
      <a href="http://localhost:5700/users/verify">http://localhost:5700/users/verify</a>
      <br/><br/>
      Have a pleasant day.`

      // Send email
      await mailer.sendEmail('fahad.aziz@miranz.net', result.value.email, 'Please verify your email!', html);

    req.flash('success','Please Check your Email')
    res.redirect('/users/login')
    // User Register Flow is end


      }




      catch(error){
        next(error);
      }
 });

router.get('/login',isNotAuthenticated,function(req, res) {
    res.render('login');
  });
  router.post('/login',passport.authenticate('local',{
    successRedirect: '/users/dashboard',
    failureRedirect: '/users/login',
    failureFlash: true

  }));
  router.get('/dashboard',isAuthenticated,function(req, res) {//middleware is between req and res when url hit there is middeleware authenticate it hit if authenticate then next mean next code after autheticate show dashbaord is run else if this middleware hit else part the code of after isAutheticate in this function is not run
    console.log('user',req.user);// it tell all the information of user currently login here we maintain the session
      res.render('dashboard',{usernames:req.user.username});
    });

    router.get('/logout',isAuthenticated,function(req, res){
      req.logout();
     req.flash('success', 'Successfully logged out. Hope to see you soon!');
    // res.render('index');//this mean url http://localhost:5700/users/logout show index view
     res.redirect('/');//this mean change url http://localhost:5700/users/logout to localhost:5700/ and at this url hit show index view

    });

    router.get('/verify', isNotAuthenticated,function(req, res)//if user is lgin and we hit this url it work so to avoid this we use isnotAutheticate MIDDLE
       {
         res.render('verify');
      });


      router.post('/verify',async function(req, res)//if user is lgin and we hit this url it work so to avoid this we use isnotAutheticate MIDDLE
         {
           try {
       const secretToken = req.body.secretToken;

       // Find account with matching secret token
       const user = await User.findOne({ 'secretToken': secretToken.trim() });
       if (!user) {
         req.flash('error', 'No user found.');
         res.redirect('/users/verify');
         return;
       }

       user.active = true;
       user.secretToken = '';
       await user.save();
       // now we compose the email

       req.flash('success', 'Thank you! Now you may login.');
       res.redirect('/users/login');
     } catch(error) {
       next(error);
     }
        });




module.exports = router;
