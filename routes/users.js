const express = require('express');
const { response } = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');

// User modal
const User = require('../models/User');

// Login
router.get('/login', (req, res) => {
    res.render("login");
});

// Register
router.get('/register', (req, res) => {
    res.render("register");
});

// register Handle
router.post('/register', (req, res) => {
    const { name, email, password, password2 } = req.body;
    let errors = [];

    // check require feilds
    if (!name || !email || !password || !password2) {
        errors.push({ msg: 'Please fill in all the feilds' });
    }

    if (password !== password2) {
        errors.push({ msg: 'Passwords do not match' });
    }

    // Check pass length
    if (password.length < 6) {
        errors.push({ msg: 'Password should be atleast 6 character long' });
    }

    if (errors.length > 0) {
        res.render('register', {
            errors,
            name,
            email,
            password,
            password2
        });
    } else {
        // Validation pass
        User.findOne({ email: email })
            .then(user => {
                if (user) {
                    errors.push({ msg: 'Email is already registered ' });
                    res.render('register', {
                        errors,
                        name,
                        email,
                        password,
                        password2
                    });
                } else {
                    const newUser = new User({
                        name,
                        email,
                        password
                    });

                    bcrypt.genSalt(10, (err, salt) => bcrypt.hash(newUser.password, salt, (err, hash) => {
                        if (err) throw err;
                        // set password to hashed
                        newUser.password = hash;
                        // save user
                        newUser.save()
                            .then(user => {
                                req.flash('success_msg', 'You are now registered and can log in');
                                res.redirect('/users/login');
                            })
                            .catch(err => console.log(err))
                    }))

                }
            });

    }
});

// Login Handle
router.post('/login', (req, res, next) => {
    passport.authenticate('local', {
        successRedirect: '/dashboard',
        failureRedirect: '/users/login',
        failureFlash: true
    })(req, res, next);
});


// Logout

router.get('/logout', (req, res) => {
    req.logout();
    req.flash('Success_msg', 'You are Logged out');
    res.redirect('/users/login');
});

module.exports = router;