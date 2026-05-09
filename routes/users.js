const express = require('express');
const db = require('../custom_modules/sql/db_connector');
const users = express.Router();
const md5 = require('md5');
const { v4: uuidv4 } = require('uuid');

users.get('/', (req, res) => {
    res.send('This route is not implemented');
});

users.get('/login', (req, res) => {
    res.render('users/login');
});

users.get('/account', (req, res) => {
    res.render('users/account');
});

users.get('/logout', (req, res) => {
    const token = req.cookies?.SessionToken;

    if (!token) {
        res.clearCookie('SessionToken');
        return res.redirect('/');
    }

    db.query(
        "DELETE FROM userSessions WHERE sessionToken = ?",
        [token],
        (err) => {
            if (err) {
                console.error(err);
            }

            res.clearCookie('SessionToken');
            res.redirect('/');
        }
    );
});

users.post('/login', (req, res) => {

    const username = req.body.username.trim().toLowerCase();

    db.query(
        "SELECT * FROM users WHERE username = ?",
        [username],
        (err, result) => {

            if (err) {
                return res.send('DATABASE ERROR! ' + err);
            }

            if (result.length === 0) {
                return res.send("User not found");
            }

            const user = result[0];

            if (
                username === user.username.toLowerCase() &&
                md5(req.body.password) === user.passwd_hash
            ) {

                const sessionToken = uuidv4();

                db.query(
                    "INSERT INTO userSessions (userId, sessionToken) VALUES (?, ?)",
                    [user.ID, sessionToken],
                    (err2) => {

                        if (err2) {
                            return res.send("DATABASE ERROR " + err2);
                        }

                        res.cookie('SessionToken', sessionToken, {
                            httpOnly: true,
                            secure: false,
                            maxAge: 1000 * 60 * 60 * 24 * 365
                        });

                        res.redirect('/users/account');
                    }
                );

            } else {
                res.send("Invalid username or password");
            }
        }
    );
});

users.get('/new', (req, res) => {
    res.render('users/register');
});

users.post('/new', (req, res) => {

    db.query(
        "SELECT * FROM users WHERE username = ?",
        [req.body.username.toLowerCase()],
        (err, result) => {

            if (err) {
                return res.send('DATABASE ERROR! ' + err);
            }

            if (result.length > 0) {
                return res.send("Username already in use");
            }

            if (!req.body.username || req.body.username.trim() === '') {
                return res.send("Username cannot be empty!");
            }

            if (!req.body.password1 || req.body.password1.trim() === '') {
                return res.send("Password cannot be empty");
            }

            if (req.body.password1 !== req.body.password2) {
                return res.send("Passwords do not match!");
            }

            const passwdHash = md5(req.body.password1);

            db.query(
                "INSERT INTO users (username, email, passwd_hash, level) VALUES (?, ?, ?, ?)",
                [
                    req.body.username.toLowerCase(),
                    req.body.email,
                    passwdHash,
                    'Unverified'
                ],
                (err2, result2) => {

                    if (err2) {
                        return res.send("DATABASE ERROR " + err2);
                    }

                    const sessionToken = uuidv4();

                    db.query(
                        "INSERT INTO userSessions (userId, sessionToken) VALUES (?, ?)",
                        [result2.insertId, sessionToken],
                        (err3) => {

                            if (err3) {
                                return res.send("DATABASE ERROR " + err3);
                            }

                            res.cookie('SessionToken', sessionToken, {
                                httpOnly: true,
                                secure: false,
                                maxAge: 1000 * 60 * 60 * 24 * 365
                            });

                            res.redirect('/users/account');
                        }
                    );
                }
            );
        }
    );
});

module.exports = users;