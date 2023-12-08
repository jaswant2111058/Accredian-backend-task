const users = require('../models/users');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sendmail2 = require('../utils/mailSender')
const connection = require("../mysqlDB/connection")
const faker = require('faker')

// --------------authMiddleware-----------------

// attach team_id (mongodb) with req
exports.authMiddleware = async (req, res, next) => {
    try {

        const authorization_header_token = req.headers.authorization;
        if (!authorization_header_token) {
            return res.status(401).json({
                message: "Unauthorized"
            });
        }
        const token = authorization_header_token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        const sqlQuery = `SELECT * FROM userDetail WHERE email = ?`;

        connection.query(sqlQuery, [decoded.email], (error, results, fields) => {
            if (error) {
                console.error('Error executing query:', error);
                connection.end();
                return res.status(500).json({
                    message: " Data Base is not working "
                });

            }

            // Process the results
            if (results.length > 0) {
                req.email = decoded.email;
                next();

            } else {
                return res.status(401).json({
                    message: "Unauthorized"
                });
            }

        });


    } catch (error) {
        if (error instanceof jwt.TokenExpiredError) {
            return res.status(401).json({
                message: "Token expired"
            });
        }

        console.log(typeof (error));
        res.status(500).json({
            message: "Something went wrong"
        });
    }
}

// -------------- authControllers --------------



exports.login = async (req, res) => {
    try {
        const { email_userName, password } = req.body;
        console.log(req.body)

        const sqlQuery = `SELECT * FROM userDetail WHERE userName = ? OR email = ?`;

        connection.query(sqlQuery, [email_userName, email_userName], (error, results, fields) => {
            if (error) {
                console.error('Error executing query:', error);
                connection.end();
                res.status(500).json({
                    message: " Data Base is not working "
                });
            }

            // Process the results
            if (results.length > 0) {

                // check if password is correct
                const isPasswordCorrect = bcrypt.compare(password, results.password);
                if (!isPasswordCorrect) {
                    return res.status(401).json({
                        message: "Incorrect password"
                    });
                }
                // generate jwt
                const token = jwt.sign({ email: results.email }, process.env.JWT_SECRET, {
                    expiresIn: "1d"
                });

                // update login_count
                res.status(200).send({
                    massage: `user logged in`, user: {
                        user_id: results._id,
                        email: results.email,
                        username: results.username,
                        token: token,
                        expires_in: new Date(Date.now() + 60 * 60 * 1000),
                    }
                });

            } else {
                connection.end();
                res.status(200).json({ massage: "user does not exist" })
            }

        });

    } catch (error) {
        console.log(error);
        res.status(500).json({
            message: "Something went wrong"
        });
    }
}

exports.signup = async (req, res) => {
    try {
        const {
            username,
            email,
            password
        } = req.body

        const sqlQuery = `SELECT * FROM userDetail WHERE userName = ? OR email = ?`;

        connection.query(sqlQuery, [username, email], (error, results, fields) => {
            if (error) {
                console.error('Error executing query:', error);
                connection.end();
                res.status(500).json({
                    message: " Data Base is not working "
                });
            }

            // Process the results
            if (results.length > 0) {
                connection.end();

                res.send({ message: "email or user Name  allready exist" })

            } else {

                const token = jwt.sign({ password: password }, process.env.JWT_SECRET, {
                    expiresIn: `${1000 * 60 * 5}`
                });
                sendmail2(username, email, token)
                connection.end();
                res.status(200).sendFile(__dirname + "../public/page/emailSend.html")
            }

        });
    }
    catch (err) {
        console.log(err);
        res.status(500).json({
            message: "Something went wrong"
        });
    }
}


exports.verifySave = async (req, res) => {

    try {

        const token = req.query.token
        const username = req.query.username
        const email = req.query.email
        const password = jwt.verify(token, process.env.JWT_SECRET);
        if (password) {
            bcrypt.hash(password.password, 12, async function (err, hash) {

                const detail = { _id: faker.datatype.uuid(), email: email, password: hash, username: username }
                const insertQuery = 'INSERT INTO userDetail SET ?';
                connection.query(insertQuery, detail, (error, results, fields) => {
                    if (error) {
                        console.error('Error inserting data: ' + error);
                    } else {
                        console.log('Data inserted successfully.');
                        connection.end();
                        res.sendFile(__dirname + "../public/pages/verifyEmail.html")
                    }

                });

            })
        }

    } catch (err) {
        console.log(err);
        res.status(500).json({
            message: "Something went wrong"
        });
    }

}


exports.resetPassword = async (req, res) => {

    try {
        const { email, otp, password } = req.body;
        const user = await users.findOne({ email });

        if (!user) {
            return res.status(400).json({
                message: "user email does not exist"
            });
        }
        if (user.otp == otp) {
            bcrypt.hash(password, 12, async function (err, hash) {
                await users.updateOne({ email }, { password: hash })
            })
            res.status(200).json({
                message: "password changed successfully",

            });
        }
        else {
            res.send(
                {
                    massage: 'enter otp is not correct'
                }
            ).status(400)
        }
    } catch (err) {
        console.log(err);
        res.status(500).json({
            message: "Something went wrong"
        });
    }
}



