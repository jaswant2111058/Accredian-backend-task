const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sendmail2 = require('../utils/mailSender')
const connection = require("../mysqlDB/connection")
const faker = require('faker')
const path = require("path")

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

                return res.status(500).json({
                    message: "Data Base is not working"
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
                    message: `user logged in`, user: {
                        user_id: results._id,
                        email: results.email,
                        username: results.userName,
                        token: token,
                        expires_in: new Date(Date.now() + 60 * 60 * 1000),
                    }
                });

            } else {

                res.status(401).json({ message: "user does not exist" })
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

                res.status(500).json({
                    message: " Data Base is not working "
                });
            }
            // Process the results
            if (results.length > 0) {
                res.status(401).send({ message: "email or user Name  allready exist" })

            } else {

                const token = jwt.sign({ password: password }, process.env.JWT_SECRET, {
                    expiresIn: `${1000 * 60 * 5}`
                });
                sendmail2(username, email, token,"/email/verify")

                res.status(200).send({ message: "Email has been sent to " + email })
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
        const token = req.query.token;
        const username = req.query.username;
        const email = req.query.email;

        // Verify JWT token
        const decodedToken = jwt.verify(token, process.env.JWT_SECRET);

        const hashedPassword = await bcrypt.hash(decodedToken.password, 12);

        // Prepare user detail object
        const detail = {
            _id: faker.datatype.uuid(),
            email: email,
            password: hashedPassword,
            userName: username
        };
        console.log(detail);

        // Insert data into the database
        const insertQuery = 'INSERT INTO userDetail SET ?';
        connection.query(insertQuery, detail, (error, results, fields) => {
            if (error) {
                console.error('Error inserting data: ' + error);
                res.status(500).json({ message: "Error inserting data" });
            } else {
                console.log('Data inserted successfully.');
                const filePath = path.join(__dirname, '../public/verifyEmail.html');
                res.sendFile(filePath);
            }
        });
    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Something went wrong" });
    }
};



exports.resetPassword = async (req, res) => {

    try {
        const { email, password } = req.body;

        const sqlQuery = `SELECT * FROM userDetail WHERE email = ?`;

        connection.query(sqlQuery, [email], (error, results, fields) => {
            if (error) {
                console.error('Error executing query:', error);

                res.status(500).json({
                    message: " Data Base is not working "
                });
            }
            // Process the results
            if (!(results.length > 0)) {
                res.status(400).send({ message: "email or user Name  not exist" })
            } else {

                const token = jwt.sign({ password: password }, process.env.JWT_SECRET, {
                    expiresIn: `${1000 * 60 * 5}`
                });
                sendmail2(results._id, email, token,"/password/reset/verify")
                res.status(200).send({ message: "Email has been sent to " + email })
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


exports.resetPasswordVerify = async (req, res) => {
    try {
        const token = req.query.token;
        const _id = req.query.username

        // Verify JWT token
        const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
        console.log(decodedToken);

        // Hash the password asynchronously
        const hashedPassword = await bcrypt.hash(decodedToken.password, 12);

        // Prepare user detail object
        const updatedDetails = {
            password: hashedPassword,
        };
        console.log(updatedDetails);

        // Update data in the database
        const updateQuery = 'UPDATE userDetail SET ? WHERE _id = ?';
        connection.query(updateQuery, [updatedDetails, _id], (error, results, fields) => {
            if (error) {
                console.error('Error updating data: ' + error);
                res.status(500).json({ message: "Error updating data" });
            } else {
                console.log('Data updated successfully.');
                const filePath = path.join(__dirname, '../public/emailSend.html');
                res.sendFile(filePath);
            }
        });
    } catch (err) {
        console.log(err);
        res.status(500).json({
            message: "Something went wrong"
        });
    }
}



