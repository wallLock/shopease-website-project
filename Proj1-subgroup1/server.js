const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
// Create a MySQL connection pool
const pool = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: '123456',
    database: 'shopeadb',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});


function sendVerificationEmail(email) {
    const transporter = nodemailer.createTransport({
        service: 'Outlook365', // Replace with your email service
        auth: {
            user: 'Testuseryt2023@outlook.com', // Replace with your Outlook email
            pass: 'oldpassword123' // Replace with your Outlook password
        }
    });

    const verificationUrl = `http://localhost:8080/api/verifyaccount`; // Update with your verification URL

    const mailOptions = {
        from: '"ShopEase" <Testuseryt2023@outlook.com>', // Replace with your sender address
        to: email, // Receiver's email address
        subject: 'Account Verification', // Subject line
        text: `Please verify your account by clicking on this link: ${verificationUrl}`,
        html: `<p>Please click on the link below to verify your account:</p><a href="${verificationUrl}">${verificationUrl}</a>`
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log('Error sending email: ', error);
        } else {
            console.log('Verification email sent: ' + info.response);
        }
    });
}

function registerAPI(req, res) {
    try {
        let body = '';
        req.on('data', chunk => {
            body += chunk.toString();
        });

        req.on('end', () => {
            const data = JSON.parse(body);
            const { email, password, username, phone_number, address } = data;

            // Check if the email already exists in the database
            pool.query('SELECT * FROM accountinfo WHERE email = ?', [email], (error, results) => {
                if (error) {
                    console.error('Error:', error);
                    res.writeHead(500, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ message: 'Error occurred while registering user.' }));
                } else {
                    if (results.length > 0) {
                        // Email already exists, return an error
                        res.writeHead(400, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ message: 'Email already exists. Please choose a different email.' }));
                    } else {
                        // Check if the username already exists in the database
                        pool.query('SELECT * FROM accountinfo WHERE username = ?', [username], (error, results) => {
                            if (error) {
                                console.error('Error:', error);
                                res.writeHead(500, { 'Content-Type': 'application/json' });
                                res.end(JSON.stringify({ message: 'Error occurred while registering user.' }));
                            } else {
                                if (results.length > 0) {
                                    res.writeHead(400, { 'Content-Type': 'application/json' });
                                    res.end(JSON.stringify({ message: 'Username already exists. Please choose a different username.' }));
                                } else {
                                    // Hash the password before inserting into the database
                                    bcrypt.hash(password, 10, (hashError, hashedPassword) => {
                                        if (hashError) {
                                            console.error('Error hashing password:', hashError);
                                            res.writeHead(500, { 'Content-Type': 'application/json' });
                                            res.end(JSON.stringify({ message: 'Error occurred while hashing password.' }));
                                        } else {
                                            // Insert the user with the hashed password
                                            pool.query('INSERT INTO accountinfo (email, password, username, phone_number, address) VALUES (?, ?, ?, ?, ?)',
                                                [email, hashedPassword, username, phone_number, address], (insertError) => {
                                                    if (insertError) {
                                                        console.error('Error:', insertError);
                                                        res.writeHead(500, { 'Content-Type': 'application/json' });
                                                        res.end(JSON.stringify({ message: 'Error occurred while registering user.' }));
                                                    } else {
                                                        res.writeHead(200, { 'Content-Type': 'application/json' });
                                                        res.end(JSON.stringify({ message: 'User registered successfully!' }));
                                                        sendVerificationEmail(email);
                                                    }
                                                });
                                        }
                                    });
                                }
                            }
                        });
                    }
                }
            });
        });
    } catch (error) {
        console.error('Error parsing JSON:', error);
    }
} //function api calls end here

function loginAPI(req, res) {
    try {
        let body = '';
        req.on('data', chunk => {
            body += chunk.toString();
        });

        req.on('end', () => {
            const data = JSON.parse(body);
            const { emailOrUsername, password } = data;

            pool.query(
                'SELECT * FROM accountinfo WHERE email = ? OR username = ?',
                [emailOrUsername, emailOrUsername],
                (error, results) => {
                    if (error) {
                        console.error('Error:', error);
                        res.writeHead(500, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ message: 'An error occurred during login.' }));
                    } else {
                        if (results.length > 0) {
                            const user = results[0];

                            bcrypt.compare(password, user.password, (compareErr, isMatch) => {
                                if (compareErr) {
                                    console.error('Error comparing passwords:', compareErr);
                                    res.writeHead(500, { 'Content-Type': 'application/json' });
                                    res.end(JSON.stringify({ message: 'An error occurred during login.' }));
                                } else {
                                    if (isMatch) {
                                        // Passwords match, generate JWT token
                                        const secretKey = 'your-secret-key'; // Replace with a secure secret key
                                        const token = jwt.sign({ userId: user.id, username: user.username }, secretKey, { expiresIn: '1h' });

                                        res.writeHead(200, {
                                            'Content-Type': 'application/json',
                                            'Authorization': `Bearer ${token}`
                                        });

                                        res.end(JSON.stringify({ message: 'Login successful', token }));
                                    } else {
                                        // Passwords do not match
                                        res.writeHead(401, { 'Content-Type': 'application/json' });
                                        res.end(JSON.stringify({ message: 'Incorrect password' }));
                                    }
                                }
                            });
                        } else {
                            // User does not exist
                            res.writeHead(404, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify({ message: 'User not found' }));
                        }
                    }
                }
            );
        });
    } catch (error) {
        console.error('Error parsing JSON:', error);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ message: 'An error occurred during login.' }));
    }
}


function changepasswordAPI(req, res) {
    let body = '';
    req.on('data', (chunk) => {
        body += chunk.toString(); // Convert Buffer to string
    });

    req.on('end', () => {
        try {
            const {old_password, new_password, repeat_password } = JSON.parse(body);

            // Check if new passwords match
            if (new_password !== repeat_password) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ message: 'New passwords do not match.' }));
                return;
            }

            // Retrieve the authorization token from the request headers
            const authToken = req.headers.authorization;

            if (!authToken) {
                res.writeHead(401, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ message: 'Unauthorized - Missing token' }));
                return;
            }

            // Extract the token part
            const token = authToken.split(' ')[1];

            jwt.verify(token, 'your-secret-key', (err, decoded) => {
                if (err) {
                    res.writeHead(401, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ message: 'Unauthorized - Invalid token' }));
                } else {
                    // Here, you can fetch user-specific data from the database using the decoded information
                    const userId = decoded.userId;

                    // Retrieve the user from the database
                    pool.query('SELECT * FROM accountinfo WHERE id = ?', [userId], (error, results) => {
                        if (error || results.length === 0) {
                            res.writeHead(404, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify({ message: 'User not found.' }));
                            return;
                        }

                        const user = results[0];

                        // Check if the old password matches the one in the database using bcrypt
                        bcrypt.compare(old_password.trim(), user.password, (compareError, isMatch) => {
                            if (compareError || !isMatch) {
                                // Old password does not match
                                res.writeHead(401, { 'Content-Type': 'application/json' });
                                res.end(JSON.stringify({ message: 'Old password is incorrect.' }));
                                return;
                            }

                            // Hash the new password before updating
                            bcrypt.hash(new_password, 10, (hashError, hashedPassword) => {
                                if (hashError) {
                                    res.writeHead(500, { 'Content-Type': 'application/json' });
                                    res.end(JSON.stringify({ message: 'Error hashing the new password.' }));
                                    return;
                                }

                                // Update the password in the database with the hashed password
                                pool.query('UPDATE accountinfo SET password = ? WHERE id = ?', [hashedPassword, userId], (updateError) => {
                                    if (updateError) {
                                        res.writeHead(500, { 'Content-Type': 'application/json' });
                                        res.end(JSON.stringify({ message: 'Error updating password in the database.' }));
                                        return;
                                    }

                                    res.writeHead(200, { 'Content-Type': 'application/json' });
                                    res.end(JSON.stringify({ message: 'Password changed successfully.' }));
                                });
                            });
                        });
                    });
                }
            });
        } catch (jsonError) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ message: 'Bad Request - Invalid JSON format.' }));
        }
    });
}

// Modify your viewProfileAPI function
function viewProfileAPI(req, res) {
    const authToken = req.headers.authorization;

    if (!authToken) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized - Missing token' }));
        return;
    }

    const token = authToken.split(' ')[1]; // Extract the token part

    jwt.verify(token, 'your-secret-key', (err, decoded) => {
        if (err) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Unauthorized - Invalid token' }));
        } else {
            // Here, you can fetch user-specific data from the database using the decoded information
            const userId = decoded.userId;            
            pool.query('SELECT * FROM accountinfo WHERE id = ?', [userId], (error, results) => {
                if (error || results.length === 0) {
                    res.writeHead(404, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ message: 'User not found.' }));
                    return;
                }

                const userData = {
                    username: results[0].username,
                    email: results[0].email,
                    phone: results[0].phone_number,
                    address: results[0].address
                    // Add other user data properties
                };

                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(userData));
            });
        }
    });
}
function getUsername(req, res) {
    const authToken = req.headers.authorization;
    if (!authToken) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized - Missing token' }));
        return;
    }

    const token = authToken.split(' ')[1];

    jwt.verify(token, 'your-secret-key', (err, decoded) => {
        if (err) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Unauthorized - Invalid token' }));
        } else {
            const username = decoded.username;

            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ username: username }));
        }
    });
}

function updateProfileAPI(req, res) { /////////////new updated
    let body = '';
    req.on('data', (chunk) => {
        body += chunk.toString(); // Convert Buffer to string
    });
    req.on('end', () => {
        try {
            const parsedobject = JSON.parse(body);
            const keys = Object.keys(parsedobject);
            // Retrieve the authorization token from the request headers
            const authToken = req.headers.authorization;

            if (!authToken) {
                res.writeHead(401, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ message: 'Unauthorized - Missing token' }));
                return;
            }

            // Extract the token part
            const token = authToken.split(' ')[1];

            jwt.verify(token, 'your-secret-key', (err, decoded) => {
                if (err) {
                    res.writeHead(401, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ message: 'Unauthorized - Invalid token' }));
                } else {
                    // Here, you can fetch user-specific data from the database using the decoded information
                    const userId = decoded.userId;

                    // Retrieve the user from the database
                    pool.query('SELECT * FROM accountinfo WHERE id = ?', [userId], (error, results) => {
                        if (error || results.length === 0) {
                            res.writeHead(404, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify({ message: 'User not found.' }));
                            return;
                        }
                        keys.forEach(key=>{
                            switch (key) {
                                case 'address':
                                    // Update address in the database
                                    pool.query('UPDATE accountinfo SET address = ? WHERE id = ?', [parsedobject[keys], userId], (updateError) => {
                                        handleUpdateResponse(res, updateError);
                                    });
                                    break;
                                case 'phone':
                                    // Update phone in the database

                                    pool.query('SELECT * FROM accountinfo WHERE phone_number = ?', [parsedobject[keys]], (error, results) => {
                                        if(error){
                                            console.error('Error:', error);
                                            res.writeHead(500, { 'Content-Type': 'application/json' });
                                            res.end(JSON.stringify({ message: 'Error occurred while validating user.' }));
                                        }else{
                                            if (results.length > 0) { //user name already existed
                                                res.writeHead(400, { 'Content-Type': 'application/json' });
                                                res.end(JSON.stringify({ message: 'Phone number already exists. Please choose a different phone number.' }));
                                            } else { //no existed username, changing proceed
                                                pool.query('UPDATE accountinfo SET phone_number = ? WHERE id = ?', [parsedobject[keys], userId], (updateError) => {
                                                    handleUpdateResponse(res, updateError);
                                                });
                                            }
                                        }
                                    } );

                                    
                                    break;
                                case 'username':
                                    // Update username in the database
                                    pool.query('SELECT * FROM accountinfo WHERE username = ?', [parsedobject[keys]], (error, results) => {
                                        if(error){
                                            console.error('Error:', error);
                                            res.writeHead(500, { 'Content-Type': 'application/json' });
                                            res.end(JSON.stringify({ message: 'Error occurred while validating user.' }));
                                        }else{
                                            console.log(results);
                                            if (results.length > 0) { //user name already existed
                                                console.log("if get called");
                                                res.writeHead(400, { 'Content-Type': 'application/json' });
                                                res.end(JSON.stringify({ message: 'Username already exists. Please choose a different username.' }));
                                            } else { //no existed username, changing proceed
                                                console.log('else get called');
                                                pool.query('UPDATE accountinfo SET username = ? WHERE id = ?', [parsedobject[keys], userId], (updateError) => {
                                                    handleUpdateResponse(res, updateError);
                                                });
                                            }
                                        }
                                    } );
                                    
                                    break;
                                default:
                                    res.writeHead(400, { 'Content-Type': 'application/json' });
                                    res.end(JSON.stringify({ message: 'Invalid update type' }));
                                    return;
                            }
                        })
                    });
                }
            });
        } catch (jsonError) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ message: 'Bad Request - Invalid JSON format.' }));
        }
    });
}

function handleUpdateResponse(res, updateError) {
    if (updateError) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ message: 'Error updating data in the database.' }));
    } else {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ message: 'Update successful' }));
    }
}

function sendPasswordResetEmail(email, token) {
    const transporter = nodemailer.createTransport({
        service: 'Outlook365', // Outlook service
        auth: {
            user: 'Testuseryt2023@outlook.com', //Outlook email
            pass: 'oldpassword123' //Outlook password
        }
    });

    const resetUrl = `http://localhost:8080/api/resetPassword?token=${token}`;

    const mailOptions = {
        from: '"Testuser" <Testuseryt2023@outlook.com>', // sender address
        to: email, // receiver
        subject: 'Password Reset', // Subject line
        text: `You requested a password reset. Please go to this link to reset your password: ${resetUrl}`,
        html: `<p>You requested a password reset. Please click on the link below to reset your password:</p><a href="${resetUrl}">${resetUrl}</a>`
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log('Error sending email: ', error);
        } else {
            console.log('Email sent: ' + info.response);
        }
    });
}

function resetPasswordRequestAPI(req, res) {
    let body = '';
    req.on('data', chunk => {
        body += chunk.toString();
    });

    req.on('end', () => {
        const { email } = JSON.parse(body);

        // Generate a unique token
        const newToken = crypto.randomBytes(20).toString('hex');

        // Store the token in the database with a timestamp
        pool.query('UPDATE accountinfo SET resetPasswordToken = ?, resetPasswordExpires = ? WHERE email = ?', 
                   [newToken, Date.now() + 600000, email], // token expires in 1 hour
                   (error, results) => {
            if (error) {
                console.error('Database query error:', error);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ message: 'Error occurred during the reset password request.' }));
            } else {
                sendPasswordResetEmail(email, newToken);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ message: 'Password reset email sent.' }));
            }
        });
    });
}

function resetPasswordAPI(req, res) {
    let body = '';
    req.on('data', chunk => {
        body += chunk.toString();
    });

    req.on('end', () => {
        const { token, newPassword } = JSON.parse(body);

        // Check if the token is valid and has not expired
        pool.query('SELECT * FROM accountinfo WHERE resetPasswordToken = ? AND resetPasswordExpires > ?', 
                   [token, Date.now()],
                   (error, results) => {
            if (error || results.length === 0) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ message: 'Password reset token is invalid or has expired.' }));
                return;
            }

            // Hash the new password
            bcrypt.hash(newPassword, 10, (hashError, hashedPassword) => {
                if (hashError) {
                    res.writeHead(500, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ message: 'Error hashing the new password.' }));
                    return;
                }

                // Update the password in the database
                pool.query('UPDATE accountinfo SET password = ?, resetPasswordToken = NULL, resetPasswordExpires = NULL WHERE email = ?', 
                           [hashedPassword, results[0].email],
                           (updateError) => {
                    if (updateError) {
                        res.writeHead(500, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ message: 'Error updating password in the database.' }));
                        return;
                    }

                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ message: 'Password has been reset successfully.' }));
                });
            });
        });
    });
}


////////new added
function sendResetEmail(email, token) { //change email functionality
    const transporter = nodemailer.createTransport({
        service: 'Outlook365', // Outlook service
        auth: {
            user: 'Testuseryt2023@outlook.com', //Outlook email
            pass: 'oldpassword123' //Outlook password
        }
    });

    const resetUrl = `http://localhost:8080/api/verify?token=${token}`;

    const mailOptions = {
        from: '"Testuser" <Testuseryt2023@outlook.com>', // sender address
        to: email, // receiver
        subject: 'Email Reset', // Subject line
        text: `You requested a email reset. Please go to this link to verify the email: ${resetUrl}`,
        html: `<p>You requested a email reset. Please click on the link to verify email:</p><a href="${resetUrl}">${resetUrl}</a>`
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log('Error sending email: ', error);
        } else {
            console.log('Email sent: ' + info.response);
        }
    });
}

/////////////new added
function changeEmailapi(req, res){
    let body = '';
    req.on('data', (chunk) => {
        body += chunk.toString(); // Convert Buffer to string
    });

    req.on('end', () => {
        try {
            const {new_email} = JSON.parse(body);
            console.log("new email ", new_email);
            

            // Retrieve the authorization token from the request headers
            const authToken = req.headers.authorization;

            if (!authToken) {
                res.writeHead(401, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ message: 'Unauthorized - Missing token' }));
                return;
            }

            // Extract the token part
            const token = authToken.split(' ')[1];

            jwt.verify(token, 'your-secret-key', (err, decoded) => {
                if (err) {
                    res.writeHead(401, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ message: 'Unauthorized - Invalid token' }));
                } else {
                    // Here, you can fetch user-specific data from the database using the decoded information
                    const userId = decoded.userId;

                    // Retrieve the user from the database
                    pool.query('SELECT * FROM accountinfo WHERE id = ?', [userId], (error, results) => {
                        if (error || results.length === 0) {
                            res.writeHead(404, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify({ message: 'User not found.' }));
                            return;
                        }

                        
                                // Update the password in the database with the hashed password
                                pool.query('UPDATE accountinfo SET email = ? WHERE id = ?', [new_email, userId], (updateError) => {
                                    if (updateError) {
                                        res.writeHead(500, { 'Content-Type': 'application/json' });
                                        res.end(JSON.stringify({ message: 'Error updating address in the database.' }));
                                        return;
                                    }

                                    res.writeHead(200, { 'Content-Type': 'application/json' });
                                    res.end(JSON.stringify({ message: 'email verify link sent' }));
                                    sendResetEmail(new_email, authToken);
                                });
                            
                        });
                    
                }
            });
        } catch (jsonError) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ message: 'Bad Request - Invalid JSON format.' }));
        }
    }); 

}


const server = http.createServer((req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Origin, X-Requested-With, Content-Type, Accept');
    const parsedUrl = url.parse(req.url, true);
    const pathname = parsedUrl.pathname;

    if (pathname === '/api/login') {
        // Serve the index.html file for the root route
        const filePath = path.join(__dirname, 'index.html');
        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) {
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end('Internal Server Error');
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(data);
        });
    } else if (pathname === '/api/signup') { //pathname === '/signup.html'
        // Serve the signup.html file for the signup route
        const filePath = path.join(__dirname, 'signup.html');
        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) {
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end('Internal Server Error');
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(data);
        });
    } else if (pathname === '/api/registrationsuccess') {
        const filePath = path.join(__dirname, 'registrationsuccess.html');
        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) {
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end('Internal Server Error');
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(data);
        });
    }else if (pathname === '/api/verifyaccount') {
        const filePath = path.join(__dirname, 'verifyaccount.html');
        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) {
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end('Internal Server Error');
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(data);
        });
    }else if (pathname === '/api/dashboard') {
        const filePath = path.join(__dirname, 'dashboard.html');
        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) {
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end('Internal Server Error');
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(data);
        });
    
    } else if (pathname === '/api/changepassword') {
        const filePath = path.join(__dirname, 'changepassword.html');
        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) {
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end('Internal Server Error');
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(data);
        });
    } else if (pathname === '/api/manageprofile') {
        const filePath = path.join(__dirname, 'manageProfile.html');
        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) {
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end('Internal Server Error');
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(data);
        });

    } else if (pathname === '/api/accountsettings') {
        const filePath = path.join(__dirname, 'accountSettings.html');
        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) {
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end('Internal Server Error');
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(data);
        });

    } else if (pathname === '/api/resetPasswordRequest') {
        const filePath = path.join(__dirname, 'resetPasswordRequest.html');
        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) {
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end('Internal Server Error');
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(data);
        });
    } else if (pathname === '/api/resetPassword') {
        const filePath = path.join(__dirname, 'resetPassword.html');
        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) {
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end('Internal Server Error');
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(data);
        });    
    
    } else if (pathname === '/api/changeEmail') { ////////////new added
        const filePath = path.join(__dirname, 'changeemail.html');
        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) {
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end('Internal Server Error');
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(data);
        });
    
    }else if (pathname === '/api/verify') { ////////////new added
        const filePath = path.join(__dirname, 'verify.html');
        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) {
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end('Internal Server Error');
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(data);
        });
    
    }else if (req.method === 'POST' && pathname === '/register') { //Zhihang Liu
        registerAPI(req, res)
    } else if (req.method === 'POST' && pathname === '/login') {
        loginAPI(req, res)
    } else if (req.method === 'PUT' && pathname === '/changepassword') { //Yi Tang
        changepasswordAPI(req, res)
    } else if (req.method === 'GET' && pathname === '/manageprofile') {
        viewProfileAPI(req, res)
    } else if (req.method === 'PUT' && pathname === '/manageprofile'){
        updateProfileAPI(req, res)
    } else if (req.method === 'GET' && pathname === '/dashboard') {
        getUsername(req, res)
    } else if (req.method === 'POST' && pathname === '/resetPasswordRequest') {
        resetPasswordRequestAPI(req, res);
    } else if (req.method === 'POST' && pathname === '/resetPassword') {
        resetPasswordAPI(req, res);
    }else if(req.method === 'PUT' && pathname === '/changeEmail'){ //////////new added
        changeEmailapi(req, res);
    }else {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
    }
})
const PORT = 8080;
server.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});