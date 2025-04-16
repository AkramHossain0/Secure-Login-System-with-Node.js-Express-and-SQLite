import db from '../lib/db.js';
import bcrypt from 'bcrypt';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
import crypto from 'crypto';
import { encryptAES, decryptAES } from '../lib/crypto.js';
dotenv.config();

const register = async (req, res) => {
    try {
        const { username, email, password, number } = req.body;

        if (!username || !email || !password || !number) {
            return res.status(400).json({ success: false, message: 'All fields are required' });
        }

        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
        if (!passwordRegex.test(password)) {
            return res.status(400).json({
                success: false,
                message: 'Password must be at least 8 characters long, contain uppercase, lowercase, a number, and a special character.',
            });
        }

        db.get(`SELECT * FROM users WHERE email = ? OR username = ?`, [email, username], async (err, user) => {
            if (err) {
                return res.status(500).json({ success: false, message: 'Database error' });
            }
            if (user) {
                return res.status(400).json({ success: false, message: 'Username or email already exists.' });
            }

            const hashedPassword = await bcrypt.hash(password, 10);
            const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
            const expirationTime = Date.now() + 5 * 60 * 1000;

            global.verificationCodes = global.verificationCodes || {};
            global.verificationCodes[email] = { username, hashedPassword, number, code: verificationCode, expirationTime };

            const transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: {
                    user: process.env.EMAIL_USER,
                    pass: process.env.EMAIL_PASS,
                },
            });

            const mailOptions = {
                from: process.env.EMAIL_USER,
                to: email,
                subject: 'Verify Your Email Address',
                html: `
                    <p>Hello,</p>
                    <p>To complete your registration, use the following verification code:</p>
                    <p><strong>${verificationCode}</strong></p>
                    <p>This code will expire in 5 minutes.</p>
                `,
            };

            transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                    console.error('Error sending email:', error);
                    return res.status(500).json({ success: false, message: 'Failed to send verification email' });
                } else {
                    console.log('Email sent:', info.response);
                    res.status(200).json({ success: true, message: 'Verification code sent to email' });
                }
            });
        });
    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).json({ success: false, message: 'Error during registration' });
    }
};

const verify = async (req, res) => {
    try {
        const { email, verificationCode } = req.body;

        if (!email || !verificationCode) {
            return res.status(400).json({ success: false, message: 'All fields are required' });
        }

        if (global.verificationCodes && global.verificationCodes[email]) {
            const { code, expirationTime, username, hashedPassword, number } = global.verificationCodes[email];

            if (Date.now() > expirationTime) {
                delete global.verificationCodes[email];
                return res.status(400).json({ success: false, message: 'Verification code has expired' });
            }

            if (code === verificationCode) {
                delete global.verificationCodes[email];

                db.run(
                    `INSERT INTO users (username, email, password, number) VALUES (?, ?, ?, ?)`,
                    [username, email, hashedPassword, number],
                    (err) => {
                        if (err) {
                            return res.status(500).json({ success: false, message: 'Database error' });
                        }

                        res.status(201).json({ success: true, message: 'User registered successfully' });
                    }
                );
            } else {
                res.status(400).json({ success: false, message: 'Invalid verification code' });
            }
        } else {
            res.status(400).json({ success: false, message: 'Invalid verification code' });
        }
    } catch (error) {
        console.error('Error during verification:', error);
        res.status(500).json({ success: false, message: 'Error during verification' });
    }
};

const login = async (req, res) => {
    try {
        const { email, number, password } = req.body;

        if (!email && !number) {
            return res.status(400).json({ message: 'Email or number is required' });
        }

        if (!password) {
            return res.status(400).json({ message: 'Password is required' });
        }

        db.get(
            `SELECT * FROM users WHERE email = ? OR number = ?`,
            [email, number],
            async (err, user) => {
                if (err) {
                    console.error('Database error:', err);
                    return res.status(500).json({ message: 'Database error' });
                }

                if (!user) {
                    return res.status(400).json({ message: 'Invalid credentials' });
                }

                const isPasswordValid = await bcrypt.compare(password, user.password);

                if (!isPasswordValid) {
                    return res.status(400).json({ message: 'Invalid credentials' });
                }

                const sessionId = crypto.randomUUID();
                const nonce = crypto.randomBytes(16).toString('hex');
                const timestamp = Date.now().toString();

                const tokenData = JSON.stringify({
                    uid: user.id,
                    sid: sessionId,
                    nonce: nonce,
                    name: user.username,
                    email: user.email,
                    number: user.number,
                    iat: timestamp,
                    exp: Date.now() + 60 * 60 * 1000, 
                });

                const secretKey = process.env.JWT_SECRET;
                const token = encryptAES(tokenData, secretKey);

                res.cookie('token', token, {
                    httpOnly: true,
                    secure: true,
                    sameSite: 'strict',
                    path: '/',
                    maxAge: 30 * 60 * 1000, 
                    signed: true,
                });

                res.status(200).json({ message: 'User logged in successfully', token });
            }
        );
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

const forget = async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ message: 'Please provide an email' });
        }

        db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ message: 'Database error' });
            }

            if (!user) {
                return res.status(400).json({ message: 'User not found' });
            }

            const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
            const expirationTime = Date.now() + 2 * 60 * 1000;

            global.resetCodes = global.resetCodes || {};
            global.resetCodes[email] = { resetCode, expirationTime };

            const transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: {
                    user: process.env.EMAIL_USER,
                    pass: process.env.EMAIL_PASS,
                },
            });

            const mailOptions = {
                from: process.env.EMAIL_USER,
                to: email,
                subject: 'Password Reset Request',
                html: `
                    <p>Hello,</p>
                    <p>We received a request to reset your password. Use the code below to proceed:</p>
                    <h1>${resetCode}</h1>
                    <p>This code will expire in 2 minutes.</p>
                    <p>If you didn’t request this, please ignore this email.</p>
                `,
            };

            transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                    console.error('Error sending email:', error);
                    return res.status(500).json({ message: 'Error sending reset email' });
                } else {
                    console.log('Email sent:', info.response);
                    res.status(200).json({ message: 'Reset code sent successfully. Please check your email.' });
                }
            });
        });
    } catch (error) {
        console.error('Error during forget password:', error);
        res.status(500).json({ message: 'Something went wrong' });
    }
};

const reset = async (req, res) => {
    try {
        const { email, resetCode, newPassword } = req.body;

        if (!email || !resetCode || !newPassword) {
            return res.status(400).json({ message: 'Please provide email, reset code, and new password' });
        }

        if (!global.resetCodes || !global.resetCodes[email]) {
            return res.status(400).json({ message: 'Reset code not found or expired' });
        }

        const { resetCode: storedCode, expirationTime } = global.resetCodes[email];

        if (Date.now() > expirationTime) {
            delete global.resetCodes[email];
            return res.status(400).json({ message: 'Reset code has expired' });
        }

        if (storedCode !== resetCode) {
            return res.status(400).json({ message: 'Invalid reset code' });
        }

        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
        if (!passwordRegex.test(newPassword)) {
            return res.status(400).json({
                message: 'Password must be at least 8 characters long and include at least one lowercase letter, one uppercase letter, one digit, and one special character',
            });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        db.run(`UPDATE users SET password = ? WHERE email = ?`, [hashedPassword, email], (err) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ message: 'Database error' });
            }

            delete global.resetCodes[email];
            res.status(200).json({ message: 'Password reset successfully' });
        });
    } catch (error) {
        console.error('Error during reset password:', error);
        res.status(500).json({ message: 'Something went wrong' });
    }
};

const update = async (req, res) => {
    try {
        const { username, email, number } = req.body;
        const userId = req.user.id;

        if (!username || !email || !number) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        db.run(`UPDATE users SET username = ?, email = ?, number = ? WHERE id = ?`, [username, email, number, userId], (err) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ message: 'Database error' });
            }

            res.status(200).json({ message: 'User updated successfully' });
        });
    } catch (error) {
        console.error('Error during update:', error);
        res.status(500).json({ message: 'Something went wrong' });
    }
};

const decryptToken = (req, res) => {
    try {
        const { token } = req.body;

        if (!token || !token.token || !token.iv || !token.authTag) {
            return res.status(400).json({ message: 'Invalid token structure. Ensure token, iv, and authTag are provided.' });
        }

        const secretKey = process.env.JWT_SECRET;

        const { token: encryptedData, iv, authTag } = token;

        const decryptedToken = decryptAES(encryptedData, secretKey, iv, authTag);

        res.status(200).json({ message: 'Token decrypted successfully', data: JSON.parse(decryptedToken) });
    } catch (error) {
        console.error('Error decrypting token:', error.message);
        res.status(500).json({ message: 'Failed to decrypt token', error: error.message });
    }
};

export { register, verify, login, forget, reset, update, decryptToken };