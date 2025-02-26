const User = require('../models/User');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const validator = require('validator');
const dns = require('dns');
const logger = require('../logger'); // Import the logger

const isEmailValid = (email) => {
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return regex.test(email);
};

const doesEmailDomainExist = (email) => {
    const domain = email.split('@')[1];
    return new Promise((resolve, reject) => {
        dns.resolveMx(domain, (err, addresses) => {
            if (err || addresses.length === 0) {
                reject(false);
            } else {
                resolve(true);
            }
        });
    });
};

exports.register = async (req, res) => {
    const { name, email, password, companyName, age, dob } = req.body;
    const image = req.file ? req.file.path : null;

    // Validate input data
    if (!name || !email || !password) {
        logger.warn('Registration failed: All fields are required');
        return res.status(400).json({ success: false, message: 'All fields are required' });
    }

    // Validate email format
    if (!isEmailValid(email)) {
        logger.warn('Registration failed: Invalid email format');
        return res.status(400).json({ success: false, message: 'Invalid email format' });
    }

    // Check if email domain exists
    try {
        const domainExists = await doesEmailDomainExist(email);
        if (!domainExists) {
            return res.status(400).json({ success: false, message: 'Email domain does not exist' });
        }
    } catch (error) {
        return res.status(400).json({ success: false, message: 'Email domain check failed' });
    }

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            logger.warn('Registration failed: Email already in use');
            return res.status(400).json({ success: false, message: 'Email already in use' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({
            name,
            email,
            password: hashedPassword,
            companyName,
            age,
            dob,
            image
        });

        await newUser.save();
        logger.info(`User registered successfully: ${email}`);
        res.status(201).json({ success: true, message: 'User registered successfully', redirect: '/thank-you' });
    } catch (error) {
        logger.error('Registration failed:', error);
        res.status(500).json({ success: false, message: 'Registration failed', error });
    }
};

exports.login = async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            logger.warn(`Login failed: User not found for email ${email}`);
            return res.status(400).json({ success: false, message: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            logger.warn(`Login failed: Invalid password for email ${email}`);
            return res.status(400).json({ success: false, message: 'Invalid credentials' });
        }

        // Generate OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        await sendOtpEmail(user.email, otp);

        // Store or update OTP in the user document
        user.otp = otp; // Store the OTP
        await user.save(); // Save the user document with the new OTP

        logger.info(`OTP sent to ${email}`);
        res.status(200).json({ success: true, message: 'OTP sent to your email' });
    } catch (error) {
        logger.error('Login failed:', error);
        res.status(500).json({ success: false, message: 'Login failed', error });
    }
};

const sendOtpEmail = async (email, otp) => {
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
        subject: 'Your OTP Code',
        text: `Your OTP code is ${otp}. It is valid for 10 minutes.`,
    };

    try {
        await transporter.sendMail(mailOptions);
    } catch (error) {
        console.error('Error sending OTP email:', error);
    }
};

// New OTP verification endpoint
exports.verifyOtp = async (req, res) => {
    const { email, otp } = req.body;

    // Validate OTP format
    if (!/^\d{6}$/.test(otp)) {
        return res.status(400).json({ success: false, message: 'OTP must be a 6-digit number' });
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            logger.warn(`OTP verification failed: User not found for email ${email}`);
            return res.status(400).json({ success: false, message: 'Invalid OTP' });
        }

        logger.info(`Verifying OTP for ${email}: received OTP ${otp}, stored OTP ${user.otp}`);

        // Check if the entered OTP matches the stored OTP
        if (user.otp !== otp) {
            logger.warn(`OTP verification failed: Invalid OTP for email ${email}`);
            return res.status(400).json({ success: false, message: 'Invalid OTP' });
        }

        // Clear OTP after verification
        user.otp = null; // Clear the OTP
        await user.save();

        logger.info(`OTP verified successfully for ${email}`);
        res.status(200).json({ success: true, message: 'OTP verified successfully' });
    } catch (error) {
        logger.error('OTP verification failed:', error);
        res.status(500).json({ success: false, message: 'OTP verification failed', error });
    }
};

exports.deleteAccount = async (req, res) => {
    const { email } = req.body;

    try {
        const result = await User.deleteOne({ email });
        if (result.deletedCount === 0) {
            return res.status(404).json({ success: false, message: 'Account not found' });
        }
        res.status(200).json({ success: true, message: 'Account deleted successfully' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Account deletion failed', error });
    }
};