const bcrypt = require('bcryptjs');
const keys = require('../config/keys');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const errorHandler = require('../utils/errorHandler');

module.exports.login = async function(req, res) {
    const candidate = await User.findOne({email: req.body.email});

    if(candidate) {
        // Check password, user is existed
        const passwordResult = bcrypt.compareSync(req.body.password, candidate.password);
        if(passwordResult) {
            // Generate token, password matched
            const token = jwt.sign({
                email: candidate.email,
                userId: candidate._id
            }, keys.jwt, {expiresIn: 60 * 60});

            res.status(200).json({
                token: `Bearer ${token}`
            })

        } else {
            // Passwords isn`t matched
            res.status(401).json({
                message: 'Passwords is not matched, please try again.'
            })
        }
    } else {
        // User not found, error
        res.status(404).json({
            message: 'User not found'
        })
    }
}

module.exports.register = async function(req, res) {
    // mail && password
    const candidate = await User.findOne({email: req.body.email});

    if(candidate) {
        // User is exists, need to throw error
        res.status(409).json({
            message: 'Email is already taken, please try another'
        })
    } else {
        // need to create user
        const salt = bcrypt.genSaltSync(10);
        const password = req.body.password
        const user = new User({
            email: req.body.email,
            password: bcrypt.hashSync(password, salt)
        });

        try {
            await user.save();
            res.status(201).json(user)
        } catch (err) {
            errorHandler(res, err);
        }

    }
}
