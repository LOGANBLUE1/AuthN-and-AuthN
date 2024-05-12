const bcrypt = require('bcrypt');
const User = require('../model/userModel');
const jwt = require('jsonwebtoken');
require('dotenv').config();


exports.signup = async (req, res) => {
    try {
        const { name, email, password, role } = req.body;
        const existingUser = await User.findOne({ email });

        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: 'User already exists'
            });
        }

        // Hash the password
        const hashPassword = await bcrypt.hash(password, 10);

        // Create entry for user
        const user = await User.create({
            name, email, password: hashPassword, role
        });

        res.status(200).json({
            success: true,
            message: 'User created successfully'
        });
    } catch (e) {
        console.error(e);
        res.status(500).json({
            success: false,
            message: 'User cannot be registered, please try again later'
        });
    }
};

exports.login = async (req,res) => {
    try{
        const {email, password} = req.body;

        if(!email || !password){
            return res.status(400).json({
                success: false,
                message: 'please fill all the details carefully'
            });
        }

        const user = await User.findOne({email});
        if(!user){
            return res.status(401).json({
                success: fakse,
                message: 'User is not registered'
            });
        }

        const payload = {
            email: user.email,
            id: user._id,
            role: user.role
        }

        //verify password and generate JWT token
        if(await bcrypt.compare(password, user.password)){
            let token = jwt.sign(payload, process.env.JWT_SECRET, {
                                                            expiresIn:"2h"
                                                                });
                                                                
            user = user.toObject();
            user.token = token;
            user.password = undefined;// to hide password


            const options = {
                expires: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000),//ms
                httpOnly: true
            }
            res.cookie("token", token, options).status(200).json({
                success:true,
                token,
                user,
                message: "User logged in successfully"
            })
        }
        else{
            return res.status(403).json({
                success: false,
                message: 'Password incorrect'
            });
        }
    }
    catch(e){

    }
};