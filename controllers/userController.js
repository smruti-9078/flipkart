import {  User } from "../models/userModel.js"
import bcrypt from "bcryptjs"

export const register = async (req, res) => {
    try {
        const {firstName, lastName, email, password } = req.body;
        if(!firstName || !lastName || !email || !password) {
             return res.status(400).json({
                success:false,
                message:"All fields are Required"

            })
        }
        const existingUser= await User.findOne({ email })
        if(existingUser) {
            res.status(400).json({
                success:false,
                message:'User already exist'
            });
        }
        const hashedPassword =await bcrypt.hash(password,10)
        const newUser = await User.create({
            firstName,
            lastName,
            email,
            password:hashedPassword

        })
        console.log (newUser)
        await newUser.save()
        return res.status(201).json({
            success:true,
            message:'User registered successfully',
            user:newUser
        })
    } catch (error) {

        return res.status(500).json({
      success: false,
      message: error.message,
    })
         
        
        
    }
}