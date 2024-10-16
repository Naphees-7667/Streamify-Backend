import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

const userSchema = new mongoose.Schema({

    username:{
        type:String,
        required:true,
        unique:true,
        lowercase:true,
        trim:true,
        index:true
    },
    email:{
        type:String,
        required:true,
        unique:true,
        lowercase:true,
        trim:true
    },

    fullname:{
        type:String,
        required:true,
        trim:true,
        index:trim
    },

    avatar:{
        type:String,// cloudinary url
        required:true
    },

    coverImage:{
        type:String,// cloudinary url
    },
    watchHistory:[
        {
            type:mongoose.Schema.Types.ObjectId,
            ref:"Video"
        }
    ],

    password:{
        type:String,
        required:[true,"Password is required"],//if you do not give password it will give this error
    },
    refreshToken:{
        type:String
    }
},{timestamps:true})

userSchema.pre("save",async function(next){
    if(!this.isModified("password")) return next();
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password,salt);
    next();
})

userSchema.methods.matchPassword = async function(enetredPassword){
    return await bcrypt.compare(enetredPassword,this.password);
}

const User = mongoose.model("User",userSchema);
export default User;