import {asyncHandler} from "../utils/asyncHandler.js";
import ApiError from "../utils/ApiError.js";
import User from "../models/user.model.js";
import uploadOnCloudinary from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";

const registerUser = asyncHandler(async (req,res) => {
    // get user details from frontend
    // validation - not empty
    // check if user already exist: username,email
    // check for images , check for avatar
    // upload them to cloudinary, avatar
    // craete a user object - create entry in db
    // remove password and refresh token field from response 
    // check for user creation
    // return response
    const {fullName,email,username,password} = req.body;
    
    if(fullName === "" || email === "" || username === "" || password === ""){
        throw new ApiError("All fields are required");
    }

    const existedUser = await User.findOne({
        $or:[{ username }, { email }]
    })

    if(existedUser){
        throw new ApiError("User already exists with same username or email");
    }

    const avatarLocalPath = req.files?.avatar[0]?.path;
    const coverImageLocalPath = req.files?.cover[0]?.path;

    if(!avatarLocalPath)throw new ApiError(400,"Avatar is required");

    const avatarCloudinaryresponse = await uploadOnCloudinary(avatarLocalPath);
    const coverImageCloudinaryresponse = await uploadOnCloudinary(coverImageLocalPath);

    if(!avatarCloudinaryresponse)throw new ApiError(400,"Avatar is required");

    const user = await User.create({
        fullName,
        email,
        username,
        password,
        avatar:avatarCloudinaryresponse.url,
        cover:coverImageCloudinaryresponse?.url || "",
    })

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )
    if(!createdUser){
        throw new ApiError(500,"Something Went Wrong while creating user"); 
    }
    return res.status(201).json(
        new ApiResponse(
            200,
            createdUser,
            "User registered successfully"
        )
    )
})

export {registerUser}