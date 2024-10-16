import {asyncHandler} from "../utils/asyncHandler.js";
import ApiError from "../utils/ApiError.js";
import User from "../models/user.model.js";
import uploadOnCloudinary from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";
const generateAccessAndRefreshToken = async(userId) => {
    try{
        const user = await User.findById(userId);
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();
        user.refreshToken = refreshToken;
        user.accessToken = accessToken;
        await user.save({validateBeforeSave: false});
        return {accessToken, refreshToken};
    }
    catch(err){
        throw new ApiError(500, err.message);
    }
}

const registerUser = asyncHandler(async (req, res) => {
    const { fullName, email, username, password } = req.body;

    if (!fullName || !email || !username || !password) {
        throw new ApiError(400, "All fields are required");
    }

    const existedUser = await User.findOne({
        $or: [{ username }, { email }]
    });

    if (existedUser) {
        throw new ApiError(400, "User already exists with the same username or email");
    }

    const avatarLocalPath = req.files?.avatar?.[0]?.path;
    const coverImageLocalPath = req.files?.cover?.[0]?.path;

    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar is required");
    }

    const avatarCloudinaryResponse = await uploadOnCloudinary(avatarLocalPath);
    const coverImageCloudinaryResponse = coverImageLocalPath ? await uploadOnCloudinary(coverImageLocalPath) : null;

    if (!avatarCloudinaryResponse) {
        throw new ApiError(400, "Avatar upload failed");
    }

    const user = await User.create({
        fullName,
        email,
        username,
        password,
        avatar: avatarCloudinaryResponse.url,
        coverImage: coverImageCloudinaryResponse?.url || "",
    });

    const createdUser = await User.findById(user._id).select("-password -refreshToken");
    if (!createdUser) {
        throw new ApiError(500, "Something went wrong while creating user");
    }

    return res.status(201).json(
        new ApiResponse(
            201,
            createdUser,
            "User registered successfully"
        )
    );
});

const loginUser = asyncHandler(async (req, res) => {
    const { email, username, password } = req.body;
    console.log(email)
    if (!(username || email)) {
        throw new ApiError(400, "username or password is required");
    }
    if(!password){
        throw new ApiError(400, "password is required");
    }
    const user = await User.findOne({ 
        $or: [{ username }, { email }]
    });
    if (!user) {
        throw new ApiError(404, "User not found");
    }
    const isPasswordValid = await user.matchPassword(password);
    if (!isPasswordValid) {
        throw new ApiError(401, "Invalid credentials");
    }
    const { accessToken, refreshToken } = await generateAccessAndRefreshToken(user._id);

    const loggedInUser = await User.findById(user._id).select("-password -refreshToken");

    const options = {
        httpOnly: true,
        secure: true,
    }

    return res.status(200).cookie("accessToken", accessToken, options).cookie("refreshToken", refreshToken, options).json(
        new ApiResponse(
            200,
            {
                user: loggedInUser,
                accessToken,refreshToken
            },
            "User logged in successfully"
        )
    )
})

const logoutUser = asyncHandler(async (req, res) => {
    await User.findByIdAndUpdate(req.user._id, {
        $set: {
            refreshToken: undefined
        }
    },
    {
        new: true,
    })

    const options = {
        httpOnly: true,
        secure: true,
    }

    return res
        .status(200)
        .clearCookie("accessToken", options)
        .clearCookie("refreshToken", options)
        .json(new ApiResponse(200, null, "User logged out successfully"));
})

const refreshAccessToken = asyncHandler(async (req, res) => {
    const incomingRefreshToken = req.cookies.refreshTokenc|| req.body.refreshToken;
    if(!incomingRefreshToken){
        throw new ApiError(401, "Unauthorized request");
    }
    try {
        const decodedRefreshToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET);
        const user = await User.findById(decodedRefreshToken._id).select("-password -refreshToken");
        if(!user){  
            throw new ApiError(401, "Invalid refresh token");    
        }
        if(incomingRefreshToken !== user?.refreshToken){
            throw new ApiError(401, "Refresh token is expired or used");
        }
    
        const option = {httpOnly: true, secure: true};
        const {accessToken, newrefreshToken} = await generateAccessAndRefreshToken(user._id);
    
        return res
            .status(200)
            .cookie("accessToken", accessToken, option)
            .cookie("refreshToken", newrefreshToken, option)
            .json(new ApiResponse(200, {accessToken, 
                refreshToken:newrefreshToken}, "Access token refreshed successfully"
            )
        );
    } catch (error) {
        throw new ApiError(401, error.message || "Invalid refresh token");
    }
})

export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken
}