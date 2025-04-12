import {asyncHandler} from "../utils/asyncHandler.js"
import {ApiError} from '../utils/apiError.js'
import {User} from '../models/user.model.js'
import {uploadOnCloudinary} from '../utils/fileUpload.js'
import { ApiResponse } from "../utils/apiResponse.js"

const registerUser = asyncHandler( async (req, res) => {
    /* register steps
    1. get user details from frontend
    2. validation - not empty
    3. check if user already exists: username & email
    4. check for images, check for avatar
    5. upload them to cloudinary, avatar
    6. create user object - create entry in db
    7. remove password and refresh token field from response
    8. check for user creation
    9. return response */

    // 1. get user details from frontend
    const {fullname, email, username, password} = req.body
    console.log("Email", email)

    // 2. validation - not empty
    // beginner check write if stmt for each field
    // if(fullname === ""){
    //    throw new ApiError(400, "fullname is required")}

    // to check all fields 
    if(
        [fullname, email, username, password].some((field) => 
            field?.trim() === "")
        ){
            throw new ApiError(400, "All fields are required")
        }
  

    // 3. check if user already exists: username & email
    const existedUser = await User.findOne({
        $or : [{username}, {email}]
    })

    if(existedUser){
        throw new ApiError(409, "User already exists")
    }

    // 4. check for images, check for avatar
    const avatarLocalPath = req.files?.avatar[0]?.path
    //const coverImageLocalPath = req.files?.coverImage[0]?.path

    // to check whether the file is present or not
    let coverImageLocalPath
    if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0){
        coverImageLocalPath = req.files.coverImage[0].path
    }

    if(!avatarLocalPath){
        throw new ApiError(400, "Avatar file is required")
    }

    // 5. upload them to cloudinary, avatar
    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if(!avatar){
        throw new ApiError(400, "Avatar file is required")
    }

    // 6. create user object - create entry in db
    const user = await User.create({
        fullname,
        avatar : avatar.url,
        coverImage : coverImage?.url || null,
        email,
        username : username.toLowerCase(),
        password
    })

    // 7. remove password and refresh token field from response
    const createdUser = await User.findById(user._id).select("-password -refreshToken")
    // select("-password") for not selection user

    
    // 8. check for user creation
    if(!createdUser){
        throw new ApiError(500, "Something went wrong while registration")
    }

    // 9. return response 
    return res.status(201).json(
        new ApiResponse(200, createdUser, "User registered successfully!!")
    )
})

export {registerUser}