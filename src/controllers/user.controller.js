import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/apiError.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/fileUpload.js";
import { ApiResponse } from "../utils/apiResponse.js";
import jwt from "jsonwebtoken"

// Method to generate access and refresh token
const generateAccessAndRefreshTokens = async(userId) => {
    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        user.refreshToken = refreshToken
        // user.save()  // this will validate all the fields before saving
        await user.save({validateBeforeSave : false}) // this will save without validation of fields

        return {accessToken, refreshToken}

    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating access and refresh token.")
    }
}

const registerUser = asyncHandler(async (req, res) => {
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
  const { fullname, email, username, password } = req.body;
  console.log("Email", email);

  // 2. validation - not empty
  // beginner check write if stmt for each field
  // if(fullname === ""){
  //    throw new ApiError(400, "fullname is required")}

  // to check all fields
  if (
    [fullname, email, username, password].some((field) => field?.trim() === "")
  ) {
    throw new ApiError(400, "All fields are required");
  }

  // 3. check if user already exists: username & email
  const existedUser = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (existedUser) {
    throw new ApiError(409, "User already exists");
  }

  // 4. check for images, check for avatar
  const avatarLocalPath = req.files?.avatar[0]?.path;
  //const coverImageLocalPath = req.files?.coverImage[0]?.path

  // to check whether the file is present or not
  let coverImageLocalPath;
  if (
    req.files &&
    Array.isArray(req.files.coverImage) &&
    req.files.coverImage.length > 0
  ) {
    coverImageLocalPath = req.files.coverImage[0].path;
  }

  if (!avatarLocalPath) {
    throw new ApiError(400, "Avatar file is required");
  }

  // 5. upload them to cloudinary, avatar
  const avatar = await uploadOnCloudinary(avatarLocalPath);
  const coverImage = await uploadOnCloudinary(coverImageLocalPath);

  if (!avatar) {
    throw new ApiError(400, "Avatar file is required");
  }

  // 6. create user object - create entry in db
  const user = await User.create({
    fullname,
    avatar: avatar.url,
    coverImage: coverImage?.url || null,
    email,
    username: username.toLowerCase(),
    password,
  });

  // 7. remove password and refresh token field from response
  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );
  // select("-password") for not selection user

  // 8. check for user creation
  if (!createdUser) {
    throw new ApiError(500, "Something went wrong while registration");
  }

  // 9. return response
  return res
    .status(201)
    .json(new ApiResponse(200, createdUser, "User registered successfully!!"));
});

const loginUser = asyncHandler(async (req, res) => {
  /* 
       1. req body -> data
       2. username or email
       3. find the user
       4. password check
       5. access and refresh token generation
       6. send cookie
    */

  // 1. req body -> data
  const {email, username, password} = req.body

  // 2. username or email
  // if(!username && !email)
  if(!(username || email)){
    throw new ApiError(400, "Username or email is required")
  }

  // If only want to check anyone either email or username then use
  // if(!username) ; if(!email)

  // 3. find the user
  // User.findOne({email})  --> to find using email 

  const user = await User.findOne({
    $or: [{username}, {email}]   // this will find value based on username or email
  })

  if(!user){
    throw new ApiError(400, "User does not exist")
  }

  // 4. password check
  // User is used while using the methods of mongodb and user is used while using methods created by us
  const isPasswordValid = await user.isPasswordCorrect(password)

  if(!isPasswordValid){
    throw new ApiError(401, "Invalid user credentials")
  }

  // 5. access and refresh token generation
  const {accessToken, refreshToken} = await generateAccessAndRefreshTokens(user._id)

  // 6. send cookie
  const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

  // cookies are modifiable but if we set httpOnly=true, then only server can modify it no one else
  const options = {
    httpOnly: true,
  //  secure: true   // If we uncomment this, we will not be able to get the cookies
  }

  return res.status(200)
  .cookie("accessToken", accessToken, options)
  .cookie("refreshToken", refreshToken, options)
  .json(
    new ApiResponse(200,
        {
            user: loggedInUser, accessToken, refreshToken
        },
        "User logged in successfully"
    )

)

});

const logoutUser = asyncHandler(async (req, res) => {
 // delete refreshToken from database or update it to undefined
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {refreshToken: undefined}
        },
        {
            new: true
        }
    )

    // delete cookies
    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(
        200, {}, "User logged out successfully"
    ))
})

const refreshAccessToken = asyncHandler(async (req, res) => {
  const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

  if(!incomingRefreshToken){
    throw new ApiError(401, "Unauthorized request")
  }

  try {
    const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET)
  
    const user = await User.findById(decodedToken?._id)
  
    if(!user){
      throw new ApiError(401, "Invalid Refresh Token")
    }
  
    if(incomingRefreshToken !== user?.refreshToken){
      throw new ApiError(401, "Refresh Token is expired")
    }
  
    const options = {
      httpOnly: true,
      // secure: true
    }
  
    const {accessToken, newRefreshToken} = await generateAccessAndRefreshTokens(user._id)
  
    return res.status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", newRefreshToken, options)
    .json(
      new ApiResponse(200, 
        {accessToken, refreshToken: newRefreshToken},
        "Access Token refreshed successfully"
      )
    )
  
  } catch (error) {
    throw new ApiError(401, error?.message || "Invalid refresh token")
  }})

export { registerUser, loginUser, logoutUser, refreshAccessToken };
