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

// Register controller
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

// Login controller
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

// Logout controller
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

// RefreshAccessToken controller
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

// change password controller
const changeCurrentPassword = asyncHandler(async (req, res) => {
  // with confirm password field
  // const {oldPassword, newPassword, confPassword} = req.body
  // if(!(newPassword === confPassword)){
  // throw new ApiError(400, "New and confirm passwords are not matching")
  //}

  const {oldPassword, newPassword} = req.body

  const user = await User.findById(req.user?._id)
  const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

  if(!isPasswordCorrect){
    throw new ApiError(400, "Invalid password")
  }

  user.password = newPassword
  await user.save({validateBeforeSave: false})

  return res.status(200)
  .json(new ApiResponse(200, {}, "Password change successfully"))
})

// get current user controller
const getCurrentUser = asyncHandler(async (req, res) =>{
  return res.status(200)
  .json(new ApiResponse(200, req.user, "Current user fetched successfully"))
})

// update account details controller
const updateAccountDetails = asyncHandler(async (req, res) => {
  // when you want to update any file provide different page for this to user as it reduces the network congestion
  const {fullname, email} = req.body

  if(!fullname || !email){
    throw new ApiError(400, "All fields are required")
  }

  const user = User.findByIdAndUpdate(
    req.user?._id,
   {
    $set: {
      fullname, email
    }
   },
   {new: true}
  ).select("-password")

  return res.status(200)
  .json(new ApiResponse(200, user, "Account details updated successfully"))
})

// update avatar image controller
const updateUserAvatar = asyncHandler(async (req, res) => {
  const avatarLocalPath = req.file?.path

  if(!avatarLocalPath){
    throw new ApiError(400, "Avatar file missing")
  }

  const avatar = await uploadOnCloudinary(avatarLocalPath)

  if(!avatar.url){
    throw new ApiError(400, "Error while uploading avatar")
  }

  const user = await User.findByIdAndUpdate(req.user?._id,
    {
      $set: {
        avatar: avatar.url
      }
    },
    {new: true}
  ).select("-password")

  return res.status(200)
  .json(new ApiResponse(200, user, "Avatar updated successfully"))
})

// update cover image controller
const updateCoverImage = asyncHandler(async (req, res) => {
  const coverImageLocalPath = req.file?.path

  if(!coverImageLocalPath){
    throw new ApiError(400, "Cover Image file missing")
  }

  const coverImage = await uploadOnCloudinary(coverImageLocalPath)

  if(!coverImage.url){
    throw new ApiError(400, "Error while uploading cover Image")
  }

  const user = await User.findByIdAndUpdate(req.user?._id,
    {
      $set: {
        coverImage: coverImage.url
      }
    },
    {new: true}
  ).select("-password")

  return res.status(200)
  .json(new ApiResponse(200, user, "Cover Image updated successfully"))
})

const getUserChannelProfile = asyncHandler(async(req, res) => {
  const {username} = req.params

  if(!username?.trim()){
    throw new ApiError(400, "Username is missing")
  }

  // Aggregation query to fetch a user's channel details along with subscription info
const channel = await User.aggregate([
  {
      // Match the user by username (converted to lowercase if it's present)
      $match: {
          username: username?.toLowerCase()
      }
  },
  {
      // Lookup subscriptions where this user is the "channel" (i.e., others subscribed to this user)
      $lookup: {
          from: "subscriptions",          // Collection to join
          localField: "_id",              // Local field from User collection
          foreignField: "channel",        // Field from Subscriptions collection
          as: "subscribers"               // Output array field
      }
  },
  {
      // Lookup subscriptions where this user is the "subscriber" (i.e., channels this user subscribed to)
      $lookup: {
          from: "subscriptions",
          localField: "_id",
          foreignField: "subscriber",
          as: "subscribedTo"
      }
  },
  {
      // Add computed fields
      $addFields: {
          // Count of users who subscribed to this channel
          subscribersCount: {
              $size: "$subscribers"
          },
          // Count of channels this user has subscribed to
          channelsSubscribedToCount: {
              $size: "$subscribedTo"
          },
          // Check if the currently authenticated user (req.user) is subscribed to this channel
          isSubscribed: {
              $cond: {
                  if: { $in: [req.user?._id, "$subscribers.subscriber"] },
                  then: true,
                  else: false
              }
          }
      }
  },
  {
      // Project only the fields needed in the final response
      $project: {
          fullName: 1,
          username: 1,
          subscribersCount: 1,
          channelsSubscribedToCount: 1,
          isSubscribed: 1,
          avatar: 1,
          coverImage: 1,
          email: 1
      }
  }
]);

// If no user is found, throw a 404 error
if (!channel?.length) {
  throw new ApiError(404, "channel does not exists");
}

// Send the user data in a successful API response
return res
  .status(200)
  .json(
      new ApiResponse(200, channel[0], "User channel fetched successfully")
  );

})

// Controller function to get the watch history of a user
const getWatchHistory = asyncHandler(async (req, res) => {
  // Aggregate data for the authenticated user
  const user = await User.aggregate([
      {
          // Match the user by their _id from the request (authentication middleware should set req.user)
          $match: {
              _id: new mongoose.Types.ObjectId(req.user._id)
          }
      },
      {
          // Perform a lookup to join video documents referenced in the user's watchHistory array
          $lookup: {
              from: "videos", // Collection to join (videos)
              localField: "watchHistory", // Field in User document
              foreignField: "_id", // Field in Video document to match with
              as: "watchHistory", // Output array field name
              pipeline: [ // Further process each video
                  {
                      // Lookup to fetch the owner (user) of the video
                      $lookup: {
                          from: "users", // Collection to join (users)
                          localField: "owner", // Field in Video document
                          foreignField: "_id", // Field in User document to match with
                          as: "owner", // Output array field
                          pipeline: [
                              {
                                  // Project only necessary fields from owner
                                  $project: {
                                      fullName: 1,
                                      username: 1,
                                      avatar: 1
                                  }
                              }
                          ]
                      }
                  },
                  {
                      // Flatten the owner array to a single object (assuming each video has one owner)
                      $addFields: {
                          owner: { $first: "$owner" }
                      }
                  }
              ]
          }
      }
  ]);

  // Send the final response with the user's populated watch history
  return res
      .status(200)
      .json(
          new ApiResponse(
              200,
              user[0].watchHistory, // Send only the watch history array
              "Watch history fetched successfully"
          )
      );
});


export { registerUser, loginUser, logoutUser, refreshAccessToken, changeCurrentPassword, getCurrentUser, updateAccountDetails, updateUserAvatar, updateCoverImage, getUserChannelProfile, getWatchHistory };
