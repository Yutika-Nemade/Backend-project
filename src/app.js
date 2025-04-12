import express from 'express'
import cookieParser from 'cookie-parser'
import cors from 'cors'

const app = express()


// configurations
app.use(cors({
    origin: process.env.CORS_ORIGIN,
    credentials: true
}))

app.use(express.json({limit: "16kb"}))
app.use(express.urlencoded({extended: true, limit: "16kb"}))
app.use(express.static("public"))
app.use(cookieParser())

// routes import
import userRouter from './routes/user.routes.js'

// routes declaration
// app.get --> when routes and controllers are in same file
// when we are separately working on routes and controllers then need to use middleware

// app.use("/users", userRouter)
// all the methods declares in user.routes.js file will be automatically appended to the url eg. http://localhost:8000/users/register, etc.

// standard practice
app.use("/api/v1/users", userRouter)

export {app}