import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";

const app = express();

app.use(cors());
app.use(cookieParser());//to make changes in cookies of the user
app.use(express.json());//used for req.body
app.use(express.urlencoded({ extended: true }));//handle something from url
app.use(express.static("public"));//public assests which we store in our assests from taking from server and accessible to everywhere in our project

export { app }