import { Router } from "express";
const router = Router();
import User from "../models/user.model.js";
import { registerUser } from "../controllers/user.controller.js";

router.route("/register").post(registerUser);

export default router