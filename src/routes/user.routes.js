import { Router } from "express";
const router = Router();
import User from "../models/user.model.js";
import { logoutUser, registerUser ,loginUser} from "../controllers/user.controller.js";
import { upload } from "../middlewares/multer.middleware.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";

router.route("/register").post(
    upload.fields([
        { name: "avatar", maxCount: 1 },
        { name: "cover", maxCount: 1 },
    ]),
    registerUser
);

router.route("/login").post(loginUser);

//secured routes
router.route("/logout").post(verifyJWT,logoutUser);

export default router;