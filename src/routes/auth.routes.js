import { Router } from "express";
import * as authController from "../controllers/auth.controller.js";
import { authMiddleware } from "../middlewares/auth.middleware.js";
import { loginLimiter } from "../middlewares/rateLimit.middleware.js";

const authRouter = Router();


/**
 * POST /api/auth/register
 */
authRouter.post("/register", authController.register)


/**
 * POST /api/auth/login
 */
authRouter.post("/login", loginLimiter, authController.login)


/**
 * GET /api/auth/get-me
 */
authRouter.get("/get-me", authMiddleware, authController.getMe)


/**
 * GET /api/auth/refresh-token
 */
authRouter.get("/refresh-token", authController.refreshToken)


/**
 * GET /api/auth/logout
 */
authRouter.get("/logout", authController.logout)

/**
 * GET /api/auth/logout-all
 */
authRouter.get("/logout-all", authController.logoutAll)

/**
 * GET /api/auth/verify-email
 */
authRouter.post("/verify-email", authController.verifyEmail)


authRouter.post("/resend-otp", authController.resendOtp);

export default authRouter;