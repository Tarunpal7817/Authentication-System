
import rateLimit from "express-rate-limit";

export const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,

    limit: 5,

    standardHeaders: "draft-8",
    legacyHeaders: false,

    message: {
        message: "Too many login attempts. Please try again after 15 minutes."
    },

    skipSuccessfulRequests: true
});
