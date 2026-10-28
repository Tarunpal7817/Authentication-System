import jwt from "jsonwebtoken";
import config from "../config/config.js";

export function authMiddleware(req, res, next) {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({
                message: "Access token is required"
            });
        }

        const accessToken = authHeader.split(" ")[1];

        if (!accessToken) {
            return res.status(401).json({
                message: "Access token is required"
            });
        }

        const decoded = jwt.verify(
            accessToken,
            config.JWT_SECRET
        );

        req.user = {
            id: decoded.id,
            sessionId: decoded.sessionId
        };

        next();
    } catch (error) {
        if (
            error.name === "TokenExpiredError" ||
            error.name === "JsonWebTokenError"
        ) {
            return res.status(401).json({
                message: "Invalid or expired access token"
            });
        }

        console.error("Authentication middleware error:", error);

        return res.status(500).json({
            message: "Authentication failed"
        });
    }
}
