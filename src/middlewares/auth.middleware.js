
import jwt from "jsonwebtoken";
import config from "../config/config.js";
import sessionModel from "../models/session.model.js";

export async function authMiddleware(req, res, next) {
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

        if (!decoded.id || !decoded.sessionId) {
            return res.status(401).json({
                message: "Invalid access token"
            });
        }

        // Check whether the session exists and is active
        const session = await sessionModel.findOne({
            _id: decoded.sessionId,
            user: decoded.id,
            revoked: false
        });

        if (!session) {
            return res.status(401).json({
                message: "Session is invalid or has been revoked"
            });
        }

        req.user = {
            id: decoded.id,
            sessionId: session._id
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
