import userModel from "../models/user.model.js";
import crypto from "crypto"
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken"
import config from "../config/config.js";
import sessionModel from "../models/session.model.js";
import { sendEmail } from "../services/email.service.js";
import { generateOtp, getOtpHtml } from "../utils/utils.js";
import otpModel from "../models/otp.model.js";



export async function register(req, res) {
    try {
        const { username, email, password } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({
                message: "Username, email and password are required"
            });
        }

        if (username.trim().length < 3) {
            return res.status(400).json({
                message: "Username must be at least 3 characters long"
            });
        }

        if (password.length < 4) {
            return res.status(400).json({
                message: "Password must be at least 4 characters long"
            });
        }

        const normalizedEmail = email.trim().toLowerCase();
        const normalizedUsername = username.trim();

        const isAlreadyRegistered = await userModel.findOne({
            $or: [
                { username: normalizedUsername },
                { email: normalizedEmail }
            ]
        });

        if (isAlreadyRegistered) {
            return res.status(409).json({
                message: "Username or email already exists"
            });
        }

        // New password hashing with bcrypt
        const hashedPassword = await bcrypt.hash(password, 12);

        const user = await userModel.create({
            username: normalizedUsername,
            email: normalizedEmail,
            password: hashedPassword
        });

        const otp = generateOtp();
        const html = getOtpHtml(otp);

        const otpHash = crypto
            .createHash("sha256")
            .update(otp)
            .digest("hex");

        await otpModel.create({
            email: normalizedEmail,
            user: user._id,
            otpHash,
            expiresAt: new Date(Date.now() + 5 * 60 * 1000)
        });

        await sendEmail(
            normalizedEmail,
            "OTP Verification",
            `Your OTP code is ${otp}`,
            html
        );

        return res.status(201).json({
            message: "User registered successfully",
            user: {
                username: user.username,
                email: user.email,
                verified: user.verified
            }
        });
    } catch (error) {
        console.error("Register error:", error);

        return res.status(500).json({
            message: "Registration failed"
        });
    }
}

export async function login(req, res) {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                message: "Email and password are required"
            });
        }

        const user = await userModel.findOne({ email });

        if (!user) {
            return res.status(401).json({
                message: "Invalid email or password"
            });
        }

        if (!user.verified) {
            return res.status(401).json({
                message: "Email not verified"
            });
        }

        let isPasswordValid = false;

        // Support bcrypt hashes and legacy SHA-256 hashes
        if (user.password.startsWith("$2")) {
            isPasswordValid = await bcrypt.compare(
                password,
                user.password
            );
        } else {
            const legacyHash = crypto
                .createHash("sha256")
                .update(password)
                .digest("hex");

            isPasswordValid = legacyHash === user.password;

            // Upgrade the password after successful legacy login
            if (isPasswordValid) {
                user.password = await bcrypt.hash(password, 12);
                await user.save();
            }
        }

        if (!isPasswordValid) {
            return res.status(401).json({
                message: "Invalid email or password"
            });
        }

        const refreshToken = jwt.sign(
            { id: user._id },
            config.JWT_SECRET,
            { expiresIn: "7d" }
        );

        const refreshTokenHash = crypto
            .createHash("sha256")
            .update(refreshToken)
            .digest("hex");

        const session = await sessionModel.create({
            user: user._id,
            refreshTokenHash,
            ip: req.ip,
            userAgent: req.headers["user-agent"]
        });

        const accessToken = jwt.sign(
            {
                id: user._id,
                sessionId: session._id
            },
            config.JWT_SECRET,
            { expiresIn: "15m" }
        );

        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        return res.status(200).json({
            message: "Logged in successfully",
            user: {
                username: user.username,
                email: user.email
            },
            accessToken
        });
    } catch (error) {
        console.error("Login error:", error);

        return res.status(500).json({
            message: "Login failed"
        });
    }
}

export async function getMe(req, res) {

    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
        return res.status(401).json({
            message: "token not found"
        })
    }

    const decoded = jwt.verify(token, config.JWT_SECRET);

    const user = await userModel.findById(decoded.id)

    res.status(200).json({
        message: "User fetched successfully",
        user: {
            username: user.username,
            email: user.email,
        }
    })
}

export async function refreshToken(req, res) {
    try {
        const token = req.cookies?.refreshToken;

        if (!token) {
            return res.status(401).json({
                message: "Refresh token not found"
            });
        }

        // Verify refresh token
        const decoded = jwt.verify(token, config.JWT_SECRET);

        // Hash the current token to find its session
        const currentTokenHash = crypto
            .createHash("sha256")
            .update(token)
            .digest("hex");

        const session = await sessionModel.findOne({
            user: decoded.id,
            refreshTokenHash: currentTokenHash,
            revoked: false
        });

        if (!session) {
            return res.status(401).json({
                message: "Invalid refresh token"
            });
        }

        // Generate a new refresh token
        const newRefreshToken = jwt.sign(
            { id: decoded.id },
            config.JWT_SECRET,
            { expiresIn: "7d" }
        );

        const newRefreshTokenHash = crypto
            .createHash("sha256")
            .update(newRefreshToken)
            .digest("hex");

        // Store the HASH, not the raw token
        session.refreshTokenHash = newRefreshTokenHash;
        await session.save();

        // Include sessionId in the access token
        const accessToken = jwt.sign(
            {
                id: decoded.id,
                sessionId: session._id
            },
            config.JWT_SECRET,
            { expiresIn: "15m" }
        );

        res.cookie("refreshToken", newRefreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        return res.status(200).json({
            message: "Access token refreshed successfully",
            accessToken
        });

    } catch (error) {
        if (error.name === "TokenExpiredError" ||
            error.name === "JsonWebTokenError") {
            return res.status(401).json({
                message: "Invalid or expired refresh token"
            });
        }

        console.error("Refresh token error:", error);

        return res.status(500).json({
            message: "Unable to refresh token"
        });
    }
}

export async function logout(req, res) {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
        return res.status(400).json({
            message: "Refresh token not found"
        })
    }

    const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

    const session = await sessionModel.findOne({
        refreshTokenHash,
        revoked: false
    })

    if (!session) {
        return res.status(400).json({
            message: "Invalid refresh token"
        })
    }

    session.revoked = true;
    await session.save();

    res.clearCookie("refreshToken")

    res.status(200).json({
        message: "Logged out successfully"
    })
}

export async function logoutAll(req, res) {

    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
        return res.status(400).json({
            message: "Refresh token not found"
        })
    }

    const decoded = jwt.verify(refreshToken, config.JWT_SECRET)

    await sessionModel.updateMany({
        user: decoded.id,
        revoked: false
    }, {
        revoked: true
    })

    res.clearCookie("refreshToken")

    res.status(200).json({
        message: "Logged out from all devices successfully"
    })
}

export async function verifyEmail(req, res) {
    try {
        const { otp, email } = req.body;

        if (!otp || !email) {
            return res.status(400).json({
                message: "Email and OTP are required"
            });
        }

        const normalizedEmail = email.trim().toLowerCase();

        // Find OTP using email first
        const otpDoc = await otpModel.findOne({
            email: normalizedEmail
        }).sort({ createdAt: -1 });

        if (!otpDoc) {
            return res.status(400).json({
                message: "OTP not found. Please register or request a new OTP."
            });
        }

        // Check OTP expiry
        if (otpDoc.expiresAt <= new Date()) {
            await otpModel.deleteOne({ _id: otpDoc._id });

            return res.status(400).json({
                message: "OTP has expired. Please request a new OTP."
            });
        }

        // Limit incorrect attempts to 5
        if (otpDoc.attempts >= 5) {
            await otpModel.deleteOne({ _id: otpDoc._id });

            return res.status(429).json({
                message: "Too many incorrect attempts. Please request a new OTP."
            });
        }

        // Compare hashed OTP
        const otpHash = crypto
            .createHash("sha256")
            .update(String(otp))
            .digest("hex");

        if (otpHash !== otpDoc.otpHash) {
            otpDoc.attempts += 1;
            await otpDoc.save();

            return res.status(400).json({
                message: "Invalid OTP",
                attemptsRemaining: Math.max(0, 5 - otpDoc.attempts)
            });
        }

        // Verify user
        const user = await userModel.findByIdAndUpdate(
            otpDoc.user,
            { verified: true },
            { new: true }
        );

        if (!user) {
            return res.status(404).json({
                message: "User not found"
            });
        }

        // Delete OTP records after successful verification
        await otpModel.deleteMany({
            user: otpDoc.user
        });

        return res.status(200).json({
            message: "Email verified successfully",
            user: {
                username: user.username,
                email: user.email,
                verified: user.verified
            }
        });

    } catch (error) {
        console.error("Email verification error:", error);

        return res.status(500).json({
            message: "Unable to verify email"
        });
    }
}

export async function resendOtp(req, res) {
    try {
        const { email } = req.body;

        if (!email || typeof email !== "string") {
            return res.status(400).json({
                message: "Valid email is required"
            });
        }

        const normalizedEmail = email.trim().toLowerCase();

        const user = await userModel.findOne({
            email: normalizedEmail
        });

        if (!user) {
            return res.status(404).json({
                message: "User not found"
            });
        }

        if (user.verified) {
            return res.status(400).json({
                message: "Email is already verified"
            });
        }

        const otpDoc = await otpModel.findOne({
            user: user._id
        }).sort({ createdAt: -1 });

        if (!otpDoc) {
            return res.status(400).json({
                message: "OTP record not found. Please register again."
            });
        }

        const now = Date.now();
        const cooldownMs = 60 * 1000;
        const maxResends = 5;

        if (
            otpDoc.lastSentAt &&
            now - new Date(otpDoc.lastSentAt).getTime() < cooldownMs
        ) {
            const remainingSeconds = Math.ceil(
                (cooldownMs -
                    (now - new Date(otpDoc.lastSentAt).getTime())) / 1000
            );

            return res.status(429).json({
                message: `Please wait ${remainingSeconds} seconds before requesting another OTP`
            });
        }

        if (otpDoc.resendCount >= maxResends) {
            return res.status(429).json({
                message: "Maximum OTP resend limit reached. Please register again or contact support."
            });
        }

        const otp = generateOtp();

        const otpHash = crypto
            .createHash("sha256")
            .update(String(otp))
            .digest("hex");

        const html = getOtpHtml(otp);

        // Send the email before replacing the current OTP
        await sendEmail(
            normalizedEmail,
            "OTP Verification",
            `Your OTP code is ${otp}`,
            html
        );

        otpDoc.otpHash = otpHash;
        otpDoc.expiresAt = new Date(now + 5 * 60 * 1000);
        otpDoc.lastSentAt = new Date(now);
        otpDoc.resendCount += 1;
        otpDoc.attempts = 0;

        await otpDoc.save();

        return res.status(200).json({
            message: "A new OTP has been sent to your email"
        });

    } catch (error) {
        console.error("Resend OTP error:", error);

        return res.status(500).json({
            message: "Unable to resend OTP"
        });
    }
}