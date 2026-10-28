
import mongoose from "mongoose";

const otpSchema = new mongoose.Schema(
    {
        email: {
            type: String,
            required: [true, "Email is required"],
            lowercase: true,
            trim: true,
            index: true
        },

        user: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "users",
            required: [true, "User is required"],
            index: true
        },

        otpHash: {
            type: String,
            required: [true, "OTP hash is required"]
        },

        expiresAt: {
            type: Date,
            required: true
        },

        attempts: {
            type: Number,
            default: 0,
            min: 0
        },


        lastSentAt: {
            type: Date,
            default: Date.now
        },

        resendCount: {
            type: Number,
            default: 0,
            min: 0
        }

    },
    {
        timestamps: true
    }
);

const otpModel = mongoose.model("otps", otpSchema);

export default otpModel;
