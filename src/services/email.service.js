import nodemailer from "nodemailer";
import config from "../config/config.js";

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        type: 'OAuth2',
        user: config.GOOGLE_USER,
        clientId: config.GOOGLE_CLIENT_ID,
        clientSecret: config.GOOGLE_CLIENT_SECRET,
        refreshToken: config.GOOGLE_REFRESH_TOKEN
    }
})


// Verify the connection configuration
transporter.verify((error, success) => {
    if (error) {
        console.error('Error connecting to email server:', error);
    } else {
        console.log('Email server is ready to send messages');
    }
});

// Function to send email

export const sendEmail = async (to, subject, text, html) => {
    const info = await transporter.sendMail({
        from: `"Auth App" <${config.GOOGLE_USER}>`,
        to,
        subject,
        text,
        html
    });

    console.log("Email sent successfully:", info.messageId);

    return info;
};


