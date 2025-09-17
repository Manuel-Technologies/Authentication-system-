const express = require("express");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const cors = require("cors");

const app = express();
app.use(express.json());

// ✅ Enable CORS for all origins
app.use(cors({ origin: "*" }));

// Load environment variables
const EMAIL_USER = process.env.EMAIL_USER || "emmanuelchekwubechukwu22@gmail.com";
const EMAIL_PASS = process.env.EMAIL_PASS || "iblyfpxtwuivtxer"; // no spaces
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey"; // change for security

// Store OTPs in memory (for testing only — in production use Redis/DB)
const otps = {};

// Signup route
app.post("/api/signup", async (req, res) => {
  try {
    const { email, name } = req.body;
    if (!email || !name) {
      return res.status(400).json({ error: "Email and name are required" });
    }

    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otps[email] = { otp, createdAt: Date.now() };

    // Send OTP via email
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: EMAIL_USER,
        pass: EMAIL_PASS,
      },
    });

    await transporter.sendMail({
      from: `"Auth System" <${EMAIL_USER}>`,
      to: email,
      subject: "Verify your email",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #333;">Email Verification</h2>
          <p>Your verification code is:</p>
          <div style="background: #f5f5f5; padding: 20px; text-align: center; margin: 20px 0;">
            <h1 style="color: #007bff; font-size: 32px; margin: 0;">${otp}</h1>
          </div>
          <p>This code will expire in 10 minutes.</p>
          <p>If you didn’t request this code, please ignore this email.</p>
        </div>
      `,
    });

    res.json({ success: true, message: "OTP sent to your email address. Please verify to complete signup.", email });
  } catch (err) {
    console.error("Error in signup:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Verify OTP
app.post("/api/verify-otp", (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) {
    return res.status(400).json({ error: "Email and OTP are required" });
  }

  const storedOtp = otps[email];
  if (!storedOtp) return res.status(400).json({ error: "No OTP found for this email" });
  if (storedOtp.otp !== otp) return res.status(400).json({ error: "Invalid OTP" });
  if (Date.now() - storedOtp.createdAt > 10 * 60 * 1000) {
    delete otps[email];
    return res.status(400).json({ error: "OTP expired" });
  }

  // Create JWT
  const token = jwt.sign({ userId: Date.now().toString(), email }, JWT_SECRET, { expiresIn: "7d" });

  res.json({
    success: true,
    message: "Email verified successfully! Account created.",
    user: { id: Date.now().toString(), email, name: req.body.name || "User", isVerified: true },
    token,
  });
});

// Protected route
app.get("/api/profile", (req, res) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ error: "Missing token" });

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ success: true, user: { id: decoded.userId, email: decoded.email, name: "User", isVerified: true, createdAt: new Date().toISOString() } });
  } catch (err) {
    res.status(401).json({ error: "Invalid or expired token" });
  }
});

// Start server
const PORT = process.env.PORT || 5000;
const RENDER_URL = process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;
app.listen(PORT, () => console.log(`✅ Server running on ${RENDER_URL}`));