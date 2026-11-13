
require("dotenv").config();
const express = require("express");
const session = require("express-session");
const { OAuth2Client } = require("google-auth-library");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;

const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;

const googleClient = CLIENT_ID ? new OAuth2Client(CLIENT_ID) : null;

const userSchema = new mongoose.Schema({
    firstName: { type: String, required: true, trim: true },
    lastName: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    passwordHash: { type: String, default: null },
    authProvider: { type: String, enum: ["local", "google"], required: true },
    googleId: { type: String, unique: true, sparse: true },
    picture: { type: String, default: "" }
}, { timestamps: true });

const User = mongoose.model("User", userSchema);

app.use(express.json());

app.use(session({
    secret: process.env.SESSION_SECRET || "local-development-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: "lax",
        secure: false
    }
}));

app.get("/", (req, res) => {
    const html = fs.readFileSync(path.join(__dirname, "public", "index.html"), "utf8").replace('data-client_id=""', `data-client_id="${CLIENT_ID || ""}"`);
    res.type("html").send(html);
});
app.use(express.static(path.join(__dirname, "public")));

app.post("/api/register", async (req, res) => {
    try {
        const { firstName, lastName, email, password } = req.body;
        if (!firstName || !lastName || !email || !password) return res.status(400).json({ error: "All fields are required" });
        if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: "Enter a valid email address" });
        if (password.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });
        const normalizedEmail = email.toLowerCase().trim();
        if (await User.exists({ email: normalizedEmail })) return res.status(409).json({ error: "An account with this email already exists" });
        const user = await User.create({ firstName, lastName, email: normalizedEmail, passwordHash: await bcrypt.hash(password, 12), authProvider: "local" });
        req.session.user = { id: user.id, firstName, lastName, name: `${firstName} ${lastName}`, email: user.email, picture: "", authProvider: "local" };
        res.status(201).json({ success: true });
    } catch (error) { console.error(error); res.status(500).json({ error: "Registration failed" }); }
});

app.post("/api/login/local", async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = email ? await User.findOne({ email: email.toLowerCase().trim(), authProvider: "local" }) : null;
        if (!user || !user.passwordHash || !(await bcrypt.compare(password || "", user.passwordHash))) return res.status(401).json({ error: "Incorrect email or password" });
        req.session.user = { id: user.id, firstName: user.firstName, lastName: user.lastName, name: `${user.firstName} ${user.lastName}`, email: user.email, picture: user.picture || "", authProvider: "local" };
        res.json({ success: true });
    } catch (error) { console.error(error); res.status(500).json({ error: "Login failed" }); }
});

app.post("/api/login", async (req, res) => {
    try {
        const { credential } = req.body;

        if (!credential) {
            return res.status(400).json({
                error: "Missing Google credential"
            });
        }

        if (!googleClient) return res.status(500).json({ error: "Google login is not configured" });
        const ticket = await googleClient.verifyIdToken({
            idToken: credential,
            audience: CLIENT_ID
        });

        const payload = ticket.getPayload();

        if (!payload || !payload.sub || !payload.email) {
            return res.status(401).json({
                error: "Invalid Google account information"
            });
        }

        const names = (payload.name || "Google user").split(" ");
        const userRecord = await User.findOneAndUpdate({ email: payload.email.toLowerCase() }, { $set: { firstName: payload.given_name || names[0], lastName: payload.family_name || names.slice(1).join(" "), email: payload.email.toLowerCase(), authProvider: "google", googleId: payload.sub, picture: payload.picture || "" } }, { new: true, upsert: true, setDefaultsOnInsert: true });
        const user = { id: userRecord.id, firstName: userRecord.firstName, lastName: userRecord.lastName, name: `${userRecord.firstName} ${userRecord.lastName}`, email: userRecord.email, picture: userRecord.picture || "", authProvider: "google" };

        console.log("Google login:", {
            id: user.id,
            name: user.name,
            email: user.email
        });

        // Require a verified email address.
        if (!payload.email_verified) {
            return res.status(401).json({
                error: "Google email is not verified"
            });
        }

        req.session.user = user;

        res.json({
            success: true,
            name: user.name
        });
    } catch (error) {
        console.error("Google login verification failed:", error.message);

        res.status(401).json({
            error: "Google login verification failed"
        });
    }
});

app.get("/api/me", (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({
            error: "Not logged in"
        });
    }

    res.json(req.session.user);
});

app.post("/api/logout", (req, res) => req.session.destroy(() => res.json({ success: true })));

async function start() {
    if (!process.env.MONGODB_URI) { console.error("MONGODB_URI is required. Copy .env.example to .env and configure it."); process.exit(1); }
    await mongoose.connect(process.env.MONGODB_URI);
    app.listen(PORT, "0.0.0.0", () => console.log(`Server running at http://localhost:${PORT}`));
}
start().catch((error) => { console.error("Database connection failed:", error.message); process.exit(1); });
