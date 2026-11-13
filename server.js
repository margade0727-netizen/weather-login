
const express = require("express");
const session = require("express-session");
const { OAuth2Client } = require("google-auth-library");
const path = require("path");

const app = express();
const PORT = 3000;

const CLIENT_ID =
    "48418985021-3ctdkce0tnkt2ie56ahl1up16ikruef9.apps.googleusercontent.com";

const googleClient = new OAuth2Client(CLIENT_ID);

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

app.use(express.static(path.join(__dirname, "public")));

app.post("/api/login", async (req, res) => {
    try {
        const { credential } = req.body;

        if (!credential) {
            return res.status(400).json({
                error: "Missing Google credential"
            });
        }

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

        const user = {
            id: payload.sub,
            name: payload.name || "",
            email: payload.email,
            picture: payload.picture || ""
        };

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

app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running at http://10.3.122.241:${PORT}`);
});
