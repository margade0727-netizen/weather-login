# Weather Login

Express weather application with MongoDB Atlas registration/login, Google OAuth, sessions, and Ulaanbaatar weather from Open-Meteo.

## Setup

1. Run `npm install`.
2. Copy `.env.example` to `.env` and set `MONGODB_URI`, `GOOGLE_CLIENT_ID`, and a strong `SESSION_SECRET`. The app loads `.env` automatically.
3. In MongoDB Atlas, create a cluster, database user, and network access rule.
4. In Google Cloud Console, add `http://localhost:3000` to authorized JavaScript origins and put the Web OAuth client ID in `.env`.
5. Run `npm start` and open `http://localhost:3000`.

Registration stores bcrypt password hashes only. Local and Google users are stored in the `users` collection and both receive the same session-backed dashboard. Weather uses Open-Meteo and needs no API key.

## Git

`git add . && git commit -m "Add database authentication" && git push origin main`
