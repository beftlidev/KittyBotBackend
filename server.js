require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const session = require("express-session");
const passport = require("passport");
const DiscordStrategy = require("passport-discord").Strategy;
const http = require("http");
const { Server } = require("socket.io");
const app = express();

module.exports = (client) => {

    const server = http.createServer(app);
    const io = new Server(server, {
        cors: {
            origin: process.env.CLIENT_URL || "http://localhost:3000",
            methods: ["GET", "POST"]
        }
    });

    app.use(helmet());
    app.use(cors({
        origin: process.env.CLIENT_URL || "http://localhost:3000",
        credentials: true
    }));
    
    app.use(session({
        secret: process.env.SESSION_SECRET || "your-secret-key",
        resave: false,
        saveUninitialized: false,
        cookie: {
            secure: process.env.NODE_ENV === "production",
            maxAge: 24 * 60 * 60 * 1000
        }
    }));

    app.use(passport.initialize());
    app.use(passport.session());

    passport.use(new DiscordStrategy({
        clientID: client?.user?.id || process.env.DISCORD_CLIENT_ID,
        clientSecret: process.env.DISCORD_CLIENT_SECRET,
        callbackURL: process.env.DISCORD_CALLBACK_URL || "/auth/discord/callback",
        scope: ["identify", "guilds"]
    }, (accessToken, refreshToken, profile, done) => {
        return done(null, profile);
    }));

    passport.serializeUser((user, done) => {
        done(null, user);
    });

    passport.deserializeUser((user, done) => {
        done(null, user);
    });
    
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));
    
    app.use((req, res, next) => {
        req.client = client;
        next();
    });

    app.use((req, res, next) => {
        req.io = io;
        next();
    });

    io.on("connection", (socket) => {
        console.log("Yeni kullanıcı bağlandı:", socket.id);
        
        socket.on("disconnect", () => {
            console.log("Kullanıcı ayrıldı:", socket.id);
        });
    });

    server.listen(process.env.PORT || 3000, () => {
        console.log(`Server is running on port ${process.env.PORT || 3000}`);
    });

    return { app, server, io };
};