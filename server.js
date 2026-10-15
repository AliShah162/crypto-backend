import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import compression from "compression";
import morgan from "morgan";
import logger from "./lib/logger.js";
import User from "./models/User.js";

// ✅ IMPORT YOUR MIDDLEWARE
import { ipBlocker } from "./middleware/ipBlocker.js";
import { autoBlocker } from "./middleware/autoBlocker.js";
import { requestLogger } from "./middleware/requestLogger.js";
import { adminRateLimiter, userRateLimiter } from "./middleware/rateLimiter.js";

import userRoutes from "./routes/userRoutes.js";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log("🔍 Checking environment variables:");
console.log("MONGO_URI exists:", !!process.env.MONGO_URI);
console.log("ADMIN_API_KEY exists:", !!process.env.ADMIN_API_KEY);
console.log("CLOUDINARY_CLOUD_NAME exists:", !!process.env.CLOUDINARY_CLOUD_NAME);
console.log("BLOCKED_IPS:", process.env.BLOCKED_IPS || "(none)");
console.log("TRUSTED_ADMIN_IPS:", process.env.TRUSTED_ADMIN_IPS || "(none)");

const app = express();

// ============================================================
// ================= TRUST PROXY (CRITICAL for Vercel) =================
// ============================================================
// Vercel sits behind a proxy. Without this, req.ip is the proxy IP,
// not the real client IP — which breaks rate limiting and IP blocking.
app.set("trust proxy", 1);

// ============================================================
// ================= BULLETPROOF CORS =================
// ============================================================

app.use((req, res, next) => {
  const origin = req.headers.origin;
  res.header("Access-Control-Allow-Origin", origin || "*");
  res.header("Access-Control-Allow-Credentials", "true");
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept, Authorization, x-admin-key, x-session-id"
  );
  res.header(
    "Access-Control-Allow-Methods",
    "GET, POST, PATCH, DELETE, PUT, OPTIONS"
  );
  res.header("Access-Control-Max-Age", "86400");

  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }
  next();
});

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin) {
        return callback(null, true);
      }
      return callback(null, true);
    },
    methods: ["GET", "POST", "PATCH", "DELETE", "PUT", "OPTIONS"],
    credentials: true,
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "x-admin-key",
      "x-session-id",
      "Accept",
      "Origin",
      "X-Requested-With",
    ],
    exposedHeaders: ["Content-Length", "X-Requested-With"],
    maxAge: 86400,
  })
);

// ================= BODY PARSERS =================
app.use(express.json({ limit: "20mb" }));
app.use(express.urlencoded({ extended: true, limit: "20mb" }));

// ================= COMPRESSION =================
app.use(
  compression({
    level: 6,
    threshold: 1024,
    filter: (req, res) => {
      if (req.headers["x-no-compression"]) return false;
      return compression.filter(req, res);
    },
  })
);

// ================= REQUEST LOGGING =================
app.use(morgan("combined", { stream: logger.stream }));

// ============================================================
// ================= SECURITY MIDDLEWARE (ORDER MATTERS!) =================
// ============================================================

// 1. IP BLOCKER — runs FIRST, cheapest check (in-memory cache)
app.use(ipBlocker);

// 2. AUTO BLOCKER — tracks request counts, auto-bans repeat offenders
app.use(autoBlocker);

// 3. REQUEST LOGGER — logs admin + sensitive endpoint access
app.use(requestLogger);

// 4. RATE LIMITERS — applied per route group below
// (Cannot apply globally because admin and user need different limits)

// ================= CACHE HEADERS =================
app.use((req, res, next) => {
  if (
    req.path.includes("/kyc") ||
    req.path.includes("/image") ||
    req.path.includes("/admin/all-kyc-requests")
  ) {
    res.set({
      "Cache-Control": "public, max-age=3600, stale-while-revalidate=86400",
      "CDN-Cache-Control": "public, max-age=7200",
      Vary: "Accept-Encoding",
    });
  }
  next();
});

// ================= TIMEOUTS =================
app.use((req, res, next) => {
  req.setTimeout(120000, () => {
    res.status(408).json({
      error: "REQUEST_TIMEOUT",
      message: "Request timed out. Please try again.",
    });
  });
  res.setTimeout(120000, () => {
    if (!res.headersSent) {
      res.status(408).json({
        error: "RESPONSE_TIMEOUT",
        message: "Server is busy. Please try again.",
      });
    }
  });
  next();
});

// ============================================================
// ================= HEALTH CHECKS (before rate limiters) =================
// ============================================================

app.get("/ping", (req, res) => {
  res.json({
    status: "ok",
    message: "Ping successful!",
    env: {
      mongoUri: !!process.env.MONGO_URI,
      adminKey: !!process.env.ADMIN_API_KEY,
      cloudinary: !!process.env.CLOUDINARY_CLOUD_NAME,
    },
    timestamp: new Date().toISOString(),
  });
});

app.get("/api/test", (req, res) => {
  res.json({
    status: "ok",
    message: "Backend is running!",
    mongodb:
      mongoose.connection.readyState === 1 ? "connected" : "disconnected",
    cloudinary: process.env.CLOUDINARY_CLOUD_NAME ? "configured" : "missing",
    timestamp: new Date().toISOString(),
  });
});

app.get("/", (req, res) => {
  res.json({
    status: "ok",
    service: "Crypto Backend",
    mongodb:
      mongoose.connection.readyState === 1 ? "connected" : "disconnected",
    version: "2.1.0",
    timestamp: new Date().toISOString(),
  });
});

// ============================================================
// ================= ROUTES WITH RATE LIMITING =================
// ============================================================

// ✅ Admin routes — strict rate limit (100 req / 15 min per IP+key)
app.use("/api/users/admin", adminRateLimiter);

// ✅ All other user routes — generous rate limit (1000 req / hour)
app.use("/api/users", userRateLimiter);

// ✅ Mount all user routes
app.use("/api/users", userRoutes);

// ============================================================
// ================= 404 =================
// ============================================================

app.use((req, res) => {
  res.status(404).json({
    error: "NOT_FOUND",
    message: `Route ${req.method} ${req.url} not found`,
  });
});

// ============================================================
// ================= ERROR HANDLER =================
// ============================================================

app.use((err, req, res, next) => {
  console.error("🚨 Error:", err.message);

  // Handle rate limiter errors specially
  if (err.status === 429) {
    return res.status(429).json({
      error: "TOO_MANY_REQUESTS",
      message: err.message || "Too many requests. Please slow down.",
    });
  }

  res.status(500).json({
    error: "INTERNAL_SERVER_ERROR",
    message:
      process.env.NODE_ENV === "production"
        ? "Something went wrong."
        : err.message,
  });
});

// ============================================================
// ================= MONGODB CONNECTION =================
// ============================================================

async function connectToMongoDB(retries = 5, delay = 5000) {
  for (let i = 0; i < retries; i++) {
    try {
      await mongoose.connect(process.env.MONGO_URI, {
        maxPoolSize: 50,
        minPoolSize: 10,
        maxIdleTimeMS: 60000,
        socketTimeoutMS: 120000,
        connectTimeoutMS: 10000,
        serverSelectionTimeoutMS: 10000,
        family: 4,
        retryWrites: true,
        retryReads: true,
        heartbeatFrequencyMS: 10000,
        bufferCommands: true,
      });

      console.log("✅ MongoDB Connected");
      console.log(`   Database: ${mongoose.connection.db.databaseName}`);
      console.log(`   Host: ${mongoose.connection.host}`);
      return;
    } catch (err) {
      console.error(`❌ MongoDB attempt ${i + 1} failed:`, err.message);
      if (i < retries - 1) {
        const wait = Math.min(delay * Math.pow(1.5, i), 30000);
        console.log(`🔄 Retrying in ${wait / 1000}s...`);
        await new Promise((r) => setTimeout(r, wait));
      } else {
        console.error("❌ All MongoDB connection attempts failed");
        process.exit(1);
      }
    }
  }
}

// ============================================================
// ================= MONGODB EVENTS =================
// ============================================================

mongoose.connection.on("connected", () => {
  console.log("✅ MongoDB Connected (event)");
});

mongoose.connection.on("error", (err) => {
  console.error("❌ MongoDB Error:", err.message);
});

mongoose.connection.on("disconnected", () => {
  console.log("⚠️ MongoDB Disconnected");
});

mongoose.connection.on("reconnected", () => {
  console.log("✅ MongoDB Reconnected");
});

// ============================================================
// ================= GRACEFUL SHUTDOWN =================
// ============================================================

process.on("SIGINT", async () => {
  console.log("🛑 Shutting down...");
  await mongoose.connection.close();
  console.log("✅ MongoDB connection closed");
  process.exit(0);
});

process.on("SIGTERM", async () => {
  console.log("🛑 SIGTERM received, shutting down...");
  await mongoose.connection.close();
  console.log("✅ MongoDB connection closed");
  process.exit(0);
});

// ============================================================
// ================= START SERVER =================
// ============================================================

const PORT = process.env.PORT || 5000;

connectToMongoDB()
  .then(async () => {
    // Add refKey field to users that don't have it
    try {
      const result = await User.updateMany(
        { refKey: { $exists: false } },
        { $set: { refKey: null } }
      );
      if (result.modifiedCount > 0) {
        console.log(`✅ refKey field added to ${result.modifiedCount} users`);
      }
    } catch (err) {
      console.log("⚠️ refKey migration note:", err.message);
    }

    // Seed default virtual admins if none exist
    try {
      const VirtualAdmin = mongoose.model("VirtualAdmin");
      const count = await VirtualAdmin.countDocuments();
      if (count === 0) {
        console.log("📝 Creating default virtual admins...");
        await VirtualAdmin.insertMany([
          { adminName: "Admin 1", username: "vadmin1", refKey: "aB9xK2mPq7", email: "vadmin1@example.com" },
          { adminName: "Admin 2", username: "vadmin2", refKey: "cD4yL3nRt8", email: "vadmin2@example.com" },
          { adminName: "Admin 3", username: "vadmin3", refKey: "eF7zM1pWb5", email: "vadmin3@example.com" },
          { adminName: "Admin 4", username: "vadmin4", refKey: "gH2kX5qJv9", email: "vadmin4@example.com" },
          { adminName: "Admin 5", username: "vadmin5", refKey: "iJ6rT8yUc3", email: "vadmin5@example.com" },
        ]);
        console.log(`✅ Created 5 virtual admins`);
      }
    } catch (err) {
      console.log("⚠️ Virtual admin creation note:", err.message);
    }

    app.listen(PORT, "0.0.0.0", () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`📍 MongoDB: ${mongoose.connection.host}`);
      console.log(
        `📍 Cloudinary: ${process.env.CLOUDINARY_CLOUD_NAME ? "✅" : "❌"}`
      );
      console.log(`📍 IP Blocker: active`);
      console.log(`📍 Auto Blocker: active`);
      console.log(`📍 Rate Limiting: active`);
      console.log(`\n🔥 Ready!`);
    });
  })
  .catch((err) => {
    console.error("❌ Failed to start server:", err);
    process.exit(1);
  });