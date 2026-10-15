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
import {
  adminRateLimiter,
  userRateLimiter,
  loginRateLimiter,
} from "./middleware/rateLimiter.js";

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
console.log(
  "Vercel KV:",
  process.env.KV_REST_API_URL ? "✅ enabled" : "⚠️ in-memory fallback"
);

const app = express();

// ============================================================
// ================= TRUST PROXY (CRITICAL for Vercel) =================
// ============================================================
app.set("trust proxy", 1);

// ============================================================
// ================= CORS (MUST BE FIRST) =================
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
  res.header("Vary", "Origin");

  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }
  next();
});

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);
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

// 1. IP BLOCKER
app.use(ipBlocker);

// 2. AUTO BLOCKER
app.use(autoBlocker);

// 3. REQUEST LOGGER
app.use(requestLogger);

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
// ================= HEALTH CHECKS =================
// ============================================================

app.get("/ping", (req, res) => {
  res.json({
    status: "ok",
    message: "Ping successful!",
    env: {
      mongoUri: !!process.env.MONGO_URI,
      adminKey: !!process.env.ADMIN_API_KEY,
      cloudinary: !!process.env.CLOUDINARY_CLOUD_NAME,
      kv: !!process.env.KV_REST_API_URL,
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
    kv: process.env.KV_REST_API_URL ? "enabled" : "fallback",
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

// ✅ Login brute-force protection
app.use("/api/users/admin/login", loginRateLimiter);
app.use("/api/users/virtual-admin/login", loginRateLimiter);
app.use("/api/users/login", loginRateLimiter);

// ✅ Admin routes — strict
app.use("/api/users/admin", adminRateLimiter);

// ✅ All other user routes — generous
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
// ================= MONGODB CONNECTION (with caching for serverless) =================
// ============================================================

// ✅ Cache connection across serverless invocations
let cachedConnection = global.mongoose;
if (!cachedConnection) {
  cachedConnection = global.mongoose = { conn: null, promise: null };
}

async function connectToMongoDB() {
  if (cachedConnection.conn) {
    return cachedConnection.conn;
  }

  if (!cachedConnection.promise) {
    cachedConnection.promise = mongoose
      .connect(process.env.MONGO_URI, {
        maxPoolSize: 10,
        minPoolSize: 1,
        maxIdleTimeMS: 60000,
        socketTimeoutMS: 60000,
        connectTimeoutMS: 10000,
        serverSelectionTimeoutMS: 10000,
        family: 4,
        retryWrites: true,
        retryReads: true,
        bufferCommands: false,
      })
      .then((m) => {
        console.log("✅ MongoDB Connected");
        console.log(`   Database: ${m.connection.db.databaseName}`);
        console.log(`   Host: ${m.connection.host}`);
        return m;
      })
      .catch((err) => {
        console.error("❌ MongoDB connection failed:", err.message);
        cachedConnection.promise = null;
        throw err;
      });
  }

  cachedConnection.conn = await cachedConnection.promise;
  return cachedConnection.conn;
}

// ============================================================
// ================= ENSURE DB CONNECTED PER REQUEST =================
// ============================================================

app.use(async (req, res, next) => {
  try {
    // Skip health checks so they always work
    if (req.path === "/ping" || req.path === "/api/test" || req.path === "/") {
      return next();
    }
    await connectToMongoDB();
    next();
  } catch (err) {
    console.error("❌ DB connection middleware error:", err.message);
    res.status(503).json({
      error: "DATABASE_UNAVAILABLE",
      message: "Database temporarily unavailable. Please try again.",
    });
  }
});

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
// ================= ONE-TIME MIGRATIONS (lazy, cached) =================
// ============================================================

let migrationsRan = false;
async function runMigrations() {
  if (migrationsRan) return;

  try {
    const result = await User.updateMany(
      { refKey: { $exists: false } },
      { $set: { refKey: null } }
    );
    if (result.modifiedCount > 0) {
      console.log(`✅ refKey added to ${result.modifiedCount} users`);
    }

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

    migrationsRan = true;
  } catch (err) {
    console.log("⚠️ Migration note:", err.message);
  }
}

// ============================================================
// ================= GRACEFUL SHUTDOWN =================
// ============================================================

process.on("SIGINT", async () => {
  console.log("🛑 Shutting down...");
  await mongoose.connection.close();
  process.exit(0);
});

process.on("SIGTERM", async () => {
  console.log("🛑 SIGTERM received, shutting down...");
  await mongoose.connection.close();
  process.exit(0);
});

// ============================================================
// ================= VERCEL SERVERLESS EXPORT =================
// ============================================================

// ✅ This is what Vercel needs — export the Express app as the handler
export default async function handler(req, res) {
  // Ensure DB connected before handling request
  try {
    if (req.url !== "/ping" && req.url !== "/api/test" && req.url !== "/") {
      await connectToMongoDB();
      await runMigrations();
    }
  } catch (err) {
    console.error("❌ Handler DB error:", err.message);
    return res.status(503).json({
      error: "DATABASE_UNAVAILABLE",
      message: "Database temporarily unavailable. Please try again.",
    });
  }

  // Hand off to Express
  return app(req, res);
}

// ============================================================
// ================= LOCAL DEV SERVER (Vercel ignores this) =================
// ============================================================

const PORT = process.env.PORT || 5000;

if (!process.env.VERCEL) {
  connectToMongoDB()
    .then(async () => {
      await runMigrations();
      app.listen(PORT, "0.0.0.0", () => {
        console.log(`🚀 Local server running on port ${PORT}`);
        console.log(`📍 MongoDB: ${mongoose.connection.host}`);
        console.log(
          `📍 Cloudinary: ${process.env.CLOUDINARY_CLOUD_NAME ? "✅" : "❌"}`
        );
        console.log(`📍 IP Blocker: active`);
        console.log(`📍 Auto Blocker: active`);
        console.log(`📍 Rate Limiting: active`);
        console.log(`📍 Login Brute-force Protection: active`);
        console.log(`\n🔥 Ready!`);
      });
    })
    .catch((err) => {
      console.error("❌ Failed to start local server:", err);
      process.exit(1);
    });
}