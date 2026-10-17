import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import compression from "compression";
import morgan from "morgan";
import logger from "./lib/logger.js";
import User from "./models/User.js";
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

const app = express();
function applyCors(req, res) {
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin || "*");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Vary", "Origin");
}

// ============================================================
// ✅ 1. TRUST PROXY
// ============================================================
app.set("trust proxy", 1);

// ============================================================
// ✅ 2. CORS — MUST BE FIRST. OPTIONS MUST BE ANSWERED HERE.
// ============================================================
app.use((req, res, next) => {
  const origin = req.headers.origin || "*";
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept, Authorization, x-admin-key, x-session-id"
  );
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, PATCH, DELETE, PUT, OPTIONS"
  );
  res.setHeader("Access-Control-Max-Age", "86400");
  res.setHeader("Vary", "Origin");

  // 🚨 CRITICAL: end OPTIONS here. Never let it reach rate limiters.
  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  next();
});

app.use(cors({ origin: true, credentials: true }));

// ============================================================
// ✅ 3. BODY PARSERS + COMPRESSION + LOGGING
// ============================================================
app.use(express.json({ limit: "20mb" }));
app.use(express.urlencoded({ extended: true, limit: "20mb" }));
app.use(compression());
app.use(morgan("combined", { stream: logger.stream }));

// ============================================================
// ✅ 4. SECURITY MIDDLEWARE
// ============================================================
app.use(ipBlocker);
app.use(autoBlocker);
app.use(requestLogger);

// ============================================================
// ✅ 5. MONGODB CONNECTION (cached for serverless)
// ============================================================
let cachedConn = global._mongooseConn;
if (!cachedConn) {
  cachedConn = global._mongooseConn = { conn: null, promise: null };
}

async function ensureDB() {
  if (cachedConn.conn && mongoose.connection.readyState === 1) {
    return cachedConn.conn;
  }

  if (!cachedConn.promise) {
    if (!process.env.MONGO_URI) {
      throw new Error("MONGO_URI not set in environment");
    }

    cachedConn.promise = mongoose
      .connect(process.env.MONGO_URI, {
        maxPoolSize: 10,
        minPoolSize: 1,
        serverSelectionTimeoutMS: 10000,
        socketTimeoutMS: 45000,
        connectTimeoutMS: 10000,
        family: 4,
        bufferCommands: false,
      })
      .then((m) => {
        console.log("✅ MongoDB connected");
        cachedConn.conn = m;
        return m;
      })
      .catch((err) => {
        console.error("❌ MongoDB connect failed:", err.message);
        cachedConn.promise = null;
        throw err;
      });
  }

  return cachedConn.promise;
}

// ============================================================
// ✅ 6. HEALTH CHECKS (no DB needed)
// ============================================================
app.get("/ping", (req, res) => res.json({ status: "ok" }));

app.get("/", (req, res) =>
  res.json({
    status: "ok",
    service: "Crypto Backend",
    version: "2.1.0",
    timestamp: new Date().toISOString(),
  })
);

app.get("/api/test", async (req, res) => {
  try {
    await ensureDB();
    res.json({
      status: "ok",
      mongodb:
        mongoose.connection.readyState === 1 ? "connected" : "disconnected",
      kv: process.env.KV_REST_API_URL ? "enabled" : "fallback",
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({
      status: "error",
      mongodb: "disconnected",
      error: err.message,
    });
  }
});

// ============================================================
// ✅ 7. ENSURE DB BEFORE EVERY DB-DEPENDENT REQUEST
// ============================================================
app.use(async (req, res, next) => {
  try {
    await ensureDB();
    next();
  } catch (err) {
    console.error("❌ DB middleware error:", err.message);
    applyCors(req, res); 
    res.status(503).json({
      error: "DATABASE_UNAVAILABLE",
      message: "Database temporarily unavailable. Please try again.",
    });
  }
});

// ============================================================
// ✅ 8. RATE LIMITERS (AFTER OPTIONS ARE HANDLED)
// ============================================================
app.use("/api/users/admin/login", loginRateLimiter);
app.use("/api/users/virtual-admin/login", loginRateLimiter);
app.use("/api/users/login", loginRateLimiter);
app.use("/api/users/admin", adminRateLimiter);
app.use("/api/users", userRateLimiter);

// ============================================================
// ✅ 9. ROUTES
// ============================================================
app.use("/api/users", userRoutes);

// ============================================================
// ✅ 10. 404
// ============================================================
app.use((req, res) => {
  res.status(404).json({ error: "NOT_FOUND", path: req.url });
});

// ============================================================
// ✅ 11. ERROR HANDLER (always sets CORS)
// ============================================================
app.use((err, req, res, next) => {
  console.error("🚨 Error:", err.message);
  const origin = req.headers.origin || "*";
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Access-Control-Allow-Credentials", "true");

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
// ✅ 12. VERCEL EXPORT — MUST BE `export default app`
// ============================================================
export default app;

// ============================================================
// ✅ 13. LOCAL DEV ONLY
// ============================================================
if (!process.env.VERCEL) {
  const PORT = process.env.PORT || 5000;
  ensureDB()
    .then(() => {
      app.listen(PORT, "0.0.0.0", () =>
        console.log(`🚀 Local dev: http://localhost:${PORT}`)
      );
    })
    .catch((err) => {
      console.error("❌ Local start failed:", err);
      process.exit(1);
    });
}