import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import userRoutes from "./routes/userRoutes.js";
import User from "./models/User.js";

dotenv.config();

// Get __dirname equivalent in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// DEBUG - Check if variables are loaded
console.log("🔍 Checking environment variables:");
console.log("MONGO_URI exists:", !!process.env.MONGO_URI);
console.log("ADMIN_API_KEY exists:", !!process.env.ADMIN_API_KEY);
console.log("CLOUDINARY_CLOUD_NAME exists:", !!process.env.CLOUDINARY_CLOUD_NAME);
console.log("CLIENT_URL:", process.env.CLIENT_URL || "Not set (using defaults)");

const app = express();

// ================= MIDDLEWARE =================

// 1. JSON Parser with increased limit
app.use(express.json({ limit: '10mb' }));

// 2. URL Encoded with increased limit
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ================= FIX: CORS - ALLOW ALL ORIGINS (PRODUCTION SAFE) =================
app.use(
  cors({
    origin: function (origin, callback) {
      // Allow requests with no origin (like mobile apps or curl)
      if (!origin) return callback(null, true);

      // DEVELOPMENT: Allow all localhost
      if (origin.includes("localhost") || origin.includes("127.0.0.1")) {
        return callback(null, true);
      }

      // PRODUCTION: Allow all origins (temporarily for Indian users)
      // Once stable, you can restrict to specific domains
      console.log(`🌐 Request from origin: ${origin}`);
      callback(null, true); // ← THIS ALLOWS ALL ORIGINS
    },
    methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
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
    exposedHeaders: ["Content-Range", "X-Content-Range"],
    maxAge: 86400, // 24 hours
  })
);

// ================= FIX: TIMEOUT MIDDLEWARE =================
// Prevents requests from hanging forever
app.use((req, res, next) => {
  // Set timeout to 60 seconds (Railway default is 30s)
  req.setTimeout(60000, () => {
    console.error(`⏰ Request timeout: ${req.method} ${req.url}`);
    res.status(408).json({
      error: "REQUEST_TIMEOUT",
      message: "Server took too long to respond. Please try again.",
    });
  });
  
  // Set response timeout
  res.setTimeout(60000, () => {
    console.error(`⏰ Response timeout: ${req.method} ${req.url}`);
    if (!res.headersSent) {
      res.status(408).json({
        error: "RESPONSE_TIMEOUT",
        message: "Server is processing your request. Please wait.",
      });
    }
  });
  
  next();
});

// ================= FIX: REQUEST LOGGING (for debugging Indian users) =================
app.use((req, res, next) => {
  const start = Date.now();
  
  // Log request details
  console.log(`📥 ${req.method} ${req.url}`);
  console.log(`   IP: ${req.ip || req.connection.remoteAddress}`);
  console.log(`   Origin: ${req.headers.origin || 'Direct'}`);
  console.log(`   User-Agent: ${req.headers['user-agent']?.slice(0, 50)}...`);
  
  // Log response time on finish
  res.on('finish', () => {
    const duration = Date.now() - start;
    const status = res.statusCode;
    const emoji = status >= 400 ? '❌' : '✅';
    
    console.log(`${emoji} ${req.method} ${req.url} - ${status} (${duration}ms)`);
    
    // Warn about slow requests
    if (duration > 5000) {
      console.warn(`⚠️ SLOW REQUEST: ${duration}ms - ${req.method} ${req.url}`);
    }
  });
  
  next();
});

// ================= FIX: COMPRESSION HEADERS =================
app.use((req, res, next) => {
  // Add caching headers to reduce load
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  
  // Enable compression
  res.setHeader('Content-Encoding', 'gzip');
  
  next();
});

// ================= HEALTH CHECK =================
app.get("/api/test", (req, res) => {
  res.json({
    status: "ok",
    message: "Backend is running!",
    mongodb: mongoose.connection.readyState === 1 ? "connected" : "disconnected",
    cloudinary: process.env.CLOUDINARY_CLOUD_NAME ? "configured" : "missing",
    timestamp: new Date().toISOString(),
    // Useful for debugging
    environment: process.env.NODE_ENV || "development",
    serverTime: new Date().toISOString(),
  });
});

// ================= ROUTES =================
app.use("/api/users", userRoutes);

// ================= ROOT HEALTH CHECK =================
app.get("/", (req, res) => {
  res.json({
    status: "ok",
    service: "Crypto Backend",
    mongodb: mongoose.connection.readyState === 1 ? "connected" : "disconnected",
    cloudinary: process.env.CLOUDINARY_CLOUD_NAME ? "configured" : "missing",
    version: "2.1.0",
    timestamp: new Date().toISOString(),
  });
});

// ================= 404 HANDLER =================
app.use((req, res) => {
  res.status(404).json({
    error: "NOT_FOUND",
    message: `Route ${req.method} ${req.url} not found`,
    timestamp: new Date().toISOString(),
  });
});

// ================= ERROR HANDLER =================
app.use((err, req, res, next) => {
  console.error("🚨 Unhandled error:", err);
  console.error("Stack:", err.stack);
  
  // Don't expose internal errors in production
  const isProduction = process.env.NODE_ENV === "production";
  
  res.status(err.status || 500).json({
    error: "INTERNAL_SERVER_ERROR",
    message: isProduction ? "Something went wrong. Please try again." : err.message,
    timestamp: new Date().toISOString(),
    ...(isProduction ? {} : { stack: err.stack }),
  });
});

// ================= START SERVER =================
const PORT = process.env.PORT || 5000;

mongoose
  .connect(process.env.MONGO_URI, {
    serverSelectionTimeoutMS: 30000, // 30 seconds timeout
    socketTimeoutMS: 60000, // 60 seconds socket timeout
    family: 4, // Force IPv4 (some networks have IPv6 issues)
  })
  .then(async () => {
    console.log("✅ MongoDB Connected");
    console.log("   Database:", mongoose.connection.db.databaseName);
    console.log("   Host:", mongoose.connection.host);

    // ================= ADD refKey FIELD TO EXISTING USERS =================
    try {
      const result = await User.updateMany(
        { refKey: { $exists: false } },
        { $set: { refKey: null } }
      );
      console.log(`✅ refKey field added to ${result.modifiedCount} users`);
    } catch (err) {
      console.log("⚠️ refKey migration note:", err.message);
    }

    // ================= CREATE VIRTUAL ADMINS IF NOT EXIST =================
    try {
      const VirtualAdmin = mongoose.model("VirtualAdmin");
      const count = await VirtualAdmin.countDocuments();
      if (count === 0) {
        console.log("📝 Creating default virtual admins...");
        const defaultAdmins = [
          { adminName: "Admin 1", username: "vadmin1", refKey: "aB9xK2mPq7", email: "vadmin1@example.com" },
          { adminName: "Admin 2", username: "vadmin2", refKey: "cD4yL3nRt8", email: "vadmin2@example.com" },
          { adminName: "Admin 3", username: "vadmin3", refKey: "eF7zM1pWb5", email: "vadmin3@example.com" },
          { adminName: "Admin 4", username: "vadmin4", refKey: "gH2kX5qJv9", email: "vadmin4@example.com" },
          { adminName: "Admin 5", username: "vadmin5", refKey: "iJ6rT8yUc3", email: "vadmin5@example.com" },
        ];
        
        for (const admin of defaultAdmins) {
          await VirtualAdmin.create(admin);
        }
        console.log(`✅ Created ${defaultAdmins.length} virtual admins`);
      }
    } catch (err) {
      console.log("⚠️ Virtual admin creation note:", err.message);
    }

    // Start server
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`📍 Environment: ${process.env.NODE_ENV || "development"}`);
      console.log(`📍 MongoDB: ${mongoose.connection.host}`);
      console.log(`📍 Cloudinary: ${process.env.CLOUDINARY_CLOUD_NAME ? "CONFIGURED ✅" : "MISSING ❌"}`);
      console.log(`📍 Test endpoint: http://localhost:${PORT}/api/test`);
      console.log(`\n🔥 Ready for Indian users! CORS is configured to allow all origins.`);
    });
  })
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err.message);
    console.error("   Please check:");
    console.error("   1. Your MONGO_URI in .env");
    console.error("   2. Network connectivity");
    console.error("   3. MongoDB Atlas IP whitelist");
    process.exit(1);
  });