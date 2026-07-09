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

// ============================================================
// ================= NUCLEAR CORS FIX =================
// ============================================================

// ✅ Nuclear option - Allow EVERYTHING
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', '*');
  res.header('Access-Control-Allow-Methods', '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// ✅ Also keep cors package as backup
app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);
      if (origin.includes('vercel.app')) return callback(null, true);
      if (origin.includes('netlify.app')) return callback(null, true);
      if (origin.includes('localhost') || origin.includes('127.0.0.1')) return callback(null, true);
      console.log(`🌐 Request from origin: ${origin} - ALLOWED`);
      callback(null, true);
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
    maxAge: 86400,
  })
);

// ================= MIDDLEWARE =================

// 1. JSON Parser with increased limit
app.use(express.json({ limit: '10mb' }));

// 2. URL Encoded with increased limit
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ================= TIMEOUT MIDDLEWARE =================
app.use((req, res, next) => {
  req.setTimeout(60000, () => {
    console.error(`⏰ Request timeout: ${req.method} ${req.url}`);
    res.status(408).json({
      error: "REQUEST_TIMEOUT",
      message: "Server took too long to respond. Please try again.",
    });
  });
  
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

// ================= REQUEST LOGGING =================
app.use((req, res, next) => {
  const start = Date.now();
  
  console.log(`📥 ${req.method} ${req.url}`);
  console.log(`   IP: ${req.ip || req.connection.remoteAddress}`);
  console.log(`   Origin: ${req.headers.origin || 'Direct'}`);
  console.log(`   User-Agent: ${req.headers['user-agent']?.slice(0, 50)}...`);
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    const status = res.statusCode;
    const emoji = status >= 400 ? '❌' : '✅';
    
    console.log(`${emoji} ${req.method} ${req.url} - ${status} (${duration}ms)`);
    
    if (duration > 5000) {
      console.warn(`⚠️ SLOW REQUEST: ${duration}ms - ${req.method} ${req.url}`);
    }
  });
  
  next();
});

// ================= NO GZIP COMPRESSION =================
app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
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
  
  const isProduction = process.env.NODE_ENV === "production";
  
  res.status(err.status || 500).json({
    error: "INTERNAL_SERVER_ERROR",
    message: isProduction ? "Something went wrong. Please try again." : err.message,
    timestamp: new Date().toISOString(),
    ...(isProduction ? {} : { stack: err.stack }),
  });
});

// ============================================================
// ================= MONGODB CONNECTION =================
// ============================================================

async function connectToMongoDB(retries = 5, delay = 5000) {
  for (let i = 0; i < retries; i++) {
    try {
      await mongoose.connect(process.env.MONGO_URI, {
        serverSelectionTimeoutMS: 30000,
        socketTimeoutMS: 60000,
        family: 4,
        connectTimeoutMS: 30000,
        retryWrites: true,
        retryReads: true,
        // ✅ SUPPORTED OPTIONS ONLY
        maxPoolSize: 20,
        minPoolSize: 5,
        maxIdleTimeMS: 30000,
        heartbeatFrequencyMS: 5000,
      });
      
      console.log('✅ MongoDB Connected');
      console.log(`   Database: ${mongoose.connection.db.databaseName}`);
      console.log(`   Host: ${mongoose.connection.host}`);
      console.log(`   Max Pool Size: 20`);
      console.log(`   Min Pool Size: 5`);
      return;
    } catch (err) {
      console.error(`❌ MongoDB connection attempt ${i + 1} failed:`, err.message);
      if (i < retries - 1) {
        const waitTime = Math.min(delay * Math.pow(1.5, i), 30000);
        console.log(`🔄 Retrying in ${waitTime/1000}s...`);
        await new Promise(resolve => setTimeout(resolve, waitTime));
      } else {
        console.error('❌ All MongoDB connection attempts failed');
        console.error('   Please check:');
        console.error('   1. Your MONGO_URI in .env');
        console.error('   2. MongoDB Atlas IP whitelist (add 0.0.0.0/0)');
        console.error('   3. Network connectivity');
        process.exit(1);
      }
    }
  }
}

// ================= MONGODB EVENT HANDLERS =================

mongoose.connection.on('connected', () => {
  console.log('✅ MongoDB Connected (event)');
  console.log(`   Pool Size: ${mongoose.connection.client?.options?.maxPoolSize || 'default'}`);
});

mongoose.connection.on('error', (err) => {
  console.error('❌ MongoDB Connection Error:', err.message);
});

mongoose.connection.on('disconnected', () => {
  console.log('⚠️ MongoDB Disconnected - will auto-reconnect');
});

mongoose.connection.on('reconnected', () => {
  console.log('✅ MongoDB Reconnected');
});

// ================= GRACEFUL SHUTDOWN =================
process.on('SIGINT', async () => {
  console.log('🛑 Shutting down...');
  await mongoose.connection.close();
  console.log('✅ MongoDB connection closed');
  process.exit(0);
});

// ============================================================
// ================= AUTO-RECONNECT MIDDLEWARE =================
// ============================================================

app.use(async (req, res, next) => {
  // If MongoDB is disconnected, try to reconnect
  if (mongoose.connection.readyState !== 1) {
    console.log('⚠️ MongoDB disconnected, attempting to reconnect...');
    try {
      await mongoose.connect(process.env.MONGO_URI, {
        serverSelectionTimeoutMS: 30000,
        socketTimeoutMS: 60000,
        family: 4,
        connectTimeoutMS: 30000,
        retryWrites: true,
        retryReads: true,
        maxPoolSize: 20,
        minPoolSize: 5,
        maxIdleTimeMS: 30000,
        heartbeatFrequencyMS: 5000,
      });
      console.log('✅ MongoDB Reconnected successfully');
    } catch (err) {
      console.error('❌ Reconnection failed:', err.message);
      return res.status(503).json({
        error: "DB_UNAVAILABLE",
        message: "Database is temporarily unavailable. Please try again."
      });
    }
  }
  next();
});

// ================= START SERVER =================

const PORT = process.env.PORT || 5000;

connectToMongoDB().then(() => {
  // ================= ADD refKey FIELD TO EXISTING USERS =================
  try {
    User.updateMany(
      { refKey: { $exists: false } },
      { $set: { refKey: null } }
    ).then((result) => {
      console.log(`✅ refKey field added to ${result.modifiedCount} users`);
    }).catch((err) => {
      console.log("⚠️ refKey migration note:", err.message);
    });
  } catch (err) {
    console.log("⚠️ refKey migration note:", err.message);
  }

  // ================= CREATE VIRTUAL ADMINS IF NOT EXIST =================
  try {
    const VirtualAdmin = mongoose.model("VirtualAdmin");
    VirtualAdmin.countDocuments().then((count) => {
      if (count === 0) {
        console.log("📝 Creating default virtual admins...");
        const defaultAdmins = [
          { adminName: "Admin 1", username: "vadmin1", refKey: "aB9xK2mPq7", email: "vadmin1@example.com" },
          { adminName: "Admin 2", username: "vadmin2", refKey: "cD4yL3nRt8", email: "vadmin2@example.com" },
          { adminName: "Admin 3", username: "vadmin3", refKey: "eF7zM1pWb5", email: "vadmin3@example.com" },
          { adminName: "Admin 4", username: "vadmin4", refKey: "gH2kX5qJv9", email: "vadmin4@example.com" },
          { adminName: "Admin 5", username: "vadmin5", refKey: "iJ6rT8yUc3", email: "vadmin5@example.com" },
        ];
        
        VirtualAdmin.insertMany(defaultAdmins).then(() => {
          console.log(`✅ Created ${defaultAdmins.length} virtual admins`);
        }).catch((err) => {
          console.log("⚠️ Virtual admin creation note:", err.message);
        });
      }
    }).catch((err) => {
      console.log("⚠️ Virtual admin creation note:", err.message);
    });
  } catch (err) {
    console.log("⚠️ Virtual admin creation note:", err.message);
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📍 Environment: ${process.env.NODE_ENV || "development"}`);
    console.log(`📍 MongoDB: ${mongoose.connection.host}`);
    console.log(`📍 Cloudinary: ${process.env.CLOUDINARY_CLOUD_NAME ? "CONFIGURED ✅" : "MISSING ❌"}`);
    console.log(`📍 Test endpoint: http://localhost:${PORT}/api/test`);
    console.log(`\n🔥 Ready for Indian users!`);
    console.log(`⚠️ CORS: ALL origins allowed (including preview Vercel URLs)`);
    console.log(`⚠️ MongoDB: Pool Size 20, Min Pool 5, Heartbeat 5s`);
  });
}).catch((err) => {
  console.error("❌ Failed to start server:", err);
  process.exit(1);
});