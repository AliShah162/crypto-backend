import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import userRoutes from "./routes/userRoutes.js";
import User from "./models/User.js";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log("🔍 Checking environment variables:");
console.log("MONGO_URI exists:", !!process.env.MONGO_URI);
console.log("ADMIN_API_KEY exists:", !!process.env.ADMIN_API_KEY);
console.log("CLOUDINARY_CLOUD_NAME exists:", !!process.env.CLOUDINARY_CLOUD_NAME);

const app = express();

// ============================================================
// ================= CORS - FIXED VERSION =================
// ============================================================

// First, set CORS headers for all responses
app.use((req, res, next) => {
  // Allow all origins (you can restrict this later)
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, x-admin-key, x-session-id');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Credentials', 'true');
  
  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// Then use cors middleware with proper configuration
app.use(
  cors({
    origin: function (origin, callback) {
      // Allow requests with no origin (like mobile apps or curl requests)
      if (!origin) return callback(null, true);
      
      // Log the origin for debugging
      console.log(`🌐 Request from origin: ${origin}`);
      
      // Allow all origins for now (you can restrict to specific domains later)
      // For production, you can use:
      // const allowedOrigins = ['vercel.app', 'netlify.app', 'localhost'];
      // const isAllowed = allowedOrigins.some(allowed => origin.includes(allowed));
      // if (isAllowed) return callback(null, true);
      
      // Allow all origins (temporary fix)
      return callback(null, true);
    },
    methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization", "x-admin-key", "x-session-id", "Accept", "Origin", "X-Requested-With"],
  })
);

// ================= MIDDLEWARE =================
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ================= TIMEOUTS =================
app.use((req, res, next) => {
  req.setTimeout(60000, () => {
    res.status(408).json({ error: "REQUEST_TIMEOUT", message: "Request timed out. Please try again." });
  });
  res.setTimeout(60000, () => {
    if (!res.headersSent) {
      res.status(408).json({ error: "RESPONSE_TIMEOUT", message: "Server is busy. Please try again." });
    }
  });
  next();
});

// ================= LOGGING =================
app.use((req, res, next) => {
  const start = Date.now();
  console.log(`📥 ${req.method} ${req.url}`);
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`${res.statusCode >= 400 ? '❌' : '✅'} ${req.method} ${req.url} - ${res.statusCode} (${duration}ms)`);
    if (duration > 5000) console.warn(`⚠️ SLOW REQUEST: ${duration}ms`);
  });
  next();
});

// ================= NO GZIP =================
app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  next();
});

// ================= HEALTH CHECKS =================
app.get("/api/test", (req, res) => {
  res.json({
    status: "ok",
    message: "Backend is running!",
    mongodb: mongoose.connection.readyState === 1 ? "connected" : "disconnected",
    cloudinary: process.env.CLOUDINARY_CLOUD_NAME ? "configured" : "missing",
    timestamp: new Date().toISOString(),
  });
});

app.get("/", (req, res) => {
  res.json({
    status: "ok",
    service: "Crypto Backend",
    mongodb: mongoose.connection.readyState === 1 ? "connected" : "disconnected",
    version: "2.1.0",
    timestamp: new Date().toISOString(),
  });
});

// ================= ROUTES =================
app.use("/api/users", userRoutes);

// ================= 404 =================
app.use((req, res) => {
  res.status(404).json({ error: "NOT_FOUND", message: `Route ${req.method} ${req.url} not found` });
});

// ================= ERROR HANDLER =================
app.use((err, req, res, next) => {
  console.error("🚨 Error:", err.message);
  res.status(500).json({
    error: "INTERNAL_SERVER_ERROR",
    message: process.env.NODE_ENV === "production" ? "Something went wrong." : err.message,
  });
});

// ============================================================
// ================= MONGODB CONNECTION - CLEAN VERSION =================
// ============================================================

async function connectToMongoDB(retries = 5, delay = 5000) {
  for (let i = 0; i < retries; i++) {
    try {
      await mongoose.connect(process.env.MONGO_URI, {
        maxPoolSize: 20,
        minPoolSize: 5,
        maxIdleTimeMS: 30000,
        socketTimeoutMS: 60000,
        connectTimeoutMS: 30000,
        serverSelectionTimeoutMS: 30000,
        family: 4,
        retryWrites: true,
        retryReads: true,
      });
      
      console.log('✅ MongoDB Connected');
      console.log(`   Database: ${mongoose.connection.db.databaseName}`);
      console.log(`   Host: ${mongoose.connection.host}`);
      console.log(`   Pool Size: 20`);
      return;
    } catch (err) {
      console.error(`❌ MongoDB attempt ${i + 1} failed:`, err.message);
      if (i < retries - 1) {
        const wait = Math.min(delay * Math.pow(1.5, i), 30000);
        console.log(`🔄 Retrying in ${wait/1000}s...`);
        await new Promise(r => setTimeout(r, wait));
      } else {
        console.error('❌ All MongoDB connection attempts failed');
        process.exit(1);
      }
    }
  }
}

// ================= MONGODB EVENTS =================
mongoose.connection.on('connected', () => {
  console.log('✅ MongoDB Connected (event)');
});

mongoose.connection.on('error', (err) => {
  console.error('❌ MongoDB Error:', err.message);
});

mongoose.connection.on('disconnected', () => {
  console.log('⚠️ MongoDB Disconnected');
});

mongoose.connection.on('reconnected', () => {
  console.log('✅ MongoDB Reconnected');
});

// ================= SHUTDOWN =================
process.on('SIGINT', async () => {
  console.log('🛑 Shutting down...');
  await mongoose.connection.close();
  console.log('✅ MongoDB connection closed');
  process.exit(0);
});

// ================= START =================
const PORT = process.env.PORT || 5000;

connectToMongoDB().then(async () => {
  // Add refKey field
  try {
    const result = await User.updateMany(
      { refKey: { $exists: false } },
      { $set: { refKey: null } }
    );
    console.log(`✅ refKey field added to ${result.modifiedCount} users`);
  } catch (err) {
    console.log("⚠️ refKey migration note:", err.message);
  }

  // Create virtual admins
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
    console.log(`📍 Cloudinary: ${process.env.CLOUDINARY_CLOUD_NAME ? "✅" : "❌"}`);
    console.log(`\n🔥 Ready for Indian users!`);
    console.log(`⚠️ MongoDB Pool Size: 20, Min Pool: 5`);
  });
}).catch((err) => {
  console.error("❌ Failed to start server:", err);
  process.exit(1);
});