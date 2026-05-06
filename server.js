import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import userRoutes from "./routes/userRoutes.js";
import User from "./models/User.js";

dotenv.config();

// DEBUG - Check if variables are loaded
console.log("🔍 Checking environment variables:");
console.log("MONGO_URI exists:", !!process.env.MONGO_URI);
console.log(
  "MONGO_URI value:",
  process.env.MONGO_URI ? "SET (hidden)" : "NOT SET",
);
console.log("ADMIN_API_KEY exists:", !!process.env.ADMIN_API_KEY);

const app = express();

// ================= MIDDLEWARE =================
app.use(express.json());

// ================= CORS (Local + Netlify Production) =================
const allowedOrigins = [
  "http://localhost:3000",
  "http://localhost:3001",
  "http://localhost:3002",
  "http://localhost:3003",
  "http://localhost:8080",
  "https://coinsync-trade.netlify.app",
  "https://vocal-naiad-d5bce1.netlify.app",
  "https://coinappbase.netlify.app",
  "https://www.coinappbase.netlify.app",
  "https://coinsys.netlify.app",
  process.env.CLIENT_URL,
].filter(Boolean);

// CORS middleware
app.use(
  cors({
    origin: function (origin, callback) {
      // Allow requests with no origin (like mobile apps or curl)
      if (!origin) return callback(null, true);

      // Allow all localhost origins (for development)
      if (origin.includes("localhost") || origin.includes("127.0.0.1")) {
        return callback(null, true);
      }

      // Check against allowed origins list
      if (allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        console.log("❌ Blocked origin:", origin);
        callback(new Error("Not allowed by CORS"));
      }
    },
    methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    credentials: true,
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "x-admin-key",
      "x-session-id",
    ],
  }),
);

// ================= TEST ENDPOINT =================
app.get("/api/test", (req, res) => {
  res.json({
    status: "ok",
    message: "Backend is running!",
    mongodb:
      mongoose.connection.readyState === 1 ? "connected" : "disconnected",
    timestamp: new Date().toISOString(),
  });
});

// ================= ROUTES =================
app.use("/api/users", userRoutes);

// ================= HEALTH CHECK =================
app.get("/", (req, res) => {
  res.send("🚀 Backend Running");
});

// ================= START SERVER =================
const PORT = process.env.PORT || 5000;

mongoose
  .connect(process.env.MONGO_URI)
  .then(async () => {
    console.log("✅ MongoDB Connected");
    console.log("   Database:", mongoose.connection.db.databaseName);

    // ================= ADD refKey FIELD TO EXISTING USERS =================
    try {
      // Import User model (need to register it first)
      const result = await User.updateMany(
        { refKey: { $exists: false } }, // ← only update docs missing the field
        { $set: { refKey: null } },
      );
      console.log(`✅ refKey field added to ${result.modifiedCount} users`);
    } catch (err) {
      console.log("⚠️ refKey migration note:", err.message);
    }
    // ================================================================

    app.listen(PORT, "0.0.0.0", () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(
        `📍 CORS enabled for origins containing localhost and:`,
        allowedOrigins,
      );
      console.log(`📍 Test endpoint: http://localhost:${PORT}/api/test`);
    });
  })
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err.message);
    process.exit(1);
  });
