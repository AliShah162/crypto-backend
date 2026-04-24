import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import userRoutes from "./routes/userRoutes.js";

dotenv.config();

const app = express();

// ================= MIDDLEWARE =================
app.use(express.json());

// ================= CORS (Local + Netlify Production) =================
const allowedOrigins = [
  "http://localhost:3000",
  "http://localhost:3001",
  "http://localhost:8080",
  process.env.CLIENT_URL,  // Your Netlify URL will come from .env
].filter(Boolean);

app.use(
  cors({
    origin: function (origin, callback) {
      // Allow requests with no origin (like mobile apps, Postman, curl)
      if (!origin) return callback(null, true);
      
      // Allow any localhost for development
      if (origin.includes("localhost") || origin.includes("127.0.0.1")) {
        return callback(null, true);
      }
      
      // Check against allowed origins (including Netlify URL)
      if (allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        console.log("❌ Blocked origin:", origin);
        callback(new Error("Not allowed by CORS"));
      }
    },
    methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization", "x-admin-key"],
  })
);

// Handle preflight requests
app.options("*", cors());

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
  .then(() => {
    console.log("✅ MongoDB Connected");

    app.listen(PORT, "0.0.0.0", () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`📍 CORS enabled for:`, allowedOrigins);
    });
  })
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err.message);
    process.exit(1);
  });