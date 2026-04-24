import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import userRoutes from "./routes/userRoutes.js";

dotenv.config();

const app = express();

// ================= MIDDLEWARE =================
app.use(express.json());

// ================= CORS (PRODUCTION READY) =================
app.use(
  cors({
    origin: process.env.CLIENT_URL,
    methods: ["GET", "POST", "PATCH", "DELETE"],
    credentials: true,
  }),
);

// ================= ROUTES =================
app.use("/api/users", userRoutes);

// ================= HEALTH CHECK =================
app.get("/", (req, res) => {
  res.send("🚀 Backend Running");
});

// ================= START SERVER =================
const PORT = process.env.PORT || 5000;

// Connect DB first, then start server
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("✅ MongoDB Connected");

    app.listen(PORT, "0.0.0.0", () => {
      console.log(`🚀 Server running on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err.message);
    process.exit(1);
  });
