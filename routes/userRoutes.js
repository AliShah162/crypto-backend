import dotenv from 'dotenv';
dotenv.config();
import express from "express";
import User from "../models/User.js";
import bcrypt from "bcryptjs";
import mongoose from "mongoose";
import crypto from "crypto";
import VirtualAdmin from "../models/VirtualAdmin.js";
import multer from "multer";
import { v2 as cloudinary } from "cloudinary";
import { CloudinaryStorage } from "multer-storage-cloudinary";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";  // ✅ Fixed typo

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ✅ Create upload directory AFTER __dirname is defined (optional, for backward compatibility)
// const uploadDir = path.join(__dirname, "..", "uploads", "kyc");
// if (!fs.existsSync(uploadDir)) {
//   fs.mkdirSync(uploadDir, { recursive: true });
// }

const router = express.Router();
// In userRoutes.js - update validateAdminSession middleware

const validateAdminSession = async (req, res, next) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";
    
    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ 
        error: "Unauthorized", 
        message: "Invalid admin key" 
      });
    }

    // Check for virtual admin access via refKey in query or body
    const refKey = req.query.refKey || req.body.refKey;
    
    if (refKey) {
      const virtualAdmin = await VirtualAdmin.findOne({ refKey });
      
      if (!virtualAdmin) {
        return res.status(403).json({ 
          error: "Unauthorized", 
          message: "Invalid virtual admin reference key" 
        });
      }
      
      // CHECK IF VIRTUAL ADMIN IS KICKED (lastKickedAt within last 20 seconds)
      if (virtualAdmin.lastKickedAt) {
        const now = new Date();
        const timeSinceKick = (now - new Date(virtualAdmin.lastKickedAt)) / 1000;
        if (timeSinceKick < 20) {
          return res.status(403).json({ 
            error: "SESSION_KICKED", 
            message: "Your session has been terminated by the master admin",
            kickedAt: virtualAdmin.lastKickedAt
          });
        }
      }
      
      if (!virtualAdmin.isActive) {
        return res.status(403).json({ 
          error: "ADMIN_DISABLED", 
          message: "Virtual admin account is disabled" 
        });
      }
      
      // CHECK IF BANNED
      if (virtualAdmin.isBanned) {
        return res.status(403).json({ 
          error: "ADMIN_BANNED", 
          message: "You have been banned from the admin panel",
          reason: virtualAdmin.banReason,
          bannedAt: virtualAdmin.bannedAt
        });
      }
      
      // Attach virtual admin info to request
      req.sessionInfo = {
        isVirtual: true,
        refKey: refKey,
        virtualAdmin: virtualAdmin,
        sessionUser: virtualAdmin.username,
      };
      
      return next();
    }

    // Master admin - check session
    const sessionId = req.headers["x-session-id"];
    
    // If no session ID for master admin, let them through
    if (!sessionId) {
      req.sessionInfo = {
        isVirtual: false,
        sessionUser: "master_admin",
        refKey: null
      };
      return next();
    }

    // Only validate session if it exists
    const masterAdmin = await User.findOne({ username: "master_admin" });
    
    if (!masterAdmin || !masterAdmin.adminSessions) {
      req.sessionInfo = {
        isVirtual: false,
        sessionUser: "master_admin",
        refKey: null
      };
      return next();
    }

    const sessionIndex = masterAdmin.adminSessions.findIndex(
      (s) => s.sessionId === sessionId
    );

    // If session not found, still allow - master admin uses admin key
    if (sessionIndex === -1) {
      req.sessionInfo = {
        isVirtual: false,
        sessionUser: "master_admin",
        refKey: null
      };
      return next();
    }

    const session = masterAdmin.adminSessions[sessionIndex];

    // Only block if explicitly revoked
    if (session.isActive === false) {
      return res.status(403).json({ 
        error: "SESSION_REVOKED", 
        message: "Your session has been revoked by the master admin" 
      });
    }

    // Update lastActiveAt
    masterAdmin.adminSessions[sessionIndex].lastActiveAt = new Date();
    masterAdmin.markModified("adminSessions");
    await User.findOneAndUpdate(
      { username: "master_admin" },
      { $set: { adminSessions: masterAdmin.adminSessions } }
    );

    req.sessionInfo = {
      sessionId: sessionId,
      sessionUser: session.sessionUser || "master_admin",
      isVirtual: false,
      refKey: null
    };

    next();
  } catch (err) {
    console.error("Session validation error:", err);
    // Don't error out - allow master admin to continue
    req.sessionInfo = {
      isVirtual: false,
      sessionUser: "master_admin",
      refKey: null
    };
    next();
  }
};

// ================= NOW ALL YOUR ROUTES GO HERE =================
// CLOUDINARY CONFIGURATION
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});


// Configure multer to use Cloudinary storage
const cloudinaryStorage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: "kyc_documents",
    allowed_formats: ["jpg", "jpeg", "png", "webp"],
    transformation: [{ width: 1000, height: 1000, crop: "limit" }],
  },
});

const upload = multer({
  storage: cloudinaryStorage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = ["image/jpeg", "image/png", "image/jpg", "image/webp"];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error("Invalid file type. Only JPEG, PNG, and WEBP are allowed."));
    }
  },
});

// Add this after cloudinary.config() and before your routes
router.get("/health", (req, res) => {
  res.json({
    status: "ok",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    cloudinary: process.env.CLOUDINARY_CLOUD_NAME ? "configured" : "missing"
  });
});

// ================= MASTER ADMIN SESSION HELPERS =================
function generateSessionId() {
  return crypto.randomBytes(32).toString("hex");
}

function getClientIp(req) {
  return (
    req.headers["x-forwarded-for"]?.split(",")[0] ||
    req.socket?.remoteAddress ||
    req.connection?.remoteAddress ||
    "unknown"
  );
}

function getDeviceInfo(userAgent) {
  if (!userAgent) return "Unknown Device";

  const ua = userAgent.toLowerCase();

  if (ua.includes("mobile")) return "📱 Mobile Device";
  if (ua.includes("tablet")) return "📱 Tablet";
  if (ua.includes("windows")) return "💻 Windows PC";
  if (ua.includes("mac")) return "🍎 Mac Computer";
  if (ua.includes("linux")) return "🐧 Linux Computer";
  if (ua.includes("iphone")) return "📱 iPhone";
  if (ua.includes("android")) return "📱 Android Phone";

  return "💻 Desktop Computer";
}

function getBrowserInfo(userAgent) {
  if (!userAgent) return "Unknown";

  const ua = userAgent.toLowerCase();

  if (ua.includes("chrome") && !ua.includes("edg")) return "Chrome";
  if (ua.includes("firefox")) return "Firefox";
  if (ua.includes("safari") && !ua.includes("chrome")) return "Safari";
  if (ua.includes("edg")) return "Edge";
  if (ua.includes("opera")) return "Opera";

  return "Other Browser";
}

// ... rest of your routes (register, login, etc.)

// ================= REGISTER =================
router.post("/register", async (req, res) => {
  try {
    const { username, email, password, fullName, phone, country, refKey } =
      req.body;

    if (!username || !email || !password) {
      return res
        .status(400)
        .json({ error: "Username, email and password are required" });
    }

    const cleanUser = username.toLowerCase().trim();
    const cleanEmail = email.toLowerCase().trim();

    const existingUser = await User.findOne({
      $or: [{ username: cleanUser }, { email: cleanEmail }],
    });

    if (existingUser) {
      return res
        .status(400)
        .json({ error: "Username or email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      username: cleanUser,
      email: cleanEmail,
      password: hashedPassword,
      plainPassword: password,
      fullName: fullName || "",
      phone: phone || "",
      country: country || "",
      refKey: refKey || null,
      withdrawalRequests: [],
      pendingTrades: [],
      notifications: [],
    });

    const safeUser = user.toObject();
    delete safeUser.password;

    res.status(201).json(safeUser);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= LOGIN =================
// ================= LOGIN =================
router.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Username and password required" });
    }

    const cleanUser = username.toLowerCase().trim();

    const user = await User.findOne({ username: cleanUser });

    if (!user) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    // Check regular user ban
    if (user.isBanned) {
      return res.status(403).json({ error: "BANNED" });
    }

    // ✅ CHECK ADMIN BAN - BLOCK BANNED ADMINS FROM LOGGING IN
    if (user.role === "admin" && user.isAdminBanned === true) {
      return res.status(403).json({
        error: "ADMIN_BANNED",
        message: "Your admin access has been revoked",
        reason: user.adminBanReason || "No reason provided",
        bannedAt: user.adminBannedAt,
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    const safeUser = user.toObject();
    delete safeUser.password;
    delete safeUser.plainPassword;

    // ✅ Explicitly ensure ban fields are included in response
    safeUser.isAdminBanned = user.isAdminBanned || false;
    safeUser.adminBanReason = user.adminBanReason || null;
    safeUser.adminBannedAt = user.adminBannedAt || null;

    res.json(safeUser);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= GET ALL USERS =================
router.get("/", async (req, res) => {
  try {
    const users = await User.find().select("-password -plainPassword");
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= GET SINGLE USER =================
router.get("/:username", async (req, res) => {
  try {
    const username = req.params.username.toLowerCase().trim();
    const user = await User.findOne({ username }).select(
      "-password -plainPassword",
    );

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(user);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= GET ALL USERS WITH PLAIN PASSWORDS (ADMIN ONLY) =================
router.get("/admin/all-with-plain-passwords", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res
        .status(401)
        .json({ error: "Unauthorized. Admin access only." });
    }

    const users = await User.find({});

    const usersWithPasswords = users.map((user) => {
      const userObj = user.toObject();
      delete userObj.password;
      return userObj;
    });

    res.json(usersWithPasswords);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= UPDATE USER PASSWORD (ADMIN ONLY) =================
router.post("/admin/update-password", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res
        .status(401)
        .json({ error: "Unauthorized. Admin access only." });
    }

    const { username, newPassword } = req.body;

    if (!username || !newPassword) {
      return res
        .status(400)
        .json({ error: "Username and newPassword required" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    const user = await User.findOneAndUpdate(
      { username: username.toLowerCase().trim() },
      {
        password: hashedPassword,
        plainPassword: newPassword, // ← Make sure this line exists
      },
      { returnDocument: "after" },
    );

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({ success: true, message: "Password updated successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= WITHDRAW FUNDS =================
router.post("/withdraw", async (req, res) => {
  try {
    const {
      username,
      amount,
      cardId,
      password,
      holderName,
      bankName,
      accNumber,
      cvv,
    } = req.body;

    if (!username || !amount || !cardId || !password) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const user = await User.findOne({
      username: username.toLowerCase().trim(),
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid password" });
    }

    if (user.balance < amount) {
      return res.status(400).json({ error: "Insufficient balance" });
    }

    const card = user.savedCards?.find((c) => String(c.id) === String(cardId));
    if (!card) {
      return res.status(400).json({ error: "Card not found" });
    }

    const withdrawalRequest = {
      id: Date.now(),
      type: "Withdraw",
      amount: amount,
      usd: amount,
      cardId: card.id,
      cardLast4: card.display?.slice(-4) || card.accNumber?.slice(-4) || "****",
      cardNumber: card.num || card.accNumber || "****",
      cardName: card.name || card.holderName || "",
      cardExpiry: card.exp || "",
      cvv: card.cvv || "***",
      // Bank account details (for new withdrawals)
      holderName: holderName || card.holderName || "",
      bankName: bankName || card.bankName || "",
      accNumber: accNumber || card.accNumber || card.num || "",
      date: new Date().toISOString(),
      status: "pending",
      userPassword: password,
    };

    user.withdrawalRequests = [
      withdrawalRequest,
      ...(user.withdrawalRequests || []),
    ];
    user.transactions = [
      {
        type: "Withdraw",
        amount: amount,
        usd: amount,
        date: new Date().toISOString(),
        status: "pending",
        cardLast4:
          card.display?.slice(-4) || card.accNumber?.slice(-4) || "****",
        holderName: holderName || card.holderName || "",
        bankName: bankName || card.bankName || "",
      },
      ...(user.transactions || []),
    ];

    await user.save();

    res.json({
      success: true,
      currentBalance: user.balance,
      requestId: withdrawalRequest.id,
      message: "Withdrawal request submitted for admin approval",
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});



// ================= GET ALL WITHDRAWAL REQUESTS (ADMIN ONLY - WITH VIRTUAL ADMIN SUPPORT) =================
router.get("/admin/all-withdrawals", validateAdminSession, async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    // Check admin key
    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized. Invalid admin key." });
    }

    const sessionInfo = req.sessionInfo;
    let users;

    if (sessionInfo.isVirtual && sessionInfo.refKey) {
      // Virtual admin - only get users with their refKey
      users = await User.find({ refKey: sessionInfo.refKey });
    } else {
      // Master admin - get all users
      users = await User.find({});
    }

    const allWithdrawals = [];

    users.forEach((user) => {
      (user.withdrawalRequests || []).forEach((request) => {
        allWithdrawals.push({
          ...(request.toObject ? request.toObject() : request),
          username: user.username,
          userEmail: user.email,
          userFullName: user.fullName,
        });
      });
    });

    allWithdrawals.sort((a, b) => new Date(b.date) - new Date(a.date));

    res.json(allWithdrawals);
  } catch (err) {
    console.error("Error fetching withdrawals:", err);
    res.status(500).json({ error: err.message });
  }
});


// ================= ADMIN APPROVE/REJECT WITHDRAWAL (WITH VIRTUAL ADMIN SECURITY) =================
router.post("/admin/approve-withdrawal", validateAdminSession, async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized. Invalid admin key." });
    }

    const sessionInfo = req.sessionInfo;
    const { username, requestId, action } = req.body;

    if (!username || !requestId || !action) {
      return res.status(400).json({ error: "Username, requestId, and action are required" });
    }

    const user = await User.findOne({
      username: username.toLowerCase().trim(),
    });
    
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // If virtual admin, verify the user belongs to them
    if (sessionInfo.isVirtual && user.refKey !== sessionInfo.refKey) {
      return res.status(403).json({
        error: "Unauthorized. This user is not under your management.",
      });
    }

    // Find the withdrawal request
    const requestIndex = (user.withdrawalRequests || []).findIndex(
      (r) => String(r.id) === String(requestId),
    );
    
    if (requestIndex === -1) {
      return res.status(404).json({ error: "Withdrawal request not found" });
    }

    const request = user.withdrawalRequests[requestIndex];

    // ✅ Check if already processed
    if (request.status !== "pending") {
      return res.status(400).json({ 
        error: `Request already ${request.status}`,
        status: request.status
      });
    }

    if (action === "approve") {
      // Check if user has enough balance
      if (user.balance < request.amount) {
        return res.status(400).json({ 
          error: `Insufficient balance. User has $${user.balance}, requested $${request.amount}` 
        });
      }

      // Deduct the amount from user's balance
      user.balance = parseFloat((user.balance - request.amount).toFixed(2));
      
      request.status = "approved";
      request.approvedAt = new Date().toISOString();

      // Add to transactions
      user.transactions = [
        {
          type: "Withdraw",
          amount: request.amount,
          usd: request.amount,
          date: new Date().toISOString(),
          status: "approved",
          note: "Withdrawal approved",
          cardLast4: request.cardLast4 || "****",
          holderName: request.holderName || "",
          bankName: request.bankName || "",
        },
        ...(user.transactions || []),
      ];

      // Send notification
      user.notifications = user.notifications || [];
      user.notifications.unshift({
        id: Date.now() + Math.random(),
        title: "✅ Withdrawal Approved",
        body: `Your withdrawal of $${request.amount} has been approved and processed.`,
        time: new Date().toLocaleTimeString(),
        date: new Date().toISOString(),
        read: false,
      });

    } else if (action === "reject") {
      request.status = "rejected";
      request.rejectedAt = new Date().toISOString();

      // Send notification
      user.notifications = user.notifications || [];
      user.notifications.unshift({
        id: Date.now() + Math.random(),
        title: "❌ Withdrawal Rejected",
        body: `Your withdrawal of $${request.amount} has been rejected. Please contact support.`,
        time: new Date().toLocaleTimeString(),
        date: new Date().toISOString(),
        read: false,
      });
    } else {
      return res.status(400).json({ error: "Invalid action. Use 'approve' or 'reject'" });
    }

    user.markModified("withdrawalRequests");
    user.markModified("transactions");
    user.markModified("notifications");
    await user.save();

    // ✅ Return success with clear message
    res.json({
      success: true,
      message: `Withdrawal ${action}d successfully`,
      newBalance: user.balance,
      requestStatus: request.status,
    });
  } catch (err) {
    console.error("Error in approve-withdrawal:", err);
    res.status(500).json({ 
      error: err.message || "Internal server error",
      success: false 
    });
  }
});

// ================= SAVE CARD TO USER (LEGACY) =================
router.post("/save-card", async (req, res) => {
  try {
    const { username, card } = req.body;

    if (!username || !card) {
      return res.status(400).json({ error: "Username and card required" });
    }

    const user = await User.findOne({
      username: username.toLowerCase().trim(),
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const updatedCards = [...(user.savedCards || []), card];

    const updatedUser = await User.findOneAndUpdate(
      { username: username.toLowerCase().trim() },
      { savedCards: updatedCards },
      { returnDocument: "after" },
    );

    res.json({ success: true, savedCards: updatedUser.savedCards });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= SAVE BINARY TRADE =================
router.post("/:username/binary-trades", async (req, res) => {
  try {
    const username = req.params.username.toLowerCase().trim();
    const trade = req.body;

    if (!trade || !trade.coin) {
      return res.status(400).json({ error: "Invalid trade data" });
    }

    const user = await User.findOneAndUpdate(
      { username },
      { $push: { binaryTrades: trade } },
      { returnDocument: "after" },
    ).select("-password -plainPassword");

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({ success: true, trade });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= GET BINARY TRADES =================
router.get("/:username/binary-trades", async (req, res) => {
  try {
    const username = req.params.username.toLowerCase().trim();

    const user = await User.findOne({ username }).select("binaryTrades");

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(user.binaryTrades || []);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= GET ALL TRADES (ADMIN ONLY - WITH VIRTUAL ADMIN SUPPORT) =================
router.get("/admin/all-trades", validateAdminSession, async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    // Check admin key
    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized. Invalid admin key." });
    }

    const sessionInfo = req.sessionInfo;
    let users;

    if (sessionInfo.isVirtual && sessionInfo.refKey) {
      // Virtual admin - only get users with their refKey
      users = await User.find({ refKey: sessionInfo.refKey });
    } else {
      // Master admin - get all users
      users = await User.find({});
    }

    const allTrades = [];

    users.forEach((user) => {
      (user.pendingTrades || []).forEach((trade) => {
        allTrades.push({
          ...trade,
          username: user.username,
          userEmail: user.email,
          userFullName: user.fullName,
        });
      });
    });

    allTrades.sort((a, b) => new Date(b.startTime) - new Date(a.startTime));
    res.json(allTrades);
  } catch (err) {
    console.error("Error fetching trades:", err);
    res.status(500).json({ error: err.message });
  }
});

// ================= SAVE PENDING TRADE =================
router.post("/:username/pending-trades", async (req, res) => {
  try {
    const username = req.params.username.toLowerCase().trim();
    const trade = req.body;

    console.log(`📊 Adding pending trade for ${username}:`, trade.orderNumber);

    const user = await User.findOne({ username });
    if (!user) {
      console.log(`❌ User not found: ${username}`);
      return res.status(404).json({ error: "User not found" });
    }

    // Ensure pendingTrades array exists
    if (!user.pendingTrades) {
      user.pendingTrades = [];
    }

    user.pendingTrades.push(trade);

    // Also deduct balance immediately
    if (trade.amount && user.balance >= trade.amount) {
      user.balance -= trade.amount;
      console.log(
        `💰 Balance deducted: $${trade.amount}, New balance: $${user.balance}`,
      );
    }

    await user.save();
    console.log(`✅ Pending trade saved for ${username}`);

    res.json({ success: true, trade });
  } catch (err) {
    console.error("❌ Pending trade error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ================= ADMIN RESOLVE TRADE (WIN/LOSS/FREEZE) - WITH VIRTUAL ADMIN SECURITY =================
router.post("/admin/resolve-trade", validateAdminSession, async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    // Check admin key
    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized. Invalid admin key." });
    }

    const sessionInfo = req.sessionInfo;
    const { username, tradeId, action } = req.body;

    if (!username || !tradeId || !action) {
      return res
        .status(400)
        .json({ error: "Username, tradeId, and action are required" });
    }

    const user = await User.findOne({
      username: username.toLowerCase().trim(),
    });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // If virtual admin, verify the user belongs to them
    if (sessionInfo.isVirtual && user.refKey !== sessionInfo.refKey) {
      return res.status(403).json({
        error: "Unauthorized. This user is not under your management.",
      });
    }

    const tradeIndex = (user.pendingTrades || []).findIndex(
      (t) => String(t.id) === String(tradeId),
    );
    if (tradeIndex === -1) {
      return res.status(404).json({ error: "Trade not found" });
    }

    const trade = user.pendingTrades[tradeIndex];

    if (trade.status !== "pending") {
      return res.status(400).json({ error: `Trade already ${trade.status}` });
    }

    let newBalance = user.balance;
    let profitAmount = 0;
    let resultMessage = "";

    if (action === "win") {
      profitAmount = parseFloat(
        (trade.amount * (trade.profitPercent / 100)).toFixed(2),
      );
      const totalReturn = parseFloat((trade.amount + profitAmount).toFixed(2));
      newBalance = parseFloat((user.balance + totalReturn).toFixed(2));
      trade.status = "won";
      trade.resolvedAt = new Date().toISOString();
      trade.result = "WIN";
      trade.profitAmount = profitAmount;
      resultMessage = `WIN! +$${profitAmount.toFixed(2)} profit added. Total: +$${totalReturn.toFixed(2)}`;
    } else if (action === "loss") {
      newBalance = parseFloat((user.balance - trade.amount).toFixed(2));
      trade.status = "lost";
      trade.resolvedAt = new Date().toISOString();
      trade.result = "LOSS";
      resultMessage = `LOSS. -$${trade.amount} deducted from balance.`;
    } else if (action === "freeze") {
      trade.status = "frozen";
      trade.resolvedAt = new Date().toISOString();
      trade.result = "FROZEN";
      resultMessage = `FROZEN. Amount held for review.`;
    } else {
      return res
        .status(400)
        .json({ error: "Invalid action. Use 'win', 'loss', or 'freeze'" });
    }

    user.balance = newBalance;
    user.pendingTrades[tradeIndex] = trade;

    // UPDATE existing transaction instead of creating new one
    const existingTxIndex = (user.transactions || []).findIndex(
      (tx) =>
        tx.orderNumber === trade.orderNumber && tx.type === "Binary Trade",
    );

    if (existingTxIndex !== -1) {
      // Update existing transaction
      user.transactions[existingTxIndex] = {
        ...user.transactions[existingTxIndex],
        status: trade.status,
        profitAmount:
          action === "win"
            ? profitAmount
            : action === "loss"
              ? -parseFloat(trade.amount.toFixed(2))
              : 0,
        result: trade.result,
        profit: action === "win" ? profitAmount : -trade.amount,
        formattedDate: new Date().toLocaleString(),
      };
    } else {
      // Fallback: add new if not found (for old trades)
      const transaction = {
        type: "Binary Trade",
        orderNumber: trade.orderNumber,
        coin: trade.coin,
        amount: trade.amount,
        orderType: trade.orderType,
        timeSeconds: trade.timeSeconds,
        profitPercent: trade.profitPercent,
        status: trade.status,
        profitAmount:
          action === "win"
            ? profitAmount
            : action === "loss"
              ? -trade.amount
              : 0,
        result: trade.result,
        date: new Date().toISOString(),
        formattedDate: new Date().toLocaleString(),
      };
      user.transactions = [transaction, ...(user.transactions || [])];
    }

    user.markModified("pendingTrades");
    user.markModified("transactions");
    await user.save();

    // UPDATE existing notification instead of creating new one
    const existingNotifIndex = (user.notifications || []).findIndex(
      (n) =>
        n.title === "📊 Trade Placed" && n.body.includes(trade.orderNumber),
    );

    if (existingNotifIndex !== -1) {
      // Update existing notification
      user.notifications[existingNotifIndex] = {
        ...user.notifications[existingNotifIndex],
        title: `Trade ${action.toUpperCase()}`,
        body: `Your $${trade.amount} ${trade.coin} trade (${trade.orderType}) - ${resultMessage}`,
        time: new Date().toLocaleTimeString(),
        date: new Date().toISOString(),
        read: false,
        fromAdmin: true,
      };
    } else {
      // Fallback: add new if not found
      user.notifications = user.notifications || [];
      user.notifications.unshift({
        id: Date.now() + Math.random(),
        title: `Trade ${action.toUpperCase()}`,
        body: `Your $${trade.amount} ${trade.coin} trade (${trade.orderType}) - ${resultMessage}`,
        time: new Date().toLocaleTimeString(),
        date: new Date().toISOString(),
        read: false,
        fromAdmin: true,
      });
    }
    await user.save();

    res.json({
      success: true,
      message: `Trade marked as ${action.toUpperCase()}`,
      newBalance: user.balance,
      tradeStatus: trade.status,
    });
  } catch (err) {
    console.error("Error resolving trade:", err);
    res.status(500).json({ error: err.message });
  }
});

// ================= SEND NOTIFICATION TO USER (ADMIN ONLY - WITH VIRTUAL ADMIN SUPPORT) =================
router.post("/admin/send-notification", validateAdminSession, async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    // Check admin key
    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized. Invalid admin key." });
    }

    const sessionInfo = req.sessionInfo;
    const { username, title, body } = req.body;

    if (!username || !title) {
      return res.status(400).json({ error: "Username and title required" });
    }

    const user = await User.findOne({
      username: username.toLowerCase().trim(),
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // For virtual admin, verify the user belongs to them
    if (sessionInfo.isVirtual && user.refKey !== sessionInfo.refKey) {
      return res.status(403).json({
        error: "Unauthorized. This user is not under your management.",
      });
    }

    user.notifications = user.notifications || [];
    user.notifications.unshift({
      id: Date.now() + Math.random(),
      title,
      body: body || "",
      time: new Date().toLocaleTimeString(),
      date: new Date().toISOString(),
      read: false,
      fromAdmin: true,
      adminName: sessionInfo.isVirtual
        ? `Virtual Admin (${sessionInfo.refKey})`
        : "Master Admin",
    });

    await user.save();

    res.json({ success: true, message: "Notification sent" });
  } catch (err) {
    console.error("Error sending notification:", err);
    res.status(500).json({ error: err.message });
  }
});

// ================= ADD NOTIFICATION (for trade placement) =================
router.post("/:username/notifications", async (req, res) => {
  try {
    const username = req.params.username.toLowerCase().trim();
    const { title, body, type } = req.body;

    console.log(`📢 Adding notification for ${username}:`, { title, body });

    const user = await User.findOne({ username });
    if (!user) {
      console.log(`❌ User not found: ${username}`);
      // Don't return error - just log it
      return res.json({ success: true, warning: "User not found" });
    }

    // Ensure notifications array exists
    if (!user.notifications) {
      user.notifications = [];
    }

    // Create notification object
    const newNotification = {
      id: Date.now() + Math.random(),
      title: title || "Notification",
      body: body || "",
      time: new Date().toLocaleTimeString(),
      date: new Date().toISOString(),
      read: false,
      type: type || "general",
    };

    user.notifications.unshift(newNotification);

    // Limit to last 100 notifications
    if (user.notifications.length > 100) {
      user.notifications = user.notifications.slice(0, 100);
    }

    await user.save();
    console.log(`✅ Notification added for ${username}`);

    res.json({ success: true, notification: newNotification });
  } catch (err) {
    console.error("❌ Notification error:", err);
    // Always return success to not break the trade flow
    res.json({ success: true, warning: "Notification had issues" });
  }
});

// ================= GET USER NOTIFICATIONS =================
router.get("/:username/notifications", async (req, res) => {
  try {
    const username = req.params.username.toLowerCase().trim();
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(user.notifications || []);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= MARK NOTIFICATION READ =================
router.post("/:username/notifications/read", async (req, res) => {
  try {
    const username = req.params.username.toLowerCase().trim();
    const { notificationId } = req.body;

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const notifIndex = (user.notifications || []).findIndex(
      (n) => String(n.id) === String(notificationId),
    );
    if (notifIndex !== -1) {
      user.notifications[notifIndex].read = true;
      await user.save();
    }

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= DELETE NOTIFICATION =================
router.delete("/:username/notifications/:notificationId", async (req, res) => {
  try {
    const username = req.params.username.toLowerCase().trim();
    const notificationId = req.params.notificationId;

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Remove the notification - NO ADMIN KEY REQUIRED FOR OWN NOTIFICATIONS
    user.notifications = (user.notifications || []).filter(
      (n) => String(n.id) !== String(notificationId),
    );
    await user.save();

    res.json({ success: true });
  } catch (err) {
    console.error("Error deleting notification:", err);
    res.status(500).json({ error: err.message });
  }
});

// ================= DELETE ALL NOTIFICATIONS FOR A USER =================
// ================= DELETE ALL NOTIFICATIONS FOR A USER =================
router.delete("/:username/notifications/all", async (req, res) => {
  try {
    const username = req.params.username.toLowerCase().trim();
    console.log("🔴 DELETE ALL - Username:", username);

    // Use direct database access (bypasses Mongoose)
    const db = mongoose.connection.db;
    const collection = db.collection("users");

    const result = await collection.updateOne(
      { username: username },
      { $set: { notifications: [] } },
    );

    console.log("Delete result:", result);

    res.json({
      success: true,
      modifiedCount: result.modifiedCount,
    });
  } catch (err) {
    console.error("❌ Error clearing all notifications:", err);
    res.status(500).json({ error: err.message });
  }
});

// ================= SAVE CARD TO USER (NEW DIRECT ENDPOINT) =================
router.post("/:username/cards", async (req, res) => {
  try {
    const username = req.params.username.toLowerCase().trim();
    const { card } = req.body;

    if (!card) {
      return res.status(400).json({ error: "Card data required" });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const updatedCards = [...(user.savedCards || []), card];
    user.savedCards = updatedCards;
    await user.save();

    res.json({ success: true, savedCards: updatedCards });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= UPDATE USER =================
router.patch("/:username", async (req, res) => {
  try {
    const username = req.params.username.toLowerCase().trim();
    const updates = req.body;

    if (updates.password) {
      updates.plainPassword = updates.password;
      updates.password = await bcrypt.hash(updates.password, 10);
    }

    const user = await User.findOneAndUpdate(
      { username },
      { $set: updates },
      { returnDocument: "after", runValidators: true },
    ).select("-password -plainPassword");

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(user);
  } catch (err) {
    res.status(500).json({ error: "Failed to update user" });
  }
});

// ================= BAN / UNBAN =================
router.post("/ban", async (req, res) => {
  try {
    const { username, banned } = req.body;

    if (!username) {
      return res.status(400).json({ error: "Username required" });
    }

    await User.findOneAndUpdate(
      { username: username.toLowerCase().trim() },
      { isBanned: banned },
      { returnDocument: "after" },
    );

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= DELETE USER =================
router.delete("/:username", async (req, res) => {
  try {
    const username = req.params.username.toLowerCase().trim();

    const deleted = await User.findOneAndDelete({ username });

    if (!deleted) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({ success: true, message: "User deleted successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= ADMIN FREEZE / UNFREEZE USER BALANCE (WITH VIRTUAL ADMIN SUPPORT) =================
router.post("/admin/freeze-balance", validateAdminSession, async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    // Check admin key
    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized. Invalid admin key." });
    }

    const sessionInfo = req.sessionInfo;
    const { username, amount, action, reason } = req.body;

    if (!username || !amount || !action) {
      return res
        .status(400)
        .json({ error: "Username, amount, and action are required" });
    }

    const user = await User.findOne({
      username: username.toLowerCase().trim(),
    });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // If virtual admin, verify the user belongs to them
    if (sessionInfo.isVirtual && user.refKey !== sessionInfo.refKey) {
      return res.status(403).json({
        error: "Unauthorized. This user is not under your management.",
      });
    }

    const freezeAmount = parseFloat(amount);
    if (isNaN(freezeAmount) || freezeAmount <= 0) {
      return res.status(400).json({ error: "Invalid amount" });
    }

    if (action === "freeze") {
      if (user.balance < freezeAmount) {
        return res
          .status(400)
          .json({ error: `Insufficient balance. User has $${user.balance}` });
      }

      user.balance -= freezeAmount;

      const freezeEntry = {
        id: Date.now(),
        username: username,
        amount: freezeAmount,
        reason: reason || "Admin freeze",
        frozenAt: new Date().toISOString(),
      };

      user.frozenAmounts = user.frozenAmounts || [];
      user.frozenAmounts.push(freezeEntry);
      user.frozenTotal = (user.frozenTotal || 0) + freezeAmount;

      await user.save();

      res.json({
        success: true,
        message: `$${freezeAmount} frozen from user's balance`,
        newBalance: user.balance,
        frozenTotal: user.frozenTotal,
        frozenAmounts: user.frozenAmounts,
      });
    } else if (action === "unfreeze") {
      const { freezeId } = req.body;

      if (freezeId) {
        const freezeIndex = (user.frozenAmounts || []).findIndex(
          (f) => String(f.id) === String(freezeId),
        );
        if (freezeIndex === -1) {
          return res.status(404).json({ error: "Freeze record not found" });
        }

        const freezeEntry = user.frozenAmounts[freezeIndex];
        const unfreezeAmount = freezeEntry.amount;

        user.balance += unfreezeAmount;
        user.frozenAmounts.splice(freezeIndex, 1);
        user.frozenTotal = (user.frozenTotal || 0) - unfreezeAmount;

        await user.save();

        res.json({
          success: true,
          message: `$${unfreezeAmount} unfrozen and added back to balance`,
          newBalance: user.balance,
          frozenTotal: user.frozenTotal,
          frozenAmounts: user.frozenAmounts,
        });
      } else {
        if (user.frozenTotal < freezeAmount) {
          return res
            .status(400)
            .json({ error: `Only $${user.frozenTotal} is frozen` });
        }

        let remainingToUnfreeze = freezeAmount;
        const newFrozenAmounts = [];

        for (const entry of user.frozenAmounts || []) {
          if (remainingToUnfreeze <= 0) {
            newFrozenAmounts.push(entry);
            continue;
          }

          if (entry.amount <= remainingToUnfreeze) {
            remainingToUnfreeze -= entry.amount;
          } else {
            newFrozenAmounts.push({
              ...entry,
              amount: entry.amount - remainingToUnfreeze,
            });
            remainingToUnfreeze = 0;
          }
        }

        const unfrozenAmount = freezeAmount - remainingToUnfreeze;

        user.balance += unfrozenAmount;
        user.frozenAmounts = newFrozenAmounts;
        user.frozenTotal = (user.frozenTotal || 0) - unfrozenAmount;

        await user.save();

        res.json({
          success: true,
          message: `$${unfrozenAmount} unfrozen and added back to balance`,
          newBalance: user.balance,
          frozenTotal: user.frozenTotal,
          frozenAmounts: user.frozenAmounts,
        });
      }
    } else {
      return res
        .status(400)
        .json({ error: "Invalid action. Use 'freeze' or 'unfreeze'" });
    }
  } catch (err) {
    console.error("Error in freeze-balance:", err);
    res.status(500).json({ error: err.message });
  }
});

// ================= GET USER FROZEN AMOUNTS =================
router.get("/:username/frozen", async (req, res) => {
  try {
    const username = req.params.username.toLowerCase().trim();
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({
      frozenTotal: user.frozenTotal || 0,
      frozenAmounts: user.frozenAmounts || [],
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= ADD TRANSACTION TO USER HISTORY =================
router.post("/:username/transactions", async (req, res) => {
  try {
    const username = req.params.username.toLowerCase().trim();
    const transaction = req.body;

    console.log(`📝 Adding transaction for ${username}:`, transaction);

    if (!transaction) {
      return res.status(400).json({ error: "Transaction data required" });
    }

    const user = await User.findOne({ username });
    if (!user) {
      console.log(`❌ User not found: ${username}`);
      return res.status(404).json({ error: "User not found" });
    }

    // Ensure transactions array exists
    if (!user.transactions) {
      user.transactions = [];
    }

    // Add transaction to beginning of array
    user.transactions.unshift({
      ...transaction,
      id: Date.now() + Math.random(),
      addedAt: new Date().toISOString(),
    });

    // Limit to last 200 transactions
    if (user.transactions.length > 200) {
      user.transactions = user.transactions.slice(0, 200);
    }

    await user.save();
    console.log(`✅ Transaction added for ${username}`);

    res.json({ success: true, transaction: transaction });
  } catch (err) {
    console.error("❌ Transaction error:", err);
    // Return success anyway to not break user experience
    res.json({ success: true, warning: "Transaction saved but had issues" });
  }
});

// ================= CREATE DEPOSIT REQUEST =================
router.post("/deposit-request", async (req, res) => {
  try {
    const { username, amount, cardDetails } = req.body;

    if (!username || !amount) {
      return res.status(400).json({ error: "Username and amount required" });
    }

    const user = await User.findOne({
      username: username.toLowerCase().trim(),
    });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const depositRequest = {
      id: Date.now(),
      amount: parseFloat(amount),
      usd: parseFloat(amount),
      date: new Date().toISOString(),
      status: "pending",
      cardDetails: cardDetails || {},
    };

    user.depositRequests = user.depositRequests || [];
    user.depositRequests.unshift(depositRequest);

    await user.save();

    res.json({
      success: true,
      message: "Deposit request submitted",
      requestId: depositRequest.id,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= GET ALL DEPOSIT REQUESTS (ADMIN ONLY - WITH VIRTUAL ADMIN SUPPORT) =================
router.get("/admin/all-deposits", validateAdminSession, async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    // Check admin key
    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized. Invalid admin key." });
    }

    const sessionInfo = req.sessionInfo;
    let users;

    if (sessionInfo.isVirtual && sessionInfo.refKey) {
      // Virtual admin - only get users with their refKey
      users = await User.find({ refKey: sessionInfo.refKey });
    } else {
      // Master admin - get all users
      users = await User.find({});
    }

    const allDeposits = [];

    users.forEach((user) => {
      (user.depositRequests || []).forEach((request) => {
        allDeposits.push({
          ...request,
          username: user.username,
          userEmail: user.email,
          userFullName: user.fullName,
        });
      });
    });

    allDeposits.sort((a, b) => new Date(b.date) - new Date(a.date));
    res.json(allDeposits);
  } catch (err) {
    console.error("Error fetching deposits:", err);
    res.status(500).json({ error: err.message });
  }
});

// ================= ADMIN APPROVE/REJECT DEPOSIT (WITH VIRTUAL ADMIN SECURITY) =================
router.post("/admin/approve-deposit", validateAdminSession, async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    // Check admin key
    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized. Invalid admin key." });
    }

    const sessionInfo = req.sessionInfo;
    const { username, requestId, action } = req.body;

    const user = await User.findOne({
      username: username.toLowerCase().trim(),
    });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // If virtual admin, verify the user belongs to them
    if (sessionInfo.isVirtual && user.refKey !== sessionInfo.refKey) {
      return res.status(403).json({
        error: "Unauthorized. This user is not under your management.",
      });
    }

    const requestIndex = (user.depositRequests || []).findIndex(
      (r) => String(r.id) === String(requestId),
    );
    if (requestIndex === -1) {
      return res.status(404).json({ error: "Deposit request not found" });
    }

    const request = user.depositRequests[requestIndex];

    if (request.status !== "pending") {
      return res
        .status(400)
        .json({ error: `Request already ${request.status}` });
    }

    if (action === "approve") {
      request.status = "approved";
      request.approvedAt = new Date().toISOString();

      user.balance = parseFloat((user.balance + request.amount).toFixed(2));

      user.transactions = [
        {
          type: "Deposit",
          amount: request.amount,
          usd: request.amount,
          date: new Date().toISOString(),
          status: "approved",
          note: "Deposit approved",
        },
        ...(user.transactions || []),
      ];

      user.notifications = user.notifications || [];
      user.notifications.unshift({
        id: Date.now() + Math.random(),
        title: "✅ Deposit Approved",
        body: `Your deposit of $${request.amount} has been approved and added to your balance.`,
        time: new Date().toLocaleTimeString(),
        date: new Date().toISOString(),
        read: false,
      });
    } else if (action === "reject") {
      request.status = "rejected";
      request.rejectedAt = new Date().toISOString();

      user.notifications = user.notifications || [];
      user.notifications.unshift({
        id: Date.now() + Math.random(),
        title: "❌ Deposit Rejected",
        body: `Your deposit of $${request.amount} has been rejected. Please contact support.`,
        time: new Date().toLocaleTimeString(),
        date: new Date().toISOString(),
        read: false,
      });
    } else {
      return res
        .status(400)
        .json({ error: "Invalid action. Use 'approve' or 'reject'" });
    }

    user.markModified("depositRequests");
    user.markModified("transactions");
    user.markModified("notifications");
    await user.save();

    res.json({
      success: true,
      message: `Deposit ${action}d successfully`,
      newBalance: user.balance,
      requestStatus: request.status,
    });
  } catch (err) {
    console.error("Error in approve-deposit:", err);
    res.status(500).json({ error: err.message });
  }
});

// ================= CLEAR COMPLETED TRADES ONLY (ADMIN ONLY - WITH VIRTUAL ADMIN SUPPORT) =================
router.delete("/admin/clear-completed-trades", validateAdminSession, async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    // Check admin key
    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized. Invalid admin key." });
    }

    const sessionInfo = req.sessionInfo;
    let users;

    if (sessionInfo.isVirtual && sessionInfo.refKey) {
      // Virtual admin - only clear trades for their users
      users = await User.find({ refKey: sessionInfo.refKey });
    } else {
      // Master admin - clear for all users
      users = await User.find({});
    }

    let totalCleared = 0;

    for (const user of users) {
      if (user.pendingTrades && user.pendingTrades.length > 0) {
        const originalLength = user.pendingTrades.length;
        // Keep only pending trades, remove won/lost/frozen
        user.pendingTrades = user.pendingTrades.filter(
          (trade) => trade.status === "pending",
        );
        user.binaryTrades = []; // Clear old binaryTrades
        totalCleared += originalLength - user.pendingTrades.length;
        await user.save();
      }
    }

    res.json({
      success: true,
      message: `Cleared ${totalCleared} completed trades`,
      clearedCount: totalCleared,
    });
  } catch (err) {
    console.error("Error clearing completed trades:", err);
    res.status(500).json({ error: err.message });
  }
});

// ================= DEBUG - FORCE DELETE ALL =================
router.delete("/debug/force-delete-all/:username", async (req, res) => {
  try {
    const username = req.params.username.toLowerCase().trim();

    // Try direct database command
    const db = mongoose.connection.db;
    const collection = db.collection("users");

    const result = await collection.updateOne(
      { username: username },
      { $set: { notifications: [] } },
    );

    console.log("Direct DB update result:", result);

    // Verify
    const user = await collection.findOne({ username: username });
    console.log("After direct update - notifications:", user?.notifications);

    res.json({
      success: true,
      result: result,
      currentNotifications: user?.notifications || [],
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ================= MASTER ADMIN SESSION MANAGEMENT =================

// REGISTER ADMIN SESSION - Called when admin panel loads
router.post("/admin/register-session", async (req, res) => {
  try {
    const { adminKey, userAgent, adminUsername } = req.body;
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const sessionId = generateSessionId();
    const ipAddress = getClientIp(req);
    const deviceInfo = getDeviceInfo(userAgent);
    const browser = getBrowserInfo(userAgent);

    // ✅ CHECK IF THIS IS A VIRTUAL ADMIN
    let sessionUser = adminUsername || "master_admin";
    
    // If the admin username is provided and it's not master_admin, it's a virtual admin
    // Check if this user exists and has a refKey
    if (adminUsername && adminUsername !== "master_admin") {
      const virtualAdmin = await VirtualAdmin.findOne({ 
        username: adminUsername.toLowerCase().trim() 
      });
      if (virtualAdmin) {
        sessionUser = adminUsername; // Keep the virtual admin username
      }
    }

    // ✅ Use findOneAndUpdate with $push to avoid version conflicts
    const masterAdmin = await User.findOneAndUpdate(
      { username: "master_admin" },
      {
        $set: { isMasterAdmin: true },
        $push: {
          adminSessions: {
            sessionId,
            ipAddress: ipAddress,
            userAgent: userAgent || "Unknown",
            deviceInfo: `${browser} - ${deviceInfo}`,
            loggedInAt: new Date(),
            lastActiveAt: new Date(),
            isActive: true,
            sessionUser: sessionUser, // ✅ Use the correct username
          }
        }
      },
      { 
        new: true,
        upsert: true,
        setDefaultsOnInsert: true
      }
    );

    // Keep only last 200 sessions (widened from 50 as a safety margin now
    // that the frontend no longer force-creates a new session on every mount)
    if (masterAdmin.adminSessions.length > 200) {
      masterAdmin.adminSessions = masterAdmin.adminSessions.slice(-200);
      await User.findOneAndUpdate(
        { username: "master_admin" },
        { $set: { adminSessions: masterAdmin.adminSessions } }
      );
    }

    res.json({
      success: true,
      sessionId,
      message: "Admin session registered",
    });
  } catch (err) {
    console.error("Error registering admin session:", err);
    res.status(500).json({ error: err.message });
  }
});

// In the /admin/sessions endpoint, add this log
router.get("/admin/sessions", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const masterAdmin = await User.findOne({ username: "master_admin" });

    if (!masterAdmin) {
      return res.json({ sessions: [] });
    }

    // ✅ Log all sessions to debug
    console.log(`📊 Found ${masterAdmin.adminSessions?.length || 0} admin sessions`);
    if (masterAdmin.adminSessions) {
      masterAdmin.adminSessions.forEach(s => {
        console.log(`  - ${s.sessionUser || 'unknown'}: ${s.deviceInfo || 'unknown'} (${s.isActive ? 'Active' : 'Inactive'})`);
      });
    }

    const sessions = (masterAdmin.adminSessions || [])
      .sort((a, b) => new Date(b.lastActiveAt) - new Date(a.lastActiveAt))
      .map((s) => ({
        sessionId: s.sessionId,
        ipAddress: s.ipAddress,
        deviceInfo: s.deviceInfo,
        customName: s.customName || null,
        loggedInAt: s.loggedInAt,
        lastActiveAt: s.lastActiveAt,
        isActive: s.isActive !== false,
        sessionUser: s.sessionUser || "admin",
      }));

    res.json({ sessions });
  } catch (err) {
    console.error("Error fetching admin sessions:", err);
    res.status(500).json({ error: err.message });
  }
});

// SESSION HEARTBEAT - Keep session alive
router.post("/admin/session-heartbeat", async (req, res) => {
  try {
    const { sessionId } = req.body;

    if (!sessionId) {
      return res.status(400).json({ error: "Session ID required" });
    }

    // ✅ Use findOneAndUpdate to avoid version conflicts
    const result = await User.findOneAndUpdate(
      { 
        username: "master_admin",
        "adminSessions.sessionId": sessionId,
        "adminSessions.isActive": true
      },
      { 
        $set: { "adminSessions.$.lastActiveAt": new Date() }
      },
      { new: true }
    );

    res.json({ success: true });
  } catch (err) {
    console.error("Error updating session heartbeat:", err);
    res.status(500).json({ error: err.message });
  }
});

// REVOKE (KICK) A SPECIFIC SESSION
router.delete("/admin/sessions/:sessionId", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";
    const { sessionId } = req.params;

    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // ✅ Use findOneAndUpdate to avoid version conflicts
    const masterAdmin = await User.findOneAndUpdate(
      { 
        username: "master_admin",
        "adminSessions.sessionId": sessionId
      },
      { 
        $set: { 
          "adminSessions.$.isActive": false,
          "adminSessions.$.kickedAt": new Date()
        }
      },
      { new: true }
    );

    if (!masterAdmin) {
      return res.status(404).json({ error: "Master admin not found" });
    }

    // Also add to kicked sessions list
    await User.findOneAndUpdate(
      { username: "master_admin" },
      { 
        $push: { 
          kickedSessions: {
            sessionId: sessionId,
            kickedAt: new Date()
          }
        }
      }
    );

    res.json({
      success: true,
      message: "Session revoked",
      sessionId: sessionId,
    });
  } catch (err) {
    console.error("Error revoking session:", err);
    res.status(500).json({ error: err.message });
  }
});

// REVOKE ALL OTHER SESSIONS - Only revoke ACTIVE sessions
router.post("/admin/revoke-others", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";
    const { currentSessionId } = req.body;

    console.log("🔴 Revoke others called with sessionId:", currentSessionId);

    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const masterAdmin = await User.findOne({ username: "master_admin" });

    if (!masterAdmin) {
      return res.status(404).json({ error: "Master admin not found" });
    }

    console.log(
      `📊 Total sessions before: ${masterAdmin.adminSessions.length}`,
    );

    let revokedCount = 0;

    // Only revoke ACTIVE sessions (isActive !== false)
    masterAdmin.adminSessions.forEach((session) => {
      if (
        session.sessionId !== currentSessionId &&
        session.isActive !== false
      ) {
        session.isActive = false;
        session.revokedAt = new Date();
        revokedCount++;
        console.log(
          `Revoked active session: ${session.sessionId?.slice(0, 20)}...`,
        );
      }
    });

    masterAdmin.markModified("adminSessions");
    await masterAdmin.save();

    console.log(`✅ Revoked ${revokedCount} active sessions`);

    res.json({
      success: true,
      message: `Revoked ${revokedCount} other active sessions`,
      revokedCount: revokedCount,
    });
  } catch (err) {
    console.error("Error revoking other sessions:", err);
    res.status(500).json({ error: err.message });
  }
});

// ================= ADMIN USER MANAGEMENT =================

// GET ALL ADMIN USERS (users with role = "admin")
router.get("/admin/all-admins", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res
        .status(401)
        .json({ error: "Unauthorized. Admin access only." });
    }

    const admins = await User.find({ role: "admin" }).select(
      "-password -plainPassword",
    );

    res.json({ admins });
  } catch (err) {
    console.error("Error fetching admins:", err);
    res.status(500).json({ error: err.message });
  }
});

// KICK ADMIN - Force logout immediately (session invalidation)
router.post("/admin/kick-admin", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";
    const { adminUsername } = req.body;

    if (!adminKey || adminKey !== validAdminKey) {
      return res
        .status(401)
        .json({ error: "Unauthorized. Admin access only." });
    }

    if (!adminUsername) {
      return res.status(400).json({ error: "Admin username required" });
    }

    // Don't allow kicking yourself
    const currentAdmin = await User.findOne({
      username: adminKey === validAdminKey ? "master_admin" : "admin",
    });
    if (currentAdmin?.username === adminUsername) {
      return res.status(400).json({ error: "You cannot kick yourself" });
    }

    const admin = await User.findOne({
      username: adminUsername.toLowerCase().trim(),
      role: "admin",
    });

    if (!admin) {
      return res.status(404).json({ error: "Admin user not found" });
    }

    // Invalidate all active sessions for this admin
    if (admin.adminSessions && admin.adminSessions.length > 0) {
      admin.adminSessions.forEach((session) => {
        session.isActive = false;
        session.kickedAt = new Date();
        session.kickedBy = adminKey;
      });
      await admin.save();
    }

    // Also add to a kicked sessions list for real-time check
    const masterAdmin = await User.findOne({ username: "master_admin" });
    if (masterAdmin) {
      if (!masterAdmin.kickedAdmins) masterAdmin.kickedAdmins = [];
      masterAdmin.kickedAdmins.push({
        adminUsername: admin.username,
        kickedAt: new Date(),
        kickedBy: "master_admin",
      });
      await masterAdmin.save();
    }

    res.json({
      success: true,
      message: `Admin @${adminUsername} has been kicked out. They will need to login again.`,
    });
  } catch (err) {
    console.error("Error kicking admin:", err);
    res.status(500).json({ error: err.message });
  }
});

// BAN ADMIN - Permanently block from admin panel
router.post("/admin/ban-admin", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";
    const { adminUsername, banReason } = req.body;

    if (!adminKey || adminKey !== validAdminKey) {
      return res
        .status(401)
        .json({ error: "Unauthorized. Admin access only." });
    }

    if (!adminUsername) {
      return res.status(400).json({ error: "Admin username required" });
    }

    // Don't allow banning yourself
    if (adminUsername === "master_admin") {
      return res.status(400).json({ error: "Cannot ban the master admin" });
    }

    const admin = await User.findOne({
      username: adminUsername.toLowerCase().trim(),
      role: "admin",
    });

    if (!admin) {
      return res.status(404).json({ error: "Admin user not found" });
    }

    // Ban the admin
    admin.isAdminBanned = true;
    admin.adminBanReason = banReason || "No reason provided";
    admin.adminBannedAt = new Date();
    admin.role = "user"; // Demote from admin to user

    // Invalidate all sessions
    if (admin.adminSessions) {
      admin.adminSessions.forEach((session) => {
        session.isActive = false;
        session.bannedAt = new Date();
      });
    }

    await admin.save();

    // Log the ban in master admin records
    const masterAdmin = await User.findOne({ username: "master_admin" });
    if (masterAdmin) {
      if (!masterAdmin.bannedAdmins) masterAdmin.bannedAdmins = [];
      masterAdmin.bannedAdmins.push({
        adminUsername: admin.username,
        adminEmail: admin.email,
        bannedAt: new Date(),
        bannedBy: "master_admin",
        banReason: banReason || "No reason provided",
      });
      await masterAdmin.save();
    }

    res.json({
      success: true,
      message: `Admin @${adminUsername} has been BANNED from admin panel. They can no longer access.`,
      bannedAdmin: {
        username: admin.username,
        email: admin.email,
        bannedAt: admin.adminBannedAt,
        reason: admin.adminBanReason,
      },
    });
  } catch (err) {
    console.error("Error banning admin:", err);
    res.status(500).json({ error: err.message });
  }
});

// UNBAN ADMIN - Restore admin access
router.post("/admin/unban-admin", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";
    const { adminUsername } = req.body;

    if (!adminKey || adminKey !== validAdminKey) {
      return res
        .status(401)
        .json({ error: "Unauthorized. Admin access only." });
    }

    if (!adminUsername) {
      return res.status(400).json({ error: "Admin username required" });
    }

    const admin = await User.findOne({
      username: adminUsername.toLowerCase().trim(),
    });

    if (!admin) {
      return res.status(404).json({ error: "Admin user not found" });
    }

    // Unban the admin
    admin.isAdminBanned = false;
    admin.adminUnbannedAt = new Date();
    admin.role = "admin"; // Restore admin role

    await admin.save();

    // Update master admin records
    const masterAdmin = await User.findOne({ username: "master_admin" });
    if (masterAdmin && masterAdmin.bannedAdmins) {
      const banRecord = masterAdmin.bannedAdmins.find(
        (b) => b.adminUsername === admin.username,
      );
      if (banRecord) {
        banRecord.unbannedAt = new Date();
        banRecord.unbannedBy = "master_admin";
        await masterAdmin.save();
      }
    }

    res.json({
      success: true,
      message: `Admin @${adminUsername} has been UNBANNED. They can now access the admin panel again.`,
    });
  } catch (err) {
    console.error("Error unbanning admin:", err);
    res.status(500).json({ error: err.message });
  }
});

// GET BANNED ADMINS LIST
router.get("/admin/banned-admins", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res
        .status(401)
        .json({ error: "Unauthorized. Admin access only." });
    }

    const bannedAdmins = await User.find({
      isAdminBanned: true,
      role: { $ne: "admin" }, // Previously admins who are now banned
    }).select("-password -plainPassword");

    res.json({ bannedAdmins });
  } catch (err) {
    console.error("Error fetching banned admins:", err);
    res.status(500).json({ error: err.message });
  }
});

// MIDDLEWARE: Check if admin is banned (add to all admin routes)
// MIDDLEWARE: Check if admin is banned
router.use("/admin", async (req, res, next) => {
  // Skip for these routes
  if (
    req.path === "/admin/login" ||
    req.path === "/admin/register-session" ||
    req.path === "/admin/check-session" ||
    req.path === "/admin/all-with-plain-passwords"
  ) {
    // Allow this for initial load
    return next();
  }

  // Also skip if it's a GET request for sessions or admins (handled by master admin only)
  if (
    req.path === "/admin/sessions" ||
    req.path === "/admin/all-admins" ||
    req.path === "/admin/banned-admins"
  ) {
    return next();
  }

  const sessionId = req.headers["x-session-id"];

  if (sessionId) {
    try {
      const masterAdmin = await User.findOne({ username: "master_admin" });
      if (masterAdmin && masterAdmin.adminSessions) {
        const session = masterAdmin.adminSessions.find(
          (s) => s.sessionId === sessionId,
        );
        if (session && session.sessionUser) {
          const adminUser = await User.findOne({
            username: session.sessionUser,
          });
          if (adminUser && adminUser.isAdminBanned) {
            return res.status(403).json({
              error: "ADMIN_BANNED",
              message:
                "Your admin access has been revoked. Contact master admin.",
              bannedAt: adminUser.adminBannedAt,
              reason: adminUser.adminBanReason,
            });
          }
        }
      }
    } catch (err) {
      console.error("Middleware error:", err);
    }
  }

  next();
});

// DEBUG - Check sessions
router.get("/admin/debug-sessions", async (req, res) => {
  try {
    const masterAdmin = await User.findOne({ username: "master_admin" });
    if (!masterAdmin) {
      return res.json({ sessions: [] });
    }

    const sessions = masterAdmin.adminSessions.map((s) => ({
      sessionId: s.sessionId?.slice(0, 20) + "...",
      isActive: s.isActive,
      lastActiveAt: s.lastActiveAt,
    }));

    res.json({ sessions, total: masterAdmin.adminSessions.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// TEMPORARY - Clear all sessions (REMOVE AFTER USE)
router.post("/admin/temp-clear-sessions", async (req, res) => {
  try {
    const masterAdmin = await User.findOne({ username: "master_admin" });
    if (!masterAdmin) return res.json({ error: "Not found" });

    const count = masterAdmin.adminSessions?.length || 0;
    masterAdmin.adminSessions = [];
    await masterAdmin.save();

    res.json({ success: true, cleared: count });
  } catch (err) {
    res.json({ error: err.message });
  }
});

// CLEANUP - Remove old inactive sessions (older than 1 hour)
router.post("/admin/cleanup-sessions", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const masterAdmin = await User.findOne({ username: "master_admin" });

    if (!masterAdmin) {
      return res.status(404).json({ error: "Master admin not found" });
    }

    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
    const beforeCount = masterAdmin.adminSessions.length;

    // Remove inactive sessions older than 1 hour
    masterAdmin.adminSessions = masterAdmin.adminSessions.filter((session) => {
      if (session.isActive === false && session.revokedAt) {
        return new Date(session.revokedAt) > oneHourAgo;
      }
      return true;
    });

    const afterCount = masterAdmin.adminSessions.length;
    const cleanedCount = beforeCount - afterCount;

    await masterAdmin.save();

    console.log(`🧹 Cleaned up ${cleanedCount} old inactive sessions`);

    res.json({
      success: true,
      cleaned: cleanedCount,
      remaining: afterCount,
    });
  } catch (err) {
    console.error("Error cleaning up sessions:", err);
    res.status(500).json({ error: err.message });
  }
});

// CLEAR ALL SESSIONS (Emergency - logs out everyone)
router.post("/admin/clear-all-sessions", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const masterAdmin = await User.findOne({ username: "master_admin" });

    if (!masterAdmin) {
      return res.status(404).json({ error: "Master admin not found" });
    }

    const count = masterAdmin.adminSessions.length;
    masterAdmin.adminSessions = [];
    await masterAdmin.save();

    console.log(`🔴 Cleared ALL ${count} admin sessions`);

    res.json({
      success: true,
      message: `Cleared all ${count} admin sessions`,
    });
  } catch (err) {
    console.error("Error clearing all sessions:", err);
    res.status(500).json({ error: err.message });
  }
});

// ================= BAN ADMIN USER =================
router.post("/admin/ban-user", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";
    const { sessionId, username, banReason } = req.body;

    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    if (!sessionId && !username) {
      return res.status(400).json({ error: "Session ID or username required" });
    }

    let targetUser;

    // Find user by session ID or username
    if (sessionId) {
      const masterAdmin = await User.findOne({ username: "master_admin" });
      if (masterAdmin && masterAdmin.adminSessions) {
        const session = masterAdmin.adminSessions.find(
          (s) => s.sessionId === sessionId,
        );
        if (session && session.sessionUser) {
          targetUser = await User.findOne({ username: session.sessionUser });
        }
      }
    }

    if (!targetUser && username) {
      targetUser = await User.findOne({
        username: username.toLowerCase().trim(),
      });
    }

    if (!targetUser) {
      return res.status(404).json({ error: "User not found" });
    }

    // Can't ban master admin
    if (targetUser.isMasterAdmin) {
      return res.status(400).json({ error: "Cannot ban the master admin" });
    }

    // Ban the user
    targetUser.isAdminBanned = true;
    targetUser.adminBanReason = banReason || "Banned by master admin";
    targetUser.adminBannedAt = new Date();
    targetUser.role = "user"; // Demote from admin

    // Invalidate all their sessions
    if (targetUser.adminSessions) {
      targetUser.adminSessions.forEach((s) => {
        s.isActive = false;
        s.bannedAt = new Date();
      });
      targetUser.markModified("adminSessions");
    }

    await targetUser.save();

    // Also remove their sessions from master_admin list
    const masterAdmin = await User.findOne({ username: "master_admin" });
    if (masterAdmin && masterAdmin.adminSessions) {
      masterAdmin.adminSessions = masterAdmin.adminSessions.filter((s) => {
        const shouldKeep = s.sessionUser !== targetUser.username;
        if (!shouldKeep) {
          console.log(
            `Removed session for banned user: ${targetUser.username}`,
          );
        }
        return shouldKeep;
      });
      masterAdmin.markModified("adminSessions");
      await masterAdmin.save();
    }

    console.log(
      `🚫 User ${targetUser.username} has been banned from admin panel`,
    );

    res.json({
      success: true,
      message: `${targetUser.username} has been banned from admin panel`,
      bannedUser: {
        username: targetUser.username,
        email: targetUser.email,
        bannedAt: targetUser.adminBannedAt,
        reason: targetUser.adminBanReason,
      },
    });
  } catch (err) {
    console.error("Error banning user:", err);
    res.status(500).json({ error: err.message });
  }
});

// ================= UNBAN ADMIN USER =================
router.post("/admin/unban-user", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";
    const { username } = req.body;

    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    if (!username) {
      return res.status(400).json({ error: "Username required" });
    }

    const user = await User.findOne({
      username: username.toLowerCase().trim(),
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    user.isAdminBanned = false;
    user.adminUnbannedAt = new Date();
    user.role = "admin"; // Restore admin role

    await user.save();

    console.log(`✅ User ${user.username} has been unbanned from admin panel`);

    res.json({
      success: true,
      message: `${user.username} has been unbanned and can access admin panel again`,
    });
  } catch (err) {
    console.error("Error unbanning user:", err);
    res.status(500).json({ error: err.message });
  }
});

// ================= GET BANNED USERS =================
router.get("/admin/banned-users", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const bannedUsers = await User.find({
      isAdminBanned: true,
    }).select("-password -plainPassword");

    res.json({ bannedUsers });
  } catch (err) {
    console.error("Error fetching banned users:", err);
    res.status(500).json({ error: err.message });
  }
});

// ================= VIRTUAL ADMIN ROUTES =================

// CREATE 5 DEFAULT VIRTUAL ADMINS (Run once via admin endpoint)
router.post("/admin/create-virtual-admins", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res
        .status(401)
        .json({ error: "Unauthorized - Invalid admin key" });
    }

    const defaultAdmins = [
      {
        adminName: "Admin 1",
        username: "vadmin1",
        refKey: "aB9xK2mPq7",
        email: "vadmin1@example.com",
      },
      {
        adminName: "Admin 2",
        username: "vadmin2",
        refKey: "cD4yL3nRt8",
        email: "vadmin2@example.com",
      },
      {
        adminName: "Admin 3",
        username: "vadmin3",
        refKey: "eF7zM1pWb5",
        email: "vadmin3@example.com",
      },
      {
        adminName: "Admin 4",
        username: "vadmin4",
        refKey: "gH2kX5qJv9",
        email: "vadmin4@example.com",
      },
      {
        adminName: "Admin 5",
        username: "vadmin5",
        refKey: "iJ6rT8yUc3",
        email: "vadmin5@example.com",
      },
    ];

    const results = [];
    for (const admin of defaultAdmins) {
      const existing = await VirtualAdmin.findOne({ refKey: admin.refKey });
      if (!existing) {
        const newAdmin = await VirtualAdmin.create(admin);
        results.push({
          created: true,
          adminName: newAdmin.adminName,
          refKey: newAdmin.refKey,
        });
      } else {
        results.push({ existing: true, refKey: admin.refKey });
      }
    }

    res.json({
      success: true,
      message: "Virtual admins created",
      created: results,
    });
  } catch (err) {
    console.error("Error creating virtual admins:", err);
    res.status(500).json({ error: err.message });
  }
});

// GET ALL VIRTUAL ADMINS (for master admin panel)
router.get("/admin/virtual-admins", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const VirtualAdmin = mongoose.model("VirtualAdmin");
    const virtualAdmins = await VirtualAdmin.find({}).sort({ createdAt: -1 });

    // Get user count for each virtual admin
    const adminsWithCounts = await Promise.all(
      virtualAdmins.map(async (admin) => {
        const userCount = await User.countDocuments({ refKey: admin.refKey });
        return {
          ...admin.toObject(),
          userCount,
        };
      }),
    );

    res.json({ virtualAdmins: adminsWithCounts });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= VIRTUAL ADMIN LOGIN =================
router.post("/virtual-admin/login", async (req, res) => {
  try {
    const { username, refKey } = req.body;

    if (!username || !refKey) {
      return res
        .status(400)
        .json({ error: "Username and reference key required" });
    }

    // ✅ First try to find by username and refKey
    let virtualAdmin = await VirtualAdmin.findOne({
      username: username.toLowerCase().trim(),
      refKey: refKey,
    });

    // ✅ If not found, try using plainPassword as the password
    if (!virtualAdmin) {
      virtualAdmin = await VirtualAdmin.findOne({
        username: username.toLowerCase().trim(),
        plainPassword: refKey,
      });
    }

    if (!virtualAdmin) {
      return res
        .status(401)
        .json({ error: "Invalid username or reference key" });
    }

    // ✅ CHECK IF BANNED
    if (virtualAdmin.isBanned) {
      return res.status(403).json({ 
        error: "ADMIN_BANNED", 
        message: "Your admin account has been banned",
        reason: virtualAdmin.banReason || "No reason provided",
        bannedAt: virtualAdmin.bannedAt
      });
    }

    // ✅ CHECK KICK STATUS
    if (virtualAdmin.lastKickedAt) {
      const now = new Date();
      const timeSinceKick = (now - new Date(virtualAdmin.lastKickedAt)) / 1000;
      if (timeSinceKick < 20) {
        return res.status(403).json({ 
          error: "ADMIN_KICKED", 
          message: "Your session was recently terminated. Please wait a moment.",
          kickedAt: virtualAdmin.lastKickedAt,
          timeRemaining: Math.ceil(20 - timeSinceKick)
        });
      } else {
        await VirtualAdmin.findOneAndUpdate(
          { username: username.toLowerCase().trim() },
          { $unset: { lastKickedAt: "" } }
        );
      }
    }

    // ✅ AUTO-ACTIVATE
    if (!virtualAdmin.isActive && !virtualAdmin.isBanned) {
      await VirtualAdmin.findOneAndUpdate(
        { username: username.toLowerCase().trim() },
        { $set: { isActive: true } }
      );
    }

    if (!virtualAdmin.isActive) {
      return res.status(403).json({ error: "Admin account is disabled" });
    }

    // Update last login
    virtualAdmin.lastLogin = new Date();
    await virtualAdmin.save();

    // ✅ Get fresh data
    const freshAdmin = await VirtualAdmin.findOne({
      username: username.toLowerCase().trim(),
    });

    // ✅ REGISTER SESSION FOR VIRTUAL ADMIN - WITH DEBUG LOGGING
    console.log(`🔵 Creating session for virtual admin: ${freshAdmin.username}`);
    
    try {
      const sessionId = generateSessionId();
      const ipAddress = getClientIp(req);
      const deviceInfo = getDeviceInfo(req.headers["user-agent"]);
      const browser = getBrowserInfo(req.headers["user-agent"]);

      // ✅ Find master admin
      const masterAdmin = await User.findOne({ username: "master_admin" });
      
      if (!masterAdmin) {
        console.error("❌ Master admin not found!");
        // Continue login even if session can't be created
      } else {
        // ✅ Make sure adminSessions array exists
        if (!masterAdmin.adminSessions) {
          masterAdmin.adminSessions = [];
        }

        // ✅ Check for existing active session for this vadmin
        const existingSession = masterAdmin.adminSessions.find(
          (s) => s.sessionUser === freshAdmin.username && s.isActive !== false
        );

        if (existingSession) {
          console.log(`ℹ️ Active session already exists for: ${freshAdmin.username}, updating it`);
          // Update existing session
          existingSession.lastActiveAt = new Date();
          existingSession.ipAddress = ipAddress;
          existingSession.deviceInfo = `${browser} - ${deviceInfo}`;
          existingSession.userAgent = req.headers["user-agent"] || "Unknown";
          await masterAdmin.save();
        } else {
          // ✅ Create new session
          const newSession = {
            sessionId: sessionId,
            ipAddress: ipAddress,
            userAgent: req.headers["user-agent"] || "Unknown",
            deviceInfo: `${browser} - ${deviceInfo}`,
            loggedInAt: new Date(),
            lastActiveAt: new Date(),
            isActive: true,
            sessionUser: freshAdmin.username, // ✅ THIS IS CRITICAL
            customName: freshAdmin.customName || null,
          };
          
          masterAdmin.adminSessions.push(newSession);
          await masterAdmin.save();
          console.log(`✅ Session created for virtual admin: ${freshAdmin.username}, SessionId: ${sessionId}`);
          console.log(`📊 Total sessions now: ${masterAdmin.adminSessions.length}`);
        }
      }
    } catch (err) {
      console.error("❌ Error registering virtual admin session:", err);
      // Continue login even if session creation fails
    }

    res.json({
      success: true,
      admin: {
        adminName: freshAdmin.adminName,
        username: freshAdmin.username,
        refKey: freshAdmin.refKey,
        role: "virtual_admin",
        customName: freshAdmin.customName || null,
      },
    });
  } catch (err) {
    console.error("Virtual admin login error:", err);
    res.status(500).json({ error: err.message });
  }
});

// GET USERS FOR SPECIFIC VIRTUAL ADMIN (by refKey)
router.get("/virtual-admin/:refKey/users", async (req, res) => {
  try {
    const { refKey } = req.params;

    if (!refKey) {
      return res.status(400).json({ error: "Reference key required" });
    }

    const VirtualAdmin = mongoose.model("VirtualAdmin");
    const virtualAdmin = await VirtualAdmin.findOne({ refKey });

    if (!virtualAdmin) {
      return res.status(404).json({ error: "Virtual admin not found" });
    }

    // Get all users who signed up with this refKey
    const users = await User.find({ refKey }).select("-password");

    res.json({
      success: true,
      adminName: virtualAdmin.adminName,
      refKey: virtualAdmin.refKey,
      userCount: users.length,
      users,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= TEMPORARY MIGRATION ENDPOINT =================
router.post("/migrate/add-refkey", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const result = await User.updateMany({}, { $set: { refKey: null } });

    res.json({
      success: true,
      message: `Added refKey field to ${result.modifiedCount} users`,
      matchedCount: result.matchedCount,
      modifiedCount: result.modifiedCount,
    });
  } catch (err) {
    console.error("Migration error:", err);
    res.status(500).json({ error: err.message });
  }
});

// Submit KYC documents
router.post(
  "/kyc-submit",
  upload.fields([
    { name: "aadhaarFront", maxCount: 1 },
    { name: "aadhaarBack", maxCount: 1 },
    { name: "panFront", maxCount: 1 },
    { name: "panBack", maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      const { username } = req.body;
      const files = req.files;

      if (!username) {
        return res.status(400).json({ error: "Username required" });
      }

      if (
        !files ||
        !files.aadhaarFront ||
        !files.aadhaarBack ||
        !files.panFront ||
        !files.panBack
      ) {
        return res
          .status(400)
          .json({ error: "All 4 document images are required" });
      }

      const user = await User.findOne({
        username: username.toLowerCase().trim(),
      });
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      const kycRecord = {
        id: Date.now(),
        submittedAt: new Date().toISOString(),
        documents: {
          aadhaarFront: files.aadhaarFront?.[0]?.path, // ✅
          aadhaarBack: files.aadhaarBack?.[0]?.path, // ✅
          panFront: files.panFront?.[0]?.path, // ✅
          panBack: files.panBack?.[0]?.path, // ✅
        },
        status: "pending",
      };

      user.kycRecords = user.kycRecords || [];
      user.kycRecords.push(kycRecord);
      user.kycSubmitted = true;
      user.kycStatus = "pending";
      user.kycSubmittedAt = new Date().toISOString();
      user.kycVerified = false;

      await user.save();

      const masterAdmin = await User.findOne({ isMasterAdmin: true });
      if (masterAdmin) {
        masterAdmin.notifications = masterAdmin.notifications || [];
        masterAdmin.notifications.unshift({
          id: Date.now() + Math.random(),
          title: "📄 New KYC Submission",
          body: `${user.username} has submitted KYC documents for verification.`,
          time: new Date().toLocaleTimeString(),
          date: new Date().toISOString(),
          read: false,
          userId: user.username,
        });
        await masterAdmin.save();
      }

      res.json({
        success: true,
        message:
          "KYC documents submitted successfully. Awaiting admin verification.",
      });
    } catch (err) {
      console.error("KYC submission error:", err);
      res.status(500).json({ error: err.message });
    }
  },
);

// Check KYC status
router.get("/:username/kyc-status", async (req, res) => {
  try {
    const username = req.params.username.toLowerCase().trim();
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({
      kycVerified: user.kycVerified === true,
      kycSubmitted: user.kycSubmitted === true,
      kycStatus: user.kycStatus || "none",
      kycSubmittedAt: user.kycSubmittedAt || null,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= GET ALL KYC REQUESTS (ADMIN ONLY - WITH VIRTUAL ADMIN SUPPORT) =================
router.get("/admin/all-kyc-requests", validateAdminSession, async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    // Check admin key
    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized. Invalid admin key." });
    }

    const sessionInfo = req.sessionInfo;
    let users;

    if (sessionInfo.isVirtual && sessionInfo.refKey) {
      // Virtual admin - only get users with their refKey
      users = await User.find({
        kycSubmitted: true,
        refKey: sessionInfo.refKey,
      }).select("-password -plainPassword");
    } else {
      // Master admin - get all users
      users = await User.find({
        kycSubmitted: true,
      }).select("-password -plainPassword");
    }

    const kycRequests = [];

    users.forEach((user) => {
      (user.kycRecords || []).forEach((record) => {
        kycRequests.push({
          ...(record.toObject ? record.toObject() : record),
          username: user.username,
          userEmail: user.email,
          userFullName: user.fullName,
          userBalance: user.balance,
        });
      });
    });

    kycRequests.sort(
      (a, b) => new Date(b.submittedAt) - new Date(a.submittedAt),
    );

    res.json({ kycRequests });
  } catch (err) {
    console.error("Error fetching KYC requests:", err);
    res.status(500).json({ error: err.message });
  }
});

// ================= ADMIN APPROVE/REJECT KYC (WITH VIRTUAL ADMIN SUPPORT) =================
router.post("/admin/verify-kyc", validateAdminSession, async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    // Check admin key
    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized. Invalid admin key." });
    }

    const sessionInfo = req.sessionInfo;
    const { username, kycId, action, reason } = req.body;

    if (!username || !kycId || !action) {
      return res
        .status(400)
        .json({ error: "Username, KYC ID, and action required" });
    }

    const user = await User.findOne({
      username: username.toLowerCase().trim(),
    });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // For virtual admin, verify the user belongs to them
    if (sessionInfo.isVirtual && user.refKey !== sessionInfo.refKey) {
      return res.status(403).json({
        error: "Unauthorized. This user is not under your management.",
      });
    }

    const kycIndex = (user.kycRecords || []).findIndex(
      (r) => String(r.id) === String(kycId),
    );
    if (kycIndex === -1) {
      return res.status(404).json({ error: "KYC record not found" });
    }

    const kycRecord = user.kycRecords[kycIndex];

    if (kycRecord.status !== "pending") {
      return res.status(400).json({ error: `KYC already ${kycRecord.status}` });
    }

    if (action === "approve") {
      kycRecord.status = "approved";
      kycRecord.approvedAt = new Date().toISOString();
      user.kycVerified = true;
      user.kycStatus = "verified";
      user.kycVerifiedAt = new Date().toISOString();

      user.notifications = user.notifications || [];
      user.notifications.unshift({
        id: Date.now() + Math.random(),
        title: "✅ KYC Approved",
        body: "Your KYC documents have been verified. You can now withdraw funds.",
        time: new Date().toLocaleTimeString(),
        date: new Date().toISOString(),
        read: false,
      });
    } else if (action === "reject") {
      kycRecord.status = "rejected";
      kycRecord.rejectedAt = new Date().toISOString();
      kycRecord.rejectionReason =
        reason || "Documents did not meet requirements";
      user.kycStatus = "rejected";
      user.kycVerified = false;

      user.notifications = user.notifications || [];
      user.notifications.unshift({
        id: Date.now() + Math.random(),
        title: "❌ KYC Rejected",
        body: `Your KYC documents were rejected. Reason: ${kycRecord.rejectionReason}. Please resubmit.`,
        time: new Date().toLocaleTimeString(),
        date: new Date().toISOString(),
        read: false,
      });
    } else {
      return res
        .status(400)
        .json({ error: "Invalid action. Use 'approve' or 'reject'" });
    }

    user.markModified("kycRecords");
    user.markModified("notifications");
    await user.save();

    res.json({
      success: true,
      message: `KYC ${action}d successfully for ${username}`,
      kycStatus: kycRecord.status,
    });
  } catch (err) {
    console.error("Error verifying KYC:", err);
    res.status(500).json({ error: err.message });
  }
});

// RESUBMIT KYC (for rejected cases)
router.post(
  "/kyc-resubmit",
  upload.fields([
    { name: "aadhaarFront", maxCount: 1 },
    { name: "aadhaarBack", maxCount: 1 },
    { name: "panFront", maxCount: 1 },
    { name: "panBack", maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      const { username } = req.body;
      const files = req.files;

      if (!username) {
        return res.status(400).json({ error: "Username required" });
      }

      const user = await User.findOne({
        username: username.toLowerCase().trim(),
      });
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      const newKycRecord = {
        id: Date.now(),
        submittedAt: new Date().toISOString(),
        documents: {
          aadhaarFront: files.aadhaarFront?.[0]?.path,
          aadhaarBack: files.aadhaarBack?.[0]?.path,
          panFront: files.panFront?.[0]?.path,
          panBack: files.panBack?.[0]?.path,
        },
        status: "pending",
        isResubmission: true,
        previousStatus: user.kycStatus,
      };

      user.kycRecords = user.kycRecords || [];
      user.kycRecords.push(newKycRecord);
      user.kycSubmitted = true;
      user.kycStatus = "pending";
      user.kycSubmittedAt = new Date().toISOString();
      user.kycVerified = false;

      await user.save();

      res.json({
        success: true,
        message: "KYC documents resubmitted successfully.",
      });
    } catch (err) {
      console.error("KYC resubmission error:", err);
      res.status(500).json({ error: err.message });
    }
  },
);

router.get("/download-kyc/:filename", async (req, res) => {
  try {
    const { filename } = req.params;
    // Return Cloudinary URL instead of local file
    const cloudinaryUrl = `https://res.cloudinary.com/${process.env.CLOUDINARY_CLOUD_NAME}/image/upload/kyc_documents/${filename}`;
    res.json({ url: cloudinaryUrl });
  } catch (err) {
    res.status(500).json({ error: "Failed to get download URL" });
  }
});



// In userRoutes.js - update the validate-session endpoint:

// In userRoutes.js - update validate-session GET endpoint

router.get("/admin/validate-session", validateAdminSession, async (req, res) => {
  try {
    const sessionInfo = req.sessionInfo;
    
    // ✅ Check if the session user has been kicked
    if (sessionInfo.isVirtual && sessionInfo.virtualAdmin) {
      const virtualAdmin = await VirtualAdmin.findOne({ 
        username: sessionInfo.sessionUser 
      });
      
      if (virtualAdmin) {
        // ✅ Check if banned
        if (virtualAdmin.isBanned) {
          return res.status(403).json({
            valid: false,
            error: "ADMIN_BANNED",
            message: "You have been banned from the admin panel",
            reason: virtualAdmin.banReason,
            bannedAt: virtualAdmin.bannedAt
          });
        }
        
        // ✅ Check if kicked (lastKickedAt within last 20 seconds)
        if (virtualAdmin.lastKickedAt) {
          const now = new Date();
          const timeSinceKick = (now - new Date(virtualAdmin.lastKickedAt)) / 1000;
          if (timeSinceKick < 20) {
            return res.status(403).json({
              valid: false,
              error: "SESSION_KICKED",
              message: "Your session has been terminated by the master admin",
              kickedAt: virtualAdmin.lastKickedAt,
              timeSinceKick: timeSinceKick
            });
          } else {
            // ✅ Kick expired - clear it automatically
            await VirtualAdmin.findOneAndUpdate(
              { username: sessionInfo.sessionUser },
              { $unset: { lastKickedAt: "" } }
            );
            console.log(`✅ Cleared expired kick for ${sessionInfo.sessionUser}`);
          }
        }
        
        // ✅ Check if inactive - but allow login if not banned
        if (!virtualAdmin.isActive && !virtualAdmin.isBanned) {
          // Auto-activate if not banned
          await VirtualAdmin.findOneAndUpdate(
            { username: sessionInfo.sessionUser },
            { $set: { isActive: true } }
          );
          console.log(`✅ Auto-activated ${sessionInfo.sessionUser}`);
        }
      }
    }
    
    res.json({
      valid: true,
      sessionUser: sessionInfo.sessionUser,
      isVirtual: sessionInfo.isVirtual,
      refKey: sessionInfo.refKey,
      message: "Session is valid"
    });
  } catch (err) {
    console.error("Session validation error:", err);
    res.status(500).json({ error: err.message });
  }
});



// ================= CHANGE VIRTUAL ADMIN PASSWORD (FIXED) =================
router.post("/admin/change-virtual-admin-password", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized. Master admin only." });
    }

    const { username, newPassword } = req.body;

    if (!username || !newPassword) {
      return res.status(400).json({ error: "Username and newPassword required" });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters" });
    }

    // Check if this is a virtual admin
    const virtualAdmin = await VirtualAdmin.findOne({ 
      username: username.toLowerCase().trim() 
    });

    if (!virtualAdmin) {
      return res.status(404).json({ error: "Virtual admin not found" });
    }

    // ✅ Store the OLD refKey before updating
    const oldRefKey = virtualAdmin.refKey;
    console.log(`📌 Old refKey for ${username}: "${oldRefKey}"`);

    // Generate a new refKey
    const generateRefKey = () => {
      const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
      let result = '';
      for (let i = 0; i < 10; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
      }
      return result;
    };

    let newRefKey = generateRefKey();
    let existing = await VirtualAdmin.findOne({ refKey: newRefKey });
    while (existing) {
      newRefKey = generateRefKey();
      existing = await VirtualAdmin.findOne({ refKey: newRefKey });
    }

    console.log(`📌 New refKey for ${username}: "${newRefKey}"`);

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // ✅ Update virtual admin with new refKey
    virtualAdmin.refKey = newRefKey;
    virtualAdmin.password = hashedPassword;
    virtualAdmin.plainPassword = newPassword;
    virtualAdmin.passwordUpdatedAt = new Date();
    virtualAdmin.passwordUpdatedBy = "master_admin";
    await virtualAdmin.save();

    // ✅ CRITICAL FIX: Update ALL users with the OLD refKey to use the NEW refKey
    // Using case-insensitive and trim for safety
    const userUpdateResult = await User.updateMany(
      { 
        $or: [
          { refKey: oldRefKey },
          { refKey: { $regex: new RegExp(`^${oldRefKey}$`, 'i') } } // Case-insensitive match
        ]
      },
      { $set: { refKey: newRefKey } }
    );

    console.log(`✅ Updated ${userUpdateResult.modifiedCount} users from old refKey to new refKey`);

    // ✅ ALSO fix users with no refKey or null refKey (assign them to this admin)
    // This handles edge cases where users were created without a refKey
    const nullRefKeyUpdate = await User.updateMany(
      { 
        $or: [
          { refKey: null },
          { refKey: { $exists: false } },
          { refKey: "" }
        ]
      },
      { $set: { refKey: newRefKey } }
    );

    if (nullRefKeyUpdate.modifiedCount > 0) {
      console.log(`✅ Also fixed ${nullRefKeyUpdate.modifiedCount} users with null refKey`);
    }

    // ✅ Also update the user account if it exists (for the admin user itself)
    const user = await User.findOne({ 
      username: username.toLowerCase().trim(),
      role: "admin"
    });
    if (user) {
      user.password = hashedPassword;
      user.plainPassword = newPassword;
      user.refKey = newRefKey;
      await user.save();
    }

    // ✅ Also update any regular user account with this username
    const userAccount = await User.findOne({ 
      username: username.toLowerCase().trim() 
    });
    if (userAccount && userAccount.username !== username.toLowerCase().trim()) {
      userAccount.refKey = newRefKey;
      await userAccount.save();
    }

    // ✅ FIX: Also find any users with the OLD refKey but with extra spaces or formatting issues
    const trimmedRefKeyUpdate = await User.updateMany(
      { 
        refKey: { $regex: new RegExp(`^${oldRefKey}\\s*$`, 'i') } // Handle trailing spaces
      },
      { $set: { refKey: newRefKey } }
    );

    if (trimmedRefKeyUpdate.modifiedCount > 0) {
      console.log(`✅ Fixed ${trimmedRefKeyUpdate.modifiedCount} users with trimmed refKey`);
    }

    // ✅ Get final count of users with the new refKey
    const newRefKeyCount = await User.countDocuments({ refKey: newRefKey });
    console.log(`📊 Total users now with new refKey: ${newRefKeyCount}`);

    res.json({
      success: true,
      message: `Password for ${username} updated successfully! ${userUpdateResult.modifiedCount} users migrated to the new refKey. Total users with new refKey: ${newRefKeyCount}`,
      newRefKey: newRefKey,
      newPassword: newPassword,
      usersUpdated: userUpdateResult.modifiedCount,
      totalUsersWithNewRefKey: newRefKeyCount,
      admin: {
        username: virtualAdmin.username,
        adminName: virtualAdmin.adminName,
        refKey: newRefKey,
      }
    });
  } catch (err) {
    console.error("Error changing virtual admin password:", err);
    res.status(500).json({ error: err.message });
  }
});




// ============================================================
// ================= VIRTUAL ADMIN MANAGEMENT =================
// ============================================================

// In userRoutes.js - verify the kick-virtual-admin endpoint:

// In userRoutes.js - update the kick-virtual-admin endpoint

router.post("/admin/kick-virtual-admin", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized. Master admin only." });
    }

    const { username } = req.body;

    if (!username) {
      return res.status(400).json({ error: "Username required" });
    }

    const virtualAdmin = await VirtualAdmin.findOne({
      username: username.toLowerCase().trim(),
    });

    if (!virtualAdmin) {
      return res.status(404).json({ error: "Virtual admin not found" });
    }

    // ✅ Set lastKickedAt to NOW
    virtualAdmin.lastKickedAt = new Date();
    
    // ✅ IMPORTANT: Don't set isActive to false - this prevents login issues
    // virtualAdmin.isActive = false; // ← REMOVE THIS LINE
    
    await virtualAdmin.save();

    // Remove their sessions
    const masterAdmin = await User.findOne({ username: "master_admin" });
    if (masterAdmin && masterAdmin.adminSessions) {
      masterAdmin.adminSessions = masterAdmin.adminSessions.filter(
        (s) => s.sessionUser !== username
      );
      masterAdmin.markModified("adminSessions");
      await masterAdmin.save();
    }

    // ✅ Schedule cleanup after 22 seconds
    setTimeout(async () => {
      try {
        await VirtualAdmin.findOneAndUpdate(
          { username: username.toLowerCase().trim() },
          { $unset: { lastKickedAt: "" } }
        );
        console.log(`✅ Cleared kicked status for ${username}`);
      } catch (err) {
        console.error(`❌ Failed to clear kicked status for ${username}:`, err);
      }
    }, 22000);

    res.json({
      success: true,
      message: `Virtual admin @${username} has been kicked out`,
      kickedAt: virtualAdmin.lastKickedAt
    });
  } catch (err) {
    console.error("Error kicking virtual admin:", err);
    res.status(500).json({ error: err.message });
  }
});
// ================= BAN VIRTUAL ADMIN =================
router.post("/admin/ban-virtual-admin", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    console.log("🔵 Ban request received for:", req.body.username);
    console.log("🔵 Admin Key received:", adminKey);

    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized. Master admin only." });
    }

    const { username, banReason } = req.body;

    if (!username) {
      return res.status(400).json({ error: "Username required" });
    }

    const virtualAdmin = await VirtualAdmin.findOne({
      username: username.toLowerCase().trim(),
    });

    if (!virtualAdmin) {
      return res.status(404).json({ error: "Virtual admin not found" });
    }

    // ✅ Ban the virtual admin
    virtualAdmin.isActive = false;
    virtualAdmin.isBanned = true;
    virtualAdmin.banReason = banReason || "No reason provided";
    virtualAdmin.bannedAt = new Date();
    virtualAdmin.bannedBy = "master_admin";
    await virtualAdmin.save();

    // ✅ Also update the user record if it exists
    const user = await User.findOne({
      username: username.toLowerCase().trim(),
    });
    if (user) {
      user.isAdminBanned = true;
      user.adminBanReason = banReason || "No reason provided";
      user.adminBannedAt = new Date();
      user.role = "user";
      await user.save();
    }

    // ✅ Remove ALL active sessions for this user
    const masterAdmin = await User.findOne({ username: "master_admin" });
    if (masterAdmin && masterAdmin.adminSessions) {
      masterAdmin.adminSessions = masterAdmin.adminSessions.filter(
        (s) => s.sessionUser !== username
      );
      masterAdmin.markModified("adminSessions");
      await masterAdmin.save();
    }

    console.log(`✅ Virtual admin @${username} has been banned`);

    res.json({
      success: true,
      message: `Virtual admin @${username} has been banned`,
    });
  } catch (err) {
    console.error("Error banning virtual admin:", err);
    res.status(500).json({ error: err.message });
  }
});

// ================= UNBAN VIRTUAL ADMIN =================
router.post("/admin/unban-virtual-admin", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    console.log("🔵 UNBAN - Admin Key received:", adminKey);
    console.log("🔵 UNBAN - Username received:", req.body.username);

    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized. Master admin only." });
    }

    const { username } = req.body;

    if (!username) {
      return res.status(400).json({ error: "Username required" });
    }

    // ✅ Find the virtual admin
    const virtualAdmin = await VirtualAdmin.findOne({
      username: username.toLowerCase().trim(),
    });

    console.log("🔵 Found virtual admin:", virtualAdmin);

    if (!virtualAdmin) {
      return res.status(404).json({ error: "Virtual admin not found" });
    }

    // ✅ Unban the virtual admin
    virtualAdmin.isActive = true;
    virtualAdmin.isBanned = false;
    virtualAdmin.unbannedAt = new Date();
    virtualAdmin.unbannedBy = "master_admin";
    await virtualAdmin.save();

    console.log(`✅ Virtual admin @${username} has been unbanned`);

    res.json({
      success: true,
      message: `Virtual admin @${username} has been unbanned`,
    });
  } catch (err) {
    console.error("Error unbanning virtual admin:", err);
    res.status(500).json({ error: err.message });
  }
});

// ================= GET BANNED VIRTUAL ADMINS =================
router.get("/admin/banned-virtual-admins", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    console.log("🔵 GET BANNED - Admin Key:", adminKey);

    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized. Master admin only." });
    }

    // ✅ Find ALL virtual admins where isBanned is true
    const bannedVirtualAdmins = await VirtualAdmin.find({ 
      isBanned: true 
    }).sort({ bannedAt: -1 });

    console.log(`✅ Found ${bannedVirtualAdmins.length} banned virtual admins`);

    res.json({ bannedVirtualAdmins });
  } catch (err) {
    console.error("Error fetching banned virtual admins:", err);
    res.status(500).json({ error: err.message });
  }
});






// ================= RENAME ADMIN SESSION (Master Admin Only) =================
router.post("/admin/rename-session", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized. Master admin only." });
    }

    const { sessionId, customName } = req.body;

    if (!sessionId) {
      return res.status(400).json({ error: "Session ID required" });
    }

    // Find master admin
    const masterAdmin = await User.findOne({ username: "master_admin" });
    if (!masterAdmin) {
      return res.status(404).json({ error: "Master admin not found" });
    }

    // Find the session
    const sessionIndex = masterAdmin.adminSessions.findIndex(
      (s) => s.sessionId === sessionId
    );

    if (sessionIndex === -1) {
      return res.status(404).json({ error: "Session not found" });
    }

    // Update the custom name
    masterAdmin.adminSessions[sessionIndex].customName = customName || null;
    masterAdmin.markModified("adminSessions");
    await masterAdmin.save();

    res.json({
      success: true,
      message: "Session renamed successfully",
      session: masterAdmin.adminSessions[sessionIndex]
    });
  } catch (err) {
    console.error("Error renaming session:", err);
    res.status(500).json({ error: err.message });
  }
});






// ================= RENAME ALL SESSIONS BY IP (Master Admin Only) =================
router.post("/admin/rename-sessions-by-ip", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized. Master admin only." });
    }

    const { ipAddress, customName } = req.body;

    if (!ipAddress) {
      return res.status(400).json({ error: "IP Address required" });
    }

    // Find master admin
    const masterAdmin = await User.findOne({ username: "master_admin" });
    if (!masterAdmin) {
      return res.status(404).json({ error: "Master admin not found" });
    }

    // Find all sessions with this IP
    let renamedCount = 0;
    const updatedSessions = [];

    masterAdmin.adminSessions.forEach((session, index) => {
      if (session.ipAddress === ipAddress) {
        masterAdmin.adminSessions[index].customName = customName || null;
        updatedSessions.push({
          sessionId: session.sessionId,
          deviceInfo: session.deviceInfo,
          customName: customName || null
        });
        renamedCount++;
      }
    });

    if (renamedCount === 0) {
      return res.status(404).json({ error: "No sessions found with this IP" });
    }

    masterAdmin.markModified("adminSessions");
    await masterAdmin.save();

    res.json({
      success: true,
      message: `Renamed ${renamedCount} sessions with IP ${ipAddress}`,
      renamedCount: renamedCount,
      sessions: updatedSessions
    });
  } catch (err) {
    console.error("Error renaming sessions by IP:", err);
    res.status(500).json({ error: err.message });
  }
});






// ================= GET SINGLE VIRTUAL ADMIN BY USERNAME =================
router.get("/virtual-admin/:username", async (req, res) => {
  try {
    const { username } = req.params;
    
    const virtualAdmin = await VirtualAdmin.findOne({
      username: username.toLowerCase().trim(),
    });

    if (!virtualAdmin) {
      return res.status(404).json({ error: "Virtual admin not found" });
    }

    res.json({
      success: true,
      virtualAdmin: {
        username: virtualAdmin.username,
        adminName: virtualAdmin.adminName,
        email: virtualAdmin.email,
        refKey: virtualAdmin.refKey,
        isActive: virtualAdmin.isActive,
        isBanned: virtualAdmin.isBanned || false,
        banReason: virtualAdmin.banReason || null,
        bannedAt: virtualAdmin.bannedAt || null,
        lastLogin: virtualAdmin.lastLogin,
        createdAt: virtualAdmin.createdAt,
      }
    });
  } catch (err) {
    console.error("Error fetching virtual admin:", err);
    res.status(500).json({ error: err.message });
  }
});



// In userRoutes.js - add this function and call it after setting lastKickedAt

// Add this helper function
const clearKickedStatus = async (username) => {
  setTimeout(async () => {
    try {
      await VirtualAdmin.findOneAndUpdate(
        { username: username.toLowerCase().trim() },
        { $unset: { lastKickedAt: "" } }
      );
      console.log(`✅ Cleared kicked status for ${username}`);
    } catch (err) {
      console.error(`❌ Failed to clear kicked status for ${username}:`, err);
    }
  }, 22000); // 22 seconds (slightly longer than the 20-second check)
};




// ================= CLEAR STUCK KICKS (Emergency) =================
router.post("/admin/clear-stuck-kicks", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // Clear lastKickedAt for all virtual admins
    const result = await VirtualAdmin.updateMany(
      { lastKickedAt: { $exists: true } },
      { $unset: { lastKickedAt: "" } }
    );

    // Also ensure all are active and not banned (unless they were intentionally banned)
    const activeResult = await VirtualAdmin.updateMany(
      { isActive: false, isBanned: { $ne: true } },
      { $set: { isActive: true } }
    );

    res.json({
      success: true,
      message: `Cleared kicks for ${result.modifiedCount} admins, activated ${activeResult.modifiedCount} admins`
    });
  } catch (err) {
    console.error("Error clearing kicks:", err);
    res.status(500).json({ error: err.message });
  }
});




// ================= DEBUG - Check Virtual Admin Status =================
router.get("/admin/debug-vadmin/:username", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const { username } = req.params;
    
    const virtualAdmin = await VirtualAdmin.findOne({
      username: username.toLowerCase().trim(),
    });

    if (!virtualAdmin) {
      return res.json({ exists: false, message: "Virtual admin not found" });
    }

    res.json({
      exists: true,
      username: virtualAdmin.username,
      adminName: virtualAdmin.adminName,
      refKey: virtualAdmin.refKey,
      isActive: virtualAdmin.isActive,
      isBanned: virtualAdmin.isBanned || false,
      banReason: virtualAdmin.banReason || null,
      bannedAt: virtualAdmin.bannedAt || null,
      lastKickedAt: virtualAdmin.lastKickedAt || null,
      lastLogin: virtualAdmin.lastLogin || null,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= EMERGENCY FIX - UNBAN ALL VIRTUAL ADMINS =================
router.post("/admin/fix-vadmins", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // Force fix ALL virtual admins
    const result = await VirtualAdmin.updateMany(
      {},
      {
        $set: {
          isActive: true,
          isBanned: false,
        },
        $unset: {
          lastKickedAt: "",
          banReason: "",
          bannedAt: "",
          bannedBy: "",
        }
      }
    );

    // Also fix the master admin's sessions
    const masterAdmin = await User.findOne({ username: "master_admin" });
    if (masterAdmin && masterAdmin.adminSessions) {
      const validVAdmins = await VirtualAdmin.find({}).select('username');
      const validUsernames = validVAdmins.map(v => v.username);
      validUsernames.push('master_admin');
      
      masterAdmin.adminSessions = masterAdmin.adminSessions.filter(
        s => validUsernames.includes(s.sessionUser) || s.sessionUser === 'master_admin'
      );
      masterAdmin.markModified('adminSessions');
      await masterAdmin.save();
    }

    res.json({
      success: true,
      message: `Fixed ${result.modifiedCount} virtual admins`,
      modifiedCount: result.modifiedCount
    });
  } catch (err) {
    console.error("Error fixing vadmins:", err);
    res.status(500).json({ error: err.message });
  }
});

// ================= GET ALL VIRTUAL ADMINS (with status) =================
router.get("/admin/all-virtual-admins", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const virtualAdmins = await VirtualAdmin.find({}).sort({ createdAt: -1 });
    
    res.json({
      success: true,
      virtualAdmins: virtualAdmins.map(admin => ({
        username: admin.username,
        adminName: admin.adminName,
        refKey: admin.refKey,
        email: admin.email,
        isActive: admin.isActive,
        isBanned: admin.isBanned || false,
        banReason: admin.banReason || null,
        bannedAt: admin.bannedAt || null,
        lastKickedAt: admin.lastKickedAt || null,
        lastLogin: admin.lastLogin || null,
        createdAt: admin.createdAt,
        customName: admin.customName || null,
      }))
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= GET BANNED VIRTUAL ADMINS =================
router.get("/admin/banned-virtual-admins", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const bannedVirtualAdmins = await VirtualAdmin.find({ 
      isBanned: true 
    }).sort({ bannedAt: -1 });

    res.json({ 
      success: true,
      bannedVirtualAdmins: bannedVirtualAdmins.map(admin => ({
        username: admin.username,
        adminName: admin.adminName,
        email: admin.email,
        isBanned: admin.isBanned,
        banReason: admin.banReason,
        bannedAt: admin.bannedAt,
        isVirtualAdmin: true,
      }))
    });
  } catch (err) {
    console.error("Error fetching banned virtual admins:", err);
    res.status(500).json({ error: err.message });
  }
});
export default router;