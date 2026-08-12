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
import Settings from "../models/Settings.js";
import { fileURLToPath } from "url";  // ✅ Fixed typo
import { getCached, setCached, deleteCached, clearCache } from "../lib/cache.js";

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
    
    // ✅ Check admin key
    if (!adminKey || adminKey !== validAdminKey) {
      console.log(`🚫 Invalid admin key attempt from IP: ${getClientIp(req)}`);
      return res.status(401).json({ 
        error: "Unauthorized", 
        message: "Invalid admin key" 
      });
    }

    // ✅ IP Whitelisting (Optional but recommended)
    const allowedIPs = process.env.ALLOWED_ADMIN_IPS?.split(',') || [];
    const clientIP = getClientIp(req);
    
    if (allowedIPs.length > 0 && !allowedIPs.includes(clientIP)) {
      console.log(`🚫 Blocked admin access from unauthorized IP: ${clientIP}`);
      return res.status(403).json({ 
        error: "UNAUTHORIZED_IP", 
        message: "Access denied from this IP address" 
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

    // ✅ Check if session was explicitly revoked
    if (session.isActive === false) {
      return res.status(403).json({ 
        error: "SESSION_REVOKED", 
        message: "Your session has been revoked by the master admin" 
      });
    }

    // ✅ ✅ ✅ NEW: Check if session was invalidated by password change ✅ ✅ ✅
    if (session.invalidatedAt) {
      // Remove this session
      masterAdmin.adminSessions.splice(sessionIndex, 1);
      await masterAdmin.save();
      return res.status(403).json({
        error: "SESSION_INVALIDATED",
        message: "Your session was invalidated. Please login again."
      });
    }

    // ✅ ✅ ✅ NEW: Check if password was changed after session creation ✅ ✅ ✅
    if (masterAdmin.passwordUpdatedAt) {
      const sessionCreatedAt = new Date(session.loggedInAt || session.createdAt || Date.now());
      const passwordChangedAt = new Date(masterAdmin.passwordUpdatedAt);
      
      if (sessionCreatedAt < passwordChangedAt) {
        // Invalidate this session
        masterAdmin.adminSessions[sessionIndex].isActive = false;
        masterAdmin.adminSessions[sessionIndex].invalidatedAt = new Date();
        masterAdmin.adminSessions[sessionIndex].invalidatedReason = "Password changed";
        await masterAdmin.save();
        
        return res.status(403).json({
          error: "PASSWORD_CHANGED",
          message: "Password was changed. Please login again."
        });
      }
    }

    // ✅ ✅ ✅ NEW: Check session timeout ✅ ✅ ✅
    const SESSION_TIMEOUT = parseInt(process.env.SESSION_TIMEOUT_MINUTES || '30') * 60 * 1000;
    if (session.lastActiveAt) {
      const timeSinceActive = Date.now() - new Date(session.lastActiveAt).getTime();
      if (timeSinceActive > SESSION_TIMEOUT) {
        masterAdmin.adminSessions[sessionIndex].isActive = false;
        masterAdmin.adminSessions[sessionIndex].expiredAt = new Date();
        await masterAdmin.save();
        return res.status(403).json({
          error: "SESSION_EXPIRED",
          message: "Your session has expired. Please login again."
        });
      }
    }

    // ✅ Update lastActiveAt
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


// Helper: Generate optimized Cloudinary URL
const getOptimizedUrl = (path, width = 300) => {
  if (!path) return null;
  const parts = path.split('/');
  const filename = parts[parts.length - 1];
  const publicId = filename.split('.')[0];
  const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
  return `https://res.cloudinary.com/${cloudName}/image/upload/w_${width},c_limit,q_auto:good,f_auto/kyc_documents/${publicId}`;
};

// Configure multer to use Cloudinary storage
const cloudinaryStorage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: "kyc_documents",
    allowed_formats: ["jpg", "jpeg", "png", "webp"],
    transformation: [
      { width: 800, height: 800, crop: "limit", quality: "auto:good" }
    ],
    eager: [
      { width: 300, height: 300, crop: "thumb", quality: "auto:low" },
      { width: 100, height: 100, crop: "thumb", quality: "auto:eco" }
    ],
    eager_async: true,
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
    const { username, email, password, fullName, phone, country, refKey } = req.body;

    if (!username || !email || !password) {
      return res
        .status(400)
        .json({ error: "Username, email and password are required" });
    }

    // ✅ REFKEY IS NOW REQUIRED
    if (!refKey || refKey.trim() === "") {
      return res.status(400).json({
        error: "REFKEY_REQUIRED",
        message: "A reference key from your admin is required to register. Please contact your admin."
      });
    }

    const cleanUser = username.toLowerCase().trim();
    const cleanEmail = email.toLowerCase().trim();
    const cleanRefKey = refKey.trim();

    const existingUser = await User.findOne({
      $or: [{ username: cleanUser }, { email: cleanEmail }],
    });

    if (existingUser) {
      return res
        .status(400)
        .json({ error: "Username or email already exists" });
    }

    // ✅ VALIDATE REFKEY
    const virtualAdmin = await VirtualAdmin.findOne({ refKey: cleanRefKey });
    
    if (!virtualAdmin) {
      return res.status(400).json({ 
        error: "INVALID_REFKEY",
        message: "Invalid reference key. Please check with your admin.",
        code: "INVALID_REFKEY"
      });
    }
    
    // Check if virtual admin is active and not banned
    if (!virtualAdmin.isActive || virtualAdmin.isBanned) {
      return res.status(400).json({ 
        error: "INACTIVE_REFKEY",
        message: "This reference key is currently inactive or banned. Please contact support.",
        code: "INACTIVE_REFKEY"
      });
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
      refKey: cleanRefKey, // ✅ ALWAYS set the refKey
      withdrawalRequests: [],
      pendingTrades: [],
      notifications: [],
    });

    const safeUser = user.toObject();
    delete safeUser.password;

    res.status(201).json(safeUser);
  } catch (err) {
    console.error("Registration error:", err);
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
    
    // ✅ Check cache
    const cacheKey = `user_${username}`;
    const cachedUser = getCached(cacheKey);
    if (cachedUser) {
      return res.json(cachedUser);
    }
    
    const user = await User.findOne({ username })
      .select("-password -plainPassword")
      .lean();

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    setCached(cacheKey, user, 30);
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/admin/all-with-plain-passwords", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized. Admin access only." });
    }

    // ✅ ADD PAGINATION
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const skip = (page - 1) * limit;

    // ✅ SEARCH — filter by username or email before paginating
    const search = (req.query.search || "").trim();
    let filter = {};
    if (search) {
      const escaped = search.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const regex = new RegExp(escaped, "i");
      filter = { $or: [{ username: regex }, { email: regex }] };
    }

    const users = await User.find(filter)
      .select("-password")  // Exclude sensitive fields
      .skip(skip)
      .limit(limit)
      .sort({ createdAt: -1 });  // Newest first

    const totalUsers = await User.countDocuments(filter);

    res.json({
      users: users,
      pagination: {
        total: totalUsers,
        page: page,
        limit: limit,
        totalPages: Math.ceil(totalUsers / limit),
      }
    });
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

    // ✅ Find the user
    const user = await User.findOne({ username: username.toLowerCase().trim() });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // ✅ Update password
    user.password = hashedPassword;
    user.plainPassword = newPassword;

    // ✅ ✅ ✅ INVALIDATE ALL SESSIONS ✅ ✅ ✅
    if (user.adminSessions && user.adminSessions.length > 0) {
      user.adminSessions = user.adminSessions.map(session => ({
        ...session,
        isActive: false,
        invalidatedAt: new Date(),
        invalidatedReason: "Password changed"
      }));
    }

    // ✅ Also add to kicked sessions
    user.kickedSessions = user.kickedSessions || [];
    user.adminSessions.forEach(session => {
      user.kickedSessions.push({
        sessionId: session.sessionId,
        kickedAt: new Date(),
        reason: "Password changed"
      });
    });

    await user.save();

    res.json({ 
      success: true, 
      message: "Password updated successfully. All sessions have been invalidated." 
    });
  } catch (err) {
    console.error("Password update error:", err);
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
    // ✅ Invalidate cache
    deleteCached(`user_${username}`);
    deleteCached(`balance_${username}`);
    deleteCached(`transactions_${username}`);

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
        time: new Date().toISOString(),
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
        time: new Date().toISOString(),
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
        formattedDate: new Date().toISOString(),
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
        formattedDate: new Date().toISOString(),
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
        time: new Date().toISOString(),
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
        time: new Date().toISOString(),
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
      time: new Date().toISOString(),
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
      time: new Date().toISOString(),
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
    
    const cacheKey = `notifications_${username}`;
    const cachedNotifs = getCached(cacheKey);
    if (cachedNotifs) {
      return res.json(cachedNotifs);
    }
    
    const user = await User.findOne({ username }).select("notifications").lean();

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const notifications = user.notifications || [];
    setCached(cacheKey, notifications, 15);
    res.json(notifications);
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
        time: new Date().toISOString(),
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
        time: new Date().toISOString(),
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

// userRoutes.js - REPLACE the entire /admin/register-session endpoint

router.post("/admin/register-session", async (req, res) => {
  try {
    const { adminKey, userAgent, adminUsername, sessionId } = req.body;
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    // ✅ Check admin key
    if (!adminKey || adminKey !== validAdminKey) {
      console.error("❌ Invalid admin key:", adminKey);
      return res.status(401).json({ 
        success: false,
        error: "Unauthorized", 
        message: "Invalid admin key" 
      });
    }

    // ✅ Use provided sessionId or generate one
    const newSessionId = sessionId || generateSessionId();
    const ipAddress = getClientIp(req);
    const deviceInfo = getDeviceInfo(userAgent);
    const browser = getBrowserInfo(userAgent);

    let sessionUser = adminUsername || "master_admin";
    
    // Check if this is a virtual admin
    if (adminUsername && adminUsername !== "master_admin") {
      const virtualAdmin = await VirtualAdmin.findOne({ 
        username: adminUsername.toLowerCase().trim() 
      });
      if (virtualAdmin) {
        sessionUser = adminUsername;
      }
    }

    // ✅ Find master admin
    let masterAdmin = await User.findOne({ username: "master_admin" });

    if (!masterAdmin) {
      masterAdmin = await User.create({
        username: "master_admin",
        email: "master@admin.com",
        password: "master_admin",
        role: "admin",
        isMasterAdmin: true,
        adminSessions: [],
      });
      console.log("✅ Created master admin");
    }

    // ✅ ALWAYS create a NEW session - DO NOT check for existing
    // This ensures each tab gets its own session
    masterAdmin.adminSessions.push({
      sessionId: newSessionId,
      ipAddress: ipAddress,
      userAgent: userAgent || "Unknown",
      deviceInfo: `${browser} - ${deviceInfo}`,
      loggedInAt: new Date(),
      lastActiveAt: new Date(),
      isActive: true,
      sessionUser: sessionUser,
      customName: null,
    });

    // Keep only last 200 sessions
    if (masterAdmin.adminSessions.length > 200) {
      masterAdmin.adminSessions = masterAdmin.adminSessions.slice(-200);
    }

    masterAdmin.markModified("adminSessions");
    await masterAdmin.save();

    // ✅ Log session count for this user
    const userSessionCount = masterAdmin.adminSessions.filter(
      s => s.sessionUser === sessionUser && s.isActive !== false
    ).length;
    console.log(`📊 ${sessionUser} now has ${userSessionCount} active sessions`);

    // ✅ Return success
    res.json({
      success: true,
      sessionId: newSessionId,
      message: "Admin session registered",
    });

  } catch (err) {
    console.error("❌ Error registering admin session:", err);
    res.status(500).json({ 
      success: false,
      error: "INTERNAL_SERVER_ERROR", 
      message: err.message 
    });
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

// userRoutes.js - Update the session heartbeat endpoint

// SESSION HEARTBEAT - Keep session alive
router.post("/admin/session-heartbeat", async (req, res) => {
  try {
    const { sessionId } = req.body;

    if (!sessionId) {
      return res.status(400).json({ error: "Session ID required" });
    }

    // ✅ Update lastActiveAt for this session
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

    if (result) {
      res.json({ success: true });
    } else {
      // ✅ If session not found in master_admin, it might be a virtual admin session
      // Try to find and update the virtual admin's lastActiveAt
      const virtualAdmin = await VirtualAdmin.findOne({
        "sessions.sessionId": sessionId,
        "sessions.isActive": true
      });
      
      if (virtualAdmin) {
        const sessionIndex = virtualAdmin.sessions.findIndex(
          (s) => s.sessionId === sessionId
        );
        if (sessionIndex !== -1) {
          virtualAdmin.sessions[sessionIndex].lastActiveAt = new Date();
          virtualAdmin.markModified("sessions");
          await virtualAdmin.save();
          res.json({ success: true });
          return;
        }
      }
      
      res.status(404).json({ error: "Session not found" });
    }
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

// userRoutes.js - FIXED Virtual Admin Login

router.post("/virtual-admin/login", async (req, res) => {
  try {
    const { username, refKey } = req.body;

    console.log("🔵 Login attempt:", { username, refKey });

    if (!username || !refKey) {
      return res
        .status(400)
        .json({ error: "Username and reference key required" });
    }

    const cleanUsername = username.toLowerCase().trim();
    const cleanInput = refKey.trim();

    // ✅ Find the vadmin by username
    const candidate = await VirtualAdmin.findOne({ username: cleanUsername });

    if (!candidate) {
      console.log(`❌ No vadmin found with username: "${cleanUsername}"`);
      return res
        .status(401)
        .json({ error: "Invalid username or reference key" });
    }

    console.log("🔵 Found candidate:", {
      username: candidate.username,
      refKey: candidate.refKey,
      plainPassword: candidate.plainPassword,
      isActive: candidate.isActive,
      isBanned: candidate.isBanned,
    });

    // ✅ Check if refKey matches (case insensitive)
    const refKeyMatches = candidate.refKey?.toLowerCase() === cleanInput.toLowerCase();
    const plainPasswordMatches = candidate.plainPassword?.toLowerCase() === cleanInput.toLowerCase();

    // ✅ Also check exact match (for case-sensitive passwords)
    const refKeyExact = candidate.refKey === cleanInput;
    const plainPasswordExact = candidate.plainPassword === cleanInput;

    // ✅ Check hashed password as fallback
    let hashedPasswordMatches = false;
    if (!refKeyMatches && !plainPasswordMatches && candidate.password) {
      try {
        hashedPasswordMatches = await bcrypt.compare(cleanInput, candidate.password);
      } catch (e) {
        hashedPasswordMatches = false;
      }
    }

    const isValid = refKeyMatches || plainPasswordMatches || refKeyExact || plainPasswordExact || hashedPasswordMatches;

    console.log("🔵 Validation results:", {
      refKeyMatches,
      plainPasswordMatches,
      refKeyExact,
      plainPasswordExact,
      hashedPasswordMatches,
      isValid
    });

    if (!isValid) {
      console.log(`❌ Credential mismatch for "${cleanUsername}"`);
      return res
        .status(401)
        .json({ error: "Invalid username or reference key" });
    }

    let virtualAdmin = candidate;

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
          { username: cleanUsername },
          { $unset: { lastKickedAt: "" } }
        );
      }
    }

    // ✅ AUTO-ACTIVATE
    if (!virtualAdmin.isActive && !virtualAdmin.isBanned) {
      await VirtualAdmin.findOneAndUpdate(
        { username: cleanUsername },
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
      username: cleanUsername,
    });

    // ✅ REGISTER SESSION
    console.log(`🔵 Creating session for virtual admin: ${freshAdmin.username}`);
    
    let sessionId = null;
    try {
      sessionId = generateSessionId();
      const ipAddress = getClientIp(req);
      const deviceInfo = getDeviceInfo(req.headers["user-agent"]);
      const browser = getBrowserInfo(req.headers["user-agent"]);

      const masterAdmin = await User.findOne({ username: "master_admin" });
      
      if (masterAdmin) {
        if (!masterAdmin.adminSessions) {
          masterAdmin.adminSessions = [];
        }

        const priorNamedSessions = masterAdmin.adminSessions.filter(
          (s) =>
            s.sessionUser === freshAdmin.username &&
            s.ipAddress === ipAddress &&
            s.customName
        );
        priorNamedSessions.sort(
          (a, b) => new Date(b.lastActiveAt || b.loggedInAt) - new Date(a.lastActiveAt || a.loggedInAt)
        );
        const inheritedCustomName = priorNamedSessions[0]?.customName || null;

        const newSession = {
          sessionId: sessionId,
          ipAddress: ipAddress,
          userAgent: req.headers["user-agent"] || "Unknown",
          deviceInfo: `${browser} - ${deviceInfo}`,
          loggedInAt: new Date(),
          lastActiveAt: new Date(),
          isActive: true,
          sessionUser: freshAdmin.username,
          customName: inheritedCustomName,
        };

        masterAdmin.adminSessions.push(newSession);
        await masterAdmin.save();
        console.log(`✅ Session created for: ${freshAdmin.username}`);
      }
    } catch (err) {
      console.error("❌ Session registration error:", err);
    }

    res.json({
      success: true,
      sessionId: sessionId,
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
// ================= GET USERS FOR SPECIFIC VIRTUAL ADMIN (WITH PAGINATION) =================
router.get("/virtual-admin/:refKey/users", async (req, res) => {
  try {
    const { refKey } = req.params;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const skip = (page - 1) * limit;
    const search = (req.query.search || "").trim();

    // Verify virtual admin exists
    const virtualAdmin = await VirtualAdmin.findOne({ refKey });
    if (!virtualAdmin) {
      return res.status(404).json({ 
        success: false, 
        error: "Virtual admin not found" 
      });
    }

    // Build filter
    let filter = { refKey };
    if (search) {
      const escaped = search.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const regex = new RegExp(escaped, "i");
      filter = { 
        refKey, 
        $or: [{ username: regex }, { email: regex }] 
      };
    }

    // Get total count
    const totalUsers = await User.countDocuments(filter);
    
    // Get paginated users
    const users = await User.find(filter)
      .select("-password")  // Exclude password hash, keep plainPassword
      .skip(skip)
      .limit(limit)
      .sort({ createdAt: -1 });

    res.json({
      success: true,
      adminName: virtualAdmin.adminName,
      refKey: virtualAdmin.refKey,
      userCount: totalUsers,
      users: users,
      pagination: {
        total: totalUsers,
        page: page,
        limit: limit,
        totalPages: Math.ceil(totalUsers / limit),
      }
    });
  } catch (err) {
    console.error("Error fetching virtual admin users:", err);
    res.status(500).json({ 
      success: false, 
      error: err.message 
    });
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
          time: new Date().toISOString(),
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

// ================= CHECK KYC STATUS =================
router.get("/:username/kyc-status", async (req, res) => {
  try {
    const username = req.params.username.toLowerCase().trim();
    
    const cacheKey = `kyc_${username}`;
    const cachedKYC = getCached(cacheKey);
    if (cachedKYC) {
      return res.json(cachedKYC);
    }
    
    const user = await User.findOne({ username })
      .select("kycVerified kycSubmitted kycStatus kycSubmittedAt")
      .lean();

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const result = {
      kycVerified: user.kycVerified === true,
      kycSubmitted: user.kycSubmitted === true,
      kycStatus: user.kycStatus || "none",
      kycSubmittedAt: user.kycSubmittedAt || null,
    };
    
    setCached(cacheKey, result, 60);
    res.json(result);
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
        time: new Date().toISOString(),
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
        time: new Date().toISOString(),
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

    // ✅ ✅ ✅ ADD THIS - Clear the cache ✅ ✅ ✅
    deleteCached(`kyc_${username}`);
    deleteCached(`user_${username}`);
    // Also clear any other cached KYC data
    const cacheKeyPattern = `kyc_${username}`;
    // If you have a function to clear by pattern, use it
    // Otherwise, just delete the specific keys

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

// Submit KYC documents - Accepts URLs from Cloudinary (NO FILE UPLOAD)
router.post("/kyc-submit", async (req, res) => {
  try {
    const { username, documents } = req.body;

    console.log("📝 KYC submission for username:", username);
    console.log("📦 Documents received:", documents);

    // Validate username
    if (!username) {
      return res.status(400).json({
        success: false,
        error: "Username required"
      });
    }

    // Validate all 4 documents are present
    if (!documents || !documents.aadhaarFront || !documents.aadhaarBack ||
        !documents.panFront || !documents.panBack) {
      return res.status(400).json({
        success: false,
        error: "All 4 document images are required"
      });
    }

    // Find the user
    const user = await User.findOne({
      username: username.toLowerCase().trim(),
    });

    if (!user) {
      console.log("❌ User not found:", username);
      return res.status(404).json({
        success: false,
        error: "User not found"
      });
    }

    console.log("✅ User found:", user.username);

    // Create KYC record with Cloudinary URLs
    const kycRecord = {
      id: Date.now(),
      submittedAt: new Date().toISOString(),
      documents: {
        aadhaarFront: documents.aadhaarFront,
        aadhaarBack: documents.aadhaarBack,
        panFront: documents.panFront,
        panBack: documents.panBack,
      },
      status: "pending",
    };

    // Save to user
    user.kycRecords = user.kycRecords || [];
    user.kycRecords.push(kycRecord);
    user.kycSubmitted = true;
    user.kycStatus = "pending";
    user.kycSubmittedAt = new Date().toISOString();
    user.kycVerified = false;

    await user.save();
    console.log("✅ KYC record saved for:", user.username);

    // Notify admin
    try {
      const masterAdmin = await User.findOne({ isMasterAdmin: true });
      if (masterAdmin) {
        masterAdmin.notifications = masterAdmin.notifications || [];
        masterAdmin.notifications.unshift({
          id: Date.now() + Math.random(),
          title: "📄 New KYC Submission",
          body: `${user.username} has submitted KYC documents for verification.`,
          time: new Date().toISOString(),
          date: new Date().toISOString(),
          read: false,
          userId: user.username,
        });
        await masterAdmin.save();
        console.log("✅ Admin notification sent");
      }
    } catch (notifErr) {
      console.error("⚠️ Failed to send admin notification:", notifErr);
      // Don't fail the request if notification fails
    }

    res.json({
      success: true,
      message: "KYC documents submitted successfully. Awaiting admin verification.",
    });

  } catch (err) {
    console.error("❌ KYC submission error:", err);
    res.status(500).json({
      success: false,
      error: err.message || "Failed to submit KYC. Please try again."
    });
  }
});

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



// userRoutes.js - Update the change-virtual-admin-password endpoint

  // ================= CHANGE VIRTUAL ADMIN PASSWORD - WITH SESSION INVALIDATION =================
router.post("/admin/change-virtual-admin-password", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized. Master admin only." });
    }

    const { username, newPassword, customRefKey } = req.body;

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

    // Store the OLD refKey before updating
    const oldRefKey = virtualAdmin.refKey;
    console.log(`📌 Old refKey for ${username}: "${oldRefKey}"`);

    // Generate a new refKey or use custom one
    let newRefKey = customRefKey;
    
    if (!newRefKey || newRefKey.trim() === "") {
      const generateRefKey = () => {
        const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        let result = '';
        for (let i = 0; i < 10; i++) {
          result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return result;
      };
      
      newRefKey = generateRefKey();
      let existing = await VirtualAdmin.findOne({ refKey: newRefKey });
      while (existing) {
        newRefKey = generateRefKey();
        existing = await VirtualAdmin.findOne({ refKey: newRefKey });
      }
    } else {
      if (newRefKey.length < 4) {
        return res.status(400).json({ error: "Reference Key must be at least 4 characters" });
      }
      if (!/^[a-zA-Z0-9]+$/.test(newRefKey)) {
        return res.status(400).json({ error: "Reference Key can only contain letters and numbers" });
      }
      
      const existing = await VirtualAdmin.findOne({ 
        refKey: newRefKey,
        username: { $ne: username.toLowerCase().trim() }
      });
      if (existing) {
        return res.status(400).json({ error: "This Reference Key is already in use by another admin" });
      }
    }

    console.log(`📌 New refKey for ${username}: "${newRefKey}"`);

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update virtual admin with new refKey
    virtualAdmin.refKey = newRefKey;
    virtualAdmin.password = hashedPassword;
    virtualAdmin.plainPassword = newPassword;
    virtualAdmin.passwordUpdatedAt = new Date();
    virtualAdmin.passwordUpdatedBy = "master_admin";
    await virtualAdmin.save();

    // ✅ ✅ ✅ INVALIDATE ALL SESSIONS FOR THIS VIRTUAL ADMIN ✅ ✅ ✅
    const masterAdmin = await User.findOne({ username: "master_admin" });
    if (masterAdmin && masterAdmin.adminSessions) {
      let removedCount = 0;
      masterAdmin.adminSessions = masterAdmin.adminSessions.filter(session => {
        if (session.sessionUser === username) {
          removedCount++;
          return false;
        }
        return true;
      });
      masterAdmin.markModified("adminSessions");
      await masterAdmin.save();
      console.log(`✅ Removed ${removedCount} sessions for ${username}`);
    }

    // Also add to kicked sessions for tracking
    const masterAdmin2 = await User.findOne({ username: "master_admin" });
    if (masterAdmin2) {
      masterAdmin2.kickedSessions = masterAdmin2.kickedSessions || [];
      masterAdmin2.kickedSessions.push({
        adminUsername: username,
        kickedAt: new Date(),
        reason: "Password changed by master admin"
      });
      await masterAdmin2.save();
    }

    // CRITICAL FIX: Update ALL users with the OLD refKey to use the NEW refKey
    const userUpdateResult = await User.updateMany(
      { 
        $or: [
          { refKey: oldRefKey },
          { refKey: { $regex: new RegExp(`^${oldRefKey}$`, 'i') } }
        ]
      },
      { $set: { refKey: newRefKey } }
    );

    console.log(`✅ Updated ${userUpdateResult.modifiedCount} users from old refKey to new refKey`);

    // ALSO fix users with no refKey or null refKey (assign them to this admin)
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

    // Also update the user account if it exists
    const user = await User.findOne({ 
      username: username.toLowerCase().trim()
    });
    if (user) {
      user.password = hashedPassword;
      user.plainPassword = newPassword;
      user.refKey = newRefKey;
      user.passwordUpdatedAt = new Date();
      await user.save();
    }

    // Get final count of users with the new refKey
    const newRefKeyCount = await User.countDocuments({ refKey: newRefKey });
    console.log(`📊 Total users now with new refKey: ${newRefKeyCount}`);

    res.json({
      success: true,
      message: `Password for ${username} updated successfully! All sessions invalidated.`,
      newRefKey: newRefKey,
      newPassword: newPassword,
      usersUpdated: userUpdateResult.modifiedCount,
      totalUsersWithNewRefKey: newRefKeyCount,
      sessionsRemoved: true,
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






// userRoutes.js - Add this endpoint if not already there

// ================= RENAME ALL SESSIONS BY IP =================
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

    // Find all active sessions with this IP
    let renamedCount = 0;
    const updatedSessions = [];

    masterAdmin.adminSessions.forEach((session, index) => {
      if (session.ipAddress === ipAddress && session.isActive !== false) {
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
      return res.status(404).json({ error: "No active sessions found with this IP" });
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




// userRoutes.js - Add this new endpoint

// ================= RENAME ALL SESSIONS BY USER AND IP =================
router.post("/admin/rename-sessions-by-user-and-ip", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized. Master admin only." });
    }

    const { ipAddress, sessionUser, customName } = req.body;

    if (!ipAddress) {
      return res.status(400).json({ error: "IP Address required" });
    }

    if (!sessionUser) {
      return res.status(400).json({ error: "Session User required" });
    }

    // Find master admin
    const masterAdmin = await User.findOne({ username: "master_admin" });
    if (!masterAdmin) {
      return res.status(404).json({ error: "Master admin not found" });
    }

    // ✅ Find ONLY sessions with THIS IP AND THIS USER
    let renamedCount = 0;
    const updatedSessions = [];

    masterAdmin.adminSessions.forEach((session, index) => {
      if (
        session.ipAddress === ipAddress &&
        session.sessionUser === sessionUser && // ✅ CRITICAL: Same user
        session.isActive !== false
      ) {
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
      return res.status(404).json({ 
        error: `No active sessions found for @${sessionUser} with IP ${ipAddress}` 
      });
    }

    masterAdmin.markModified("adminSessions");
    await masterAdmin.save();

    res.json({
      success: true,
      message: `Renamed ${renamedCount} sessions for @${sessionUser} with IP ${ipAddress}`,
      renamedCount: renamedCount,
      sessions: updatedSessions
    });
  } catch (err) {
    console.error("Error renaming sessions by user and IP:", err);
    res.status(500).json({ error: err.message });
  }
});




// userRoutes.js - Add this debug endpoint

router.post("/debug/vadmin-login-check", async (req, res) => {
  try {
    const { username, refKey } = req.body;
    
    const cleanUsername = username.toLowerCase().trim();
    const cleanInput = refKey.trim();
    
    const candidate = await VirtualAdmin.findOne({ username: cleanUsername });
    
    if (!candidate) {
      return res.json({
        success: false,
        error: "User not found",
        username: cleanUsername
      });
    }
    
    const refKeyMatches = candidate.refKey === cleanInput;
    const plainPasswordMatches = candidate.plainPassword === cleanInput;
    const refKeyCaseInsensitive = candidate.refKey?.toLowerCase() === cleanInput.toLowerCase();
    const plainPasswordCaseInsensitive = candidate.plainPassword?.toLowerCase() === cleanInput.toLowerCase();
    
    return res.json({
      success: true,
      user: {
        username: candidate.username,
        refKey: candidate.refKey,
        plainPassword: candidate.plainPassword,
      },
      input: {
        username: cleanUsername,
        refKey: cleanInput,
      },
      matches: {
        refKeyMatches,
        plainPasswordMatches,
        refKeyCaseInsensitive,
        plainPasswordCaseInsensitive,
      },
      conclusion: refKeyMatches || plainPasswordMatches || refKeyCaseInsensitive || plainPasswordCaseInsensitive
        ? "✅ Should login successfully"
        : "❌ No match found"
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});






// Add this endpoint if you don't have it
router.post("/admin/logout", async (req, res) => {
  try {
    const { sessionId } = req.body;
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    if (!sessionId) {
      return res.status(400).json({ error: "Session ID required" });
    }

    // ✅ Mark session as inactive
    const masterAdmin = await User.findOne({ username: "master_admin" });
    if (!masterAdmin) {
      return res.status(404).json({ error: "Master admin not found" });
    }

    const sessionIndex = masterAdmin.adminSessions.findIndex(
      (s) => s.sessionId === sessionId
    );

    if (sessionIndex === -1) {
      return res.status(404).json({ error: "Session not found" });
    }

    masterAdmin.adminSessions[sessionIndex].isActive = false;
    masterAdmin.adminSessions[sessionIndex].loggedOutAt = new Date();
    masterAdmin.markModified("adminSessions");
    await masterAdmin.save();

    res.json({ success: true, message: "Logged out successfully" });
  } catch (err) {
    console.error("Logout error:", err);
    res.status(500).json({ error: err.message });
  }
});


// ================= DEPOSIT REQUEST WITH SCREENSHOT =================
router.post(
  "/deposit-request",
  upload.single("screenshot"),
  async (req, res) => {
    try {
      console.log("🔵 ===== DEPOSIT REQUEST START =====");
      console.log("🔵 Request body:", req.body);
      console.log("🔵 Request file:", req.file ? req.file.path : "No file");
      console.log("🔵 Request headers:", req.headers);

      const { username, amount, currency, paymentMethod } = req.body;
      const screenshot = req.file;

      // Validate required fields
      if (!username) {
        console.log("❌ Username missing");
        return res.status(400).json({ 
          success: false,
          error: "Username is required" 
        });
      }

      if (!amount) {
        console.log("❌ Amount missing");
        return res.status(400).json({ 
          success: false,
          error: "Amount is required" 
        });
      }

      const parsedAmount = parseFloat(amount);
      if (isNaN(parsedAmount) || parsedAmount <= 0) {
        console.log("❌ Invalid amount:", amount);
        return res.status(400).json({ 
          success: false,
          error: "Invalid amount" 
        });
      }

      console.log(`🔵 Looking for user: ${username.toLowerCase().trim()}`);
      
      const user = await User.findOne({
        username: username.toLowerCase().trim(),
      });
      
      if (!user) {
        console.log("❌ User not found:", username);
        return res.status(404).json({ 
          success: false,
          error: "User not found" 
        });
      }

      console.log(`🔵 User found: ${user.username}, Balance: ${user.balance}`);

      // Create deposit request
      const depositRequest = {
        id: Date.now(),
        amount: parsedAmount,
        currency: currency || "USD",
        paymentMethod: paymentMethod || "bank",
        date: new Date().toISOString(),
        status: "pending",
        screenshot: screenshot ? screenshot.path : null,
        screenshotFilename: screenshot ? screenshot.filename : null,
        userNote: req.body.note || "",
      };

      // Initialize arrays if they don't exist
      if (!user.depositRequests) {
        user.depositRequests = [];
      }
      if (!user.transactions) {
        user.transactions = [];
      }

      user.depositRequests.unshift(depositRequest);

      // Add to transactions
      user.transactions.unshift({
        type: "Deposit",
        amount: parsedAmount,
        currency: currency || "USD",
        usd: parsedAmount,
        date: new Date().toISOString(),
        status: "pending",
        paymentMethod: paymentMethod || "bank",
        note: `Deposit request via ${paymentMethod || "bank"} - ${currency || "USD"}`,
      });

      await user.save();
      // ✅ Invalidate cache
      deleteCached(`user_${username}`);
      deleteCached(`balance_${username}`);
      deleteCached(`transactions_${username}`);
      console.log(`✅ Deposit request saved for ${user.username}`);

      // Notify admin
      try {
        const masterAdmin = await User.findOne({ isMasterAdmin: true });
        if (masterAdmin) {
          if (!masterAdmin.notifications) {
            masterAdmin.notifications = [];
          }
          masterAdmin.notifications.unshift({
            id: Date.now() + Math.random(),
            title: "💰 New Deposit Request",
            body: `${user.username} requested deposit of ${parsedAmount} ${currency || "USD"}`,
            time: new Date().toISOString(),
            date: new Date().toISOString(),
            read: false,
            userId: user.username,
            depositId: depositRequest.id,
          });
          await masterAdmin.save();
          console.log("✅ Admin notification sent");
        }
      } catch (notifErr) {
        console.error("⚠️ Failed to send admin notification:", notifErr);
        // Don't fail the request if notification fails
      }

      res.json({
        success: true,
        message: "Deposit request submitted",
        requestId: depositRequest.id,
      });
    } catch (err) {
      console.error("❌ Deposit request error:", err);
      console.error("❌ Error stack:", err.stack);
      res.status(500).json({ 
        success: false,
        error: err.message || "Internal server error",
        details: process.env.NODE_ENV === "development" ? err.stack : undefined
      });
    }
  }
);

// ================= ADMIN APPROVE/REJECT DEPOSIT =================
router.post("/admin/approve-deposit", validateAdminSession, async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized. Invalid admin key." });
    }

    const sessionInfo = req.sessionInfo;
    const { username, requestId, action } = req.body;

    console.log("📝 Approve deposit request:", { username, requestId, action });

    if (!username || !requestId || !action) {
      return res.status(400).json({ error: "Username, requestId, and action required" });
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

    const requestIndex = (user.depositRequests || []).findIndex(
      (r) => String(r.id) === String(requestId)
    );
    if (requestIndex === -1) {
      return res.status(404).json({ error: "Deposit request not found" });
    }

    const request = user.depositRequests[requestIndex];

    if (request.status !== "pending") {
      return res.status(400).json({ error: `Request already ${request.status}` });
    }

    if (action === "approve") {
      request.status = "approved";
      request.approvedAt = new Date().toISOString();

      // Add amount to balance
      const amountToAdd = parseFloat(request.amount);
      user.balance = parseFloat((user.balance + amountToAdd).toFixed(2));

      // Update transaction
      const txIndex = (user.transactions || []).findIndex(
        (tx) => tx.status === "pending" && tx.type === "Deposit" && 
        Math.abs(tx.amount - request.amount) < 0.001
      );
      if (txIndex !== -1) {
        user.transactions[txIndex].status = "approved";
        user.transactions[txIndex].approvedAt = new Date().toISOString();
      }

      // Notification
      if (!user.notifications) {
        user.notifications = [];
      }
      user.notifications.unshift({
        id: Date.now() + Math.random(),
        title: "✅ Deposit Approved",
        body: `Your deposit of ${request.amount} ${request.currency || "USD"} has been approved and added to your balance.`,
        time: new Date().toISOString(),
        date: new Date().toISOString(),
        read: false,
      });
    } else if (action === "reject") {
      request.status = "rejected";
      request.rejectedAt = new Date().toISOString();

      // Update transaction
      const txIndex = (user.transactions || []).findIndex(
        (tx) => tx.status === "pending" && tx.type === "Deposit" && 
        Math.abs(tx.amount - request.amount) < 0.001
      );
      if (txIndex !== -1) {
        user.transactions[txIndex].status = "rejected";
        user.transactions[txIndex].rejectedAt = new Date().toISOString();
      }

      // Notification
      if (!user.notifications) {
        user.notifications = [];
      }
      user.notifications.unshift({
        id: Date.now() + Math.random(),
        title: "❌ Deposit Rejected",
        body: `Your deposit of ${request.amount} ${request.currency || "USD"} has been rejected. Please contact support.`,
        time: new Date().toISOString(),
        date: new Date().toISOString(),
        read: false,
      });
    } else {
      return res.status(400).json({ error: "Invalid action. Use 'approve' or 'reject'" });
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
    console.error("❌ Error in approve-deposit:", err);
    res.status(500).json({ error: err.message });
  }
});

// ================= GET PAYMENT DETAILS (WITH VIRTUAL ADMIN SUPPORT) =================
router.get("/admin/payment-details", validateAdminSession, async (req, res) => {
  try {
    const sessionInfo = req.sessionInfo;
    
    // ✅ If Virtual Admin, return THEIR payment settings
    if (sessionInfo.isVirtual && sessionInfo.virtualAdmin) {
      const virtualAdmin = await VirtualAdmin.findOne({ 
        refKey: sessionInfo.refKey 
      });
      
      if (!virtualAdmin) {
        return res.status(404).json({ error: "Virtual admin not found" });
      }
      
      // Return virtual admin's payment settings
      return res.json({
        success: true,
        details: virtualAdmin.paymentSettings || {
          bank: { accountNumber: "", accountHolder: "", bankName: "", ifsc: "", additionalInfo: "" },
          crypto: { address: "", additionalInfo: "" },
          upi: { address: "", additionalInfo: "" },
        },
        isVirtualAdmin: true,
        adminName: virtualAdmin.adminName,
        refKey: virtualAdmin.refKey,
      });
    }
    
    // ✅ Master Admin - get global settings or return empty
    const Settings = mongoose.model("Settings");
    let settings = await Settings.findOne({ key: "paymentDetails" });
    
    if (!settings) {
      return res.json({
        success: true,
        details: {
          bank: { accountNumber: "", accountHolder: "", bankName: "", ifsc: "", additionalInfo: "" },
          crypto: { address: "", additionalInfo: "" },
          upi: { address: "", additionalInfo: "" },
        },
        isVirtualAdmin: false,
      });
    }
    
    res.json({ 
      success: true, 
      details: settings.value || {},
      isVirtualAdmin: false,
    });
  } catch (err) {
    console.error("Error fetching payment details:", err);
    res.status(500).json({ error: err.message });
  }
});

// ================= ADMIN UPDATE PAYMENT DETAILS (WITH VIRTUAL ADMIN SUPPORT) =================
router.post("/admin/update-payment-details", validateAdminSession, async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized. Admin access only." });
    }

    const sessionInfo = req.sessionInfo;
    const { method, address, additionalInfo } = req.body;

    if (!method || !address) {
      return res.status(400).json({ error: "Method and address required" });
    }

    // ✅ If Virtual Admin, update THEIR payment settings
    if (sessionInfo.isVirtual && sessionInfo.virtualAdmin) {
      const virtualAdmin = await VirtualAdmin.findOne({ 
        refKey: sessionInfo.refKey 
      });

      if (!virtualAdmin) {
        return res.status(404).json({ error: "Virtual admin not found" });
      }

      // Initialize paymentSettings if it doesn't exist
      if (!virtualAdmin.paymentSettings) {
        virtualAdmin.paymentSettings = {
          bank: { accountNumber: "", accountHolder: "", bankName: "", ifsc: "", additionalInfo: "" },
          crypto: { address: "", additionalInfo: "" },
          upi: { address: "", additionalInfo: "" },
        };
      }

      // Update the specific method
      if (method === "bank") {
        try {
          const bankInfo = JSON.parse(additionalInfo || "{}");
          virtualAdmin.paymentSettings.bank = {
            accountNumber: address,
            accountHolder: bankInfo.accountHolder || "",
            bankName: bankInfo.bankName || "",
            ifsc: bankInfo.ifsc || "",
            additionalInfo: bankInfo.additionalInfo || "",
            updatedAt: new Date(),
          };
        } catch (e) {
          virtualAdmin.paymentSettings.bank.accountNumber = address;
          virtualAdmin.paymentSettings.bank.additionalInfo = additionalInfo || "";
          virtualAdmin.paymentSettings.bank.updatedAt = new Date();
        }
      } else if (method === "crypto") {
        virtualAdmin.paymentSettings.crypto = {
          address: address,
          additionalInfo: additionalInfo || "",
          updatedAt: new Date(),
        };
      } else if (method === "upi") {
        virtualAdmin.paymentSettings.upi = {
          address: address,
          additionalInfo: additionalInfo || "",
          updatedAt: new Date(),
        };
      }

      virtualAdmin.markModified("paymentSettings");
      await virtualAdmin.save();

      return res.json({
        success: true,
        message: `Payment details for ${method} updated successfully for ${virtualAdmin.adminName}`,
        details: virtualAdmin.paymentSettings[method],
        isVirtualAdmin: true,
        adminName: virtualAdmin.adminName,
      });
    }

    // ✅ Master Admin - update global settings
    const Settings = mongoose.model("Settings");
    let settings = await Settings.findOne({ key: "paymentDetails" });
    
    if (!settings) {
      settings = new Settings({ 
        key: "paymentDetails", 
        value: {} 
      });
    }

    settings.value = settings.value || {};
    
    if (method === "bank") {
      try {
        const bankInfo = JSON.parse(additionalInfo || "{}");
        settings.value.bank = {
          accountNumber: address,
          accountHolder: bankInfo.accountHolder || "",
          bankName: bankInfo.bankName || "",
          ifsc: bankInfo.ifsc || "",
          additionalInfo: bankInfo.additionalInfo || "",
          updatedAt: new Date(),
        };
      } catch (e) {
        settings.value.bank = {
          accountNumber: address,
          additionalInfo: additionalInfo || "",
          updatedAt: new Date(),
        };
      }
    } else if (method === "crypto") {
      settings.value.crypto = {
        address: address,
        additionalInfo: additionalInfo || "",
        updatedAt: new Date(),
      };
    } else if (method === "upi") {
      settings.value.upi = {
        address: address,
        additionalInfo: additionalInfo || "",
        updatedAt: new Date(),
      };
    }

    settings.markModified("value");
    await settings.save();

    res.json({
      success: true,
      message: `Payment details for ${method} updated successfully`,
      details: settings.value[method],
      isVirtualAdmin: false,
    });
  } catch (err) {
    console.error("Error updating payment details:", err);
    res.status(500).json({ error: err.message });
  }
});

// ================= GET PAYMENT DETAILS BY REFKEY (PUBLIC - FOR USERS) =================
router.get("/public/payment-details/:refKey", async (req, res) => {
  try {
    const { refKey } = req.params;
    
    const virtualAdmin = await VirtualAdmin.findOne({ refKey });
    
    if (!virtualAdmin) {
      // If no virtual admin found, return default/global settings
      const Settings = mongoose.model("Settings");
      const settings = await Settings.findOne({ key: "paymentDetails" });
      
      return res.json({
        success: true,
        details: settings?.value || {
          bank: { accountNumber: "Not configured", accountHolder: "", bankName: "", ifsc: "" },
          crypto: { address: "Not configured", additionalInfo: "" },
          upi: { address: "Not configured", additionalInfo: "" },
        },
        adminName: "Default",
      });
    }
    
    // Return the virtual admin's payment settings
    res.json({
      success: true,
      details: virtualAdmin.paymentSettings || {
        bank: { accountNumber: "", accountHolder: "", bankName: "", ifsc: "", additionalInfo: "" },
        crypto: { address: "", additionalInfo: "" },
        upi: { address: "", additionalInfo: "" },
      },
      adminName: virtualAdmin.adminName,
      refKey: virtualAdmin.refKey,
    });
  } catch (err) {
    console.error("Error fetching public payment details:", err);
    res.status(500).json({ error: err.message });
  }
});

// ================= ADMIN UPDATE PAYMENT DETAILS =================
router.post("/admin/update-payment-details", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized. Admin access only." });
    }

    const { method, address, additionalInfo } = req.body;

    if (!method || !address) {
      return res.status(400).json({ error: "Method and address required" });
    }

    // Store in database or environment variables
    // For now, we'll store in a settings collection (you'll need to create a Settings model)
    const Settings = mongoose.model("Settings");
    let settings = await Settings.findOne({ key: "paymentDetails" });
    
    if (!settings) {
      settings = new Settings({ 
        key: "paymentDetails", 
        value: {} 
      });
    }

    settings.value = settings.value || {};
    settings.value[method] = {
      address,
      additionalInfo: additionalInfo || "",
      updatedAt: new Date().toISOString(),
    };
    settings.markModified("value");
    await settings.save();

    res.json({ 
      success: true, 
      message: `Payment details for ${method} updated successfully`,
      details: settings.value[method]
    });
  } catch (err) {
    console.error("Error updating payment details:", err);
    res.status(500).json({ error: err.message });
  }
});

// ================= CACHE STATS (Admin Only) =================
router.get("/admin/cache-stats", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized. Admin access only." });
    }

    const stats = {
      keys: cache.keys(),
      totalKeys: cache.keys().length,
      memoryUsage: process.memoryUsage(),
    };
    
    res.json(stats);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= CLEAR CACHE (Admin Only) =================
router.post("/admin/clear-cache", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized. Admin access only." });
    }

    clearCache();
    res.json({ success: true, message: "Cache cleared successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
export default router;