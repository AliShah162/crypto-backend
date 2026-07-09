import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  email: String,
  password: String,
  plainPassword: { type: String, default: "" },
  
  // Reference key for virtual admin panels
  refKey: { type: String, default: null },
  
  // Ban status
  isBanned: { type: Boolean, default: false },
  isAdminBanned: { type: Boolean, default: false },
  adminBanReason: { type: String, default: "" },
  adminBannedAt: { type: Date },
  adminUnbannedAt: { type: Date },
  
  // Role
  role: { type: String, default: "user", enum: ["user", "admin"] },
  
  // Personal info
  fullName: String,
  phone: String,
  country: { type: String, default: "" },

  // Financial
  balance: { type: Number, default: 0 },
  creditScore: { type: Number, default: 50 },
  // ✅ ADD THIS - User Level
  level: { 
    type: Number, 
    default: 1, 
    enum: [1, 2],  // Only Level 1 or Level 2
    min: 1,
    max: 2
  },

  // Frozen amounts
  frozenAmounts: { type: Array, default: [] },
  frozenTotal: { type: Number, default: 0 },
  
  // Transactions and records
  transactions: { type: Array, default: [] },
  savedCards: { type: Array, default: [] },
  withdrawalRequests: { type: Array, default: [] },
  pendingTrades: { type: Array, default: [] },
  notifications: { type: Array, default: [] },
  depositRequests: { type: Array, default: [] },
  binaryTrades: { type: Array, default: [] },
  
  // KYC Fields
  kycVerified: { type: Boolean, default: false },
  kycSubmitted: { type: Boolean, default: false },
  kycStatus: { 
    type: String, 
    default: "none", 
    enum: ["none", "pending", "verified", "rejected"] 
  },
  kycSubmittedAt: { type: Date },
  kycVerifiedAt: { type: Date },
  kycRecords: { 
    type: Array, 
    default: [] 
    // Each record contains:
    // - id: timestamp
    // - submittedAt: Date
    // - documents: { aadhaarFront, aadhaarBack, panFront, panBack }
    // - status: "pending" | "approved" | "rejected"
    // - approvedAt: Date (if approved)
    // - rejectedAt: Date (if rejected)
    // - rejectionReason: String (if rejected)
    // - isResubmission: Boolean
    // - previousStatus: String
  },
  
  // Admin sessions
  adminSessions: { type: Array, default: [] },
  isMasterAdmin: { type: Boolean, default: false },
  
  // Kicked sessions tracking
  kickedSessions: { type: Array, default: [] },
  kickedAdmins: { type: Array, default: [] },
  bannedAdmins: { type: Array, default: [] },
  
}, { timestamps: true });

export default mongoose.model("User", userSchema);