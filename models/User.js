import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  // ===== AUTHENTICATION =====
  username: { 
    type: String, 
    unique: true, 
    required: true,
    trim: true,
    lowercase: true
  },
  email: { 
    type: String,
    trim: true,
    lowercase: true
  },
  password: { 
    type: String,
    required: true
  },
  plainPassword: { 
    type: String, 
    default: "" 
  },
  
  // ✅ NEW: Track when password was last changed
  passwordUpdatedAt: { 
    type: Date, 
    default: Date.now 
  },

  // ===== REFERENCE KEY =====
  refKey: { 
    type: String, 
    default: null,
    index: true
  },

  // ===== BAN STATUS =====
  isBanned: { 
    type: Boolean, 
    default: false 
  },
  isAdminBanned: { 
    type: Boolean, 
    default: false 
  },
  adminBanReason: { 
    type: String, 
    default: "" 
  },
  adminBannedAt: { 
    type: Date 
  },
  adminUnbannedAt: { 
    type: Date 
  },

  // ===== ROLE =====
  role: { 
    type: String, 
    default: "user", 
    enum: ["user", "admin"] 
  },
  isMasterAdmin: { 
    type: Boolean, 
    default: false 
  },

  // ===== PERSONAL INFO =====
  fullName: { 
    type: String, 
    default: "" 
  },
  phone: { 
    type: String, 
    default: "" 
  },
  country: { 
    type: String, 
    default: "" 
  },

  // ===== FINANCIAL =====
  balance: { 
    type: Number, 
    default: 0 
  },
  creditScore: { 
    type: Number, 
    default: 50 
  },
  
  // ===== USER LEVEL =====
  level: { 
    type: Number, 
    default: 1, 
    enum: [1, 2],
    min: 1,
    max: 2
  },

  // ===== FROZEN AMOUNTS =====
  frozenAmounts: { 
    type: Array, 
    default: [] 
  },
  frozenTotal: { 
    type: Number, 
    default: 0 
  },

  // ===== TRANSACTIONS & RECORDS =====
  transactions: { 
    type: Array, 
    default: [] 
  },
  savedCards: { 
    type: Array, 
    default: [] 
  },
  withdrawalRequests: { 
    type: Array, 
    default: [] 
  },
  pendingTrades: { 
    type: Array, 
    default: [] 
  },
  notifications: { 
    type: Array, 
    default: [] 
  },
  depositRequests: { 
    type: Array, 
    default: [] 
  },
  binaryTrades: { 
    type: Array, 
    default: [] 
  },

  // ===== KYC FIELDS =====
  kycVerified: { 
    type: Boolean, 
    default: false 
  },
  kycSubmitted: { 
    type: Boolean, 
    default: false 
  },
  kycStatus: { 
    type: String, 
    default: "none", 
    enum: ["none", "pending", "verified", "rejected"] 
  },
  kycSubmittedAt: { 
    type: Date 
  },
  kycVerifiedAt: { 
    type: Date 
  },
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

  // ===== ADMIN SESSIONS =====
  adminSessions: { 
    type: Array, 
    default: [] 
  },

  // ===== KICKED SESSIONS TRACKING =====
  kickedSessions: { 
    type: Array, 
    default: [] 
  },
  kickedAdmins: { 
    type: Array, 
    default: [] 
  },
  bannedAdmins: { 
    type: Array, 
    default: [] 
  },

  // ===== CVV/IFC LABEL SETTINGS =====
  cvvLabel: { 
    type: String, 
    default: "CVV" 
  },

}, { 
  timestamps: true 
});

// ✅ Create indexes for faster queries
userSchema.index({ username: 1 });
userSchema.index({ email: 1 });
userSchema.index({ refKey: 1 });
userSchema.index({ kycStatus: 1, kycSubmitted: 1 });

// ✅ Virtual field to check if user is admin
userSchema.virtual('isAdmin').get(function() {
  return this.role === 'admin' || this.isMasterAdmin === true;
});

// ✅ Virtual field to check if user is banned from admin
userSchema.virtual('isAdminBannedStatus').get(function() {
  return this.isAdminBanned === true || this.isBanned === true;
});

// ✅ Method to invalidate all sessions
userSchema.methods.invalidateAllSessions = function(reason = "Manual invalidation") {
  if (this.adminSessions && this.adminSessions.length > 0) {
    this.adminSessions = this.adminSessions.map(session => ({
      ...session,
      isActive: false,
      invalidatedAt: new Date(),
      invalidatedReason: reason
    }));
  }
  return this;
};

// ✅ Method to add a kicked session
userSchema.methods.addKickedSession = function(sessionId, reason = "Kicked by admin") {
  this.kickedSessions = this.kickedSessions || [];
  this.kickedSessions.push({
    sessionId: sessionId,
    kickedAt: new Date(),
    reason: reason
  });
  return this;
};

// ✅ Method to clean old sessions
userSchema.methods.cleanOldSessions = function(maxSessions = 50) {
  if (this.adminSessions && this.adminSessions.length > maxSessions) {
    // Keep only the most recent maxSessions
    this.adminSessions = this.adminSessions.slice(-maxSessions);
  }
  if (this.kickedSessions && this.kickedSessions.length > maxSessions) {
    this.kickedSessions = this.kickedSessions.slice(-maxSessions);
  }
  return this;
};

export default mongoose.model("User", userSchema);