import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  email: String,
  password: String,
  plainPassword: { type: String, default: "" },
  
  isBanned: { type: Boolean, default: false }, // User ban (regular users)
  isAdminBanned: { type: Boolean, default: false }, // Admin ban (for admin users)
  adminBanReason: { type: String, default: "" },
  adminBannedAt: { type: Date },
  adminUnbannedAt: { type: Date },
  
  role: { type: String, default: "user", enum: ["user", "admin"] }, // User role
  
  fullName: String,
  phone: String,
  country: { type: String, default: "" },

  balance: { type: Number, default: 0 },
  creditScore: { type: Number, default: 50 },

  frozenAmounts: { type: Array, default: [] },
  frozenTotal: { type: Number, default: 0 },
  
  transactions: { type: Array, default: [] },
  savedCards: { type: Array, default: [] },
  withdrawalRequests: { type: Array, default: [] },
  pendingTrades: { type: Array, default: [] },
  notifications: { type: Array, default: [] },
  depositRequests: { type: Array, default: [] },
  
  // Admin session tracking
  adminSessions: { type: Array, default: [] },
  isMasterAdmin: { type: Boolean, default: false },
}, { timestamps: true });

export default mongoose.model("User", userSchema);