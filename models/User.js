import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  email: String,
  password: String,
  plainPassword: { type: String, default: "" },
  
  // NEW: Reference key for virtual admin panels
  refKey: { type: String, default: null },
  
  isBanned: { type: Boolean, default: false },
  isAdminBanned: { type: Boolean, default: false },
  adminBanReason: { type: String, default: "" },
  adminBannedAt: { type: Date },
  adminUnbannedAt: { type: Date },
  
  role: { type: String, default: "user", enum: ["user", "admin"] },
  
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
  
  adminSessions: { type: Array, default: [] },
  isMasterAdmin: { type: Boolean, default: false },
}, { timestamps: true });



export default mongoose.model("User", userSchema);