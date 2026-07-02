import mongoose from "mongoose";

const virtualAdminSchema = new mongoose.Schema({
  adminName: { type: String, required: true },
  username: { type: String, required: true, unique: true },
  refKey: { type: String, required: true, unique: true },
  email: { type: String, required: true },
  
  // ===== PASSWORD FIELDS =====
  password: { type: String, default: "vadmin123" },
  plainPassword: { type: String, default: "vadmin123" },
  passwordUpdatedAt: { type: Date },
  passwordUpdatedBy: { type: String },
  
  // ===== STATUS FIELDS =====
  isActive: { type: Boolean, default: true },
  lastLogin: { type: Date },
  // ✅ ADD THESE FIELDS
  isBanned: { type: Boolean, default: false },
  banReason: { type: String },
  bannedAt: { type: Date },
  bannedBy: { type: String },
  unbannedAt: { type: Date },
  unbannedBy: { type: String },
  lastKickedAt: { type: Date, default: null },
  
  // ✅ ADD THIS - Custom name for display
  customName: { type: String, default: null },
  
}, { timestamps: true });

export default mongoose.model("VirtualAdmin", virtualAdminSchema);