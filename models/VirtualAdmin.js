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
  
}, { timestamps: true });

export default mongoose.model("VirtualAdmin", virtualAdminSchema);