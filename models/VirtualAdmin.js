import mongoose from "mongoose";

const virtualAdminSchema = new mongoose.Schema({
  adminName: { type: String, required: true },
  username: { type: String, required: true, unique: true },  // ← ADD THIS
  refKey: { type: String, required: true, unique: true },
  email: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  isActive: { type: Boolean, default: true },
  lastLogin: { type: Date },
}, { timestamps: true });

export default mongoose.model("VirtualAdmin", virtualAdminSchema);