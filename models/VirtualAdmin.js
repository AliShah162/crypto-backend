import mongoose from "mongoose";

const virtualAdminSchema = new mongoose.Schema({
  // ================= BASIC INFO =================
  adminName: {
    type: String,
    required: true,
  },
  username: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
  },
  
  // ================= AUTHENTICATION =================
  refKey: {
    type: String,
    required: true,
    unique: true,
    trim: true,
  },
  password: {
    type: String,
    default: "",
  },
  plainPassword: {
    type: String,
    default: "",
  },
  
  // ================= STATUS =================
  isActive: {
    type: Boolean,
    default: true,
  },
  isBanned: {
    type: Boolean,
    default: false,
  },
  banReason: {
    type: String,
    default: null,
  },
  bannedAt: {
    type: Date,
    default: null,
  },
  bannedBy: {
    type: String,
    default: null,
  },
  unbannedAt: {
    type: Date,
    default: null,
  },
  unbannedBy: {
    type: String,
    default: null,
  },
  lastKickedAt: {
    type: Date,
    default: null,
  },
  lastLogin: {
    type: Date,
    default: null,
  },
  
  // ================= PAYMENT SETTINGS (PER VIRTUAL ADMIN) =================
  // ✅ ADD THIS - Each Virtual Admin has their own payment details
  paymentSettings: {
    bank: {
      accountNumber: { type: String, default: "" },
      accountHolder: { type: String, default: "" },
      bankName: { type: String, default: "" },
      ifsc: { type: String, default: "" },
      additionalInfo: { type: String, default: "" },
      updatedAt: { type: Date, default: null },
    },
    crypto: {
      address: { type: String, default: "" },
      additionalInfo: { type: String, default: "" },
      updatedAt: { type: Date, default: null },
    },
    upi: {
      address: { type: String, default: "" },
      additionalInfo: { type: String, default: "" },
      updatedAt: { type: Date, default: null },
    },
  },
  
  // ================= SESSIONS =================
  sessions: [{
    sessionId: { type: String },
    ipAddress: { type: String },
    userAgent: { type: String },
    deviceInfo: { type: String },
    loggedInAt: { type: Date, default: Date.now },
    lastActiveAt: { type: Date, default: Date.now },
    isActive: { type: Boolean, default: true },
    customName: { type: String, default: null },
  }],
  
  // ================= METADATA =================
  createdAt: {
    type: Date,
    default: Date.now,
  },
  updatedAt: {
    type: Date,
    default: Date.now,
  },
  passwordUpdatedAt: {
    type: Date,
    default: null,
  },
  passwordUpdatedBy: {
    type: String,
    default: null,
  },
});

// Update the updatedAt timestamp on save
virtualAdminSchema.pre('save', function(next) {
  this.updatedAt = new Date();
  next();
});

const VirtualAdmin = mongoose.models.VirtualAdmin || mongoose.model("VirtualAdmin", virtualAdminSchema);

export default VirtualAdmin;