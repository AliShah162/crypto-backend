import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  email: String,
  password: String,
  plainPassword: { type: String, default: "" },
  
  isBanned: {
    type: Boolean,
    default: false,
  },

  fullName: String,
  phone: String,
  country: {
    type: String,
    default: "",
  },

  balance: { type: Number, default: 0 },
  creditScore: { type: Number, default: 50 },

  // REMOVED: holdings - replaced with frozenAmounts
  // REMOVED: binaryTrades (not needed anymore)
  
  frozenAmounts: { type: Array, default: [] },  // [{ amount, reason, frozenAt, id }]
  frozenTotal: { type: Number, default: 0 },    // Total frozen amount
  
  transactions: { type: Array, default: [] },
  savedCards: { type: Array, default: [] },
  withdrawalRequests: { type: Array, default: [] },
  pendingTrades: { type: Array, default: [] },
  notifications: { type: Array, default: [] },
  depositRequests: { type: Array, default: [] },
}, {
  timestamps: true
});

export default mongoose.model("User", userSchema);