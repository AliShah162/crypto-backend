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
  dob: String,

  country: {
    type: String,
    default: "",
  },

  balance: { type: Number, default: 0 },
  creditScore: { type: Number, default: 50 },

  transactions: { type: Array, default: [] },
  holdings: { type: Object, default: {} },
  savedCards: { type: Array, default: [] },
  binaryTrades: { type: Array, default: [] },
  withdrawalRequests: { type: Array, default: [] },
  pendingTrades: { type: Array, default: [] },
  notifications: { type: Array, default: [] },
}, {
  timestamps: true
});

export default mongoose.model("User", userSchema);