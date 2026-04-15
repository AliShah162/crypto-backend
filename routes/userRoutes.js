import express from "express";
import User from "../models/User.js";
import bcrypt from "bcryptjs";

const router = express.Router();

// ================= REGISTER =================
router.post("/register", async (req, res) => {
  try {
    const { username, email, password, fullName, phone, dob, country } = req.body;

    const cleanUser = username.toLowerCase().trim();
    const cleanEmail = email.toLowerCase().trim();

    const existingUsername = await User.findOne({ username: cleanUser });
    if (existingUsername) {
      return res.status(400).json({ error: "Username already taken." });
    }

    const existingEmail = await User.findOne({ email: cleanEmail });
    if (existingEmail) {
      return res.status(400).json({ error: "An account with this email already exists." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      username: cleanUser,
      email: cleanEmail,
      password: hashedPassword,
      fullName: fullName || "",
      phone: phone || "",
      dob: dob || "",
      country: country || "",
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

    const cleanUser = username.toLowerCase().trim();

    const user = await User.findOne({ username: cleanUser });

    if (!user) {
      return res.status(400).json({ error: "User not found" });
    }

    if (user.isBanned) {
      return res.status(403).json({ error: "BANNED" });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ error: "Invalid password" });
    }

    const safeUser = user.toObject();
    delete safeUser.password;

    res.json(safeUser);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ================= GET ALL USERS =================
router.get("/", async (req, res) => {
  try {
    const users = await User.find().select("-password");
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ================= UPDATE USER =================
router.patch("/:username", async (req, res) => {
  try {
    const { username } = req.params;
    const updates = req.body;

    const user = await User.findOneAndUpdate(
      { username: username.toLowerCase().trim() },
      { $set: updates },
      { new: true }
    ).select("-password");

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

    await User.findOneAndUpdate(
      { username: username.toLowerCase().trim() },
      { isBanned: banned }
    );

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ================= DELETE USER (NEW) =================
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