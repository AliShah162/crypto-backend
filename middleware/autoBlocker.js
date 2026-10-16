// middleware/autoBlocker.js
import { getCached, setCached, incrementCached } from "../lib/cache.js";
import User from "../models/User.js";

// ✅ KILL SWITCH — set IP_BLOCKING_ENABLED=false to disable
const BLOCKING_ENABLED = process.env.IP_BLOCKING_ENABLED === "true";

const getClientIP = (req) =>
  req.headers["x-forwarded-for"]?.split(",")[0].trim() || req.ip;

const TRUSTED_IPS = (process.env.TRUSTED_ADMIN_IPS || "")
  .split(",")
  .map((ip) => ip.trim())
  .filter(Boolean);

const WINDOW_SECONDS = 300;

export const autoBlocker = async (req, res, next) => {
  try {
    // ✅ Kill switch
    if (!BLOCKING_ENABLED) {
      return next();
    }

    if (req.method === "OPTIONS") {
      return next();
    }

    const clientIP = getClientIP(req);

    if (
      req.path === "/health" ||
      req.path === "/ping" ||
      req.path === "/api/test" ||
      req.path === "/"
    ) {
      return next();
    }

    if (TRUSTED_IPS.includes(clientIP)) {
      return next();
    }

    // ✅ Skip admin routes
    if (req.path.includes("/admin/")) {
      return next();
    }

    const isBlocked = await getCached(`blocked_${clientIP}`);
    if (isBlocked === true) {
      return res.status(403).json({
        error: "ACCESS_DENIED",
        message: "Your IP has been temporarily blocked.",
      });
    }

    const windowKey = `req:user:${clientIP}`;
    const count = await incrementCached(windowKey, WINDOW_SECONDS);
    const limit = 500;

    if (count > limit) {
      const blockTTL = 1800;
      await setCached(`blocked_${clientIP}`, true, blockTTL);

      console.log(
        `🔴 Auto-blocked IP: ${clientIP} (${count} req to ${req.path})`
      );

      logAutoBlock(clientIP, count, req.path).catch((err) =>
        console.error("Failed to log auto-block:", err)
      );

      return res.status(403).json({
        error: "ACCESS_DENIED",
        message: "Too many requests. Please try again later.",
      });
    }

    next();
  } catch (err) {
    console.error("autoBlocker error:", err.message);
    next();
  }
};

async function logAutoBlock(ip, count, path) {
  const masterAdmin = await User.findOne({ username: "master_admin" });
  if (!masterAdmin) return;

  masterAdmin.kickedSessions = masterAdmin.kickedSessions || [];
  masterAdmin.kickedSessions.push({
    ip,
    kickedAt: new Date(),
    reason: `Auto-blocked: ${count} requests to ${path} in 5 min`,
    action: "auto_block",
  });

  if (masterAdmin.kickedSessions.length > 200) {
    masterAdmin.kickedSessions = masterAdmin.kickedSessions.slice(-200);
  }

  await masterAdmin.save();
}