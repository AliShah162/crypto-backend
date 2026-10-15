// middleware/autoBlocker.js
import { getCached, setCached, incrementCached } from "../lib/cache.js";
import User from "../models/User.js";

const getClientIP = (req) =>
  req.headers["x-forwarded-for"]?.split(",")[0].trim() || req.ip;

const TRUSTED_IPS = (process.env.TRUSTED_ADMIN_IPS || "")
  .split(",")
  .map((ip) => ip.trim())
  .filter(Boolean);

const WINDOW_SECONDS = 300; // 5 minutes

export const autoBlocker = async (req, res, next) => {
  try {
    // ✅ CRITICAL: Never count OPTIONS preflight
    if (req.method === "OPTIONS") {
      return next();
    }

    const clientIP = getClientIP(req);

    // ✅ Skip health checks
    if (
      req.path === "/health" ||
      req.path === "/ping" ||
      req.path === "/api/test" ||
      req.path === "/"
    ) {
      return next();
    }

    // ✅ Skip trusted IPs
    if (TRUSTED_IPS.includes(clientIP)) {
      return next();
    }

    // ✅ Already blocked?
    const isBlocked = await getCached(`blocked_${clientIP}`);
    if (isBlocked === true) {
      return res.status(403).json({
        error: "ACCESS_DENIED",
        message: "Your IP has been temporarily blocked.",
      });
    }

    // ✅ Atomic increment (KV-safe across instances)
    const isAdminPath = req.path.includes("/admin/");
    const windowKey = `req:${isAdminPath ? "admin" : "user"}:${clientIP}`;
    const count = await incrementCached(windowKey, WINDOW_SECONDS);

    const limit = isAdminPath ? 100 : 500;

    if (count > limit) {
      const blockTTL = isAdminPath ? 3600 : 1800;
      await setCached(`blocked_${clientIP}`, true, blockTTL);

      console.log(
        `🔴 Auto-blocked IP: ${clientIP} (${count} req to ${req.path})`
      );

      // Fire-and-forget DB log
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
    next(); // Fail open
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