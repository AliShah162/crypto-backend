// middleware/autoBlocker.js
import { getCached, setCached } from "../lib/cache.js";
import User from "../models/User.js";

export const autoBlocker = async (req, res, next) => {
  const clientIP =
    req.headers["x-forwarded-for"]?.split(",")[0].trim() || req.ip;

  // ✅ Skip health checks FIRST
  if (
    req.path === "/health" ||
    req.path === "/ping" ||
    req.path === "/api/test" ||
    req.path === "/"
  ) {
    return next();
  }

  // ✅ Skip trusted IPs
  const trustedIPs = (process.env.TRUSTED_ADMIN_IPS || "")
    .split(",")
    .map((ip) => ip.trim())
    .filter(Boolean);
  if (trustedIPs.includes(clientIP)) {
    return next();
  }

  // ✅ Skip if already blocked
  if (getCached(`blocked_${clientIP}`)) {
    return res.status(403).json({
      error: "ACCESS_DENIED",
      message: "Your IP has been temporarily blocked.",
    });
  }

  // ✅ Track request count with sliding window
  const key = `requests_${clientIP}`;
  const now = Date.now();
  const WINDOW_MS = 5 * 60 * 1000; // 5 minutes

  let requests = getCached(key);
  if (!requests || now - requests.firstSeen > WINDOW_MS) {
    requests = { count: 0, firstSeen: now };
  }

  requests.count++;

  const isAdminPath = req.path.includes("/admin/");
  const limit = isAdminPath ? 100 : 500;

  if (requests.count > limit) {
    setCached(`blocked_${clientIP}`, true, isAdminPath ? 3600 : 1800);
    console.log(
      `🔴 Auto-blocked IP: ${clientIP} (${requests.count} req to ${req.path})`
    );

    // Log to master admin (fire and forget)
    User.findOne({ username: "master_admin" })
      .then((masterAdmin) => {
        if (!masterAdmin) return;
        masterAdmin.kickedSessions = masterAdmin.kickedSessions || [];
        masterAdmin.kickedSessions.push({
          ip: clientIP,
          kickedAt: new Date(),
          reason: `Auto-blocked: ${requests.count} requests to ${req.path} in 5 min`,
          action: "auto_block",
        });
        // Keep only last 200 entries
        if (masterAdmin.kickedSessions.length > 200) {
          masterAdmin.kickedSessions = masterAdmin.kickedSessions.slice(-200);
        }
        return masterAdmin.save();
      })
      .catch((err) => console.error("Failed to log auto-block:", err));

    return res.status(403).json({
      error: "ACCESS_DENIED",
      message: "Too many requests. Please try again later.",
    });
  }

  // ✅ Save with TTL matching the window
  setCached(key, requests, Math.ceil(WINDOW_MS / 1000));
  next();
};