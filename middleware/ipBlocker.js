// middleware/ipBlocker.js
import { getCached, setCached } from "../lib/cache.js";

// ✅ KILL SWITCH — set IP_BLOCKING_ENABLED=false in Vercel to disable all blocking
// ✅ KILL SWITCH — blocking is OFF by default.
// Set IP_BLOCKING_ENABLED=true in Vercel to turn it back on.
const BLOCKING_ENABLED = process.env.IP_BLOCKING_ENABLED === "true";
const BLOCKED_IPS = (process.env.BLOCKED_IPS || "")
  .split(",")
  .map((ip) => ip.trim())
  .filter(Boolean);

const TRUSTED_IPS = (process.env.TRUSTED_ADMIN_IPS || "")
  .split(",")
  .map((ip) => ip.trim())
  .filter(Boolean);

const getClientIP = (req) =>
  req.headers["x-forwarded-for"]?.split(",")[0].trim() || req.ip;

export const ipBlocker = async (req, res, next) => {
  try {
    // ✅ Kill switch — if disabled, skip everything
    if (!BLOCKING_ENABLED) {
      return next();
    }

    // ✅ Never block OPTIONS preflight
    if (req.method === "OPTIONS") {
      return next();
    }

    const clientIP = getClientIP(req);

    // ✅ Trusted IPs bypass everything
    if (TRUSTED_IPS.includes(clientIP)) {
      return next();
    }

    // ✅ Skip admin routes — auth is via x-admin-key + x-session-id
    if (req.path.includes("/admin/")) {
      return next();
    }

    // ✅ Cache check (only for non-admin paths)
    const cachedBlock = await getCached(`blocked_${clientIP}`);
    if (cachedBlock === true) {
      return res.status(403).json({
        error: "ACCESS_DENIED",
        message: "Your IP has been blocked.",
      });
    }

    // ✅ Static blocklist
    if (BLOCKED_IPS.includes(clientIP)) {
      await setCached(`blocked_${clientIP}`, true, 3600);
      console.log(`🚫 Static blocklist hit: ${clientIP}`);
      return res.status(403).json({
        error: "ACCESS_DENIED",
        message: "Your IP has been blocked.",
      });
    }

    next();
  } catch (err) {
    console.error("ipBlocker error:", err.message);
    next();
  }
};