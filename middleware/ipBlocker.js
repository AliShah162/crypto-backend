// middleware/ipBlocker.js
import { getCached, setCached } from "../lib/cache.js";

const BLOCKED_IPS = (process.env.BLOCKED_IPS || "")
  .split(",")
  .map((ip) => ip.trim())
  .filter(Boolean);

const TRUSTED_IPS = (process.env.TRUSTED_ADMIN_IPS || "")
  .split(",")
  .map((ip) => ip.trim())
  .filter(Boolean);

export const ipBlocker = (req, res, next) => {
  const clientIP =
    req.headers["x-forwarded-for"]?.split(",")[0].trim() || req.ip;

  // ✅ Trusted IPs bypass everything
  if (TRUSTED_IPS.includes(clientIP)) {
    return next();
  }

  // ✅ Cache check first
  if (getCached(`blocked_${clientIP}`) === true) {
    return res.status(403).json({
      error: "ACCESS_DENIED",
      message: "Your IP has been blocked.",
    });
  }

  // ✅ Static blocklist check
  if (BLOCKED_IPS.includes(clientIP)) {
    setCached(`blocked_${clientIP}`, true, 3600);
    console.log(`🚫 Static blocklist hit: ${clientIP}`);
    return res.status(403).json({
      error: "ACCESS_DENIED",
      message: "Your IP has been blocked.",
    });
  }

  // ✅ Admin routes: enforce whitelist in production
  if (req.path.includes("/admin/")) {
    if (
      process.env.NODE_ENV === "production" &&
      TRUSTED_IPS.length > 0 &&
      !TRUSTED_IPS.includes(clientIP)
    ) {
      console.log(`🚫 Admin access denied for IP: ${clientIP}`);
      return res.status(403).json({
        error: "UNAUTHORIZED_IP",
        message: "Admin access restricted. Please contact support.",
      });
    }
  }

  next();
};