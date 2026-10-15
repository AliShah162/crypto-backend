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

const getClientIP = (req) =>
  req.headers["x-forwarded-for"]?.split(",")[0].trim() || req.ip;

export const ipBlocker = async (req, res, next) => {
  try {
    const clientIP = getClientIP(req);

    // ✅ Trusted IPs bypass everything
    if (TRUSTED_IPS.includes(clientIP)) {
      return next();
    }

    // ✅ Cache check (async now)
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
  } catch (err) {
    console.error("ipBlocker error:", err.message);
    // Fail open — don't block legit users if cache is down
    next();
  }
};