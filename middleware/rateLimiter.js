// middleware/rateLimiter.js
import { incrementCached } from "../lib/cache.js";

// ✅ KILL SWITCH — set IP_BLOCKING_ENABLED=false to disable
const RATE_LIMITING_ENABLED = process.env.IP_BLOCKING_ENABLED === "true";

const getClientIP = (req) =>
  req.headers["x-forwarded-for"]?.split(",")[0].trim() || req.ip;

const TRUSTED_IPS = (process.env.TRUSTED_ADMIN_IPS || "")
  .split(",")
  .map((ip) => ip.trim())
  .filter(Boolean);

function createRateLimiter({ windowSeconds, max, prefix, keyFn }) {
  return async (req, res, next) => {
    try {
      // ✅ Kill switch
      if (!RATE_LIMITING_ENABLED) {
        return next();
      }

      if (req.method === "OPTIONS") {
        return next();
      }

      if (["/health", "/ping", "/api/test", "/"].includes(req.path)) {
        return next();
      }

      const clientIP = getClientIP(req);
      if (TRUSTED_IPS.includes(clientIP)) {
        return next();
      }

      const key = `${prefix}:${keyFn(req)}`;
      const count = await incrementCached(key, windowSeconds);

      res.set("RateLimit-Limit", String(max));
      res.set("RateLimit-Remaining", String(Math.max(0, max - count)));
      res.set(
        "RateLimit-Reset",
        String(Math.floor(Date.now() / 1000) + windowSeconds)
      );

     if (count > max) {
  // ✅ Assert CORS so the browser never reports this as net::ERR_FAILED
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin || "*");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Vary", "Origin");

  console.warn(
    `⚠️ Rate limit: ${key} (${count}/${max} in ${windowSeconds}s)`
  );
  return res.status(429).json({
    error: "TOO_MANY_REQUESTS",
    message: "Too many requests. Please slow down and try again later.",
    retryAfter: windowSeconds,
  });
}

      next();
    } catch (err) {
      console.error("rateLimiter error:", err.message);
      next();
    }
  };
}

export const adminRateLimiter = createRateLimiter({
  windowSeconds: 15 * 60,
  max: 1000,
  prefix: "rl:admin",
  keyFn: (req) => {
    const ip = getClientIP(req);
    const adminKey = req.headers["x-admin-key"] || "none";
    return `${ip}:${adminKey}`;
  },
});

export const userRateLimiter = createRateLimiter({
  windowSeconds: 60 * 60,
  max: 1000,
  prefix: "rl:user",
  keyFn: (req) => {
    const ip = getClientIP(req);
    const username =
      req.params?.username || req.body?.username || "anonymous";
    return `${ip}:${username}`;
  },
});

export const loginRateLimiter = createRateLimiter({
  windowSeconds: 15 * 60,
  max: 10,
  prefix: "rl:login",
  keyFn: (req) => getClientIP(req),
});