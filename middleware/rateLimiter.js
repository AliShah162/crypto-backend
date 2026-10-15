// middleware/rateLimiter.js
import rateLimit from "express-rate-limit";

const getIP = (req) => {
  return req.headers["x-forwarded-for"]?.split(",")[0].trim() || req.ip;
};

export const adminRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: {
    error: "TOO_MANY_REQUESTS",
    message: "Too many admin requests. Please wait.",
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    const ip = getIP(req);
    const adminKey = req.headers["x-admin-key"] || "none";
    return `${ip}:${adminKey}`;
  },
  skip: (req) => {
    const trustedIPs = (process.env.TRUSTED_ADMIN_IPS || "")
      .split(",")
      .map((ip) => ip.trim())
      .filter(Boolean);
    if (trustedIPs.includes(getIP(req))) return true;
    if (["/health", "/ping", "/api/test"].includes(req.path)) return true;
    return false;
  },
});

export const userRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 1000,
  message: {
    error: "TOO_MANY_REQUESTS",
    message: "Too many requests. Please slow down.",
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    const ip = getIP(req);
    const username =
      req.params.username || req.body?.username || "anonymous";
    return `${ip}:${username}`;
  },
  skip: (req) => {
    if (["/health", "/ping", "/api/test"].includes(req.path)) return true;
    return false;
  },
});