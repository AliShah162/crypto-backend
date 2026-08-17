import rateLimit from 'express-rate-limit';
import { getCached, setCached } from '../lib/cache.js';

// ✅ Smart rate limiter that adapts to network conditions
export const adminRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per 15 minutes (generous for slow connections)
  message: { 
    error: "TOO_MANY_REQUESTS", 
    message: "Please wait a moment before making more admin requests." 
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    // Use IP + Admin Key as identifier
    const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.ip;
    const adminKey = req.headers['x-admin-key'] || 'none';
    return `${ip}:${adminKey}`;
  },
  skip: (req) => {
    // ✅ Allow localhost and trusted IPs
    const trustedIPs = (process.env.TRUSTED_ADMIN_IPS || '').split(',');
    const clientIP = req.headers['x-forwarded-for']?.split(',')[0] || req.ip;
    
    // ✅ Skip for trusted IPs
    if (trustedIPs.includes(clientIP)) return true;
    
    // ✅ Skip for health checks
    if (req.path === '/health' || req.path === '/ping' || req.path === '/api/test') return true;
    
    return false;
  }
});

// ✅ Different limiter for regular users (more generous)
export const userRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 1000, // 1000 requests per hour
  message: { 
    error: "TOO_MANY_REQUESTS", 
    message: "Too many requests. Please slow down." 
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.ip;
    const username = req.params.username || req.body.username || 'anonymous';
    return `${ip}:${username}`;
  },
  skip: (req) => {
    // Skip health checks
    if (req.path === '/health' || req.path === '/ping' || req.path === '/api/test') return true;
    return false;
  }
});