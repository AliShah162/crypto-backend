import { getCached, setCached } from '../lib/cache.js';

// ✅ Blocked IPs (can be updated dynamically)
const BLOCKED_IPS = (process.env.BLOCKED_IPS || '182.176.117.109').split(',');

// ✅ Trusted IPs (bypass all restrictions)
const TRUSTED_IPS = (process.env.TRUSTED_ADMIN_IPS || '').split(',');

export const ipBlocker = (req, res, next) => {
  const clientIP = req.headers['x-forwarded-for']?.split(',')[0] || req.ip;
  
  // ✅ Check cache first for performance
  const isBlocked = getCached(`blocked_${clientIP}`);
  if (isBlocked === true) {
    console.log(`🚫 Blocked request from ${clientIP}`);
    return res.status(403).json({ 
      error: "ACCESS_DENIED", 
      message: "Your IP has been blocked." 
    });
  }
  
  // Check static block list
  if (BLOCKED_IPS.includes(clientIP)) {
    setCached(`blocked_${clientIP}`, true, 3600); // Cache for 1 hour
    console.log(`🚫 Blocked request from ${clientIP}`);
    return res.status(403).json({ 
      error: "ACCESS_DENIED", 
      message: "Your IP has been blocked." 
    });
  }
  
  // ✅ For ADMIN routes only, check whitelist
  if (req.path.includes('/admin/')) {
    // In production, enforce whitelist
    if (process.env.NODE_ENV === 'production' && TRUSTED_IPS.length > 0) {
      // ✅ Allow if IP matches OR if it's a health check
      if (!TRUSTED_IPS.includes(clientIP)) {
        console.log(`🚫 Admin access denied for IP: ${clientIP}`);
        return res.status(403).json({ 
          error: "UNAUTHORIZED_IP", 
          message: "Admin access restricted. Please contact support." 
        });
      }
    }
  }
  
  next();
};