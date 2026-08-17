import { getCached, setCached } from '../lib/cache.js';
import User from '../models/User.js';

export const autoBlocker = async (req, res, next) => {
  const clientIP = req.headers['x-forwarded-for']?.split(',')[0] || req.ip;
  
  // ✅ Skip if already blocked
  if (getCached(`blocked_${clientIP}`)) {
    return res.status(403).json({ 
      error: "ACCESS_DENIED", 
      message: "Your IP has been temporarily blocked." 
    });
  }
  
  // ✅ Skip health checks
  if (req.path === '/health' || req.path === '/ping' || req.path === '/api/test') {
    return next();
  }
  
  // ✅ Track request count
  const key = `requests_${clientIP}`;
  const requests = getCached(key) || { count: 0, firstSeen: Date.now() };
  
  requests.count++;
  
  // ✅ If > 100 requests in 5 minutes on admin endpoints
  if (req.path.includes('/admin/')) {
    if (requests.count > 100) {
      // Auto-block
      setCached(`blocked_${clientIP}`, true, 3600);
      console.log(`🔴 Auto-blocked IP: ${clientIP} (${requests.count} requests)`);
      
      // Log to database
      try {
        const masterAdmin = await User.findOne({ username: "master_admin" });
        if (masterAdmin) {
          masterAdmin.kickedSessions = masterAdmin.kickedSessions || [];
          masterAdmin.kickedSessions.push({
            ip: clientIP,
            kickedAt: new Date(),
            reason: `Auto-blocked: ${requests.count} admin requests in 5 minutes`,
            action: "auto_block"
          });
          await masterAdmin.save();
        }
      } catch (err) {
        console.error("Failed to log auto-block:", err);
      }
      
      return res.status(403).json({ 
        error: "ACCESS_DENIED", 
        message: "Too many requests. Please try again later." 
      });
    }
    
    setCached(key, requests, 300); // Reset after 5 minutes
  } else {
    // For non-admin, higher limit
    if (requests.count > 500) {
      setCached(`blocked_${clientIP}`, true, 1800);
      console.log(`🔴 Auto-blocked IP (non-admin): ${clientIP} (${requests.count} requests)`);
      return res.status(403).json({ 
        error: "ACCESS_DENIED", 
        message: "Too many requests. Please try again later." 
      });
    }
    setCached(key, requests, 600); // Reset after 10 minutes
  }
  
  next();
};