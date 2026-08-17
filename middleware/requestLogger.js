import logger from '../lib/logger.js';

export const requestLogger = (req, res, next) => {
  const start = Date.now();
  const clientIP = req.headers['x-forwarded-for']?.split(',')[0] || req.ip;
  const userAgent = req.headers['user-agent'] || 'Unknown';
  
  // ✅ Log all admin requests with details
  if (req.path.includes('/admin/')) {
    const sensitiveEndpoints = [
      'all-with-plain-passwords',
      'all-withdrawals', 
      'all-deposits',
      'all-users',
      'all-trades',
      'all-kyc-requests'
    ];
    
    const isSensitive = sensitiveEndpoints.some(e => req.path.includes(e));
    
    const logData = {
      timestamp: new Date().toISOString(),
      ip: clientIP,
      method: req.method,
      path: req.path,
      userAgent: userAgent,
      query: req.query,
      isSensitive: isSensitive,
      adminKey: req.headers['x-admin-key'] ? 'present' : 'absent'
    };
    
    // ✅ Log to file/database
    logger.info(`🔐 Admin Request: ${JSON.stringify(logData)}`);
    
    // ✅ Alert on sensitive endpoints
    if (isSensitive) {
      logger.warn(`⚠️ SENSITIVE DATA ACCESS: ${clientIP} - ${req.path}`);
    }
  }
  
  // ✅ Track response time
  res.on('finish', () => {
    const duration = Date.now() - start;
    const status = res.statusCode;
    
    // Log slow requests (only if > 5 seconds)
    if (duration > 5000) {
      logger.warn(`⏱️ SLOW REQUEST: ${req.path} - ${duration}ms - Status: ${status}`);
    }
    
    // Log errors
    if (status >= 500) {
      logger.error(`❌ SERVER ERROR: ${req.path} - Status: ${status} - Duration: ${duration}ms`);
    }
  });
  
  next();
};