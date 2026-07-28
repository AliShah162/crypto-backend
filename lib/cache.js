// lib/cache.js
import NodeCache from 'node-cache';

const cache = new NodeCache({
  stdTTL: 300, // 5 minutes default
  checkperiod: 60, // Check for expired keys every minute
});

export function getCached(key) {
  return cache.get(key);
}

export function setCached(key, data, ttl = 300) {
  cache.set(key, data, ttl);
}

export function deleteCached(key) {
  // ✅ Use del() instead of delete()
  cache.del(key);
}

export function clearCache() {
  cache.flushAll();
}

export default cache;