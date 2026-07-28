// lib/cache.js
import NodeCache from 'node-cache';

const cache = new NodeCache({
  stdTTL: 300,
  checkperiod: 60,
});

export function getCached(key) {
  return cache.get(key);
}

export function setCached(key, data, ttl = 300) {
  cache.set(key, data, ttl);
}

export function deleteCached(key) {
  cache.delete(key);
}

export function clearCache() {
  cache.flushAll();
}

export default cache;