// lib/cache.js
import { kv } from "@vercel/kv";
import NodeCache from "node-cache";

// ✅ Local fallback for development (no KV locally)
const localCache = new NodeCache({
  stdTTL: 300,
  checkperiod: 60,
});

// ✅ Detect if KV is configured (production on Vercel)
const KV_ENABLED =
  !!process.env.KV_REST_API_URL && !!process.env.KV_REST_API_TOKEN;

if (!KV_ENABLED) {
  console.log("⚠️ Vercel KV not configured — using in-memory cache (dev only)");
} else {
  console.log("✅ Vercel KV cache enabled");
}

export async function getCached(key) {
  try {
    if (KV_ENABLED) {
      return await kv.get(key);
    }
    return localCache.get(key);
  } catch (err) {
    console.error("Cache GET error:", err.message);
    return null;
  }
}

export async function setCached(key, data, ttl = 300) {
  try {
    if (KV_ENABLED) {
      await kv.set(key, data, { ex: ttl });
      return;
    }
    localCache.set(key, data, ttl);
  } catch (err) {
    console.error("Cache SET error:", err.message);
  }
}

export async function deleteCached(key) {
  try {
    if (KV_ENABLED) {
      await kv.del(key);
      return;
    }
    localCache.del(key);
  } catch (err) {
    console.error("Cache DEL error:", err.message);
  }
}

export async function clearCache() {
  try {
    if (KV_ENABLED) {
      console.warn("clearCache() called but KV does not support flushAll");
      return;
    }
    localCache.flushAll();
  } catch (err) {
    console.error("Cache CLEAR error:", err.message);
  }
}

// ✅ Atomic increment — CRITICAL for accurate rate limiting
export async function incrementCached(key, ttl = 300) {
  try {
    if (KV_ENABLED) {
      const count = await kv.incr(key);
      if (count === 1) {
        await kv.expire(key, ttl);
      }
      return count;
    }
    const existing = localCache.get(key) || 0;
    const next = existing + 1;
    localCache.set(key, next, ttl);
    return next;
  } catch (err) {
    console.error("Cache INCR error:", err.message);
    return 0;
  }
}

export default localCache;