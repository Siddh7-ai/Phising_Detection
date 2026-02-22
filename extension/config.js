// Configuration - ML Only (No Whitelist)

const CONFIG = {
  // ✅ PRODUCTION: Render backend URL
  API_URL: 'https://phishguardai-nnez.onrender.com/api/scan',

  // Cache duration (15 minutes)
  CACHE_TTL_MS: 15 * 60 * 1000,

  // Request timeout
  REQUEST_TIMEOUT_MS: 10000,

  // ✅ No whitelist — every URL goes through ML model
  WHITELIST: []
};

export default CONFIG;