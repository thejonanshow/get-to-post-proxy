const express = require(‘express’);
const crypto = require(‘crypto’);

const app = express();
const PORT = process.env.PORT || 3000;

// Configuration from environment variables
const HMAC_SECRET = process.env.HMAC_SECRET;
const RATE_LIMIT_PER_MINUTE = parseInt(process.env.RATE_LIMIT_PER_MINUTE || ‘60’);

// In-memory rate limiting (resets on service restart)
const rateLimits = new Map();

// Middleware
app.use(express.json({ limit: ‘10mb’ }));

// CORS middleware
app.use((req, res, next) => {
res.header(‘Access-Control-Allow-Origin’, ‘*’);
res.header(‘Access-Control-Allow-Methods’, ‘GET, OPTIONS’);
res.header(‘Access-Control-Allow-Headers’, ‘Content-Type’);
if (req.method === ‘OPTIONS’) {
return res.status(200).end();
}
next();
});

// Rate limiting function
function checkRateLimit(identifier) {
const now = Date.now();
const minute = Math.floor(now / 60000);
const key = `${identifier}:${minute}`;

const current = rateLimits.get(key) || 0;

if (current >= RATE_LIMIT_PER_MINUTE) {
return { allowed: false, retryAfter: 60 - Math.floor((now % 60000) / 1000) };
}

rateLimits.set(key, current + 1);

// Cleanup old entries periodically
if (rateLimits.size > 10000) {
const oldKeys = Array.from(rateLimits.keys()).slice(0, 5000);
oldKeys.forEach(k => rateLimits.delete(k));
}

return { allowed: true };
}

// HMAC generation
function generateHmac(message, secret) {
return crypto.createHmac(‘sha256’, secret).update(message).digest(‘hex’);
}

// Constant-time comparison to prevent timing attacks
function constantTimeCompare(a, b) {
if (a.length !== b.length) return false;
let result = 0;
for (let i = 0; i < a.length; i++) {
result |= a.charCodeAt(i) ^ b.charCodeAt(i);
}
return result === 0;
}

// SSRF protection - block private IP ranges
function isPrivateIP(hostname) {
const privateRanges = [
/^127./,
/^10./,
/^172.(1[6-9]|2[0-9]|3[0-1])./,
/^192.168./,
/^169.254./,
/^::1$/,
/^fe80:/i,
/^fc00:/i,
/^fd00:/i
];
return privateRanges.some(range => range.test(hostname));
}

// Health check endpoint
app.get(’/health’, (req, res) => {
res.json({
status: ‘ok’,
timestamp: new Date().toISOString(),
hmacConfigured: !!HMAC_SECRET
});
});

// Main proxy endpoint
app.get(’/’, async (req, res) => {
try {
// Extract parameters
const targetUrl = req.query.url;
const method = (req.query.method || ‘POST’).toUpperCase();
const body = req.query.body || ‘’;
const hmac = req.query.hmac;

```
// Validate required parameters
if (!targetUrl) {
  return res.status(400).json({ error: 'Missing required parameter: url' });
}

if (!hmac) {
  return res.status(400).json({ error: 'Missing required parameter: hmac' });
}

// Validate HMAC_SECRET is configured
if (!HMAC_SECRET) {
  return res.status(500).json({ error: 'Server misconfigured: HMAC_SECRET not set' });
}

// Rate limiting
const clientIP = req.headers['x-forwarded-for']?.split(',')[0] || req.connection.remoteAddress;
const rateLimitCheck = checkRateLimit(clientIP);
if (!rateLimitCheck.allowed) {
  return res.status(429).json({
    error: 'Rate limit exceeded',
    retryAfter: rateLimitCheck.retryAfter
  });
}

// Parse URL for SSRF protection
let urlObj;
try {
  urlObj = new URL(targetUrl);
} catch (e) {
  return res.status(400).json({ error: 'Invalid target URL' });
}

// SSRF protection
if (urlObj.protocol !== 'https:' && urlObj.hostname !== 'localhost') {
  return res.status(400).json({ error: 'Only HTTPS URLs allowed (except localhost for testing)' });
}

if (isPrivateIP(urlObj.hostname)) {
  return res.status(403).json({ error: 'Private IP addresses are not allowed' });
}

// Extract headers from query parameters
const headers = {};
for (const [key, value] of Object.entries(req.query)) {
  if (key.startsWith('header_')) {
    const headerName = key.replace('header_', '');
    headers[headerName] = value;
  }
}

// Build HMAC message (must match client-side calculation)
const sortedHeaders = Object.keys(headers)
  .sort()
  .map(k => `${k}:${headers[k]}`)
  .join('|');

const messageToSign = `${targetUrl}${method}${body}${sortedHeaders}`;
const expectedHmac = generateHmac(messageToSign, HMAC_SECRET);

// Constant-time HMAC comparison
if (!constantTimeCompare(hmac, expectedHmac)) {
  return res.status(403).json({ error: 'Invalid HMAC signature' });
}

// Make the proxied request with timeout
const controller = new AbortController();
const timeout = setTimeout(() => controller.abort(), 30000); // 30 second timeout

try {
  const response = await fetch(targetUrl, {
    method: method,
    headers: {
      ...headers,
      'User-Agent': 'Omnibot-Proxy/1.0'
    },
    body: method !== 'GET' && method !== 'HEAD' && body ? body : undefined,
    signal: controller.signal
  });
  
  clearTimeout(timeout);
  
  // Get response body
  const responseText = await response.text();
  
  // Return proxied response
  res.status(response.status).json({
    success: response.ok,
    status: response.status,
    statusText: response.statusText,
    body: responseText,
    headers: Object.fromEntries(response.headers.entries())
  });
  
} catch (fetchError) {
  clearTimeout(timeout);
  
  if (fetchError.name === 'AbortError') {
    return res.status(504).json({ error: 'Request timeout (30s limit)' });
  }
  
  return res.status(502).json({
    error: 'Proxy request failed',
    details: fetchError.message
  });
}
```

} catch (error) {
console.error(‘Proxy error:’, error);
res.status(500).json({
error: ‘Internal server error’,
details: error.message
});
}
});

// Start server
app.listen(PORT, () => {
console.log(`Omnibot GET-to-POST Proxy listening on port ${PORT}`);
console.log(`Rate limit: ${RATE_LIMIT_PER_MINUTE} requests per minute`);
console.log(`HMAC Secret configured: ${HMAC_SECRET ? 'Yes ✓' : 'No ✗'}`);
});