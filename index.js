const express = require('express');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

const HMAC_SECRET = process.env.HMAC_SECRET;
const RATE_LIMIT_PER_MINUTE = parseInt(process.env.RATE_LIMIT_PER_MINUTE || '60');

const rateLimits = new Map();
const multipartStore = new Map(); // Stores multi-part request data

app.use(express.json({ limit: '10mb' }));

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  next();
});

function checkRateLimit(identifier) {
  const now = Date.now();
  const minute = Math.floor(now / 60000);
  const key = `${identifier}:${minute}`;
  const current = rateLimits.get(key) || 0;
  if (current >= RATE_LIMIT_PER_MINUTE) {
    return { allowed: false, retryAfter: 60 - Math.floor((now % 60000) / 1000) };
  }
  rateLimits.set(key, current + 1);
  if (rateLimits.size > 10000) {
    const oldKeys = Array.from(rateLimits.keys()).slice(0, 5000);
    oldKeys.forEach(k => rateLimits.delete(k));
  }
  return { allowed: true };
}

function generateHmac(message, secret) {
  return crypto.createHmac('sha256', secret).update(message).digest('hex');
}

function constantTimeCompare(a, b) {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

function isPrivateIP(hostname) {
  const privateRanges = [
    /^127\./, /^10\./, /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
    /^192\.168\./, /^169\.254\./, /^::1$/, /^fe80:/i, /^fc00:/i, /^fd00:/i
  ];
  return privateRanges.some(range => range.test(hostname));
}

// Cleanup old multipart data every minute
setInterval(() => {
  const now = Date.now();
  for (const [key, data] of multipartStore.entries()) {
    if (now - data.timestamp > 300000) { // 5 minutes
      multipartStore.delete(key);
    }
  }
}, 60000);

app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    hmacConfigured: !!HMAC_SECRET,
    multipartSupport: true
  });
});

app.get('/', async (req, res) => {
  try {
    // Check for multi-part request
    const partId = req.query.part_id;
    const partNum = parseInt(req.query.part_num);
    const partTotal = parseInt(req.query.part_total);
    const partData = req.query.part_data;

    if (partId && partNum && partTotal) {
      // Multi-part request handling
      if (!multipartStore.has(partId)) {
        multipartStore.set(partId, {
          parts: new Array(partTotal),
          totalParts: partTotal,
          timestamp: Date.now()
        });
      }

      const store = multipartStore.get(partId);
      store.parts[partNum - 1] = partData;

      // Check if we have all parts
      const allPartsReceived = store.parts.every(p => p !== undefined);

      if (!allPartsReceived) {
        return res.json({
          success: true,
          message: `Part ${partNum}/${partTotal} received`,
          partsReceived: store.parts.filter(p => p !== undefined).length,
          totalParts: partTotal
        });
      }

      // All parts received - assemble and process
      const assembledBody = store.parts.join('');
      multipartStore.delete(partId);

      // Now process as normal request with assembled body
      req.query.body = assembledBody;
    }

    // Normal proxy logic from here
    const targetUrl = req.query.url;
    const method = (req.query.method || 'POST').toUpperCase();
    const body = req.query.body || '';
    const hmac = req.query.hmac;
    
    if (!targetUrl) {
      return res.status(400).json({ error: 'Missing required parameter: url' });
    }
    
    if (!hmac) {
      return res.status(400).json({ error: 'Missing required parameter: hmac' });
    }
    
    if (!HMAC_SECRET) {
      return res.status(500).json({ error: 'Server misconfigured: HMAC_SECRET not set' });
    }
    
    const clientIP = req.headers['x-forwarded-for']?.split(',')[0] || req.connection.remoteAddress;
    const rateLimitCheck = checkRateLimit(clientIP);
    if (!rateLimitCheck.allowed) {
      return res.status(429).json({
        error: 'Rate limit exceeded',
        retryAfter: rateLimitCheck.retryAfter
      });
    }
    
    let urlObj;
    try {
      urlObj = new URL(targetUrl);
    } catch (e) {
      return res.status(400).json({ error: 'Invalid target URL' });
    }
    
    if (urlObj.protocol !== 'https:' && urlObj.hostname !== 'localhost') {
      return res.status(400).json({ error: 'Only HTTPS URLs allowed' });
    }
    
    if (isPrivateIP(urlObj.hostname)) {
      return res.status(403).json({ error: 'Private IP addresses not allowed' });
    }
    
    const headers = {};
    for (const [key, value] of Object.entries(req.query)) {
      if (key.startsWith('header_')) {
        const headerName = key.replace('header_', '');
        headers[headerName] = value;
      }
    }
    
    const sortedHeaders = Object.keys(headers)
      .sort()
      .map(k => `${k}:${headers[k]}`)
      .join('|');
    
    const messageToSign = `${targetUrl}${method}${body}${sortedHeaders}`;
    const expectedHmac = generateHmac(messageToSign, HMAC_SECRET);
    
    if (!constantTimeCompare(hmac, expectedHmac)) {
      return res.status(403).json({ error: 'Invalid HMAC signature' });
    }
    
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30000);
    
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
      
      const responseText = await response.text();
      
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
        return res.status(504).json({ error: 'Request timeout' });
      }
      
      return res.status(502).json({
        error: 'Proxy request failed',
        details: fetchError.message
      });
    }
    
  } catch (error) {
    console.error('Proxy error:', error);
    res.status(500).json({
      error: 'Internal server error',
      details: error.message
    });
  }
});

app.listen(PORT, () => {
  console.log(`Omnibot proxy on port ${PORT}`);
  console.log(`Rate limit: ${RATE_LIMIT_PER_MINUTE}/min`);
  console.log(`HMAC: ${HMAC_SECRET ? 'configured' : 'missing'}`);
  console.log(`Multi-part: enabled`);
});
