// Universal GET-to-POST Proxy - Railway.app Version
// Express.js server that translates GET requests to POST/PUT/DELETE/PATCH

import express from 'express';
import crypto from 'crypto';
import zlib from 'zlib';

const app = express();
const PORT = process.env.PORT || 3000;

// Rate limiting state (in-memory)
const rateLimits = new Map();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'get-to-post-proxy' });
});

// Main proxy endpoint
app.get('/proxy', async (req, res) => {
  try {
    // Rate limiting
    const clientIp = req.ip || req.connection.remoteAddress;
    const rateLimitResult = checkRateLimit(clientIp);
    
    if (!rateLimitResult.allowed) {
      return res.status(429).json({
        error: 'Rate limit exceeded',
        retryAfter: rateLimitResult.retryAfter
      });
    }

    // Extract parameters
    const {
      url: targetUrl,
      method = 'POST',
      body,
      hmac,
      compressed,
      ...queryParams
    } = req.query;

    // Validate required params
    if (!targetUrl || !hmac) {
      return res.status(400).json({
        error: 'Missing required parameters',
        required: ['url', 'hmac'],
        optional: ['method', 'body', 'header_*']
      });
    }

    // Validate URL
    if (!isValidUrl(targetUrl)) {
      return res.status(400).json({
        error: 'Invalid target URL',
        hint: 'Must be HTTPS and not a private IP'
      });
    }

    // Extract headers from query params
    const headers = {};
    for (const [key, value] of Object.entries(queryParams)) {
      if (key.startsWith('header_')) {
        const headerName = key
          .replace('header_', '')
          .split('_')
          .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
          .join('-');
        headers[headerName] = value;
      }
    }

    // Ensure Content-Type for requests with body
    if (body && !headers['Content-Type']) {
      headers['Content-Type'] = 'application/json';
    }

    // Validate HMAC
    const isValidHmac = validateHmac(
      { targetUrl, method, body, headers },
      hmac,
      process.env.HMAC_SECRET
    );

    if (!isValidHmac) {
      return res.status(403).json({
        error: 'Invalid HMAC signature',
        hint: 'HMAC = HMAC-SHA256(url + method + body + sorted_headers, secret)'
      });
    }

    // Decompress body if needed
    let requestBody = body;
    if (compressed === 'true' && requestBody) {
      try {
        requestBody = decompressBody(requestBody);
      } catch (error) {
        return res.status(400).json({
          error: 'Decompression failed',
          message: error.message
        });
      }
    }

    // Make the proxied request
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30000);

    try {
      const response = await fetch(targetUrl, {
        method: method.toUpperCase(),
        headers: headers,
        body: requestBody,
        signal: controller.signal
      });

      clearTimeout(timeout);

      const responseText = await response.text();

      // Return proxied response
      res.status(response.status)
        .set('Content-Type', response.headers.get('Content-Type') || 'application/json')
        .set('X-Proxy-Status', 'success')
        .set('X-Original-Status', response.status.toString())
        .send(responseText);

    } catch (fetchError) {
      clearTimeout(timeout);
      
      if (fetchError.name === 'AbortError') {
        return res.status(504).json({
          error: 'Request timeout',
          message: 'Target API took longer than 30 seconds'
        });
      }
      
      throw fetchError;
    }

  } catch (error) {
    console.error('Proxy error:', error);
    res.status(500).json({
      error: 'Proxy request failed',
      message: error.message,
      type: error.name
    });
  }
});

// Rate limiting function
function checkRateLimit(clientId) {
  const limit = parseInt(process.env.RATE_LIMIT_PER_MINUTE || '60');
  const now = Date.now();
  const windowMs = 60000; // 1 minute

  const record = rateLimits.get(clientId) || {
    count: 0,
    resetAt: now + windowMs
  };

  if (now > record.resetAt) {
    record.count = 1;
    record.resetAt = now + windowMs;
  } else {
    record.count++;
  }

  rateLimits.set(clientId, record);

  // Cleanup old records every 100 requests
  if (Math.random() < 0.01) {
    for (const [key, value] of rateLimits.entries()) {
      if (now > value.resetAt + windowMs) {
        rateLimits.delete(key);
      }
    }
  }

  if (record.count > limit) {
    return {
      allowed: false,
      retryAfter: Math.ceil((record.resetAt - now) / 1000)
    };
  }

  return { allowed: true };
}

// Validate HMAC
function validateHmac(params, receivedHmac, secret) {
  if (!secret) {
    throw new Error('HMAC_SECRET not configured');
  }

  // Build message: url + method + body + sorted headers
  const headerString = Object.keys(params.headers)
    .sort()
    .map(key => `${key}:${params.headers[key]}`)
    .join('|');

  const message = `${params.targetUrl}${params.method}${params.body || ''}${headerString}`;

  // Generate HMAC
  const hmac = crypto
    .createHmac('sha256', secret)
    .update(message)
    .digest('hex');

  // Constant-time comparison
  return crypto.timingSafeEqual(
    Buffer.from(receivedHmac),
    Buffer.from(hmac)
  );
}

// Decompress base64-encoded gzipped body
function decompressBody(compressedBase64) {
  const compressed = Buffer.from(compressedBase64, 'base64');
  return zlib.gunzipSync(compressed).toString('utf8');
}

// Validate URL
function isValidUrl(urlString) {
  try {
    const url = new URL(urlString);

    // Only allow HTTPS
    if (url.protocol !== 'https:') {
      return false;
    }

    // Block private IPs (SSRF protection)
    const hostname = url.hostname;
    const privatePatterns = [
      /^localhost$/i,
      /^127\./,
      /^192\.168\./,
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
      /^0\.0\.0\.0$/,
      /^::1$/
    ];

    for (const pattern of privatePatterns) {
      if (pattern.test(hostname)) {
        return false;
      }
    }

    return true;
  } catch {
    return false;
  }
}

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 GET-to-POST Proxy running on port ${PORT}`);
  console.log(`📝 Health check: http://localhost:${PORT}/health`);
  console.log(`🔐 HMAC validation: ${process.env.HMAC_SECRET ? 'ENABLED' : 'DISABLED'}`);
});
