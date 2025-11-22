const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const HMAC_SECRET = process.env.HMAC_SECRET;
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const RATE_LIMIT_PER_MINUTE = parseInt(process.env.RATE_LIMIT_PER_MINUTE || '60');

const rateLimits = new Map();
const sessions = new Map();

app.use(express.json({ limit: '10mb' }));
app.use((req, res, next) => {
res.header('Access-Control-Allow-Origin', '*');
res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
res.header('Access-Control-Allow-Headers', 'Content-Type');
if (req.method === 'OPTIONS') return res.status(200).end();
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
// Clean up expired entries (older than 2 minutes)
if (rateLimits.size > 10000) {
for (const [k] of rateLimits.entries()) {
  const [, keyMinute] = k.split(':');
  if (minute - parseInt(keyMinute) > 1) {
    rateLimits.delete(k);
  }
}
}
return { allowed: true };
}

function generateHmac(message, secret) {
return crypto.createHmac('sha256', secret).update(message).digest('hex');
}

function constantTimeCompare(a, b) {
if (a.length !== b.length) return false;
let result = 0;
for (let i = 0; i < a.length; i++) result |= a.charCodeAt(i) ^ b.charCodeAt(i);
return result === 0;
}

function isPrivateIP(hostname) {
return [/^127./, /^10./, /^172.(1[6-9]|2[0-9]|3[0-1])./, /^192.168./, /^169.254./, /^::1$/, /^fe80:/i, /^fc00:/i, /^fd00:/i]
.some(range => range.test(hostname));
}

setInterval(() => {
const now = Date.now();
for (const [key, data] of sessions.entries()) {
if (now - data.timestamp > 300000) sessions.delete(key);
}
}, 60000);

app.get('/health', (req, res) => {
res.json({
status: 'ok',
timestamp: new Date().toISOString(),
hmacConfigured: !!HMAC_SECRET,
githubConfigured: !!GITHUB_TOKEN
});
});

app.get('/s', (req, res) => {
if (!req.query.u) {
return res.status(400).json({ error: 'Missing URL parameter (u)' });
}

const sid = Date.now().toString(36);
sessions.set(sid, {
url: req.query.u,
method: req.query.m,
headers: {},
timestamp: Date.now()
});

Object.keys(req.query).forEach(k => {
if (k.startsWith('h')) {
const idx = k.substring(1);
sessions.get(sid).headers[`h${idx}`] = req.query[k];
}
});

res.json({ sid, expires: '5min' });
});

app.get('/x', async (req, res) => {
const sid = req.query.s;
const body = req.query.b || '';
const hmac = req.query.h;

if (!sid) {
return res.status(400).json({ error: 'Missing session ID parameter (s)' });
}

if (!hmac) {
return res.status(400).json({ error: 'Missing HMAC parameter (h)' });
}

if (!sessions.has(sid)) {
return res.status(404).json({ error: 'Session expired or invalid' });
}

const config = sessions.get(sid);
const targetUrl = config.url;
const method = config.method || 'POST';

const headers = {};
Object.keys(config.headers).forEach(k => {
const name = k === 'h1' ? 'Authorization' : k === 'h2' ? 'Content-Type' : k;
headers[name] = config.headers[k];
});

// Auto-inject GitHub token for GitHub API requests
if (GITHUB_TOKEN && targetUrl.includes('api.github.com')) {
headers['Authorization'] = `Bearer ${GITHUB_TOKEN}`;
headers['Accept'] = headers['Accept'] || 'application/vnd.github+json';
headers['X-GitHub-Api-Version'] = headers['X-GitHub-Api-Version'] || '2022-11-28';
}

if (!HMAC_SECRET) return res.status(500).json({ error: 'HMAC not configured' });

const sortedHeaders = Object.keys(headers).sort().map(k => `${k}:${headers[k]}`).join('|');
const messageToSign = `${targetUrl}${method}${body}${sortedHeaders}`;
const expectedHmac = generateHmac(messageToSign, HMAC_SECRET);

if (!constantTimeCompare(hmac, expectedHmac)) {
return res.status(403).json({ error: 'Invalid HMAC' });
}

sessions.delete(sid);

const clientIP = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;
const rateCheck = checkRateLimit(clientIP);
if (!rateCheck.allowed) {
return res.status(429).json({ error: 'Rate limit exceeded', retryAfter: rateCheck.retryAfter });
}

let urlObj;
try {
urlObj = new URL(targetUrl);
} catch (e) {
return res.status(400).json({ error: 'Invalid URL' });
}

if (urlObj.protocol !== 'https:' && urlObj.hostname !== 'localhost') {
return res.status(400).json({ error: 'HTTPS only' });
}

if (isPrivateIP(urlObj.hostname)) {
return res.status(403).json({ error: 'Private IP blocked' });
}

const controller = new AbortController();
const timeout = setTimeout(() => controller.abort(), 30000);

try {
const response = await fetch(targetUrl, {
method,
headers: { ...headers, 'User-Agent': 'Omnibot-Proxy/1.0' },
body: method !== 'GET' && method !== 'HEAD' && body ? body : undefined,
signal: controller.signal
});

clearTimeout(timeout);
const responseText = await response.text();

res.status(response.status).json({
  success: response.ok,
  status: response.status,
  body: responseText
});

} catch (fetchError) {
clearTimeout(timeout);
if (fetchError.name === 'AbortError') return res.status(504).json({ error: 'Timeout' });
return res.status(502).json({ error: 'Proxy failed', details: fetchError.message });
}
});

app.get('/', (req, res) => {
if (Object.keys(req.query).length === 0) {
const indexPath = path.join(__dirname, 'index.html');
if (fs.existsSync(indexPath)) {
return res.sendFile(indexPath);
}
return res.status(404).send('index.html not found');
}
return res.status(400).json({ error: 'Use /s and /x endpoints for proxy requests' });
});

app.listen(PORT, () => {
console.log(`Proxy on ${PORT}`);
console.log(`GitHub: ${GITHUB_TOKEN ? 'configured' : 'missing'}`);
});