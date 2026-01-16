/**
 * HalfCourse Vendor API v2 – OAuth (Stabilized + Vendor-Safe)
 */

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const multer = require('multer');
const crypto = require('crypto');
const fetch = require('node-fetch');

const app = express();
const upload = multer({ storage: multer.memoryStorage() });

// ================= CONFIG =================

const SHOPIFY_CLIENT_ID = process.env.SHOPIFY_CLIENT_ID;
const SHOPIFY_CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET;
const SHOPIFY_STORE = process.env.SHOPIFY_STORE?.trim(); // optional fallback: 0ugisc-62.myshopify.com
const SHOPIFY_SCOPES =
  process.env.SHOPIFY_SCOPES ||
  'read_products,write_products,read_metafields,write_metafields,read_collections';
const APP_URL = process.env.APP_URL;
const API_VERSION = '2024-01';

// ⚠️ In-memory token store (replace with DB / Redis later)
const accessTokens = {};

// ================= MIDDLEWARE =================

app.use(
  cors({
    origin: [
      'https://halfcourse.com',
      'https://www.halfcourse.com',
      /\.myshopify\.com$/,
    ],
    credentials: true,
  })
);

app.use(express.json());

// ================= VENDOR MAP =================

const VENDOR_MAP = {
  liandros: "Liandro's",
};

function getVendorName(handle) {
  return VENDOR_MAP[handle] || handle;
}

// ================= VENDOR AUTH =================

// Simple vendor credential store (replace later if needed)
const VENDOR_CREDENTIALS = {
  liandros: {
    password: process.env.VENDOR_LIANDROS_PASSWORD || 'halfcourse2024',
  },
};

// In-memory vendor sessions
const vendorSessions = {};

// ================= HELPERS =================

function normalizeShop(shop) {
  return shop?.trim().toLowerCase();
}

/**
 * Returns the currently connected shop.
 * (Single-store app assumption — fine for HalfCourse)
 */
function getActiveShop() {
  return Object.keys(accessTokens)[0] || null;
}

function getAccessToken() {
  const shop = getActiveShop();
  return shop ? accessTokens[shop] : null;
}

function getShopifyHeaders(shop) {
  const token = accessTokens[shop];
  if (!token) throw new Error('No access token');
  return {
    'Content-Type': 'application/json',
    'X-Shopify-Access-Token': token,
  };
}

function getBaseUrl(shop) {
  return `https://${shop}/admin/api/${API_VERSION}`;
}

// ================= OAUTH =================

// Start OAuth
app.get('/auth', (req, res) => {
  // For real installs Shopify will pass ?shop=...
  // For manual testing you can omit it if SHOPIFY_STORE is set.
  const shop = req.query.shop || SHOPIFY_STORE;

  if (!shop) {
    return res.status(400).send('Missing shop parameter');
  }

  const normalizedShop = normalizeShop(shop);
  const state = crypto.randomBytes(16).toString('hex');
  const redirectUri = `${APP_URL}/auth/callback`;

  const authUrl =
    `https://${normalizedShop}/admin/oauth/authorize` +
    `?client_id=${SHOPIFY_CLIENT_ID}` +
    `&scope=${encodeURIComponent(SHOPIFY_SCOPES)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=${state}`;

  res.redirect(authUrl);
});

// OAuth callback
app.get('/auth/callback', async (req, res) => {
  const { code, shop } = req.query;

  if (!code || !shop) {
    return res.status(400).send('Missing OAuth parameters');
  }

  const normalizedShop = normalizeShop(shop);

  try {
    const response = await fetch(
      `https://${normalizedShop}/admin/oauth/access_token`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_id: SHOPIFY_CLIENT_ID,
          client_secret: SHOPIFY_CLIENT_SECRET,
          code,
        }),
      }
    );

    const data = await response.json();

    if (!data.access_token) {
      console.error('OAuth token error:', data);
      throw new Error(data.error || 'No access token returned');
    }

    // ✅ Store token under normalized shop domain
    accessTokens[normalizedShop] = data.access_token;

    console.log('✅ Shopify connected:', normalizedShop);
    console.log('🔐 Connected shops:', Object.keys(accessTokens));

    res.send(`
      <html>
        <body style="font-family:sans-serif;text-align:center;padding:50px;">
          <h1>✅ Connected!</h1>
          <p>Your store is now connected.</p>
          <p>You can close this window.</p>
        </body>
      </html>
    `);
  } catch (err) {
    console.error('OAuth error:', err);
    res.status(500).send('OAuth failed');
  }
});

// ================= VENDOR LOGIN =================

app.post('/api/vendor/login', (req, res) => {
  const { handle, password } = req.body;

  if (!handle || !password) {
    return res.status(400).json({ error: 'Missing credentials' });
  }

  const vendor = VENDOR_CREDENTIALS[handle];

  if (!vendor || vendor.password !== password) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Create simple session token
  const token = crypto.randomBytes(24).toString('hex');

  vendorSessions[token] = {
    handle,
    createdAt: Date.now(),
  };

  res.json({
    token,
    handle,
  });
});

// ================= AUTH MIDDLEWARE =================

function requireAuth(req, res, next) {
  const shop = getActiveShop();
  const token = getAccessToken();

  if (!shop || !token) {
    return res.status(401).json({
      error: 'Not authenticated (Shopify not connected)',
      authUrl: `${APP_URL}/auth${SHOPIFY_STORE ? '' : '?shop=YOURSHOP.myshopify.com'}`,
    });
  }

  req.shop = shop;
  req.accessToken = token;
  next();
}

// ================= VENDOR AUTH MIDDLEWARE =================

function requireVendor(req, res, next) {
  const auth = req.headers.authorization;

  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing vendor token' });
  }

  const token = auth.replace('Bearer ', '');
  const session = vendorSessions[token];

  if (!session) {
    return res.status(401).json({ error: 'Invalid vendor token' });
  }

  req.vendorHandle = session.handle;
  next();
}

// ================= API =================

// Health / debug
app.get('/health', (req, res) => {
  const connectedShops = Object.keys(accessTokens);

  res.json({
    status: 'ok',
    authenticated: connectedShops.length > 0,
    connectedShops,
    vendorSessions: Object.keys(vendorSessions).length, // just a count
    timestamp: new Date().toISOString(),
  });
});

// ✅ Vendor products (LOCKED to logged-in vendor)
app.get(
  '/api/vendors/:handle/products',
  requireVendor,
  async (req, res) => {
  const requestedHandle = req.params.handle;

  // Prevent a vendor from accessing another vendor's products
  if (requestedHandle !== req.vendorHandle) {
    return res.status(403).json({ error: 'Forbidden: vendor mismatch' });
  }

  const vendorName = getVendorName(req.vendorHandle);

  try {
    const response = await fetch(
      `${getBaseUrl(req.shop)}/products.json?vendor=${encodeURIComponent(vendorName)}&limit=250`,
      { headers: getShopifyHeaders(req.shop) }
    );

    const data = await response.json();
    res.json(data.products || []);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

// ================= UI =================

app.get('/', (req, res) => {
  const connected = !!getAccessToken();

  res.send(`
    <html>
      <head><title>HalfCourse Vendor API</title></head>
      <body style="font-family:sans-serif;text-align:center;padding:50px;">
        <h1>HalfCourse Vendor API</h1>
        ${
          connected
            ? '<p style="color:green;">✅ Connected to Shopify</p>'
            : `<p style="color:orange;">⚠️ Not connected</p>
               <p>Install the app via the Shopify Partner Dashboard (or visit /auth?shop=YOURSHOP.myshopify.com)</p>`
        }
      </body>
    </html>
  `);
});

// ================= START =================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 HalfCourse Vendor API running on port ${PORT}`);
});

module.exports = app;
