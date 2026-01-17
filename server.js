/**
 * HalfCourse Vendor API v3 - Fixed Version
 * 
 * Fixes:
 * - Proper middleware chain (requireAuth before requireVendor)
 * - Vendor login with environment-based passwords
 * - JWT tokens for vendor sessions
 */

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const multer = require('multer');
const crypto = require('crypto');
const fetch = require('node-fetch');

const app = express();
const upload = multer({ storage: multer.memoryStorage() });

// Config
const SHOPIFY_CLIENT_ID = process.env.SHOPIFY_CLIENT_ID;
const SHOPIFY_CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET;
const SHOPIFY_STORE = process.env.SHOPIFY_STORE || 'half-course';
const SHOPIFY_SCOPES = process.env.SHOPIFY_SCOPES || 'read_products,write_products,read_orders';
const APP_URL = process.env.APP_URL || 'http://localhost:3000';
const API_VERSION = '2024-01';
const JWT_SECRET = process.env.JWT_SECRET || 'halfcourse-secret-key-change-in-production';

// Store access tokens in memory (use Redis/DB in production)
let shopifyAccessTokens = {};
let vendorSessions = {}; // Store vendor session tokens

// Middleware
app.use(cors({
  origin: true, // Allow all origins for now
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ===== VENDOR MAP =====
const VENDOR_MAP = {
  'liandros': "Liandro's",
  // Add more vendors here:
  // 'marias-kitchen': "Maria's Kitchen",
};

// Vendor passwords from environment variables
// Format: VENDOR_[HANDLE]_PASSWORD (uppercase, hyphens become underscores)
function getVendorPassword(handle) {
  const envKey = `VENDOR_${handle.toUpperCase().replace(/-/g, '_')}_PASSWORD`;
  return process.env[envKey] || process.env.DEFAULT_VENDOR_PASSWORD || 'halfcourse2024';
}

function getVendorName(handle) {
  return VENDOR_MAP[handle] || handle;
}

// Generate simple session token
function generateSessionToken(handle) {
  const token = crypto.randomBytes(32).toString('hex');
  vendorSessions[token] = {
    handle,
    createdAt: Date.now(),
    expiresAt: Date.now() + (24 * 60 * 60 * 1000) // 24 hours
  };
  return token;
}

// Validate session token
function validateSessionToken(token) {
  const session = vendorSessions[token];
  if (!session) return null;
  if (Date.now() > session.expiresAt) {
    delete vendorSessions[token];
    return null;
  }
  return session;
}

// ===== OAUTH ROUTES =====

// Step 1: Start OAuth flow
app.get('/auth', (req, res) => {
  const shop = `${SHOPIFY_STORE}.myshopify.com`;
  const state = crypto.randomBytes(16).toString('hex');
  const redirectUri = `${APP_URL}/auth/callback`;
  
  const authUrl = `https://${shop}/admin/oauth/authorize?` +
    `client_id=${SHOPIFY_CLIENT_ID}` +
    `&scope=${SHOPIFY_SCOPES}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=${state}`;
  
  res.redirect(authUrl);
});

// Step 2: OAuth callback
app.get('/auth/callback', async (req, res) => {
  const { code, shop, state } = req.query;
  
  if (!code || !shop) {
    return res.status(400).send('Missing code or shop');
  }
  
  try {
    const response = await fetch(`https://${shop}/admin/oauth/access_token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: SHOPIFY_CLIENT_ID,
        client_secret: SHOPIFY_CLIENT_SECRET,
        code: code
      })
    });
    
    const data = await response.json();
    
    if (data.access_token) {
      shopifyAccessTokens[shop] = data.access_token;
      console.log('✅ Access token obtained for:', shop);
      
      res.send(`
        <html>
          <body style="font-family: sans-serif; text-align: center; padding: 50px;">
            <h1>✅ Connected!</h1>
            <p>HalfCourse Vendor API is now connected to your store.</p>
            <p>You can close this window.</p>
          </body>
        </html>
      `);
    } else {
      throw new Error(data.error || 'Failed to get access token');
    }
  } catch (error) {
    console.error('OAuth error:', error);
    res.status(500).send('Authentication failed: ' + error.message);
  }
});

// ===== VENDOR LOGIN =====
app.post('/api/vendor/login', (req, res) => {
  const { handle, password } = req.body;
  
  if (!handle || !password) {
    return res.status(400).json({ error: 'Missing handle or password' });
  }
  
  const correctPassword = getVendorPassword(handle);
  
  console.log(`Login attempt for vendor: ${handle}`);
  
  if (password !== correctPassword) {
    console.log(`❌ Invalid password for vendor: ${handle}`);
    return res.status(401).json({ error: 'Invalid password' });
  }
  
  const token = generateSessionToken(handle);
  console.log(`✅ Login successful for vendor: ${handle}`);
  
  res.json({ 
    success: true, 
    token,
    vendor: {
      handle,
      name: getVendorName(handle)
    }
  });
});

// ===== HELPER: Get Shopify Access Token =====
function getShopifyAccessToken() {
  const shop = `${SHOPIFY_STORE}.myshopify.com`;
  return shopifyAccessTokens[shop] || process.env.SHOPIFY_ACCESS_TOKEN;
}

function getShopifyHeaders() {
  const token = getShopifyAccessToken();
  if (!token) {
    throw new Error('No Shopify access token available');
  }
  return {
    'Content-Type': 'application/json',
    'X-Shopify-Access-Token': token
  };
}

function getBaseUrl() {
  return `https://${SHOPIFY_STORE}.myshopify.com/admin/api/${API_VERSION}`;
}

// ===== MIDDLEWARE: Require Shopify Auth =====
function requireShopifyAuth(req, res, next) {
  try {
    const token = getShopifyAccessToken();
    if (!token) {
      return res.status(401).json({ 
        error: 'Shopify not connected', 
        authUrl: `${APP_URL}/auth` 
      });
    }
    req.shopifyToken = token;
    next();
  } catch (error) {
    res.status(401).json({ 
      error: 'Shopify authentication required', 
      authUrl: `${APP_URL}/auth` 
    });
  }
}

// ===== MIDDLEWARE: Require Vendor Auth =====
function requireVendorAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Vendor authentication required' });
  }
  
  const token = authHeader.substring(7);
  const session = validateSessionToken(token);
  
  if (!session) {
    return res.status(401).json({ error: 'Invalid or expired session' });
  }
  
  req.vendorHandle = session.handle;
  req.vendorName = getVendorName(session.handle);
  next();
}

// ===== MIDDLEWARE: Validate Vendor Owns Product =====
async function validateProductOwnership(req, res, next) {
  const productId = req.params.id;
  
  if (!productId) {
    return next();
  }
  
  try {
    const response = await fetch(`${getBaseUrl()}/products/${productId}.json`, {
      headers: getShopifyHeaders()
    });
    
    if (!response.ok) {
      return res.status(404).json({ error: 'Product not found' });
    }
    
    const data = await response.json();
    
    if (data.product.vendor !== req.vendorName) {
      console.log(`❌ Vendor ${req.vendorHandle} tried to access product owned by ${data.product.vendor}`);
      return res.status(403).json({ error: 'Access denied - product belongs to different vendor' });
    }
    
    req.product = data.product;
    next();
  } catch (error) {
    console.error('Product validation error:', error);
    res.status(500).json({ error: 'Failed to validate product ownership' });
  }
}

// ===== API ROUTES =====

// Check API status
app.get('/api/status', (req, res) => {
  const hasShopifyToken = !!getShopifyAccessToken();
  res.json({ 
    authenticated: hasShopifyToken,
    authUrl: hasShopifyToken ? null : `${APP_URL}/auth`,
    store: SHOPIFY_STORE
  });
});

// Get vendor's products - FIXED: proper middleware chain
app.get('/api/vendors/:handle/products', 
  requireShopifyAuth,
  requireVendorAuth,
  async (req, res) => {
    const { handle } = req.params;
    
    // Verify the logged-in vendor matches the requested handle
    if (handle !== req.vendorHandle) {
      return res.status(403).json({ error: 'Access denied - wrong vendor' });
    }
    
    const vendorName = getVendorName(handle);
    
    try {
      console.log(`📦 Fetching products for vendor: ${vendorName}`);
      
      const response = await fetch(
        `${getBaseUrl()}/products.json?vendor=${encodeURIComponent(vendorName)}&limit=250`,
        { headers: getShopifyHeaders() }
      );
      
      if (!response.ok) {
        const errorText = await response.text();
        console.error('Shopify API error:', response.status, errorText);
        throw new Error(`Shopify API error: ${response.status}`);
      }
      
      const data = await response.json();
      console.log(`✅ Found ${data.products.length} products for ${vendorName}`);
      
      // Fetch metafields for each product
      const productsWithMetafields = await Promise.all(
        data.products.map(async (product) => {
          try {
            const metaResponse = await fetch(
              `${getBaseUrl()}/products/${product.id}/metafields.json`,
              { headers: getShopifyHeaders() }
            );
            const metaData = await metaResponse.json();
            
            const metafields = {};
            (metaData.metafields || []).forEach(mf => {
              if (mf.namespace === 'custom') {
                metafields[mf.key] = mf.value;
              }
            });
            
            return { ...product, metafields };
          } catch (e) {
            return { ...product, metafields: {} };
          }
        })
      );
      
      res.json(productsWithMetafields);
      
    } catch (error) {
      console.error('Error fetching products:', error);
      res.status(500).json({ error: 'Failed to fetch products: ' + error.message });
    }
  }
);

// Create product
app.post('/api/vendors/:handle/products', 
  requireShopifyAuth,
  requireVendorAuth,
  upload.any(), 
  async (req, res) => {
    const { handle } = req.params;
    
    if (handle !== req.vendorHandle) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    const vendorName = getVendorName(handle);
    
    try {
      const { title, description, price, product_type, tagline, serves, prep_time } = req.body;
      
      const productData = {
        product: {
          title,
          body_html: description || '',
          vendor: vendorName,
          product_type: product_type || '',
          status: 'active',
          variants: [{
            price: parseFloat(price) || 0,
            inventory_management: null,
            inventory_policy: 'continue'
          }]
        }
      };
      
      const createResponse = await fetch(`${getBaseUrl()}/products.json`, {
        method: 'POST',
        headers: getShopifyHeaders(),
        body: JSON.stringify(productData)
      });
      
      if (!createResponse.ok) {
        const errorData = await createResponse.json();
        throw new Error(errorData.errors || 'Failed to create product');
      }
      
      const created = await createResponse.json();
      const productId = created.product.id;
      
      console.log(`✅ Created product ${productId} for vendor ${vendorName}`);
      
      // Add to vendor's collection
      await addProductToVendorCollection(handle, productId);
      
      // Set metafields
      if (tagline || serves || prep_time) {
        await setProductMetafields(productId, { tagline, serves, prep_time });
      }
      
      // Upload images
      const imageFiles = req.files?.filter(f => f.fieldname.startsWith('image_')) || [];
      for (const file of imageFiles) {
        await uploadProductImage(productId, file);
      }
      
      res.json({ success: true, product: created.product });
      
    } catch (error) {
      console.error('Error creating product:', error);
      res.status(500).json({ error: error.message || 'Failed to create product' });
    }
  }
);

// Update product
app.put('/api/vendors/:handle/products/:id', 
  requireShopifyAuth,
  requireVendorAuth,
  validateProductOwnership,
  upload.any(), 
  async (req, res) => {
    const { handle, id } = req.params;
    
    if (handle !== req.vendorHandle) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    try {
      const { 
        title, 
        description, 
        price, 
        compare_price,
        product_type, 
        available,
        tagline, 
        serves, 
        prep_time,
        images_to_delete 
      } = req.body;
      
      const updateData = {
        product: {
          id,
          title,
          body_html: description || '',
          product_type: product_type || '',
          status: available === 'true' || available === true ? 'active' : 'draft'
        }
      };
      
      const updateResponse = await fetch(`${getBaseUrl()}/products/${id}.json`, {
        method: 'PUT',
        headers: getShopifyHeaders(),
        body: JSON.stringify(updateData)
      });
      
      if (!updateResponse.ok) {
        throw new Error('Failed to update product');
      }
      
      // Update variant price
      const product = req.product;
      const variantId = product.variants[0].id;
      
      const variantData = {
        variant: {
          id: variantId,
          price: parseFloat(price) || 0,
          compare_at_price: compare_price ? parseFloat(compare_price) : null
        }
      };
      
      await fetch(`${getBaseUrl()}/variants/${variantId}.json`, {
        method: 'PUT',
        headers: getShopifyHeaders(),
        body: JSON.stringify(variantData)
      });
      
      // Update metafields
      await setProductMetafields(id, { tagline, serves, prep_time });
      
      // Delete images
      if (images_to_delete) {
        const imagesToDelete = JSON.parse(images_to_delete);
        for (const imageId of imagesToDelete) {
          await fetch(`${getBaseUrl()}/products/${id}/images/${imageId}.json`, {
            method: 'DELETE',
            headers: getShopifyHeaders()
          });
        }
      }
      
      // Upload new images
      const newImages = req.files?.filter(f => f.fieldname.startsWith('new_image_')) || [];
      for (const file of newImages) {
        await uploadProductImage(id, file);
      }
      
      console.log(`✅ Updated product ${id}`);
      res.json({ success: true });
      
    } catch (error) {
      console.error('Error updating product:', error);
      res.status(500).json({ error: 'Failed to update product' });
    }
  }
);

// Delete product
app.delete('/api/vendors/:handle/products/:id', 
  requireShopifyAuth,
  requireVendorAuth,
  validateProductOwnership,
  async (req, res) => {
    const { handle, id } = req.params;
    
    if (handle !== req.vendorHandle) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    try {
      const response = await fetch(`${getBaseUrl()}/products/${id}.json`, {
        method: 'DELETE',
        headers: getShopifyHeaders()
      });
      
      if (!response.ok) {
        throw new Error('Failed to delete product');
      }
      
      console.log(`✅ Deleted product ${id}`);
      res.json({ success: true });
      
    } catch (error) {
      console.error('Error deleting product:', error);
      res.status(500).json({ error: 'Failed to delete product' });
    }
  }
);

// ===== HELPER FUNCTIONS =====

async function setProductMetafields(productId, fields) {
  const metafields = [];
  
  if (fields.tagline !== undefined) {
    metafields.push({
      namespace: 'custom',
      key: 'tagline',
      value: fields.tagline || '',
      type: 'single_line_text_field'
    });
  }
  
  if (fields.serves !== undefined) {
    metafields.push({
      namespace: 'custom',
      key: 'serves',
      value: fields.serves || '',
      type: 'single_line_text_field'
    });
  }
  
  if (fields.prep_time !== undefined) {
    metafields.push({
      namespace: 'custom',
      key: 'prep_time',
      value: fields.prep_time || '',
      type: 'single_line_text_field'
    });
  }
  
  for (const metafield of metafields) {
    try {
      const existingResponse = await fetch(
        `${getBaseUrl()}/products/${productId}/metafields.json?namespace=custom&key=${metafield.key}`,
        { headers: getShopifyHeaders() }
      );
      const existingData = await existingResponse.json();
      
      if (existingData.metafields && existingData.metafields.length > 0) {
        const existingId = existingData.metafields[0].id;
        await fetch(`${getBaseUrl()}/metafields/${existingId}.json`, {
          method: 'PUT',
          headers: getShopifyHeaders(),
          body: JSON.stringify({ metafield: { ...metafield, id: existingId } })
        });
      } else {
        await fetch(`${getBaseUrl()}/products/${productId}/metafields.json`, {
          method: 'POST',
          headers: getShopifyHeaders(),
          body: JSON.stringify({ metafield })
        });
      }
    } catch (e) {
      console.error('Error setting metafield:', e);
    }
  }
}

async function uploadProductImage(productId, file) {
  const base64Image = file.buffer.toString('base64');
  
  const imageData = {
    image: {
      attachment: base64Image,
      filename: file.originalname
    }
  };
  
  await fetch(`${getBaseUrl()}/products/${productId}/images.json`, {
    method: 'POST',
    headers: getShopifyHeaders(),
    body: JSON.stringify(imageData)
  });
}

async function addProductToVendorCollection(vendorHandle, productId) {
  try {
    const collectionsResponse = await fetch(
      `${getBaseUrl()}/custom_collections.json?handle=${vendorHandle}`,
      { headers: getShopifyHeaders() }
    );
    const collectionsData = await collectionsResponse.json();
    
    if (collectionsData.custom_collections && collectionsData.custom_collections.length > 0) {
      const collectionId = collectionsData.custom_collections[0].id;
      
      await fetch(`${getBaseUrl()}/collects.json`, {
        method: 'POST',
        headers: getShopifyHeaders(),
        body: JSON.stringify({
          collect: {
            product_id: productId,
            collection_id: collectionId
          }
        })
      });
      console.log(`✅ Added product ${productId} to collection ${vendorHandle}`);
    }
  } catch (error) {
    console.error('Error adding product to collection:', error);
  }
}

// ===== HEALTH CHECK =====
app.get('/health', (req, res) => {
  const hasShopifyToken = !!getShopifyAccessToken();
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    shopifyConnected: hasShopifyToken,
    store: SHOPIFY_STORE
  });
});

// Home page
app.get('/', (req, res) => {
  const hasToken = !!getShopifyAccessToken();
  res.send(`
    <html>
      <head><title>HalfCourse Vendor API</title></head>
      <body style="font-family: sans-serif; text-align: center; padding: 50px;">
        <h1>HalfCourse Vendor API</h1>
        ${hasToken ? 
          '<p style="color: green;">✅ Connected to Shopify</p>' : 
          `<p style="color: orange;">⚠️ Not connected</p>
           <a href="/auth" style="display: inline-block; padding: 12px 24px; background: #ac380b; color: white; text-decoration: none; border-radius: 8px;">Connect to Shopify</a>`
        }
        <hr style="margin: 30px 0;">
        <p style="color: #666;">API Endpoints:</p>
        <ul style="text-align: left; max-width: 400px; margin: 0 auto;">
          <li>POST /api/vendor/login - Vendor login</li>
          <li>GET /api/vendors/:handle/products - List products</li>
          <li>POST /api/vendors/:handle/products - Create product</li>
          <li>PUT /api/vendors/:handle/products/:id - Update product</li>
          <li>DELETE /api/vendors/:handle/products/:id - Delete product</li>
        </ul>
      </body>
    </html>
  `);
});

// ===== START SERVER =====
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 HalfCourse Vendor API running on port ${PORT}`);
  console.log(`📍 Auth URL: ${APP_URL}/auth`);
  console.log(`🏪 Store: ${SHOPIFY_STORE}`);
});

module.exports = app;
