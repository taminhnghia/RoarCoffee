import 'dotenv/config';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import express from 'express';
import { createServer as createViteServer } from 'vite';
import {
  attachAuth,
  type AuthedRequest,
  hashPassword,
  requireAdmin,
  requireAuth,
  SESSION_COOKIE_NAME,
  signSessionToken,
  verifyPassword,
} from './server/auth.ts';
import { db, initDatabase, logAudit } from './server/db.ts';

initDatabase();

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';

app.set('trust proxy', 1);
app.use(express.json({ limit: '4mb' }));
app.use(attachAuth);

function isHttpsRequest(req: express.Request): boolean {
  const xfProto = req.headers['x-forwarded-proto'];
  if (typeof xfProto === 'string' && xfProto.includes('https')) return true;
  return Boolean(req.secure || IS_PROD);
}

function setSessionCookie(req: express.Request, res: express.Response, token: string): void {
  const https = isHttpsRequest(req);
  res.cookie(SESSION_COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: https ? 'none' : 'lax',
    secure: https,
    maxAge: 1000 * 60 * 60 * 24 * 7,
    path: '/',
  });
}

function getPointsSummary(userId: number) {
  const rows = db
    .prepare('SELECT entry_type, points, expires_at FROM points_ledger WHERE user_id = ?')
    .all(userId) as Array<{ entry_type: string; points: number; expires_at: string | null }>;

  let available = 0;
  let pending = 0;
  let redeemed = 0;
  let expired = 0;
  let expiringSoon = 0;
  const thirtyDaysOut = Date.now() + 30 * 24 * 60 * 60 * 1000;

  for (const r of rows) {
    if (r.entry_type === 'earn_available' || r.entry_type === 'admin_adjustment') {
      available += r.points;
      if (r.expires_at && new Date(r.expires_at).getTime() <= thirtyDaysOut && r.points > 0) {
        expiringSoon += r.points;
      }
    } else if (r.entry_type === 'earn_pending') {
      pending += r.points;
    } else if (r.entry_type === 'redeem') {
      redeemed += Math.abs(r.points);
      available -= Math.abs(r.points);
    } else if (r.entry_type === 'reverse') {
      available -= Math.abs(r.points);
    } else if (r.entry_type === 'expire') {
      expired += Math.abs(r.points);
      available -= Math.abs(r.points);
    }
  }

  return {
    available: Math.max(0, available),
    pending: Math.max(0, pending),
    redeemed,
    expired,
    expiringSoon: Math.min(Math.max(0, available), expiringSoon),
  };
}

// ---------- SEO ROUTES ----------
app.get('/robots.txt', (_req, res) => {
  res.type('text/plain').send(
    [
      'User-agent: *',
      'Allow: /',
      'Disallow: /admin',
      'Disallow: /api/',
      `Sitemap: ${process.env.APP_URL || ''}/sitemap.xml`,
    ].join('\n')
  );
});

app.get('/sitemap.xml', (_req, res) => {
  const baseUrl = (process.env.APP_URL || '').replace(/\/$/, '');
  const staticPaths = [
    '',
    '/shop',
    '/coffee/roasted',
    '/coffee/green-beans',
    '/coffee/instant',
    '/personalities',
    '/origins',
    '/farm-to-cup',
    '/brewing',
    '/about',
    '/signature-reserve',
    '/promotions',
    '/partners',
    '/oem-export',
    '/farm-membership',
    '/journal',
    '/contact',
  ];
  const products = db.prepare("SELECT slug FROM products WHERE status != 'draft'").all() as Array<{ slug: string }>;
  const articles = db.prepare('SELECT slug FROM journal_articles WHERE published = 1').all() as Array<{ slug: string }>;
  const personalities = db.prepare('SELECT slug FROM personalities').all() as Array<{ slug: string }>;

  const allPaths = [
    ...staticPaths,
    ...products.map((p) => `/product/${p.slug}`),
    ...articles.map((a) => `/journal/${a.slug}`),
    ...personalities.map((p) => `/personalities/${p.slug}`),
  ];

  const urls = allPaths
    .flatMap((p) => [
      `  <url><loc>${baseUrl}${p || '/'}</loc><xhtml:link rel="alternate" hreflang="vi" href="${baseUrl}${p || '/'}"/><xhtml:link rel="alternate" hreflang="en" href="${baseUrl}/en${p}"/></url>`,
      `  <url><loc>${baseUrl}/en${p}</loc><xhtml:link rel="alternate" hreflang="vi" href="${baseUrl}${p || '/'}"/><xhtml:link rel="alternate" hreflang="en" href="${baseUrl}/en${p}"/></url>`,
    ])
    .join('\n');

  res.type('application/xml').send(
    `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">\n${urls}\n</urlset>`
  );
});

// ---------- AUTH ROUTES ----------
app.post('/api/auth/register', (req, res) => {
  const { email, password, fullName, phone, roleIntent, companyName } = req.body || {};
  if (!email || !password || !fullName) {
    res.status(400).json({ error: 'Missing required registration fields' });
    return;
  }
  if (typeof password !== 'string' || password.length < 8) {
    res.status(400).json({ error: 'Password must be at least 8 characters' });
    return;
  }
  const normalizedEmail = String(email).trim().toLowerCase();
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(normalizedEmail);
  if (existing) {
    res.status(409).json({ error: 'Email already registered' });
    return;
  }

  const role = roleIntent === 'b2b_partner' ? 'b2b_partner' : 'customer';
  const memberCode = `RC-${role === 'b2b_partner' ? 'B2B' : 'MEM'}-${Math.floor(100000 + Math.random() * 900000)}`;
  const verificationToken = crypto.randomBytes(16).toString('hex');

  const result = db
    .prepare(`
      INSERT INTO users (email, password_hash, full_name, phone, role, member_code, tier, email_verified, verification_token, company_name)
      VALUES (?, ?, ?, ?, ?, ?, 'ROAR Member', 0, ?, ?)
    `)
    .run(
      normalizedEmail,
      hashPassword(password),
      String(fullName).trim(),
      String(phone || '').trim(),
      role,
      memberCode,
      verificationToken,
      String(companyName || '').trim()
    );

  const userId = Number(result.lastInsertRowid);
  const token = signSessionToken({ userId, email: normalizedEmail, role });
  setSessionCookie(req, res, token);

  res.status(201).json({
    token,
    user: {
      id: userId,
      email: normalizedEmail,
      fullName: String(fullName).trim(),
      phone: String(phone || '').trim(),
      role,
      memberCode,
      tier: 'ROAR Member',
      emailVerified: false,
      verificationTokenPreview: verificationToken,
    },
  });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    res.status(400).json({ error: 'Email and password are required' });
    return;
  }
  const normalizedEmail = String(email).trim().toLowerCase();
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(normalizedEmail) as any;
  if (!user || !verifyPassword(String(password), user.password_hash)) {
    res.status(401).json({ error: 'Invalid email or password' });
    return;
  }

  const token = signSessionToken({ userId: user.id, email: user.email, role: user.role });
  setSessionCookie(req, res, token);

  res.json({
    token,
    user: {
      id: user.id,
      email: user.email,
      fullName: user.full_name,
      phone: user.phone,
      role: user.role,
      memberCode: user.member_code,
      tier: user.tier,
      emailVerified: Boolean(user.email_verified),
      companyName: user.company_name,
      b2bVerified: Boolean(user.b2b_verified),
    },
  });
});

app.post('/api/auth/logout', (req, res) => {
  const https = isHttpsRequest(req);
  res.clearCookie(SESSION_COOKIE_NAME, {
    path: '/',
    sameSite: https ? 'none' : 'lax',
    secure: https,
  });
  res.json({ ok: true });
});

app.post('/api/auth/verify-email', requireAuth, (req: AuthedRequest, res) => {
  db.prepare('UPDATE users SET email_verified = 1, verification_token = NULL WHERE id = ?').run(req.authUser!.userId);
  res.json({ ok: true, emailVerified: true });
});

app.post('/api/auth/forgot-password', (req, res) => {
  const { email } = req.body || {};
  if (!email) {
    res.status(400).json({ error: 'Email is required' });
    return;
  }
  const normalizedEmail = String(email).trim().toLowerCase();
  const user = db.prepare('SELECT id FROM users WHERE email = ?').get(normalizedEmail) as { id: number } | undefined;
  if (!user) {
    res.json({ ok: true, message: 'If an account matches this email, recovery instructions have been issued.' });
    return;
  }
  const resetToken = crypto.randomBytes(6).toString('hex').toUpperCase();
  const resetExpires = Math.floor(Date.now() / 1000) + 1800;
  db.prepare('UPDATE users SET reset_token = ?, reset_expires = ? WHERE id = ?').run(resetToken, resetExpires, user.id);
  res.json({
    ok: true,
    demoResetCode: resetToken,
    message: 'Password recovery token issued (displayed in development mode because SMTP is not connected).',
  });
});

app.post('/api/auth/reset-password', (req, res) => {
  const { email, token, newPassword } = req.body || {};
  if (!email || !token || !newPassword || String(newPassword).length < 8) {
    res.status(400).json({ error: 'Valid email, recovery code, and new password (min 8 chars) required' });
    return;
  }
  const user = db.prepare('SELECT id, reset_token, reset_expires FROM users WHERE email = ?').get(String(email).trim().toLowerCase()) as any;
  if (!user || user.reset_token !== String(token).trim().toUpperCase() || !user.reset_expires || user.reset_expires < Math.floor(Date.now() / 1000)) {
    res.status(400).json({ error: 'Invalid or expired recovery code' });
    return;
  }
  db.prepare('UPDATE users SET password_hash = ?, reset_token = NULL, reset_expires = NULL WHERE id = ?').run(
    hashPassword(String(newPassword)),
    user.id
  );
  res.json({ ok: true });
});

app.get('/api/auth/me', (req: AuthedRequest, res) => {
  if (!req.authUser) {
    res.json({ user: null });
    return;
  }
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.authUser.userId) as any;
  if (!user) {
    res.json({ user: null });
    return;
  }
  const points = getPointsSummary(user.id);
  res.json({
    user: {
      id: user.id,
      email: user.email,
      fullName: user.full_name,
      phone: user.phone,
      role: user.role,
      memberCode: user.member_code,
      tier: user.tier,
      emailVerified: Boolean(user.email_verified),
      addresses: JSON.parse(user.addresses_json || '[]'),
      notificationPrefs: JSON.parse(user.notification_prefs_json || '{}'),
      privacyPrefs: JSON.parse(user.privacy_prefs_json || '{}'),
      deletionRequested: Boolean(user.deletion_requested),
      companyName: user.company_name,
      b2bVerified: Boolean(user.b2b_verified),
      points,
    },
  });
});

// ---------- MEMBER PROFILE & ACCOUNT ----------
app.patch('/api/account/profile', requireAuth, (req: AuthedRequest, res) => {
  const { fullName, phone, addresses, notificationPrefs, privacyPrefs } = req.body || {};
  const userId = req.authUser!.userId;
  const current = db.prepare('SELECT * FROM users WHERE id = ?').get(userId) as any;
  if (!current) {
    res.status(404).json({ error: 'Account not found' });
    return;
  }
  db.prepare(`
    UPDATE users SET full_name = ?, phone = ?, addresses_json = ?, notification_prefs_json = ?, privacy_prefs_json = ?
    WHERE id = ?
  `).run(
    fullName ? String(fullName).trim() : current.full_name,
    phone !== undefined ? String(phone).trim() : current.phone,
    addresses ? JSON.stringify(addresses) : current.addresses_json,
    notificationPrefs ? JSON.stringify(notificationPrefs) : current.notification_prefs_json,
    privacyPrefs ? JSON.stringify(privacyPrefs) : current.privacy_prefs_json,
    userId
  );
  res.json({ ok: true });
});

app.post('/api/account/change-password', requireAuth, (req: AuthedRequest, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword || String(newPassword).length < 8) {
    res.status(400).json({ error: 'Current password and new password (min 8 chars) required' });
    return;
  }
  const user = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(req.authUser!.userId) as any;
  if (!user || !verifyPassword(String(currentPassword), user.password_hash)) {
    res.status(401).json({ error: 'Current password is incorrect' });
    return;
  }
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hashPassword(String(newPassword)), req.authUser!.userId);
  res.json({ ok: true });
});

app.post('/api/account/request-deletion', requireAuth, (req: AuthedRequest, res) => {
  db.prepare('UPDATE users SET deletion_requested = 1 WHERE id = ?').run(req.authUser!.userId);
  res.json({ ok: true });
});

app.get('/api/account/dashboard', requireAuth, (req: AuthedRequest, res) => {
  const userId = req.authUser!.userId;
  const user = db.prepare('SELECT id, email, full_name, phone, role, member_code, tier, email_verified, addresses_json, notification_prefs_json, privacy_prefs_json, deletion_requested FROM users WHERE id = ?').get(userId) as any;
  const points = getPointsSummary(userId);
  const ledger = db
    .prepare('SELECT * FROM points_ledger WHERE user_id = ? ORDER BY created_at DESC, id DESC LIMIT 50')
    .all(userId);
  const orders = db
    .prepare('SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC, id DESC')
    .all(userId) as any[];
  const ordersWithItems = orders.map((o) => ({
    ...o,
    items: db
      .prepare('SELECT oi.*, p.slug as product_slug, p.image_key as product_image_key FROM order_items oi LEFT JOIN products p ON oi.product_id = p.id WHERE oi.order_id = ?')
      .all(o.id),
  }));
  const now = new Date().toISOString().slice(0, 10);
  const activeVouchers = db
    .prepare('SELECT * FROM promotions WHERE active = 1 AND start_date <= ? AND end_date >= ? ORDER BY id DESC')
    .all(now, now);
  const tiers = db.prepare('SELECT * FROM membership_tiers ORDER BY min_spend_vnd ASC').all();
  const loyaltySettings = db.prepare('SELECT * FROM loyalty_settings WHERE id = 1').get();

  res.json({
    user: {
      ...user,
      addresses: JSON.parse(user.addresses_json || '[]'),
      notificationPrefs: JSON.parse(user.notification_prefs_json || '{}'),
      privacyPrefs: JSON.parse(user.privacy_prefs_json || '{}'),
    },
    points,
    ledger,
    orders: ordersWithItems,
    activeVouchers,
    tiers,
    loyaltySettings,
  });
});

// ---------- PUBLIC STOREFRONT & CATALOG ----------
app.get('/api/site-bootstrap', (_req, res) => {
  const settingsRows = db.prepare('SELECT key, value FROM site_settings').all() as Array<{ key: string; value: string }>;
  const settings: Record<string, string> = {};
  for (const row of settingsRows) settings[row.key] = row.value;

  const personalities = db.prepare('SELECT * FROM personalities ORDER BY sort_order ASC').all();
  const origins = db.prepare('SELECT * FROM coffee_origins ORDER BY id ASC').all().map((o: any) => ({
    ...o,
    related_skus: JSON.parse(o.related_skus_json || '[]'),
  }));
  const tiers = db.prepare('SELECT * FROM membership_tiers ORDER BY min_spend_vnd ASC').all();
  const loyaltySettings = db.prepare('SELECT * FROM loyalty_settings WHERE id = 1').get();

  res.json({ settings, personalities, origins, tiers, loyaltySettings });
});

app.get('/api/products', (req, res) => {
  const { category, search, screen, processing, coffee_type, mascot, status } = req.query;
  let sql = "SELECT * FROM products WHERE status != 'draft'";
  const params: any[] = [];

  if (category && category !== 'all') {
    sql += ' AND category = ?';
    params.push(category);
  }
  if (screen && screen !== 'all') {
    sql += ' AND screen_size = ?';
    params.push(screen);
  }
  if (processing && processing !== 'all') {
    sql += ' AND processing_method = ?';
    params.push(processing);
  }
  if (coffee_type && coffee_type !== 'all') {
    sql += ' AND LOWER(coffee_type) LIKE ?';
    params.push(`%${String(coffee_type).toLowerCase()}%`);
  }
  if (mascot) {
    sql += ' AND mascot_slug = ?';
    params.push(mascot);
  }
  if (status && status !== 'all') {
    sql += ' AND status = ?';
    params.push(status);
  }
  if (search) {
    const q = `%${String(search).trim().toLowerCase()}%`;
    sql += ' AND (LOWER(name_vi) LIKE ? OR LOWER(name_en) LIKE ? OR LOWER(sku) LIKE ? OR LOWER(coffee_type) LIKE ? OR LOWER(origin_region) LIKE ?)';
    params.push(q, q, q, q, q);
  }

  sql += ' ORDER BY featured DESC, id ASC';
  const rows = db.prepare(sql).all(...params) as any[];
  const products = rows.map((p) => ({
    ...p,
    blend_summary_vi: p.blend_public ? p.blend_summary_vi : 'Tỷ lệ phối trộn bảo mật nội bộ',
    blend_summary_en: p.blend_public ? p.blend_summary_en : 'Confidential proprietary blend ratio',
    brewing_methods: JSON.parse(p.brewing_methods_json || '[]'),
    variants: JSON.parse(p.variants_json || '[]'),
    packaging_options: JSON.parse(p.packaging_options_json || '[]'),
  }));
  res.json({ products });
});

app.get('/api/products/:slug', (req, res) => {
  const p = db.prepare("SELECT * FROM products WHERE slug = ? AND status != 'draft'").get(req.params.slug) as any;
  if (!p) {
    res.status(404).json({ error: 'Product not found' });
    return;
  }
  const reviews = db
    .prepare('SELECT * FROM product_reviews WHERE product_id = ? ORDER BY created_at DESC')
    .all(p.id);
  const related = db
    .prepare("SELECT * FROM products WHERE category = ? AND id != ? AND status != 'draft' LIMIT 4")
    .all(p.category, p.id) as any[];

  res.json({
    product: {
      ...p,
      blend_summary_vi: p.blend_public ? p.blend_summary_vi : 'Tỷ lệ phối trộn bảo mật nội bộ',
      blend_summary_en: p.blend_public ? p.blend_summary_en : 'Confidential proprietary blend ratio',
      brewing_methods: JSON.parse(p.brewing_methods_json || '[]'),
      variants: JSON.parse(p.variants_json || '[]'),
      packaging_options: JSON.parse(p.packaging_options_json || '[]'),
    },
    reviews,
    related: related.map((r) => ({
      ...r,
      variants: JSON.parse(r.variants_json || '[]'),
    })),
  });
});

app.post('/api/products/:slug/reviews', requireAuth, (req: AuthedRequest, res) => {
  const { rating, comment } = req.body || {};
  const product = db.prepare('SELECT id FROM products WHERE slug = ?').get(req.params.slug) as { id: number } | undefined;
  if (!product) {
    res.status(404).json({ error: 'Product not found' });
    return;
  }
  const r = Number(rating);
  if (!Number.isInteger(r) || r < 1 || r > 5 || !comment || String(comment).trim().length < 5) {
    res.status(400).json({ error: 'Valid rating (1-5) and comment required' });
    return;
  }
  const user = db.prepare('SELECT full_name FROM users WHERE id = ?').get(req.authUser!.userId) as { full_name: string };
  const verifiedOrder = db
    .prepare(`
      SELECT o.id FROM orders o
      JOIN order_items oi ON oi.order_id = o.id
      WHERE o.user_id = ? AND oi.product_id = ? AND o.order_status = 'Completed'
      LIMIT 1
    `)
    .get(req.authUser!.userId, product.id);

  db.prepare(`
    INSERT INTO product_reviews (product_id, user_id, author_name, rating, comment, verified_purchase)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(product.id, req.authUser!.userId, user.full_name, r, String(comment).trim(), verifiedOrder ? 1 : 0);

  res.status(201).json({ ok: true });
});

// ---------- PROMOTIONS ----------
app.get('/api/promotions', (_req, res) => {
  const today = new Date().toISOString().slice(0, 10);
  const rows = db
    .prepare('SELECT * FROM promotions WHERE active = 1 AND start_date <= ? AND end_date >= ? AND used_count < usage_limit ORDER BY id DESC')
    .all(today, today);
  res.json({ promotions: rows });
});

app.post('/api/promotions/validate', (req: AuthedRequest, res) => {
  const { code, subtotal } = req.body || {};
  if (!code) {
    res.status(400).json({ error: 'Promo code required' });
    return;
  }
  const today = new Date().toISOString().slice(0, 10);
  const promo = db
    .prepare('SELECT * FROM promotions WHERE UPPER(code) = ? AND active = 1 AND start_date <= ? AND end_date >= ?')
    .get(String(code).trim().toUpperCase(), today, today) as any;

  if (!promo) {
    res.status(404).json({ error: 'Promotion code not found or expired' });
    return;
  }
  if (promo.used_count >= promo.usage_limit) {
    res.status(400).json({ error: 'Promotion usage limit reached' });
    return;
  }
  if (Number(subtotal || 0) < promo.min_order_value) {
    res.status(400).json({ error: `Minimum order value of ${promo.min_order_value.toLocaleString()} VND required` });
    return;
  }
  if (promo.member_only && !req.authUser) {
    res.status(401).json({ error: 'Sign in as a ROAR Member to redeem this voucher' });
    return;
  }

  let discount = 0;
  const sub = Number(subtotal || 0);
  if (promo.discount_type === 'percent') {
    discount = Math.round((sub * promo.discount_value) / 100);
    if (promo.max_discount > 0) discount = Math.min(discount, promo.max_discount);
  } else if (promo.discount_type === 'fixed') {
    discount = promo.discount_value;
  } else if (promo.discount_type === 'free_shipping') {
    discount = promo.discount_value;
  }

  res.json({ valid: true, promo, discountAmount: discount });
});

// ---------- CHECKOUT & ORDERS ----------
app.post('/api/orders', (req: AuthedRequest, res) => {
  const {
    customerName,
    customerEmail,
    customerPhone,
    shippingAddress,
    currency = 'VND',
    items,
    voucherCode,
    pointsToRedeem = 0,
    paymentMethod,
    notes = '',
  } = req.body || {};

  if (!customerName || !customerEmail || !customerPhone || !shippingAddress || !Array.isArray(items) || items.length === 0) {
    res.status(400).json({ error: 'Missing required checkout details or items' });
    return;
  }

  const createOrderTx = db.transaction(() => {
    let subtotal = 0;
    const resolvedItems: Array<{
      productId: number;
      sku: string;
      nameVi: string;
      nameEn: string;
      variantLabel: string;
      quantity: number;
      unitPriceVnd: number;
      lineTotalVnd: number;
    }> = [];

    for (const item of items) {
      const product = db.prepare('SELECT * FROM products WHERE id = ?').get(Number(item.productId)) as any;
      if (!product) throw new Error('Product not found in catalog');
      const qty = Math.max(1, Number(item.quantity || 1));
      const variants = JSON.parse(product.variants_json || '[]') as Array<{ label: string; priceVnd: number }>;
      const matchedVariant = variants.find((v) => v.label === item.variantLabel);
      const unitPriceVnd = matchedVariant ? matchedVariant.priceVnd : product.price_vnd;
      const lineTotalVnd = unitPriceVnd * qty;
      subtotal += lineTotalVnd;
      resolvedItems.push({
        productId: product.id,
        sku: product.sku,
        nameVi: product.name_vi,
        nameEn: product.name_en,
        variantLabel: matchedVariant ? matchedVariant.label : String(item.variantLabel || 'Standard'),
        quantity: qty,
        unitPriceVnd,
        lineTotalVnd,
      });

      if (product.inventory > 0) {
        db.prepare('UPDATE products SET inventory = MAX(0, inventory - ?) WHERE id = ?').run(qty, product.id);
      }
    }

    const baseShippingFee = subtotal >= 500000 ? 0 : 35000;
    let shippingFee = baseShippingFee;
    let discountAmount = 0;
    let appliedVoucher = '';

    if (voucherCode) {
      const today = new Date().toISOString().slice(0, 10);
      const promo = db
        .prepare('SELECT * FROM promotions WHERE UPPER(code) = ? AND active = 1 AND start_date <= ? AND end_date >= ? AND used_count < usage_limit')
        .get(String(voucherCode).trim().toUpperCase(), today, today) as any;
      if (promo && subtotal >= promo.min_order_value && (!promo.member_only || req.authUser)) {
        appliedVoucher = promo.code;
        if (promo.discount_type === 'percent') {
          discountAmount = Math.round((subtotal * promo.discount_value) / 100);
          if (promo.max_discount > 0) discountAmount = Math.min(discountAmount, promo.max_discount);
        } else if (promo.discount_type === 'fixed') {
          discountAmount = Math.min(subtotal, promo.discount_value);
        } else if (promo.discount_type === 'free_shipping') {
          shippingFee = 0;
        }
        db.prepare('UPDATE promotions SET used_count = used_count + 1 WHERE id = ?').run(promo.id);
      }
    }

    let pointsRedeemed = 0;
    let pointsDiscount = 0;
    const requestedPoints = Math.max(0, Math.floor(Number(pointsToRedeem || 0)));

    if (requestedPoints > 0 && req.authUser) {
      const loyalty = db.prepare('SELECT * FROM loyalty_settings WHERE id = 1').get() as any;
      const summary = getPointsSummary(req.authUser.userId);
      const maxDiscountVnd = Math.floor((subtotal * (loyalty?.max_redeem_percent || 30)) / 100);
      const maxPointsByRule = Math.floor(maxDiscountVnd / (loyalty?.vnd_per_point || 100));
      pointsRedeemed = Math.min(requestedPoints, summary.available, maxPointsByRule);
      pointsDiscount = pointsRedeemed * (loyalty?.vnd_per_point || 100);
    }

    const total = Math.max(0, subtotal - discountAmount - pointsDiscount + shippingFee);
    const orderNumber = `RC-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}-${Math.floor(1000 + Math.random() * 9000)}`;

    const orderResult = db
      .prepare(`
        INSERT INTO orders (
          order_number, user_id, customer_name, customer_email, customer_phone, shipping_address,
          currency, subtotal, discount_amount, points_redeemed, points_discount, shipping_fee, total,
          voucher_code, payment_method, payment_status, order_status, notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'awaiting_payment', 'Pending', ?)
      `)
      .run(
        orderNumber,
        req.authUser ? req.authUser.userId : null,
        String(customerName).trim(),
        String(customerEmail).trim().toLowerCase(),
        String(customerPhone).trim(),
        String(shippingAddress).trim(),
        currency === 'USD' ? 'USD' : 'VND',
        subtotal,
        discountAmount,
        pointsRedeemed,
        pointsDiscount,
        shippingFee,
        total,
        appliedVoucher,
        String(paymentMethod || 'cod'),
        String(notes || '').trim()
      );

    const orderId = Number(orderResult.lastInsertRowid);
    const insertItem = db.prepare(`
      INSERT INTO order_items (order_id, product_id, sku, product_name_vi, product_name_en, variant_label, quantity, unit_price_vnd, line_total_vnd)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    for (const ri of resolvedItems) {
      insertItem.run(orderId, ri.productId, ri.sku, ri.nameVi, ri.nameEn, ri.variantLabel, ri.quantity, ri.unitPriceVnd, ri.lineTotalVnd);
    }

    if (pointsRedeemed > 0 && req.authUser) {
      db.prepare(`
        INSERT INTO points_ledger (user_id, order_id, entry_type, points, description_vi, description_en)
        VALUES (?, ?, 'redeem', ?, ?, ?)
      `).run(
        req.authUser.userId,
        orderId,
        -pointsRedeemed,
        `Quy đổi ${pointsRedeemed} điểm cho đơn hàng ${orderNumber}`,
        `Redeemed ${pointsRedeemed} points on order ${orderNumber}`
      );
    }

    if (req.authUser) {
      const loyalty = db.prepare('SELECT * FROM loyalty_settings WHERE id = 1').get() as any;
      const userRow = db.prepare('SELECT tier FROM users WHERE id = ?').get(req.authUser.userId) as { tier: string };
      const tierRow = db.prepare('SELECT point_multiplier FROM membership_tiers WHERE name = ?').get(userRow?.tier || 'ROAR Member') as { point_multiplier: number } | undefined;
      const mult = tierRow?.point_multiplier || 1.0;
      const netEligible = Math.max(0, subtotal - discountAmount - pointsDiscount);
      const pendingPoints = Math.floor((netEligible / 10000) * (loyalty?.points_per_10k_vnd || 1) * mult);
      if (pendingPoints > 0) {
        db.prepare(`
          INSERT INTO points_ledger (user_id, order_id, entry_type, points, description_vi, description_en)
          VALUES (?, ?, 'earn_pending', ?, ?, ?)
        `).run(
          req.authUser.userId,
          orderId,
          pendingPoints,
          `Điểm chờ duyệt từ đơn hàng ${orderNumber} (Cộng chính thức khi hoàn tất)`,
          `Pending points for order ${orderNumber} (Credited upon completion)`
        );
      }
    }

    return {
      orderId,
      orderNumber,
      total,
      subtotal,
      discountAmount,
      pointsDiscount,
      shippingFee,
      paymentMethod: String(paymentMethod || 'cod'),
      customerEmail: String(customerEmail).trim().toLowerCase(),
    };
  });

  try {
    const created = createOrderTx();
    res.status(201).json({ ok: true, order: created });
  } catch (err: any) {
    res.status(400).json({ error: err.message || 'Unable to create order' });
  }
});

app.post('/api/orders/:orderNumber/confirm-payment-reference', (req, res) => {
  const { email, transactionRef = '' } = req.body || {};
  const order = db
    .prepare('SELECT * FROM orders WHERE order_number = ? AND LOWER(customer_email) = ?')
    .get(req.params.orderNumber, String(email || '').trim().toLowerCase()) as any;
  if (!order) {
    res.status(404).json({ error: 'Order not found' });
    return;
  }
  const refNote = transactionRef
    ? ` [Customer QR/Wallet Ref: ${String(transactionRef).trim()}]`
    : ' [Customer reported QR/Wallet transfer completed - pending reconciliation]';
  db.prepare("UPDATE orders SET payment_status = 'pending_verification', notes = notes || ?, updated_at = datetime('now') WHERE id = ?").run(
    refNote,
    order.id
  );
  res.json({ ok: true, paymentStatus: 'pending_verification' });
});

app.get('/api/orders/track', (req, res) => {
  const { orderNumber, email } = req.query;
  if (!orderNumber || !email) {
    res.status(400).json({ error: 'Order number and email are required' });
    return;
  }
  const order = db
    .prepare('SELECT * FROM orders WHERE order_number = ? AND LOWER(customer_email) = ?')
    .get(String(orderNumber).trim(), String(email).trim().toLowerCase()) as any;
  if (!order) {
    res.status(404).json({ error: 'Order not found' });
    return;
  }
  const items = db.prepare('SELECT * FROM order_items WHERE order_id = ?').all(order.id);
  res.json({ order: { ...order, items } });
});

app.post('/api/orders/:orderNumber/request-action', requireAuth, (req: AuthedRequest, res) => {
  const { action } = req.body || {};
  const order = db
    .prepare('SELECT * FROM orders WHERE order_number = ? AND user_id = ?')
    .get(req.params.orderNumber, req.authUser!.userId) as any;
  if (!order) {
    res.status(404).json({ error: 'Order not found' });
    return;
  }
  if (action === 'cancel' && (order.order_status === 'Pending' || order.order_status === 'Confirmed')) {
    db.prepare("UPDATE orders SET order_status = 'Cancelled', updated_at = datetime('now') WHERE id = ?").run(order.id);
    db.prepare("DELETE FROM points_ledger WHERE order_id = ? AND entry_type = 'earn_pending'").run(order.id);
    res.json({ ok: true, status: 'Cancelled' });
    return;
  }
  if (action === 'return' && order.order_status === 'Completed') {
    db.prepare("UPDATE orders SET notes = notes || ' [Return Requested]', updated_at = datetime('now') WHERE id = ?").run(order.id);
    res.json({ ok: true, status: 'Return Requested' });
    return;
  }
  res.status(400).json({ error: 'Action not allowed for current order status' });
});

// ---------- B2B / OEM / EXPORT / CONTACT / NEWSLETTER ----------
app.post('/api/b2b/inquiries', (req, res) => {
  const {
    inquiryType,
    companyName = '',
    contactName,
    email,
    phone,
    country = 'Vietnam',
    businessType = '',
    productSku = '',
    packagingOption = '',
    estimatedVolume = '',
    message,
  } = req.body || {};

  if (!inquiryType || !contactName || !email || !phone || !message) {
    res.status(400).json({ error: 'Please complete all required inquiry fields' });
    return;
  }
  const validTypes = [
    'sample_request',
    'green_quotation',
    'wholesale_partner',
    'horeca',
    'oem_private_label',
    'export_inquiry',
    'corporate_gifting',
    'contact',
  ];
  if (!validTypes.includes(inquiryType)) {
    res.status(400).json({ error: 'Invalid inquiry type' });
    return;
  }

  const result = db
    .prepare(`
      INSERT INTO b2b_inquiries (
        inquiry_type, company_name, contact_name, email, phone, country,
        business_type, product_sku, packaging_option, estimated_volume, message
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
    .run(
      inquiryType,
      String(companyName).trim(),
      String(contactName).trim(),
      String(email).trim().toLowerCase(),
      String(phone).trim(),
      String(country).trim(),
      String(businessType).trim(),
      String(productSku).trim(),
      String(packagingOption).trim(),
      String(estimatedVolume).trim(),
      String(message).trim()
    );

  res.status(201).json({ ok: true, inquiryId: Number(result.lastInsertRowid) });
});

app.post('/api/newsletter', (req, res) => {
  const { email, lang = 'vi' } = req.body || {};
  if (!email || !String(email).includes('@')) {
    res.status(400).json({ error: 'Valid email address is required' });
    return;
  }
  const normalized = String(email).trim().toLowerCase();
  db.prepare('INSERT OR IGNORE INTO newsletter_subscribers (email, lang) VALUES (?, ?)').run(normalized, lang === 'en' ? 'en' : 'vi');
  res.status(201).json({ ok: true });
});

// ---------- JOURNAL ----------
app.get('/api/journal', (req, res) => {
  const { category, search } = req.query;
  let sql = 'SELECT * FROM journal_articles WHERE published = 1';
  const params: any[] = [];
  if (category && category !== 'all') {
    sql += ' AND category = ?';
    params.push(category);
  }
  if (search) {
    const q = `%${String(search).trim().toLowerCase()}%`;
    sql += ' AND (LOWER(title_vi) LIKE ? OR LOWER(title_en) LIKE ? OR LOWER(excerpt_vi) LIKE ? OR LOWER(excerpt_en) LIKE ?)';
    params.push(q, q, q, q);
  }
  sql += ' ORDER BY published_at DESC, id DESC';
  const articles = db.prepare(sql).all(...params).map((a: any) => ({
    ...a,
    tags: JSON.parse(a.tags_json || '[]'),
  }));
  res.json({ articles });
});

app.get('/api/journal/:slug', (req, res) => {
  const article = db.prepare('SELECT * FROM journal_articles WHERE slug = ? AND published = 1').get(req.params.slug) as any;
  if (!article) {
    res.status(404).json({ error: 'Article not found' });
    return;
  }
  const related = db.prepare('SELECT * FROM journal_articles WHERE id != ? AND published = 1 LIMIT 3').all(article.id);
  res.json({
    article: { ...article, tags: JSON.parse(article.tags_json || '[]') },
    related,
  });
});

// ---------- PROTECTED ADMIN CMS ROUTES ----------
app.get('/api/admin/overview', requireAdmin, (_req, res) => {
  const revRow = db
    .prepare("SELECT COALESCE(SUM(total), 0) as revenue, COUNT(*) as totalOrders, COALESCE(AVG(total), 0) as aov FROM orders WHERE order_status != 'Cancelled'")
    .get() as { revenue: number; totalOrders: number; aov: number };
  const memberCount = (db.prepare("SELECT COUNT(*) as c FROM users WHERE role = 'customer'").get() as { c: number }).c;
  const b2bCount = (db.prepare('SELECT COUNT(*) as c FROM b2b_inquiries').get() as { c: number }).c;
  const issuedPts = (db.prepare("SELECT COALESCE(SUM(points), 0) as s FROM points_ledger WHERE entry_type IN ('earn_available','admin_adjustment') AND points > 0").get() as { s: number }).s;
  const redeemedPts = (db.prepare("SELECT COALESCE(SUM(ABS(points)), 0) as s FROM points_ledger WHERE entry_type = 'redeem'").get() as { s: number }).s;
  const productPerf = db
    .prepare(`
      SELECT sku, product_name_en, SUM(quantity) as units_sold, SUM(line_total_vnd) as revenue
      FROM order_items
      GROUP BY sku, product_name_en
      ORDER BY revenue DESC
      LIMIT 8
    `)
    .all();
  const auditLogs = db.prepare('SELECT * FROM audit_logs ORDER BY id DESC LIMIT 40').all();

  res.json({
    metrics: {
      revenue: revRow.revenue,
      totalOrders: revRow.totalOrders,
      avgOrderValue: Math.round(revRow.aov),
      members: memberCount,
      b2bInquiries: b2bCount,
      pointsIssued: issuedPts,
      pointsRedeemed: redeemedPts,
    },
    productPerformance: productPerf,
    auditLogs,
  });
});

app.get('/api/admin/products', requireAdmin, (_req, res) => {
  const products = db.prepare('SELECT * FROM products ORDER BY category ASC, id ASC').all();
  res.json({ products });
});

app.post('/api/admin/products', requireAdmin, (req: AuthedRequest, res) => {
  const b = req.body || {};
  if (!b.sku || !b.slug || !b.name_vi || !b.name_en || !b.category) {
    res.status(400).json({ error: 'SKU, slug, category, and bilingual names are required' });
    return;
  }
  const result = db
    .prepare(`
      INSERT INTO products (
        slug, sku, category, sub_category, name_vi, name_en, subtitle_vi, subtitle_en,
        description_vi, description_en, coffee_type, blend_summary_vi, blend_summary_en, blend_public,
        roast_profile_vi, roast_profile_en, tasting_notes_vi, tasting_notes_en,
        brewing_methods_json, variants_json, packaging_options_json,
        price_vnd, price_usd, inventory, moq, status, is_demo_data,
        mascot_slug, screen_size, processing_method, origin_region,
        harvest_year, moisture_content, density, defect_info, grading_spec, image_key, featured
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
    .run(
      b.slug,
      b.sku,
      b.category,
      b.sub_category || '',
      b.name_vi,
      b.name_en,
      b.subtitle_vi || '',
      b.subtitle_en || '',
      b.description_vi || '',
      b.description_en || '',
      b.coffee_type || '',
      b.blend_summary_vi || '',
      b.blend_summary_en || '',
      b.blend_public ? 1 : 0,
      b.roast_profile_vi || '',
      b.roast_profile_en || '',
      b.tasting_notes_vi || '',
      b.tasting_notes_en || '',
      JSON.stringify(b.brewing_methods || []),
      JSON.stringify(b.variants || []),
      JSON.stringify(b.packaging_options || []),
      Number(b.price_vnd || 0),
      Number(b.price_usd || 0),
      Number(b.inventory || 0),
      b.moq || '1',
      b.status || 'active',
      b.is_demo_data ? 1 : 0,
      b.mascot_slug || '',
      b.screen_size || '',
      b.processing_method || '',
      b.origin_region || '',
      b.harvest_year || 'Pending verified lot',
      b.moisture_content || 'Pending verified COA',
      b.density || 'Pending verified COA',
      b.defect_info || 'Pending verified COA',
      b.grading_spec || '',
      b.image_key || 'product_robusta_house',
      b.featured ? 1 : 0
    );

  logAudit(req.authUser!.userId, req.authUser!.email, 'CREATE_PRODUCT', 'product', Number(result.lastInsertRowid), { sku: b.sku });
  res.status(201).json({ ok: true, id: Number(result.lastInsertRowid) });
});

app.patch('/api/admin/products/:id', requireAdmin, (req: AuthedRequest, res) => {
  const id = Number(req.params.id);
  const existing = db.prepare('SELECT * FROM products WHERE id = ?').get(id) as any;
  if (!existing) {
    res.status(404).json({ error: 'Product not found' });
    return;
  }
  const b = req.body || {};
  db.prepare(`
    UPDATE products SET
      name_vi = ?, name_en = ?, price_vnd = ?, price_usd = ?, inventory = ?, status = ?,
      blend_public = ?, harvest_year = ?, moisture_content = ?, density = ?, defect_info = ?,
      grading_spec = ?, origin_region = ?, tasting_notes_vi = ?, tasting_notes_en = ?
    WHERE id = ?
  `).run(
    b.name_vi ?? existing.name_vi,
    b.name_en ?? existing.name_en,
    b.price_vnd !== undefined ? Number(b.price_vnd) : existing.price_vnd,
    b.price_usd !== undefined ? Number(b.price_usd) : existing.price_usd,
    b.inventory !== undefined ? Number(b.inventory) : existing.inventory,
    b.status ?? existing.status,
    b.blend_public !== undefined ? (b.blend_public ? 1 : 0) : existing.blend_public,
    b.harvest_year ?? existing.harvest_year,
    b.moisture_content ?? existing.moisture_content,
    b.density ?? existing.density,
    b.defect_info ?? existing.defect_info,
    b.grading_spec ?? existing.grading_spec,
    b.origin_region ?? existing.origin_region,
    b.tasting_notes_vi ?? existing.tasting_notes_vi,
    b.tasting_notes_en ?? existing.tasting_notes_en,
    id
  );
  logAudit(req.authUser!.userId, req.authUser!.email, 'UPDATE_PRODUCT', 'product', id, { sku: existing.sku });
  res.json({ ok: true });
});

app.get('/api/admin/orders', requireAdmin, (_req, res) => {
  const orders = db.prepare('SELECT * FROM orders ORDER BY id DESC').all() as any[];
  const enriched = orders.map((o) => ({
    ...o,
    items: db.prepare('SELECT * FROM order_items WHERE order_id = ?').all(o.id),
  }));
  res.json({ orders: enriched });
});

app.patch('/api/admin/orders/:id', requireAdmin, (req: AuthedRequest, res) => {
  const id = Number(req.params.id);
  const { orderStatus, paymentStatus, trackingCode } = req.body || {};
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(id) as any;
  if (!order) {
    res.status(404).json({ error: 'Order not found' });
    return;
  }

  const updateTx = db.transaction(() => {
    const nextStatus = orderStatus || order.order_status;
    db.prepare(`
      UPDATE orders SET order_status = ?, payment_status = ?, tracking_code = ?, updated_at = datetime('now') WHERE id = ?
    `).run(nextStatus, paymentStatus || order.payment_status, trackingCode ?? order.tracking_code, id);

    // Server-side loyalty points settlement: credit on Completed (prevent duplicate credits!), reverse on Cancelled/Returned
    if (order.user_id && nextStatus === 'Completed' && !order.points_awarded) {
      const loyalty = db.prepare('SELECT * FROM loyalty_settings WHERE id = 1').get() as any;
      const user = db.prepare('SELECT tier FROM users WHERE id = ?').get(order.user_id) as { tier: string };
      const tier = db.prepare('SELECT point_multiplier FROM membership_tiers WHERE name = ?').get(user?.tier || 'ROAR Member') as { point_multiplier: number } | undefined;
      const netEligible = Math.max(0, order.subtotal - order.discount_amount - order.points_discount);
      const pts = Math.floor((netEligible / 10000) * (loyalty?.points_per_10k_vnd || 1) * (tier?.point_multiplier || 1));

      db.prepare("DELETE FROM points_ledger WHERE order_id = ? AND entry_type = 'earn_pending'").run(order.id);
      if (pts > 0) {
        db.prepare(`
          INSERT INTO points_ledger (user_id, order_id, entry_type, points, description_vi, description_en, expires_at)
          VALUES (?, ?, 'earn_available', ?, ?, ?, datetime('now', '+${loyalty?.expiration_days || 365} days'))
        `).run(
          order.user_id,
          order.id,
          pts,
          `Tích điểm hoàn tất đơn hàng ${order.order_number}`,
          `Earned points from completed order ${order.order_number}`
        );
      }
      db.prepare('UPDATE orders SET points_awarded = ? WHERE id = ?').run(pts, order.id);
    }

    if (order.user_id && (nextStatus === 'Cancelled' || nextStatus === 'Returned') && order.points_awarded > 0) {
      const alreadyReversed = db.prepare("SELECT id FROM points_ledger WHERE order_id = ? AND entry_type = 'reverse'").get(order.id);
      if (!alreadyReversed) {
        db.prepare(`
          INSERT INTO points_ledger (user_id, order_id, entry_type, points, description_vi, description_en)
          VALUES (?, ?, 'reverse', ?, ?, ?)
        `).run(
          order.user_id,
          order.id,
          -order.points_awarded,
          `Hoàn trừ điểm do đơn hàng ${order.order_number} bị ${nextStatus}`,
          `Reversed points for ${nextStatus.toLowerCase()} order ${order.order_number}`
        );
      }
    }
  });

  updateTx();
  logAudit(req.authUser!.userId, req.authUser!.email, 'UPDATE_ORDER', 'order', id, { orderStatus, paymentStatus });
  res.json({ ok: true });
});

app.get('/api/admin/customers', requireAdmin, (_req, res) => {
  const users = db
    .prepare('SELECT id, email, full_name, phone, role, member_code, tier, email_verified, company_name, b2b_verified, deletion_requested, created_at FROM users ORDER BY id DESC')
    .all() as any[];
  const enriched = users.map((u) => ({
    ...u,
    points: getPointsSummary(u.id),
  }));
  const tiers = db.prepare('SELECT * FROM membership_tiers ORDER BY min_spend_vnd ASC').all();
  const loyaltySettings = db.prepare('SELECT * FROM loyalty_settings WHERE id = 1').get();
  res.json({ customers: enriched, tiers, loyaltySettings });
});

app.patch('/api/admin/customers/:id', requireAdmin, (req: AuthedRequest, res) => {
  const id = Number(req.params.id);
  const { tier, b2bVerified, pointsDelta, adjustmentNote } = req.body || {};
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id) as any;
  if (!user) {
    res.status(404).json({ error: 'User not found' });
    return;
  }
  if (tier) db.prepare('UPDATE users SET tier = ? WHERE id = ?').run(tier, id);
  if (b2bVerified !== undefined) db.prepare('UPDATE users SET b2b_verified = ? WHERE id = ?').run(b2bVerified ? 1 : 0, id);
  if (pointsDelta && Number(pointsDelta) !== 0) {
    const delta = Math.trunc(Number(pointsDelta));
    db.prepare(`
      INSERT INTO points_ledger (user_id, entry_type, points, description_vi, description_en)
      VALUES (?, 'admin_adjustment', ?, ?, ?)
    `).run(id, delta, adjustmentNote || 'Điều chỉnh điểm bởi Quản trị viên', adjustmentNote || 'Administrator adjustment');
  }
  logAudit(req.authUser!.userId, req.authUser!.email, 'UPDATE_CUSTOMER', 'user', id, { tier, pointsDelta });
  res.json({ ok: true });
});

app.patch('/api/admin/loyalty-settings', requireAdmin, (req: AuthedRequest, res) => {
  const { pointsPer10kVnd, vndPerPoint, expirationDays, maxRedeemPercent } = req.body || {};
  db.prepare(`
    UPDATE loyalty_settings SET points_per_10k_vnd = ?, vnd_per_point = ?, expiration_days = ?, max_redeem_percent = ?, updated_at = datetime('now')
    WHERE id = 1
  `).run(
    Number(pointsPer10kVnd || 1),
    Number(vndPerPoint || 100),
    Number(expirationDays || 365),
    Number(maxRedeemPercent || 30)
  );
  logAudit(req.authUser!.userId, req.authUser!.email, 'UPDATE_LOYALTY_POLICY', 'loyalty_settings', 1, req.body);
  res.json({ ok: true });
});

app.get('/api/admin/promotions', requireAdmin, (_req, res) => {
  res.json({ promotions: db.prepare('SELECT * FROM promotions ORDER BY id DESC').all() });
});

app.post('/api/admin/promotions', requireAdmin, (req: AuthedRequest, res) => {
  const b = req.body || {};
  if (!b.code || !b.title_vi || !b.title_en || !b.start_date || !b.end_date) {
    res.status(400).json({ error: 'Code, bilingual titles, start_date, and end_date are required' });
    return;
  }
  const result = db
    .prepare(`
      INSERT INTO promotions (
        code, title_vi, title_en, description_vi, description_en, promo_type, discount_type,
        discount_value, max_discount, min_order_value, eligible_category, start_date, end_date,
        usage_limit, member_only, min_tier, terms_vi, terms_en, active
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
    `)
    .run(
      String(b.code).trim().toUpperCase(),
      b.title_vi,
      b.title_en,
      b.description_vi || '',
      b.description_en || '',
      b.promo_type || 'seasonal',
      b.discount_type || 'percent',
      Number(b.discount_value || 0),
      Number(b.max_discount || 0),
      Number(b.min_order_value || 0),
      b.eligible_category || 'all',
      b.start_date,
      b.end_date,
      Number(b.usage_limit || 500),
      b.member_only ? 1 : 0,
      b.min_tier || '',
      b.terms_vi || '',
      b.terms_en || ''
    );
  logAudit(req.authUser!.userId, req.authUser!.email, 'CREATE_PROMOTION', 'promotion', Number(result.lastInsertRowid), { code: b.code });
  res.status(201).json({ ok: true });
});

app.patch('/api/admin/promotions/:id', requireAdmin, (req: AuthedRequest, res) => {
  const id = Number(req.params.id);
  const { active } = req.body || {};
  db.prepare('UPDATE promotions SET active = ? WHERE id = ?').run(active ? 1 : 0, id);
  logAudit(req.authUser!.userId, req.authUser!.email, 'TOGGLE_PROMOTION', 'promotion', id, { active });
  res.json({ ok: true });
});

app.get('/api/admin/b2b', requireAdmin, (_req, res) => {
  res.json({ inquiries: db.prepare('SELECT * FROM b2b_inquiries ORDER BY id DESC').all() });
});

app.patch('/api/admin/b2b/:id', requireAdmin, (req: AuthedRequest, res) => {
  const id = Number(req.params.id);
  const { status, quotedPrice, adminNotes } = req.body || {};
  db.prepare('UPDATE b2b_inquiries SET status = ?, quoted_price = ?, admin_notes = ? WHERE id = ?').run(
    status || 'reviewing',
    quotedPrice || '',
    adminNotes || '',
    id
  );
  logAudit(req.authUser!.userId, req.authUser!.email, 'UPDATE_B2B_INQUIRY', 'b2b_inquiry', id, { status });
  res.json({ ok: true });
});

app.patch('/api/admin/personalities/:id', requireAdmin, (req: AuthedRequest, res) => {
  const id = Number(req.params.id);
  const { customImageUrl, storyVi, storyEn, traitsVi, traitsEn } = req.body || {};
  const existing = db.prepare('SELECT * FROM personalities WHERE id = ?').get(id) as any;
  if (!existing) {
    res.status(404).json({ error: 'Personality not found' });
    return;
  }
  db.prepare(`
    UPDATE personalities SET custom_image_url = ?, story_vi = ?, story_en = ?, traits_vi = ?, traits_en = ? WHERE id = ?
  `).run(
    customImageUrl ?? existing.custom_image_url,
    storyVi ?? existing.story_vi,
    storyEn ?? existing.story_en,
    traitsVi ?? existing.traits_vi,
    traitsEn ?? existing.traits_en,
    id
  );
  logAudit(req.authUser!.userId, req.authUser!.email, 'UPDATE_PERSONALITY', 'personality', id, {});
  res.json({ ok: true });
});

app.patch('/api/admin/origins/:id', requireAdmin, (req: AuthedRequest, res) => {
  const id = Number(req.params.id);
  const b = req.body || {};
  const existing = db.prepare('SELECT * FROM coffee_origins WHERE id = ?').get(id) as any;
  if (!existing) {
    res.status(404).json({ error: 'Origin not found' });
    return;
  }
  db.prepare(`
    UPDATE coffee_origins SET sourcing_status = ?, characteristics_vi = ?, characteristics_en = ?, photo_attribution = ? WHERE id = ?
  `).run(
    b.sourcing_status ?? existing.sourcing_status,
    b.characteristics_vi ?? existing.characteristics_vi,
    b.characteristics_en ?? existing.characteristics_en,
    b.photo_attribution ?? existing.photo_attribution,
    id
  );
  logAudit(req.authUser!.userId, req.authUser!.email, 'UPDATE_ORIGIN', 'coffee_origin', id, {});
  res.json({ ok: true });
});

app.post('/api/admin/journal', requireAdmin, (req: AuthedRequest, res) => {
  const b = req.body || {};
  if (!b.slug || !b.title_vi || !b.title_en || !b.category) {
    res.status(400).json({ error: 'Slug, category, and bilingual titles required' });
    return;
  }
  const resInsert = db
    .prepare(`
      INSERT INTO journal_articles (slug, category, tags_json, title_vi, title_en, excerpt_vi, excerpt_en, content_vi, content_en, author, read_minutes, image_key, published)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
    `)
    .run(
      b.slug,
      b.category,
      JSON.stringify(b.tags || []),
      b.title_vi,
      b.title_en,
      b.excerpt_vi || '',
      b.excerpt_en || '',
      b.content_vi || '',
      b.content_en || '',
      b.author || 'ROAR Coffee Editorial',
      Number(b.read_minutes || 4),
      b.image_key || 'hero_roar_coffee'
    );
  logAudit(req.authUser!.userId, req.authUser!.email, 'CREATE_ARTICLE', 'journal_article', Number(resInsert.lastInsertRowid), { slug: b.slug });
  res.status(201).json({ ok: true });
});

app.patch('/api/admin/settings', requireAdmin, (req: AuthedRequest, res) => {
  const updates = req.body || {};
  const upsert = db.prepare('INSERT INTO site_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value');
  for (const [k, v] of Object.entries(updates)) {
    upsert.run(k, String(v));
  }
  logAudit(req.authUser!.userId, req.authUser!.email, 'UPDATE_SITE_SETTINGS', 'site_settings', 'global', updates);
  res.json({ ok: true });
});

// ---------- VITE / STATIC SERVING ----------
async function startServer() {
  if (!IS_PROD) {
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        allowedHosts: true,
        hmr: process.env.DISABLE_HMR !== 'true',
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use('/src/assets', express.static(path.resolve(process.cwd(), 'src/assets')));
    const distDir = path.resolve(process.cwd(), 'dist');
    if (fs.existsSync(distDir)) {
      app.use(express.static(distDir));
      app.get('*', (_req, res) => {
        res.sendFile(path.join(distDir, 'index.html'));
      });
    }
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`ROAR COFFEE platform listening on http://localhost:${PORT}`);
  });
}

startServer();
