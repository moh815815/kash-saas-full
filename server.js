/**
 * KASH SaaS Backend — Multi-Tenant POS & Accounting
 * Stack: Express + better-sqlite3 + JWT
 * Single server.js — runs on any $10 VPS
 */

const express    = require('express');
const Database   = require('better-sqlite3');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const cors       = require('cors');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const { v4: uuid } = require('uuid');
const path       = require('path');

// ─── CONFIG ────────────────────────────────────────────
const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'kash-secret-change-in-production';
const DB_FILE    = process.env.DB_FILE   || './kash.db';

// ─── DATABASE ──────────────────────────────────────────
const db = new Database(DB_FILE);
db.pragma('journal_mode = WAL');   // Better concurrent read performance
db.pragma('foreign_keys = ON');

// ─── SCHEMA ────────────────────────────────────────────
db.exec(`
  -- Every business that subscribes is a "tenant"
  CREATE TABLE IF NOT EXISTS tenants (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    slug        TEXT UNIQUE NOT NULL,         -- e.g. "pharmacy-nour"
    type        TEXT NOT NULL,                -- pharmacy | supermarket | restaurant | clothes
    plan        TEXT DEFAULT 'free',          -- free | pro | enterprise
    plan_until  INTEGER,                      -- Unix timestamp expiry
    created_at  INTEGER DEFAULT (unixepoch())
  );

  -- Users belong to ONE tenant
  CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    email       TEXT NOT NULL,
    password    TEXT NOT NULL,
    role        TEXT DEFAULT 'cashier',       -- owner | manager | cashier
    created_at  INTEGER DEFAULT (unixepoch())
  );
  CREATE UNIQUE INDEX IF NOT EXISTS idx_user_email ON users(tenant_id, email);

  -- Products/inventory per tenant
  CREATE TABLE IF NOT EXISTS products (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    barcode     TEXT,
    category    TEXT,
    price       REAL NOT NULL DEFAULT 0,
    cost        REAL DEFAULT 0,
    stock       REAL DEFAULT 0,
    min_stock   REAL DEFAULT 5,
    unit        TEXT DEFAULT 'قطعة',
    active      INTEGER DEFAULT 1,
    created_at  INTEGER DEFAULT (unixepoch())
  );
  CREATE INDEX IF NOT EXISTS idx_products_tenant ON products(tenant_id);
  CREATE INDEX IF NOT EXISTS idx_products_barcode ON products(tenant_id, barcode);

  -- Sales invoice header
  CREATE TABLE IF NOT EXISTS sales (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id     TEXT NOT NULL,
    invoice_no  TEXT NOT NULL,
    total       REAL NOT NULL DEFAULT 0,
    discount    REAL DEFAULT 0,
    tax         REAL DEFAULT 0,
    paid        REAL DEFAULT 0,
    change      REAL DEFAULT 0,
    payment     TEXT DEFAULT 'cash',          -- cash | card | transfer
    status      TEXT DEFAULT 'completed',     -- completed | returned | draft
    note        TEXT,
    created_at  INTEGER DEFAULT (unixepoch())
  );
  CREATE INDEX IF NOT EXISTS idx_sales_tenant ON sales(tenant_id);
  CREATE INDEX IF NOT EXISTS idx_sales_date   ON sales(tenant_id, created_at);

  -- Sale line items
  CREATE TABLE IF NOT EXISTS sale_items (
    id          TEXT PRIMARY KEY,
    sale_id     TEXT NOT NULL REFERENCES sales(id) ON DELETE CASCADE,
    tenant_id   TEXT NOT NULL,
    product_id  TEXT NOT NULL,
    name        TEXT NOT NULL,
    qty         REAL NOT NULL,
    price       REAL NOT NULL,
    cost        REAL DEFAULT 0,
    total       REAL NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_sale_items_sale ON sale_items(sale_id);

  -- Expenses per tenant
  CREATE TABLE IF NOT EXISTS expenses (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id     TEXT NOT NULL,
    category    TEXT NOT NULL,
    amount      REAL NOT NULL,
    note        TEXT,
    created_at  INTEGER DEFAULT (unixepoch())
  );
  CREATE INDEX IF NOT EXISTS idx_expenses_tenant ON expenses(tenant_id);

  -- Subscriptions/payments log (owner-level — platform revenue)
  CREATE TABLE IF NOT EXISTS subscriptions (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id),
    plan        TEXT NOT NULL,
    amount      REAL NOT NULL,
    months      INTEGER DEFAULT 1,
    paid_at     INTEGER DEFAULT (unixepoch())
  );
`);

// ─── APP SETUP ─────────────────────────────────────────
const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Rate limiting
const limiter = rateLimit({ windowMs: 15*60*1000, max: 300 });
app.use('/api/', limiter);

const authLimiter = rateLimit({ windowMs: 60*60*1000, max: 20, message: { error: 'محاولات كثيرة، حاول بعد ساعة' } });

// ─── HELPERS ───────────────────────────────────────────
const ok  = (res, data)         => res.json({ ok: true, ...data });
const err = (res, msg, code=400) => res.status(code).json({ ok: false, error: msg });

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}

function nextInvoiceNo(tenantId) {
  const row = db.prepare(`
    SELECT invoice_no FROM sales WHERE tenant_id=? ORDER BY created_at DESC LIMIT 1
  `).get(tenantId);
  if (!row) return 'INV-0001';
  const num = parseInt(row.invoice_no.split('-')[1] || 0) + 1;
  return 'INV-' + String(num).padStart(4, '0');
}

// ─── MIDDLEWARE ────────────────────────────────────────
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return err(res, 'مطلوب تسجيل الدخول', 401);
  try {
    req.user = jwt.verify(header.replace('Bearer ', ''), JWT_SECRET);
    next();
  } catch {
    err(res, 'الجلسة منتهية، سجّل دخول من جديد', 401);
  }
}

// Multitenancy guard: every request must carry the correct tenant
function tenant(req, res, next) {
  const t = db.prepare('SELECT * FROM tenants WHERE id=?').get(req.user.tenant_id);
  if (!t) return err(res, 'المنشأة غير موجودة', 404);
  req.tenant = t;
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) return err(res, 'صلاحيات غير كافية', 403);
    next();
  };
}

// Plan limits
const PLAN_LIMITS = {
  free:       { cashiers: 1,  products: 200, reports: 'weekly'  },
  pro:        { cashiers: 3,  products: Infinity, reports: 'live' },
  enterprise: { cashiers: Infinity, products: Infinity, reports: 'live' }
};

function checkPlan(feature) {
  return (req, res, next) => {
    const plan  = req.tenant.plan;
    const limit = PLAN_LIMITS[plan] || PLAN_LIMITS.free;
    if (feature === 'cashiers') {
      const count = db.prepare(`SELECT COUNT(*) as c FROM users WHERE tenant_id=? AND role='cashier'`).get(req.user.tenant_id).c;
      if (count >= limit.cashiers) return err(res, `خطة ${plan} تسمح بـ ${limit.cashiers} كاشير فقط. ترقّى للـ Pro`, 403);
    }
    if (feature === 'products') {
      const count = db.prepare(`SELECT COUNT(*) as c FROM products WHERE tenant_id=? AND active=1`).get(req.user.tenant_id).c;
      if (count >= limit.products) return err(res, `وصلت لحد الأصناف في خطتك (${limit.products}). ترقّى للـ Pro`, 403);
    }
    next();
  };
}

// ═══════════════════════════════════════════════════════
//  ROUTES
// ═══════════════════════════════════════════════════════

// ── 1. TENANT REGISTRATION ──────────────────────────────
app.post('/api/register', authLimiter, async (req, res) => {
  const { businessName, businessType, ownerName, email, password } = req.body;
  if (!businessName || !email || !password || !ownerName)
    return err(res, 'جميع الحقول مطلوبة');
  if (password.length < 6)
    return err(res, 'كلمة المرور 6 أحرف على الأقل');

  const slug      = businessName.trim().toLowerCase().replace(/\s+/g, '-') + '-' + Date.now().toString(36);
  const tenantId  = uuid();
  const userId    = uuid();
  const hash      = await bcrypt.hash(password, 10);

  const insert = db.transaction(() => {
    db.prepare(`INSERT INTO tenants(id,name,slug,type) VALUES(?,?,?,?)`).run(tenantId, businessName, slug, businessType || 'general');
    db.prepare(`INSERT INTO users(id,tenant_id,name,email,password,role) VALUES(?,?,?,?,?,'owner')`).run(userId, tenantId, ownerName, email, hash);
  });

  try {
    insert();
    const token = signToken({ id: userId, tenant_id: tenantId, role: 'owner', name: ownerName });
    ok(res, { token, tenant: { id: tenantId, slug, name: businessName, plan: 'free' } });
  } catch (e) {
    if (e.message.includes('UNIQUE')) return err(res, 'البريد الإلكتروني مسجّل من قبل');
    throw e;
  }
});

// ── 2. LOGIN ────────────────────────────────────────────
app.post('/api/login', authLimiter, async (req, res) => {
  const { email, password, tenantSlug } = req.body;
  if (!email || !password) return err(res, 'ادخل البريد وكلمة المرور');

  let user;
  if (tenantSlug) {
    // Login by tenant slug (for cashier login pages)
    const t = db.prepare('SELECT id FROM tenants WHERE slug=?').get(tenantSlug);
    if (!t) return err(res, 'المنشأة غير موجودة', 404);
    user = db.prepare('SELECT * FROM users WHERE tenant_id=? AND email=?').get(t.id, email);
  } else {
    user = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  }

  if (!user) return err(res, 'بيانات خاطئة', 401);
  const match = await bcrypt.compare(password, user.password);
  if (!match)  return err(res, 'بيانات خاطئة', 401);

  const t     = db.prepare('SELECT * FROM tenants WHERE id=?').get(user.tenant_id);
  const token = signToken({ id: user.id, tenant_id: user.tenant_id, role: user.role, name: user.name });
  ok(res, { token, user: { id: user.id, name: user.name, role: user.role }, tenant: t });
});

// ── 3. PRODUCTS (Inventory) ─────────────────────────────
const prodRouter = express.Router();
prodRouter.use(auth, tenant);

prodRouter.get('/', (req, res) => {
  const { search, category, low_stock } = req.query;
  let sql = 'SELECT * FROM products WHERE tenant_id=? AND active=1';
  const params = [req.user.tenant_id];
  if (search)    { sql += ' AND (name LIKE ? OR barcode LIKE ?)'; params.push(`%${search}%`, `%${search}%`); }
  if (category)  { sql += ' AND category=?'; params.push(category); }
  if (low_stock) { sql += ' AND stock <= min_stock'; }
  sql += ' ORDER BY name';
  ok(res, { products: db.prepare(sql).all(...params) });
});

prodRouter.post('/', requireRole('owner','manager'), checkPlan('products'), (req, res) => {
  const { name, barcode, category, price, cost, stock, min_stock, unit } = req.body;
  if (!name || price == null) return err(res, 'الاسم والسعر مطلوبان');
  const id = uuid();
  db.prepare(`
    INSERT INTO products(id,tenant_id,name,barcode,category,price,cost,stock,min_stock,unit)
    VALUES(?,?,?,?,?,?,?,?,?,?)
  `).run(id, req.user.tenant_id, name, barcode||null, category||null, price, cost||0, stock||0, min_stock||5, unit||'قطعة');
  ok(res, { product: db.prepare('SELECT * FROM products WHERE id=?').get(id) });
});

prodRouter.put('/:id', requireRole('owner','manager'), (req, res) => {
  const p = db.prepare('SELECT * FROM products WHERE id=? AND tenant_id=?').get(req.params.id, req.user.tenant_id);
  if (!p) return err(res, 'الصنف غير موجود', 404);
  const { name, barcode, category, price, cost, stock, min_stock, unit } = req.body;
  db.prepare(`
    UPDATE products SET name=?,barcode=?,category=?,price=?,cost=?,stock=?,min_stock=?,unit=? WHERE id=?
  `).run(
    name||p.name, barcode||p.barcode, category||p.category,
    price??p.price, cost??p.cost, stock??p.stock, min_stock??p.min_stock, unit||p.unit,
    req.params.id
  );
  ok(res, { product: db.prepare('SELECT * FROM products WHERE id=?').get(req.params.id) });
});

prodRouter.delete('/:id', requireRole('owner','manager'), (req, res) => {
  const result = db.prepare('UPDATE products SET active=0 WHERE id=? AND tenant_id=?').run(req.params.id, req.user.tenant_id);
  if (!result.changes) return err(res, 'الصنف غير موجود', 404);
  ok(res, { message: 'تم الحذف' });
});

app.use('/api/products', prodRouter);

// ── 4. SALES (POS) ──────────────────────────────────────
const saleRouter = express.Router();
saleRouter.use(auth, tenant);

// Create sale (checkout)
saleRouter.post('/', (req, res) => {
  const { items, payment, discount, paid, note } = req.body;
  if (!items || !items.length) return err(res, 'الفاتورة فاضية');

  // Validate & enrich items
  const enriched = [];
  for (const item of items) {
    const p = db.prepare('SELECT * FROM products WHERE id=? AND tenant_id=? AND active=1').get(item.product_id, req.user.tenant_id);
    if (!p) return err(res, `الصنف ${item.product_id} غير موجود`);
    if (p.stock < item.qty) return err(res, `رصيد ${p.name} غير كافٍ (${p.stock} متاح)`);
    enriched.push({ ...item, name: p.name, price: item.price ?? p.price, cost: p.cost });
  }

  const subtotal   = enriched.reduce((s, i) => s + (i.price * i.qty), 0);
  const tax        = +(subtotal * 0.00).toFixed(2);   // Set tax rate here if needed
  const disc       = +(discount || 0);
  const total      = +(subtotal + tax - disc).toFixed(2);
  const paidAmt    = +(paid || total);
  const change     = +(paidAmt - total).toFixed(2);
  const saleId     = uuid();
  const invoiceNo  = nextInvoiceNo(req.user.tenant_id);

  const doSale = db.transaction(() => {
    db.prepare(`
      INSERT INTO sales(id,tenant_id,user_id,invoice_no,total,discount,tax,paid,change,payment,note)
      VALUES(?,?,?,?,?,?,?,?,?,?,?)
    `).run(saleId, req.user.tenant_id, req.user.id, invoiceNo, total, disc, tax, paidAmt, change, payment||'cash', note||null);

    for (const i of enriched) {
      db.prepare(`
        INSERT INTO sale_items(id,sale_id,tenant_id,product_id,name,qty,price,cost,total)
        VALUES(?,?,?,?,?,?,?,?,?)
      `).run(uuid(), saleId, req.user.tenant_id, i.product_id, i.name, i.qty, i.price, i.cost, +(i.price*i.qty).toFixed(2));
      // Deduct stock
      db.prepare('UPDATE products SET stock=stock-? WHERE id=?').run(i.qty, i.product_id);
    }
  });

  doSale();

  const sale = db.prepare('SELECT * FROM sales WHERE id=?').get(saleId);
  const saleItems = db.prepare('SELECT * FROM sale_items WHERE sale_id=?').all(saleId);
  ok(res, { sale: { ...sale, items: saleItems } });
});

// List sales with pagination
saleRouter.get('/', (req, res) => {
  const { from, to, page=1, limit=50 } = req.query;
  const offset = (page-1) * limit;
  let sql = 'SELECT * FROM sales WHERE tenant_id=?';
  const params = [req.user.tenant_id];
  if (from) { sql += ' AND created_at >= ?'; params.push(Math.floor(new Date(from)/1000)); }
  if (to)   { sql += ' AND created_at <= ?'; params.push(Math.floor(new Date(to)/1000)); }
  sql += ` ORDER BY created_at DESC LIMIT ${limit} OFFSET ${offset}`;

  const sales = db.prepare(sql).all(...params);
  const total = db.prepare('SELECT COUNT(*) as c FROM sales WHERE tenant_id=?').get(req.user.tenant_id).c;
  ok(res, { sales, total, page: +page });
});

// Get single sale with items
saleRouter.get('/:id', (req, res) => {
  const sale = db.prepare('SELECT * FROM sales WHERE id=? AND tenant_id=?').get(req.params.id, req.user.tenant_id);
  if (!sale) return err(res, 'الفاتورة غير موجودة', 404);
  const items = db.prepare('SELECT * FROM sale_items WHERE sale_id=?').all(req.params.id);
  ok(res, { sale: { ...sale, items } });
});

// Return/refund a sale
saleRouter.post('/:id/return', requireRole('owner','manager'), (req, res) => {
  const sale = db.prepare('SELECT * FROM sales WHERE id=? AND tenant_id=?').get(req.params.id, req.user.tenant_id);
  if (!sale) return err(res, 'الفاتورة غير موجودة', 404);
  if (sale.status === 'returned') return err(res, 'الفاتورة مرجعة بالفعل');

  const items = db.prepare('SELECT * FROM sale_items WHERE sale_id=?').all(req.params.id);
  const doReturn = db.transaction(() => {
    db.prepare("UPDATE sales SET status='returned' WHERE id=?").run(req.params.id);
    for (const i of items) {
      db.prepare('UPDATE products SET stock=stock+? WHERE id=?').run(i.qty, i.product_id);
    }
  });
  doReturn();
  ok(res, { message: 'تم الإرجاع وإعادة المخزون' });
});

app.use('/api/sales', saleRouter);

// ── 5. EXPENSES ─────────────────────────────────────────
app.post('/api/expenses', auth, tenant, requireRole('owner','manager'), (req, res) => {
  const { category, amount, note } = req.body;
  if (!category || !amount) return err(res, 'التصنيف والمبلغ مطلوبان');
  const id = uuid();
  db.prepare('INSERT INTO expenses(id,tenant_id,user_id,category,amount,note) VALUES(?,?,?,?,?,?)').run(id, req.user.tenant_id, req.user.id, category, amount, note||null);
  ok(res, { expense: db.prepare('SELECT * FROM expenses WHERE id=?').get(id) });
});

app.get('/api/expenses', auth, tenant, (req, res) => {
  const { from, to } = req.query;
  let sql = 'SELECT * FROM expenses WHERE tenant_id=?';
  const params = [req.user.tenant_id];
  if (from) { sql += ' AND created_at >= ?'; params.push(Math.floor(new Date(from)/1000)); }
  if (to)   { sql += ' AND created_at <= ?'; params.push(Math.floor(new Date(to)/1000)); }
  sql += ' ORDER BY created_at DESC';
  ok(res, { expenses: db.prepare(sql).all(...params) });
});

// ── 6. REPORTS ──────────────────────────────────────────
const reportRouter = express.Router();
reportRouter.use(auth, tenant);

// Dashboard KPIs — today vs yesterday
reportRouter.get('/dashboard', (req, res) => {
  const todayStart = Math.floor(new Date().setHours(0,0,0,0)/1000);
  const yestStart  = todayStart - 86400;

  const todaySales = db.prepare(`
    SELECT COUNT(*) as invoices, COALESCE(SUM(total),0) as revenue, COALESCE(SUM(total-discount-(SELECT COALESCE(SUM(cost*qty),0) FROM sale_items WHERE sale_id=sales.id)),0) as profit
    FROM sales WHERE tenant_id=? AND created_at>=? AND status='completed'
  `).get(req.user.tenant_id, todayStart);

  const yestSales = db.prepare(`
    SELECT COALESCE(SUM(total),0) as revenue FROM sales
    WHERE tenant_id=? AND created_at>=? AND created_at<? AND status='completed'
  `).get(req.user.tenant_id, yestStart, todayStart);

  const lowStock = db.prepare(`
    SELECT * FROM products WHERE tenant_id=? AND active=1 AND stock<=min_stock ORDER BY stock ASC LIMIT 10
  `).all(req.user.tenant_id);

  const topProducts = db.prepare(`
    SELECT si.name, SUM(si.qty) as qty, SUM(si.total) as revenue
    FROM sale_items si JOIN sales s ON s.id=si.sale_id
    WHERE si.tenant_id=? AND s.created_at>=? AND s.status='completed'
    GROUP BY si.product_id ORDER BY revenue DESC LIMIT 5
  `).all(req.user.tenant_id, todayStart - 7*86400);

  const revenueChange = yestSales.revenue > 0
    ? (((todaySales.revenue - yestSales.revenue) / yestSales.revenue) * 100).toFixed(1)
    : null;

  ok(res, { today: todaySales, yesterday: yestSales, revenueChange, lowStock, topProducts });
});

// Weekly sales chart (last 7 days)
reportRouter.get('/weekly', (req, res) => {
  const days = [];
  for (let i=6; i>=0; i--) {
    const d     = new Date(); d.setDate(d.getDate()-i); d.setHours(0,0,0,0);
    const start = Math.floor(d/1000);
    const end   = start + 86400;
    const row   = db.prepare(`
      SELECT COALESCE(SUM(total),0) as revenue, COUNT(*) as invoices
      FROM sales WHERE tenant_id=? AND created_at>=? AND created_at<? AND status='completed'
    `).get(req.user.tenant_id, start, end);
    days.push({ date: d.toISOString().split('T')[0], ...row });
  }
  ok(res, { days });
});

// Monthly summary
reportRouter.get('/monthly', requireRole('owner','manager'), (req, res) => {
  const { year = new Date().getFullYear() } = req.query;
  const months = [];
  for (let m=0; m<12; m++) {
    const start = Math.floor(new Date(year, m, 1)/1000);
    const end   = Math.floor(new Date(year, m+1, 1)/1000);
    const row   = db.prepare(`
      SELECT COALESCE(SUM(total),0) as revenue, COUNT(*) as invoices,
             COALESCE(SUM(discount),0) as discounts
      FROM sales WHERE tenant_id=? AND created_at>=? AND created_at<? AND status='completed'
    `).get(req.user.tenant_id, start, end);
    const expenses = db.prepare(`SELECT COALESCE(SUM(amount),0) as total FROM expenses WHERE tenant_id=? AND created_at>=? AND created_at<?`).get(req.user.tenant_id, start, end);
    months.push({ month: m+1, ...row, expenses: expenses.total, net: row.revenue - expenses.total });
  }
  ok(res, { months });
});

app.use('/api/reports', reportRouter);

// ── 7. USER MANAGEMENT ──────────────────────────────────
app.get('/api/users', auth, tenant, requireRole('owner'), (req, res) => {
  const users = db.prepare('SELECT id,name,email,role,created_at FROM users WHERE tenant_id=?').all(req.user.tenant_id);
  ok(res, { users });
});

app.post('/api/users', auth, tenant, requireRole('owner'), checkPlan('cashiers'), async (req, res) => {
  const { name, email, password, role='cashier' } = req.body;
  if (!name || !email || !password) return err(res, 'جميع الحقول مطلوبة');
  const hash = await bcrypt.hash(password, 10);
  const id   = uuid();
  try {
    db.prepare('INSERT INTO users(id,tenant_id,name,email,password,role) VALUES(?,?,?,?,?,?)').run(id, req.user.tenant_id, name, email, hash, role);
    ok(res, { user: db.prepare('SELECT id,name,email,role FROM users WHERE id=?').get(id) });
  } catch {
    err(res, 'البريد الإلكتروني مستخدم من قبل');
  }
});

// ── 8. TENANT INFO & SETTINGS ───────────────────────────
app.get('/api/tenant', auth, tenant, (req, res) => {
  const stats = db.prepare('SELECT COUNT(*) as users FROM users WHERE tenant_id=?').get(req.user.tenant_id);
  const products = db.prepare('SELECT COUNT(*) as total FROM products WHERE tenant_id=? AND active=1').get(req.user.tenant_id);
  ok(res, { tenant: req.tenant, stats: { ...stats, ...products }, limits: PLAN_LIMITS[req.tenant.plan] });
});

app.put('/api/tenant', auth, tenant, requireRole('owner'), (req, res) => {
  const { name, type } = req.body;
  db.prepare('UPDATE tenants SET name=?,type=? WHERE id=?').run(name||req.tenant.name, type||req.tenant.type, req.user.tenant_id);
  ok(res, { tenant: db.prepare('SELECT * FROM tenants WHERE id=?').get(req.user.tenant_id) });
});

// ── 9. PLATFORM ADMIN (Super Admin) ─────────────────────
// Separate secret header — not exposed to tenants
app.get('/api/admin/overview', (req, res) => {
  if (req.headers['x-admin-key'] !== process.env.ADMIN_KEY) return err(res, 'غير مصرّح', 403);
  const tenants    = db.prepare('SELECT COUNT(*) as c FROM tenants').get().c;
  const users      = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
  const sales      = db.prepare('SELECT COUNT(*) as c, COALESCE(SUM(total),0) as gmv FROM sales WHERE status="completed"').get();
  const plans      = db.prepare('SELECT plan, COUNT(*) as c FROM tenants GROUP BY plan').all();
  const recentSubs = db.prepare('SELECT t.name, s.plan, s.amount, s.paid_at FROM subscriptions s JOIN tenants t ON t.id=s.tenant_id ORDER BY s.paid_at DESC LIMIT 20').all();
  ok(res, { tenants, users, sales, plans, recentSubs });
});

// ── 10. HEALTH CHECK ────────────────────────────────────
app.get('/api/health', (req, res) => ok(res, { status: 'ok', ts: Date.now() }));

// Serve frontend for all non-API routes (SPA support)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── GLOBAL ERROR HANDLER ──────────────────────────────
app.use((error, req, res, next) => {
  console.error(error);
  res.status(500).json({ ok: false, error: 'خطأ في السيرفر' });
});

// ─── START ─────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✅ KASH running on http://localhost:${PORT}`);
  console.log(`📦 Database: ${DB_FILE}`);
});
