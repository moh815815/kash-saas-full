/**
 * KASH — Paymob Subscription Module
 * أضف السطور دي في server.js بعد سطر require(uuid)
 *
 * npm install axios
 */

// ─── في الـ server.js أضف: ──────────────────────────────
// const subscriptions = require('./subscriptions');
// app.use('/api/subscribe', subscriptions(db));

const express = require('express');
const https   = require('https');

// ─── PLANS ─────────────────────────────────────────────
const PLANS = {
  pro:        { price: 200, months: 1,  label: 'احترافي شهري'  },
  pro_year:   { price: 1800, months: 12, label: 'احترافي سنوي'  },
  enterprise: { price: 500, months: 1,  label: 'مؤسسي شهري'    },
};

// ─── HELPERS ───────────────────────────────────────────
function paymobRequest(path, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const options = {
      hostname: 'accept.paymob.com',
      port: 443,
      path: '/api/' + path,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) }
    };
    const req = https.request(options, res => {
      let s = '';
      res.on('data', d => s += d);
      res.on('end', () => resolve(JSON.parse(s)));
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

// ─── MODULE ────────────────────────────────────────────
module.exports = function subscriptionsRouter(db) {
  const router  = express.Router();
  const jwt     = require('jsonwebtoken');
  const { v4: uuid } = require('uuid');

  const PAYMOB_API_KEY      = process.env.PAYMOB_API_KEY      || '';
  const PAYMOB_INTEGRATION  = process.env.PAYMOB_INTEGRATION  || ''; // Card integration ID
  const PAYMOB_IFRAME       = process.env.PAYMOB_IFRAME       || ''; // iFrame ID
  const PAYMOB_HMAC         = process.env.PAYMOB_HMAC_SECRET  || '';
  const APP_URL             = process.env.APP_URL             || 'http://localhost:3000';
  const JWT_SECRET          = process.env.JWT_SECRET          || 'kash-secret';

  // ── Middleware ─────────────────────────────────────
  function auth(req, res, next) {
    try {
      req.user = jwt.verify((req.headers.authorization||'').replace('Bearer ',''), JWT_SECRET);
      next();
    } catch { res.status(401).json({ ok:false, error:'غير مصرّح' }); }
  }

  // ── 1. Get available plans ──────────────────────────
  router.get('/plans', (req, res) => {
    res.json({ ok: true, plans: PLANS });
  });

  // ── 2. Create payment link (Paymob 3-step flow) ─────
  router.post('/create', auth, async (req, res) => {
    const { plan_key } = req.body;
    const plan = PLANS[plan_key];
    if (!plan) return res.status(400).json({ ok:false, error:'خطة غير موجودة' });

    const tenant = db.prepare('SELECT * FROM tenants WHERE id=?').get(req.user.tenant_id);
    const owner  = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);

    try {
      // Step 1: Auth token
      const auth_resp = await paymobRequest('auth/tokens', { api_key: PAYMOB_API_KEY });
      const auth_token = auth_resp.token;

      // Step 2: Create order
      const order_resp = await paymobRequest('ecommerce/orders', {
        auth_token,
        delivery_needed: false,
        amount_cents: plan.price * 100,   // EGP → cents
        currency: 'EGP',
        merchant_order_id: `kash-${req.user.tenant_id}-${plan_key}-${Date.now()}`,
        items: [{
          name: `اشتراك كاش — ${plan.label}`,
          amount_cents: plan.price * 100,
          description: `${plan.months} شهر`,
          quantity: 1
        }]
      });

      // Step 3: Payment key
      const pk_resp = await paymobRequest('acceptance/payment_keys', {
        auth_token,
        amount_cents: plan.price * 100,
        expiration: 3600,
        order_id: order_resp.id,
        currency: 'EGP',
        integration_id: parseInt(PAYMOB_INTEGRATION),
        billing_data: {
          first_name: owner.name.split(' ')[0] || owner.name,
          last_name:  owner.name.split(' ')[1] || '.',
          email: owner.email,
          phone_number: 'NA',
          apartment: 'NA', floor: 'NA', street: 'NA',
          building: 'NA', shipping_method: 'NA',
          postal_code: 'NA', city: 'NA', country: 'EG', state: 'NA'
        }
      });

      const payment_url = `https://accept.paymob.com/api/acceptance/iframes/${PAYMOB_IFRAME}?payment_token=${pk_resp.token}`;

      // Log pending subscription
      db.prepare(`
        INSERT INTO subscriptions(id,tenant_id,plan,amount,months)
        VALUES(?,?,?,?,?)
      `).run(uuid(), req.user.tenant_id, plan_key, plan.price, plan.months);

      res.json({
        ok: true,
        payment_url,
        order_id: order_resp.id,
        plan
      });

    } catch (e) {
      console.error('Paymob error:', e);
      res.status(500).json({ ok:false, error:'خطأ في بوابة الدفع، حاول مرة أخرى' });
    }
  });

  // ── 3. Webhook (Paymob callback) ────────────────────
  router.post('/webhook', express.raw({ type: '*/*' }), (req, res) => {
    // Verify HMAC
    const body = typeof req.body === 'string' ? req.body : req.body.toString();
    let data;
    try { data = JSON.parse(body); } catch { return res.sendStatus(400); }

    if (PAYMOB_HMAC) {
      const crypto   = require('crypto');
      const { obj }  = data;
      // Paymob HMAC concatenation order (exact)
      const hmac_str = [
        obj.amount_cents, obj.created_at, obj.currency, obj.error_occured,
        obj.has_parent_transaction, obj.id, obj.integration_id, obj.is_3d_secure,
        obj.is_auth, obj.is_capture, obj.is_refunded, obj.is_standalone_payment,
        obj.is_voided, obj.order.id, obj.owner, obj.pending,
        obj.source_data.pan, obj.source_data.sub_type, obj.source_data.type,
        obj.success
      ].join('');
      const computed = crypto.createHmac('sha512', PAYMOB_HMAC).update(hmac_str).digest('hex');
      if (computed !== req.query.hmac) return res.sendStatus(400);
    }

    const txn = data.obj;
    if (txn.success && !txn.is_refunded) {
      // Extract tenant_id from merchant_order_id: kash-{tenant_id}-{plan}-{ts}
      const parts = (txn.order?.merchant_order_id || '').split('-');
      if (parts.length >= 3) {
        const tenant_id = parts[1];
        const plan_key  = parts[2];
        const plan      = PLANS[plan_key];
        if (plan && tenant_id) {
          const now      = Math.floor(Date.now()/1000);
          const until    = now + plan.months * 30 * 24 * 3600;
          db.prepare('UPDATE tenants SET plan=?, plan_until=? WHERE id=?').run(plan_key.replace('_year',''), until, tenant_id);
          console.log(`✅ Subscription activated: tenant=${tenant_id} plan=${plan_key} until=${new Date(until*1000).toLocaleDateString('ar')}`);
        }
      }
    }
    res.sendStatus(200);
  });

  // ── 4. Current subscription status ──────────────────
  router.get('/status', auth, (req, res) => {
    const tenant = db.prepare('SELECT plan, plan_until FROM tenants WHERE id=?').get(req.user.tenant_id);
    const history = db.prepare('SELECT * FROM subscriptions WHERE tenant_id=? ORDER BY paid_at DESC LIMIT 10').all(req.user.tenant_id);
    const daysLeft = tenant.plan_until ? Math.max(0, Math.ceil((tenant.plan_until - Date.now()/1000) / 86400)) : null;
    res.json({ ok:true, plan: tenant.plan, plan_until: tenant.plan_until, daysLeft, history });
  });

  // ── 5. Manual upgrade (admin/cash) ──────────────────
  router.post('/manual', (req, res) => {
    if (req.headers['x-admin-key'] !== process.env.ADMIN_KEY)
      return res.status(403).json({ ok:false, error:'غير مصرّح' });
    const { tenant_id, plan_key, months=1 } = req.body;
    const plan = PLANS[plan_key] || { price:0, months };
    const now   = Math.floor(Date.now()/1000);
    const t     = db.prepare('SELECT * FROM tenants WHERE id=?').get(tenant_id);
    if (!t) return res.status(404).json({ ok:false, error:'المنشأة غير موجودة' });
    const base  = Math.max(now, t.plan_until || now); // extend if already subscribed
    const until = base + months * 30 * 24 * 3600;
    db.prepare('UPDATE tenants SET plan=?, plan_until=? WHERE id=?').run(plan_key.replace('_year',''), until, tenant_id);
    db.prepare('INSERT INTO subscriptions(id,tenant_id,plan,amount,months) VALUES(?,?,?,?,?)').run(uuid(), tenant_id, plan_key, plan.price*months, months);
    res.json({ ok:true, plan: plan_key, until: new Date(until*1000).toLocaleDateString('ar') });
  });

  return router;
};

/*
═══════════════════════════════════════════
 إضافة لملف .env.example:

PAYMOB_API_KEY=your_paymob_api_key
PAYMOB_INTEGRATION=your_card_integration_id
PAYMOB_IFRAME=your_iframe_id
PAYMOB_HMAC_SECRET=your_hmac_secret
APP_URL=https://kash.yourdomain.com

═══════════════════════════════════════════
 إضافة في server.js:

const subscriptions = require('./subscriptions');
app.use('/api/subscribe', subscriptions(db));

═══════════════════════════════════════════
 Paymob Webhook URL (في dashboard Paymob):
 https://yourdomain.com/api/subscribe/webhook

═══════════════════════════════════════════
 API Endpoints:

GET  /api/subscribe/plans          — عرض الخطط والأسعار
POST /api/subscribe/create         — إنشاء رابط دفع
     body: { plan_key: "pro" | "pro_year" | "enterprise" }
     returns: { payment_url, order_id, plan }

POST /api/subscribe/webhook        — Paymob callback (HMAC verified)

GET  /api/subscribe/status         — حالة الاشتراك + السجل
POST /api/subscribe/manual         — ترقية يدوية (admin key)
     header: x-admin-key
     body: { tenant_id, plan_key, months }
═══════════════════════════════════════════
*/
