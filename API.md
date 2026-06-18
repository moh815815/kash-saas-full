# KASH API Reference

Base URL: `http://your-server:3000/api`

All protected routes require:
```
Authorization: Bearer <token>
```

---

## Auth

### POST /register
```json
{ "businessName":"صيدلية النور", "businessType":"pharmacy",
  "ownerName":"أحمد", "email":"a@a.com", "password":"123456" }
```
Returns `{ token, tenant }`

### POST /login
```json
{ "email":"a@a.com", "password":"123456", "tenantSlug":"pharmacy-nour-xyz" }
```
Returns `{ token, user, tenant }`

---

## Products

| Method | Endpoint | Role |
|--------|----------|------|
| GET | /products | any |
| GET | /products?search=بنادول&low_stock=1 | any |
| POST | /products | owner/manager |
| PUT | /products/:id | owner/manager |
| DELETE | /products/:id | owner/manager |

### POST /products body:
```json
{ "name":"بنادول 500mg", "barcode":"6221234", "category":"مسكنات",
  "price":15, "cost":10, "stock":100, "min_stock":20, "unit":"علبة" }
```

---

## Sales (POS Checkout)

### POST /sales
```json
{
  "items": [
    { "product_id":"uuid", "qty":2, "price":15 }
  ],
  "payment": "cash",
  "discount": 5,
  "paid": 30
}
```
Returns full invoice + change amount. Automatically deducts stock.

### GET /sales?from=2026-01-01&to=2026-12-31&page=1
### GET /sales/:id
### POST /sales/:id/return  (owner/manager only)

---

## Reports

| Endpoint | Returns |
|----------|---------|
| GET /reports/dashboard | Today KPIs, low stock, top 5 products |
| GET /reports/weekly | Last 7 days revenue chart |
| GET /reports/monthly?year=2026 | 12-month summary with expenses |

---

## Expenses

### POST /expenses
```json
{ "category":"إيجار", "amount":5000, "note":"يناير 2026" }
```

### GET /expenses?from=2026-01-01&to=2026-01-31

---

## Users (Cashiers)

### GET /users  (owner only)
### POST /users (owner only, plan limits apply)
```json
{ "name":"كاشير سارة", "email":"sara@nour.com", "password":"pass123", "role":"cashier" }
```

---

## Tenant

### GET /tenant — tenant info + plan limits
### PUT /tenant — update name/type (owner only)

---

## Plan Limits

| Feature | Free | Pro (200 ج) | Enterprise (500 ج) |
|---------|------|------------|-------------------|
| Cashiers | 1 | 3 | ∞ |
| Products | 200 | ∞ | ∞ |
| Reports | Weekly | Live | Live |

---

## Platform Admin (hidden from tenants)

```
GET /api/admin/overview
Header: x-admin-key: your-admin-key
```
Returns: total tenants, GMV, plan breakdown, recent subscriptions.

---

## Deployment (VPS $10/month)

```bash
git clone ...
cd kash-backend
npm install
cp .env.example .env
# Edit .env with your secrets
node server.js

# Or with PM2 (recommended):
npm i -g pm2
pm2 start server.js --name kash
pm2 save && pm2 startup
```

## Nginx reverse proxy (optional):
```nginx
server {
    listen 80;
    server_name yourdomain.com;
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_cache_bypass $http_upgrade;
    }
}
```
