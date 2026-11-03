# IT Hardware Platform - Hostinger Business Shared Web Hosting Deployment Guide

This guide explains how to deploy **IT Hardware Platform** on a **Hostinger Business Shared Web Hosting** plan with **MySQL** database (managed via phpMyAdmin).

---

## 📋 Hostinger Environment Overview

| Item | Details |
| :--- | :--- |
| **Hosting Plan** | Hostinger Business Web Hosting / Cloud Startup |
| **Control Panel** | Hostinger hPanel |
| **Web Server** | LiteSpeed Enterprise (uses `.htaccess`) |
| **Database** | MySQL 8.0+ / MariaDB 10.4+ with phpMyAdmin |
| **Runtime** | Node.js (via Hostinger Node.js Selector) or Static Frontend + Node API |
| **App Name** | IT Hardware Platform (for AadiTech Solution) |

---

## 🚀 Step 1: Create MySQL Database in Hostinger hPanel

1. Log into your **Hostinger hPanel** (`hpanel.hostinger.com`).
2. Go to **Databases** ➔ **MySQL Databases**.
3. Create a new database:
   - **MySQL Database Name**: e.g. `u123456789_ithardware`
   - **MySQL Username**: e.g. `u123456789_admin`
   - **Password**: Create a strong password (save this for `.env`)
4. Click **Create**.
5. Note the details:
   - **Host**: `localhost` (in Hostinger, the database is on localhost)
   - **Port**: `3306`

---

## 🗄️ Step 2: Import Database Schema into phpMyAdmin

1. In hPanel ➔ **Databases**, find your new database and click **Enter phpMyAdmin**.
2. Inside phpMyAdmin, click on your database name in the left sidebar.
3. Click the **Import** tab in the top menu.
4. Click **Choose File** and upload `/database/schema.sql` from this project.
5. Click **Import / Go** at the bottom.
6. ✅ All 10+ tables (`app_users`, `company_profiles`, `customers`, `leads`, `products_catalog`, `quotations`, `sales_orders`, `purchase_orders`, `gem_tenders`, `audit_logs`) will be created along with initial AadiTech Solution master credentials.

---

## ⚙️ Step 3: Configure Environment Variables (`.env`)

In your Hostinger app directory (or via File Manager / SSH):
Create or update the `.env` file:

```env
NODE_ENV=production
PORT=3000

# Hostinger MySQL Database Credentials
DB_HOST=localhost
DB_PORT=3306
DB_USER=u123456789_admin
DB_PASSWORD=your_secure_mysql_password
DB_NAME=u123456789_ithardware
DB_SSL=false

# Gemini AI Key (for Solution BOM & autonomous AI agents)
GEMINI_API_KEY=your_gemini_api_key_here

# Telegram Bot Hub (for Real-time Profit Margin Exception approvals)
TELEGRAM_BOT_TOKEN=your_bot_father_token
TELEGRAM_ADMIN_CHAT_ID=your_telegram_id_or_group_id
```

---

## 📦 Step 4: Hostinger Node.js App Setup (hPanel)

Hostinger Business Plan includes a **Node.js Selector**:

1. In hPanel, search for **Node.js** in the search bar.
2. Click **Create Application**:
   - **Node.js version**: Choose `18.x`, `20.x`, or `22.x`.
   - **Application mode**: `Production`.
   - **Application root**: `public_html` (or a subdomain folder like `it-hardware`).
   - **Application startup file**: `dist/server.cjs`
3. Upload your project files (via Git, File Manager, or SSH).
4. Run npm install and build:
   ```bash
   npm install
   npm run build
   ```
5. Click **Start App** / **Restart App** in hPanel.

---

## 🌐 Step 5: LiteSpeed / Apache Routing (`.htaccess`)

The included `/public/.htaccess` file automatically handles:
- **HTTPS Redirection**: Forces SSL encryption across all routes.
- **SPA Fallback**: Ensures client-side routing works smoothly without 404 errors on browser page reloads.
- **Security Headers**: Blocks direct browser access to `.env` and `schema.sql`.

---

## 🔍 Verification & Diagnostics

Once deployed on your Hostinger domain, you can check system health:
- `https://yourdomain.com/api/health` ➔ Checks server and AI key status.
- `https://yourdomain.com/api/db/status` ➔ Confirms MySQL connection and shows table count.
- `https://yourdomain.com/api/hostinger/readiness` ➔ Live checklist of deployment readiness.
