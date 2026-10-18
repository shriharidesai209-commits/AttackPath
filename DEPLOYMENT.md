# AttackPath — Production Deployment Guide

This guide provides step-by-step instructions for deploying the AttackPath platform to production:
- **Backend API**: Hosted on [Render](https://render.com) (FastAPI + Uvicorn)
- **Frontend App**: Hosted on [Vercel](https://vercel.com) (Next.js 16 + React Flow)
- **Graph Database**: Managed [FalkorDB Cloud](https://falkordb.com) instance

---

## 1. Architecture & Network Flow

```
[Browser / Security Analyst]
             │
             ▼
    [Vercel: Next.js Frontend]
      (Root Directory: frontend)
             │
             │ Server-Side Proxy Rewrites (/api/v1/*, /health/*)
             │ Configured via: BACKEND_URL=https://<render-service>.onrender.com
             ▼
    [Render: FastAPI Backend]
      (uvicorn attackpath.api.app:app --host 0.0.0.0 --port $PORT)
             │
             │ Secure TLS (rediss://)
             ▼
    [FalkorDB Cloud Instance]
      (Graph: attackpath_baseline)
```

---

## 2. Step 1: Deploy Backend on Render

Deploy the backend first so you have its public URL ready before configuring the frontend.

### Option A: Via Render Dashboard (Recommended)

1. Log in to your [Render Dashboard](https://dashboard.render.com/).
2. Click **New +** → **Web Service**.
3. Connect your GitHub repository: `https://github.com/shriharidesai209-commits/AttackPath`.
4. Configure service settings:
   - **Name**: `attackpath-api` (or your preferred name)
   - **Region**: Choose the region closest to your FalkorDB Cloud instance
   - **Branch**: `main`
   - **Root Directory**: `.` (leave as root)
   - **Runtime**: `Python 3`
   - **Build Command**:
     ```bash
     pip install --upgrade pip && pip install -r requirements.txt
     ```
   - **Start Command**:
     ```bash
     uvicorn attackpath.api.app:app --host 0.0.0.0 --port $PORT
     ```
   - **Instance Type**: Free or Starter
5. Under **Advanced**, set **Health Check Path** to:
   ```text
   /health
   ```
   *(Note: `/health` is the lightweight liveness probe. It confirms process readiness without overloading the database during zero-downtime rolling deploys.)*
6. Add the following **Environment Variables** (enter real secrets securely in the Render dashboard):

   | Variable Name | Example / Default Value | Purpose |
   | :--- | :--- | :--- |
   | `APP_ENV` | `production` | Enables production mode & strict error handling |
   | `LOG_LEVEL` | `INFO` | Global application logging level |
   | `FALKORDB_HOST` | `your-cluster.cloud.falkordb.com` | FalkorDB Cloud hostname (from FalkorDB console) |
   | `FALKORDB_PORT` | `6379` | FalkorDB Cloud port (typically 6379 or 6380) |
   | `FALKORDB_USERNAME` | *(leave empty or enter if required)* | FalkorDB Cloud username (often empty for default) |
   | `FALKORDB_PASSWORD` | `your-falkordb-password` | **Private** FalkorDB Cloud password |
   | `FALKORDB_SSL` | `true` | **Must be `true`** for FalkorDB Cloud TLS |
   | `FALKORDB_BASELINE_GRAPH` | `attackpath_baseline` | Target graph key |
   | `FALKORDB_TIMEOUT_MS` | `5000` | Query timeout in milliseconds |
   | `LLM_PROVIDER` | `none` | Deterministic security rule engine |

7. Click **Create Web Service**.
8. Wait for Render to build and deploy. Once live, note your public Render URL:
   ```text
   https://attackpath-api-xxxx.onrender.com
   ```

### Option B: Via Render Blueprint (`render.yaml`)

The repository includes a ready-to-use `render.yaml` configuration.
1. In Render, select **New +** → **Blueprint**.
2. Select the `AttackPath` repository.
3. Render will parse `render.yaml` automatically. Enter your private FalkorDB credentials for the variables marked `sync: false`.

### Verify Backend Health

From your terminal or browser, verify both endpoints:
```bash
# 1. Liveness check (process running)
curl https://attackpath-api-xxxx.onrender.com/health

# Expected response:
# {"status":"ok","app":"AttackPath","environment":"production"}

# 2. Database readiness check (connected to FalkorDB Cloud)
curl https://attackpath-api-xxxx.onrender.com/health/ready

# Expected response:
# {"status":"ready","database":"connected","graph":"attackpath_baseline"}
```

---

## 3. Step 2: Deploy Frontend on Vercel

### Deploy via Vercel Dashboard

1. Log in to [Vercel](https://vercel.com).
2. Click **Add New…** → **Project**.
3. Import the GitHub repository: `shriharidesai209-commits/AttackPath`.
4. In the **Configure Project** screen:
   - **Project Name**: `attackpath` (or preferred name)
   - **Framework Preset**: `Next.js`
   - **Root Directory**: Click **Edit** and set to:
     ```text
     frontend
     ```
     *(CRITICAL: The Next.js frontend code is located inside the `frontend/` directory.)*
   - **Build and Output Settings**: Leave defaults (`npm run build`, output `.next`).
5. Under **Environment Variables**, add:

   | Variable Name | Value | Purpose |
   | :--- | :--- | :--- |
   | `BACKEND_URL` | `https://attackpath-api-xxxx.onrender.com` | Render Backend URL (no trailing slash) |

   *(Important: Do NOT prefix with `NEXT_PUBLIC_`. The Next.js server-side proxy rewrites use this privately to route `/api/v1/*` and `/health/*` calls without exposing the backend URL or credentials in client bundles.)*

6. Click **Deploy**.
7. Vercel will build the frontend bundle and generate static pages. Once complete, your site will be live at:
   ```text
   https://attackpath-xxxx.vercel.app
   ```

---

## 4. End-to-End Production Verification Checklist

1. **Sign-In & Auth (`/`)**:
   - Open `https://attackpath-xxxx.vercel.app/`.
   - Verify the login screen renders cleanly with the warm cream aesthetic.
   - Enter credentials or click "Sign In to Investigation Platform".
2. **Investigation Workspace (`/investigate`)**:
   - Confirm that the attack graph loads nodes and relationships from the live FalkorDB Cloud instance.
   - Verify two attack paths are discovered between `John Doe (usr_jdoe)` and `Customer-Vault-DB (db_customer_vault)`.
   - Test the Hop Navigator: inspect all hops ("Signs In To", "Runs With Permissions Of", "Can Access"). Confirm labels are readable and unclipped.
   - Verify the Evidence & Risk Inspector displays the active-hop directional flow, Cypher notation, and observed evidence.
3. **Remediation Studio (`/remediate`)**:
   - Verify Outcome B shows 1 residual route and Target Reachable.
   - Test "Simulate Revocation (Outcome A)" and confirm 0 residual routes, Target Severed, and Risk 0/100.
   - Test Reset to restore baseline state.
   - Test "Export Remediation Policy" modal: copy Terraform / AWS IAM policy block.

---

## 5. Troubleshooting & Common Issues

| Issue | Root Cause | Solution |
| :--- | :--- | :--- |
| **Backend Health Check Times Out on Render** | Render health check configured to `/health/ready` when DB connection is slow. | Ensure **Health Check Path** is set to `/health` (liveness), not `/health/ready`. |
| **FalkorDB Database Unavailable (503)** | Missing TLS or wrong port/password in Render environment variables. | Verify `FALKORDB_SSL=true`. Double-check `FALKORDB_HOST`, `FALKORDB_PORT`, and `FALKORDB_PASSWORD` in Render dashboard. |
| **Frontend Shows "Cannot Connect to Backend" or 404** | Missing or incorrect `BACKEND_URL` in Vercel settings. | Set `BACKEND_URL=https://<render-url>.onrender.com` in Vercel Environment Variables and trigger a **Redeploy**. |
| **Vercel Build Fails to Find `package.json`** | Root Directory in Vercel left as `.` instead of `frontend`. | Go to Vercel Project Settings → General → **Root Directory**, set to `frontend`, and redeploy. |
| **Render Service Goes to Sleep (Free Tier)** | Render free tier spins down after 15 minutes of inactivity. | Allow 30–50 seconds on the first cold request, or upgrade to Render Starter plan for persistent uptime. |
