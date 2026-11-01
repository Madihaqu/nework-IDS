# Static Deployment Guide: Hybrid NIDS

This repository is configured as a **100% static React + Vite web application**. The machine learning engine (synthetic network traffic generation, Random Forest signature matching, Isolation Forest anomaly scoring, and Decision Fusion) runs entirely in client-side JavaScript in the user's browser. **No Python or backend server is required.**

---

## 🛠️ Build Commands

```bash
# 1. Install dependencies
npm install

# 2. Build production static bundle (outputs to /dist)
npm run build

# 3. Test the static production bundle locally
npm run preview
```

The resulting `dist/` folder contains pure static HTML, JavaScript, CSS, and SVG files ready to be served by any CDN or static file host.

---

## 🚀 Option 1: Deploy to Vercel (Recommended, Instant)

### Method A: Deploy via GitHub (Zero Configuration)
1. Push your repository to GitHub (`main` or `master` branch).
2. Go to [vercel.com/new](https://vercel.com/new).
3. Import your GitHub repository.
4. Vercel will automatically detect `framework: vite`, `buildCommand: npm run build`, and `outputDirectory: dist`.
5. Click **Deploy**. Your site will be live on a `*.vercel.app` domain in ~30 seconds!

> **Note:** The included `vercel.json` already contains SPA routing rewrites (`/(.*) -> /index.html`) and cache headers for static assets.

### Method B: Deploy via Vercel CLI
```bash
# Install Vercel CLI globally
npm i -g vercel

# Deploy preview
vercel

# Deploy to production
vercel --prod
```

---

## 🐙 Option 2: Deploy to GitHub Pages

GitHub Pages can serve this app directly with **zero blank screen issues** because `vite.config.ts` uses `base: './'` (relative asset paths) and `public/404.html` handles SPA routing.

### Method A: Automated Deployment via GitHub Actions (Included!)
A GitHub Actions workflow is already pre-configured in `.github/workflows/deploy.yml`.

1. Push your code to GitHub.
2. In your GitHub repository, go to **Settings** → **Pages** (in the left sidebar).
3. Under **Build and deployment** → **Source**, select:
   - **GitHub Actions** (instead of "Deploy from a branch").
4. Push a commit to `main` (or go to the **Actions** tab and click **Run workflow**).
5. In ~1 minute, your site will be live at:
   `https://<your-username>.github.io/<your-repo-name>/`

### Method B: Manual Deployment via `gh-pages` Package
If you prefer deploying via terminal:
```bash
# 1. Install gh-pages as a dev dependency
npm install -D gh-pages

# 2. Add deploy script to package.json (already supported):
#    "predeploy": "npm run build",
#    "deploy": "gh-pages -d dist"

# 3. Deploy to gh-pages branch
npx gh-pages -d dist
```
Then in GitHub repository **Settings** → **Pages**, set branch to `gh-pages` and root `/`.

---

## 🛡️ Zero Blank Page Architecture Checklist

| Common Static Hosting Trap | How This Project Solves It |
| :--- | :--- |
| **Asset 404s on subpaths** (`/repo-name/assets/index.js` looking at root domain) | `vite.config.ts` specifies `base: './'`, generating relative asset URLs like `./assets/index-xxx.js` that work on any subfolder. |
| **404 on page refresh** on GitHub Pages | `public/404.html` and SPA redirect script in `index.html` seamlessly redirect route refreshes back into the app. |
| **Client-Side ML Execution** | All feature scaling, Random Forest decision heuristics, Isolation Forest anomaly scoring, and Decision Fusion run 100% in pure client-side TypeScript without calling any Python endpoints. |
| **Missing Data File** | Built-in fallback synthetic network generator creates 3,000+ realistic network flows (CIC-IDS2017 schema) on memory startup. |

---

## 📦 Deploying to Other Static Platforms

- **Netlify**: Set Build command `npm run build`, Publish directory `dist`. Add `_redirects` with `/* /index.html 200`.
- **Cloudflare Pages**: Framework preset `Vite`, Build command `npm run build`, Output directory `dist`.
- **AWS S3 / Firebase Hosting**: Upload all files inside `dist/` directly into your static bucket/hosting site.
