import React, { useState } from 'react';
import {
  Rocket,
  CheckCircle2,
  Copy,
  Check,
  Terminal,
  Globe,
  Github,
  ServerOff,
  ShieldCheck,
  ExternalLink,
  Cpu,
  Layers,
  FileCode,
  AlertCircle
} from 'lucide-react';

export const DeploymentGuide: React.FC = () => {
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [activePlatform, setActivePlatform] = useState<'vercel' | 'github' | 'checklist'>('vercel');

  const handleCopy = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const VERCEL_JSON_TEXT = `{
  "framework": "vite",
  "buildCommand": "npm run build",
  "outputDirectory": "dist",
  "rewrites": [
    {
      "source": "/(.*)",
      "destination": "/index.html"
    }
  ]
}`;

  const GITHUB_ACTIONS_YML = `name: Deploy Static NIDS App to GitHub Pages

on:
  push:
    branches: [ main, master ]
  workflow_dispatch:

permissions:
  contents: read
  pages: write
  id-token: write

concurrency:
  group: 'pages'
  cancel-in-progress: false

jobs:
  build-and-deploy:
    environment:
      name: github-pages
      url: \${{ steps.deployment.outputs.page_url }}
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Node.js 20
        uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: 'npm'

      - name: Install dependencies
        run: npm ci || npm install

      - name: Build static site
        run: npm run build

      - name: Setup Pages
        uses: actions/configure-pages@v5

      - name: Upload artifact
        uses: actions/upload-pages-artifact@v3
        with:
          path: './dist'

      - name: Deploy to GitHub Pages
        id: deployment
        uses: actions/deploy-pages@v4`;

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Hero Banner */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-blue-950/70 via-slate-900 to-indigo-950/60 border border-blue-500/30 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <span className="p-1.5 rounded-lg bg-blue-500/20 text-blue-400 border border-blue-500/30">
              <Rocket className="w-5 h-5" />
            </span>
            <span className="text-xs font-bold uppercase tracking-wider text-blue-400">
              Zero-Server Static Deployment
            </span>
            <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
              Vercel & GitHub Pages Ready
            </span>
          </div>
          <h2 className="text-xl font-bold text-slate-100">
            Deploy Hybrid NIDS Anywhere Without a Python Backend
          </h2>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl leading-relaxed">
            The entire Hybrid NIDS architecture (synthetic flow generation, Random Forest signature matching, Isolation Forest anomaly scoring, and Decision Fusion) runs 100% client-side in the browser. Build it into static HTML/CSS/JS and host it for free on Vercel or GitHub Pages.
          </p>
        </div>

        <div className="flex flex-col sm:flex-row gap-2 shrink-0">
          <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 text-xs flex items-center gap-2.5">
            <ServerOff className="w-4 h-4 text-emerald-400" />
            <div>
              <div className="font-semibold text-slate-200">Zero Backend Servers</div>
              <div className="text-[10px] text-slate-400">Pure Client-Side React + Vite</div>
            </div>
          </div>
        </div>
      </div>

      {/* Platform Switcher */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
        <button
          onClick={() => setActivePlatform('vercel')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition-all ${
            activePlatform === 'vercel'
              ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/20'
              : 'text-slate-400 hover:text-slate-200 bg-slate-900 border border-slate-800 hover:border-slate-700'
          }`}
        >
          <Globe className="w-4 h-4" />
          Deploy to Vercel (Instant)
        </button>

        <button
          onClick={() => setActivePlatform('github')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition-all ${
            activePlatform === 'github'
              ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/20'
              : 'text-slate-400 hover:text-slate-200 bg-slate-900 border border-slate-800 hover:border-slate-700'
          }`}
        >
          <Github className="w-4 h-4" />
          Deploy to GitHub Pages
        </button>

        <button
          onClick={() => setActivePlatform('checklist')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition-all ${
            activePlatform === 'checklist'
              ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/20'
              : 'text-slate-400 hover:text-slate-200 bg-slate-900 border border-slate-800 hover:border-slate-700'
          }`}
        >
          <ShieldCheck className="w-4 h-4" />
          Zero Blank Screen Architecture Check
        </button>
      </div>

      {/* Platform Content: VERCEL */}
      {activePlatform === 'vercel' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Step 1: Push & Connect */}
            <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-blue-400 uppercase tracking-wider">
                  Method 1: Git Integration (Easiest)
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-500/10 text-blue-300 border border-blue-500/20">
                  30 Seconds
                </span>
              </div>
              <h3 className="text-sm font-semibold text-slate-100">
                Automatic Vercel Import
              </h3>
              <ol className="text-xs text-slate-300 space-y-2.5 list-decimal list-inside leading-relaxed">
                <li>Push this repository to your GitHub account (branch <code>main</code>).</li>
                <li>Go to <a href="https://vercel.com/new" target="_blank" rel="noreferrer" className="text-blue-400 underline font-semibold">vercel.com/new</a> and connect your GitHub account.</li>
                <li>Click <strong>Import</strong> next to your repository.</li>
                <li>Vercel automatically detects Vite with:
                  <div className="mt-1 p-2 rounded bg-slate-950 font-mono text-[11px] text-slate-300 space-y-0.5 border border-slate-800">
                    <div>Framework Preset: <strong>Vite</strong></div>
                    <div>Build Command: <strong>npm run build</strong></div>
                    <div>Output Directory: <strong>dist</strong></div>
                  </div>
                </li>
                <li>Click <strong>Deploy</strong>. Your static site is live on HTTPS immediately!</li>
              </ol>
            </div>

            {/* Step 2: Vercel CLI */}
            <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-emerald-400 uppercase tracking-wider">
                  Method 2: Command Line (CLI)
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/20">
                  Terminal
                </span>
              </div>
              <h3 className="text-sm font-semibold text-slate-100">
                Deploy with 2 Commands
              </h3>
              <p className="text-xs text-slate-400">
                Deploy directly from your computer terminal without creating a Git repository:
              </p>

              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-emerald-400 relative group">
                <button
                  onClick={() => handleCopy('cli-cmd', 'npm i -g vercel\nvercel --prod')}
                  className="absolute right-2 top-2 p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
                >
                  {copiedId === 'cli-cmd' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
                <div className="text-slate-500"># 1. Install Vercel CLI</div>
                <div>npm i -g vercel</div>
                <div className="text-slate-500 mt-2"># 2. Deploy to Production</div>
                <div>vercel --prod</div>
              </div>
            </div>
          </div>

          {/* Vercel Configuration Code Box */}
          <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <h4 className="text-xs font-semibold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                  <FileCode className="w-4 h-4 text-purple-400" />
                  Pre-configured <code>vercel.json</code> (Already Created in Root)
                </h4>
                <p className="text-xs text-slate-400 mt-0.5">
                  Provides SPA client-side rewrite rules so route refreshes never return a 404 error.
                </p>
              </div>
              <button
                onClick={() => handleCopy('vercel-json', VERCEL_JSON_TEXT)}
                className="py-1 px-2.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs flex items-center gap-1.5 transition-colors"
              >
                {copiedId === 'vercel-json' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                Copy vercel.json
              </button>
            </div>

            <pre className="p-4 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 overflow-x-auto">
              {VERCEL_JSON_TEXT}
            </pre>
          </div>
        </div>
      )}

      {/* Platform Content: GITHUB PAGES */}
      {activePlatform === 'github' && (
        <div className="space-y-6">
          <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                  <Github className="w-4 h-4 text-slate-100" />
                  Automated GitHub Pages Deployment (Zero Blank Screen)
                </h3>
                <p className="text-xs text-slate-400">
                  Follow these 3 simple clicks in your GitHub repository:
                </p>
              </div>
              <span className="text-xs font-mono text-emerald-400 bg-emerald-500/10 px-2.5 py-1 rounded border border-emerald-500/30">
                Built-in Actions Workflow
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
              <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5">
                <span className="w-5 h-5 rounded-full bg-blue-600/30 text-blue-400 border border-blue-500/40 inline-flex items-center justify-center font-bold text-[11px] mb-1">
                  1
                </span>
                <div className="font-semibold text-slate-200">Push to GitHub</div>
                <p className="text-slate-400">
                  Push this repository to GitHub on <code>main</code> or <code>master</code>.
                </p>
              </div>

              <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5">
                <span className="w-5 h-5 rounded-full bg-blue-600/30 text-blue-400 border border-blue-500/40 inline-flex items-center justify-center font-bold text-[11px] mb-1">
                  2
                </span>
                <div className="font-semibold text-slate-200">Enable GitHub Pages</div>
                <p className="text-slate-400">
                  In your repository, go to <strong>Settings</strong> &rarr; <strong>Pages</strong>. Under <strong>Source</strong>, choose <strong>GitHub Actions</strong>.
                </p>
              </div>

              <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5">
                <span className="w-5 h-5 rounded-full bg-blue-600/30 text-blue-400 border border-blue-500/40 inline-flex items-center justify-center font-bold text-[11px] mb-1">
                  3
                </span>
                <div className="font-semibold text-slate-200">Site is Live!</div>
                <p className="text-slate-400">
                  GitHub will automatically run <code>deploy.yml</code> and host your app at <code>https://&lt;user&gt;.github.io/&lt;repo&gt;/</code>.
                </p>
              </div>
            </div>

            <div className="pt-2">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-semibold text-slate-300">
                  Included Workflow: <code>.github/workflows/deploy.yml</code>
                </span>
                <button
                  onClick={() => handleCopy('gh-yml', GITHUB_ACTIONS_YML)}
                  className="py-1 px-2.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs flex items-center gap-1.5 transition-colors"
                >
                  {copiedId === 'gh-yml' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  Copy Workflow YAML
                </button>
              </div>
              <pre className="p-4 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 overflow-x-auto max-h-72">
                {GITHUB_ACTIONS_YML}
              </pre>
            </div>
          </div>
        </div>
      )}

      {/* Platform Content: CHECKLIST & ANTI-BLANK-SCREEN */}
      {activePlatform === 'checklist' && (
        <div className="space-y-4">
          <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-4">
            <div>
              <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                Zero Blank Page Architecture Safeguards
              </h3>
              <p className="text-xs text-slate-400">
                Why standard React projects often break on GitHub Pages and how this project prevents it:
              </p>
            </div>

            <div className="space-y-3">
              {/* Check 1 */}
              <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 flex items-start gap-3">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                <div>
                  <div className="text-xs font-bold text-slate-200">
                    Relative Base Asset Path (<code>base: './'</code>)
                  </div>
                  <p className="text-xs text-slate-400 mt-0.5">
                    <strong>Problem:</strong> Default Vite builds use <code>base: '/'</code>, which requests <code>https://user.github.io/assets/index.js</code> instead of <code>https://user.github.io/my-repo/assets/index.js</code>, resulting in 404s and a blank white screen.
                    <br />
                    <strong>Our Solution:</strong> <code>vite.config.ts</code> is set to <code>base: './'</code>. Built assets load relatively regardless of domain or subfolder.
                  </p>
                </div>
              </div>

              {/* Check 2 */}
              <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 flex items-start gap-3">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                <div>
                  <div className="text-xs font-bold text-slate-200">
                    SPA Route Fallback (<code>public/404.html</code> &amp; <code>vercel.json</code>)
                  </div>
                  <p className="text-xs text-slate-400 mt-0.5">
                    <strong>Problem:</strong> Refreshing the browser on a sub-route produces a hosting provider 404 error page.
                    <br />
                    <strong>Our Solution:</strong> <code>vercel.json</code> rewrites all paths to <code>/index.html</code>, and <code>public/404.html</code> smoothly redirects back into the SPA.
                  </p>
                </div>
              </div>

              {/* Check 3 */}
              <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 flex items-start gap-3">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                <div>
                  <div className="text-xs font-bold text-slate-200">
                    Client-Side Machine Learning Execution
                  </div>
                  <p className="text-xs text-slate-400 mt-0.5">
                    <strong>Problem:</strong> Traditional NIDS prototypes require a live Python backend running Streamlit, Flask, or FastAPI, which cannot be hosted on free static tiers like GitHub Pages or Vercel Hobby.
                    <br />
                    <strong>Our Solution:</strong> All feature scaling, Random Forest classification heuristics, Isolation Forest anomaly scoring, and Decision Fusion run 100% in client-side TypeScript in the browser.
                  </p>
                </div>
              </div>

              {/* Check 4 */}
              <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 flex items-start gap-3">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                <div>
                  <div className="text-xs font-bold text-slate-200">
                    Out-of-the-Box In-Memory Data Generation
                  </div>
                  <p className="text-xs text-slate-400 mt-0.5">
                    <strong>Problem:</strong> Missing local CSV files cause runtime crashes on remote deployment.
                    <br />
                    <strong>Our Solution:</strong> Built-in realistic synthetic generator populates 3,000+ flows (CIC-IDS2017 schema) on initial load, with support for uploading external CSV files dynamically.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Local Testing Box */}
      <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-slate-300">
          <Terminal className="w-4 h-4 text-cyan-400" />
          <span>Test the production static build locally before deploying:</span>
        </div>
        <div className="p-1.5 px-3 rounded bg-slate-900 border border-slate-800 font-mono text-cyan-400 text-[11px] select-all">
          npm run build &amp;&amp; npm run preview
        </div>
      </div>
    </div>
  );
};
