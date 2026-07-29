# Sentinel — AI Threat Detection Agent

An interactive security operations dashboard demo. Simulates live log ingestion,
rule-based risk scoring, MITRE ATT&CK-mapped threat classification, and
incident mitigation recommendations.

**Note:** this is a working prototype with simulated data — it is not connected
to a real network or log source.

## Run it locally

You'll need [Node.js](https://nodejs.org) (v18 or newer) installed.

```bash
npm install
npm run dev
```

Open the URL it prints (usually `http://localhost:5173`).

## Build for production

```bash
npm run build
```

This creates a `dist/` folder with the static site, ready to deploy anywhere.

## Deploy a live demo (free options)

### Option A: Vercel (easiest)
1. Push this project to a GitHub repo (see below).
2. Go to [vercel.com](https://vercel.com), sign in with GitHub.
3. Click "Add New Project," select this repo.
4. Vercel auto-detects Vite — leave defaults, click Deploy.
5. You'll get a live URL like `threat-detection-dashboard.vercel.app`.

### Option B: Netlify
1. Push this project to GitHub.
2. Go to [netlify.com](https://netlify.com) → "Add new site" → "Import an existing project."
3. Select the repo. Build command: `npm run build`. Publish directory: `dist`.
4. Deploy — you'll get a live URL.

### Option C: GitHub Pages
```bash
npm install --save-dev gh-pages
```
Add to `package.json` scripts: `"deploy": "gh-pages -d dist"`, and set `"homepage"` to
your GitHub Pages URL. Then:
```bash
npm run build
npm run deploy
```

## Push to GitHub

If you haven't already:

```bash
git init
git add .
git commit -m "Initial commit: Sentinel threat detection dashboard"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
git push -u origin main
```

## Project structure

```
threat-detection-dashboard/
├── index.html              # HTML entry point
├── package.json            # Dependencies and scripts
├── vite.config.js          # Build tool config
└── src/
    ├── main.jsx             # React app entry point
    └── ThreatDetectionDashboard.jsx   # The dashboard component
```

## Tech stack

- **React** — UI framework
- **Vite** — build tool / dev server
- **Recharts** — timeline chart
- **lucide-react** — icons
