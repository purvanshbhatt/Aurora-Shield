# AuroraShield — Real-time AI & Phishing Protection

AuroraShield is a browser security layer designed to protect users from prompt-injection attacks, phishing, and suspicious URLs. It combines lightweight client-side detection with a backend analysis service. This repository contains the browser extension, a mock backend for development, and the web backend (separate) integration points.

This README documents project goals, architecture, developer setup, testing, release, and contribution guidelines.

--

## Highlights

- Detects prompt-injection attempts in chat inputs (ChatGPT, Gemini, etc.) and surfaces in-page warnings.
- Scans page content and emails for phishing indicators and suspicious link patterns.
- Provides a compact SOC-style popup UI with a risk gauge, breakdown bars, live feed, and quick actions.
- Designed to be lightweight, privacy-conscious, and easy to demo.

## Repository Layout

- `artifacts/aurora-shield-ext/` — Browser extension source, popup UI, content script, background worker, mock backend and packaged ZIP.
- `artifacts/aurora-shield/` — Frontend web app (dashboard, demo). (Separate deployment.)
- `api-server/` — Backend demo server for analysis (separate, may require its own deployment).
- `lib/` — Shared libraries and client SDKs.

## Architecture

1. Browser extension (content script + background worker + popup) runs in the user's browser.
2. Extension sends analysis requests to the AuroraShield backend API for intensive checks.
3. Backend returns structured results: risk_score (0-100), category, explanation, and optional patterns.
4. Extension renders overlays, input glows, banners, and updates the popup dashboard.

Local dev includes a mock backend (`mock-backend.mjs`) to test the extension without a live API.

## Getting Started (Developer)

Prerequisites

- Node.js (>=18 recommended)
- pnpm (preferred) or npm
- Chrome or Chromium-based browser for extension testing

Install

```bash
pnpm install
```

Run the mock backend (for local extension testing)

```bash
pnpm mock:aurora
```

Load the extension (Chrome)

1. Open `chrome://extensions`
2. Enable Developer mode
3. Click "Load unpacked"
4. Select `artifacts/aurora-shield-ext` directory

In the popup, set Backend URL to `http://127.0.0.1:8787/api` to point at the mock backend and enable **Use mock analyzer**.

Running the full backend

The repo includes `api-server/` that can be deployed separately. Point the popup backend URL to your deployed API base like `https://aurora.example.com/api` and disable mock mode.

## Packaging & Release

Create a distributable ZIP (already provided at `artifacts/aurora-shield-ext.zip`):

```powershell
Compress-Archive -Path artifacts/aurora-shield-ext/* -DestinationPath artifacts/aurora-shield-ext.zip
```

Commit, tag, and create a GitHub release (example):

```bash
git add artifacts/aurora-shield-ext/* package.json
git commit -m "chore(release): AuroraShield extension v1.0.0"
git tag -a v1.0.0 -m "AuroraShield v1.0.0"
git push origin main && git push origin v1.0.0
gh release create v1.0.0 artifacts/aurora-shield-ext.zip --title "AuroraShield v1.0.0" --notes "Live backend, mock backend for dev, popup backend setting, packaged ZIP."
```

## Privacy & Security

- By default, the extension sends content to a backend API for analysis. You are responsible for deploying and securing that backend and for informing users about data collection and retention.
- The popup includes a backend URL setting so deployments can be self-hosted. The mock backend never leaves the local machine.
- For production, ensure your backend enforces authentication, rate limiting, and strict CORS rules allowing only your extension origins if necessary.

## Development notes

- The extension uses `chrome.storage.local` to persist the backend URL and mock toggle.
- `content.js` performs in-page highlights and injects minimal UI elements — keep it as non-invasive as possible.
- `background.js` acts as a caching proxy and is responsible for making API requests and updating the extension badge.

## Contributing

Contributions are welcome. Please open issues or PRs. For significant changes, open an issue first to discuss the design.

Before submitting PRs:

- Run linters and formatters (repo uses Prettier and TypeScript where applicable)
- Ensure sensitive keys are never committed

## License

This project is licensed under the GNU Affero General Public License v3.0. See the `LICENSE` file for details.

---

If you'd like, I can also open a release on GitHub and attach the packaged ZIP (requires your approval to run git/gh commands from this environment).
