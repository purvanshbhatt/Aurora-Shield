# AuroraShield Browser Extension

Real-time browser protection against prompt injection, phishing, and suspicious URLs.

## Files

| File | Description |
| --- | --- |
| `manifest.json` | Extension manifest (Manifest V3) |
| `content.js` | Injected into ChatGPT, Gmail, Outlook |
| `background.js` | Service worker for API calls, caching, badge updates |
| `popup.html` | Extension popup UI |
| `popup.css` | Popup styles |
| `popup.js` | Popup logic |
| `mock-backend.mjs` | Local-only mock backend for development |

## Release Setup

### 1. Live backend

The extension is preconfigured to use the live AuroraShield backend:

- API base: `https://aurora-shield--PurvanshBhatt.replit.app/api`
- Dashboard: `https://aurora-shield--PurvanshBhatt.replit.app/`

The popup includes a backend URL setting if you need to point a test install at another deployment.

Mock analysis is available only for local development by checking **Use mock analyzer** in the popup.

### 2. Add Extension Icons

Create an `icons/` directory with PNG icons at these sizes:

- `icons/icon16.png`
- `icons/icon32.png`
- `icons/icon48.png`
- `icons/icon128.png`

### 3. Install in Chrome (Developer Mode)

1. Go to `chrome://extensions`
2. Enable "Developer mode" (top right)
3. Click "Load unpacked"
4. Select this directory

### 4. Install in Firefox

1. Go to `about:debugging`
2. Click "This Firefox"
3. Click "Load Temporary Add-on"
4. Select `manifest.json`

### 5. Safari

Requires Xcode and the Safari Web Extension Converter:

```bash
xcrun safari-web-extension-converter /path/to/aurora-shield-ext
```

## Features

- **Prompt Injection Detection**: Monitors ChatGPT text inputs for injection patterns with real-time risk overlay
- **Before-You-Send Warning**: Intercepts high-risk submissions before they reach the AI
- **Phishing Detection**: Scans Gmail/Outlook email content for phishing indicators
- **Email Phrase Highlighting**: Red-underlines suspicious phrases in email content
- **URL Analysis**: Checks all page links for suspicious patterns and risk badges
- **Risk Badge**: Toolbar badge shows GREEN/YELLOW/RED risk level per tab
- **Popup Dashboard**: Shows current page risk, session stats, and recent threats

## Local Mock Backend

If you want to test without the live API, run the mock backend from the repository root:

```bash
pnpm mock:aurora
```

Then set the popup backend URL to `http://127.0.0.1:8787/api` and enable **Use mock analyzer**.
