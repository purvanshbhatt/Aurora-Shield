# AuroraShield Browser Extension

Real-time browser protection against prompt injection, phishing, and suspicious URLs.

## Files

| File | Description |
|------|-------------|
| `manifest.json` | Extension manifest (Manifest V3) |
| `content.js` | Injected into ChatGPT, Gmail, Outlook |
| `background.js` | Service worker — API calls, caching, badge |
| `popup.html` | Extension popup UI |
| `popup.css` | Popup styles |
| `popup.js` | Popup logic |

## Setup

### 1. Configure API URL

In both `content.js` and `background.js`, replace:
```
const API_BASE = "https://your-api-host.replit.app/api";
```
With your deployed AuroraShield API URL.

Also update the dashboard link in `popup.js`:
```
chrome.tabs.create({ url: "https://your-api-host.replit.app/" });
```

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
