# AuroraShield

## Overview

Full-stack AI browser security platform. Consists of three parts:
1. **Dashboard web app** (`artifacts/aurora-shield`) — SOC-style React dashboard at `/`
2. **API server** (`artifacts/api-server`) — Express backend with detection engines at `/api`
3. **Browser extension** (`artifacts/aurora-shield-ext/`) — Loadable MV3 extension files

## Stack

- **Monorepo tool**: pnpm workspaces
- **Node.js version**: 24
- **Package manager**: pnpm
- **TypeScript version**: 5.9
- **Frontend**: React + Vite + Tailwind CSS + shadcn/ui
- **API framework**: Express 5
- **Database**: PostgreSQL + Drizzle ORM
- **Validation**: Zod (`zod/v4`), `drizzle-zod`
- **API codegen**: Orval (from OpenAPI spec)
- **Build**: esbuild (CJS bundle)

## Key Commands

- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)

## Database Schema

- **threat_events** — Logged security events (prompt injection, phishing, suspicious URLs)
  - `id`, `type` (enum), `risk_level` (enum), `risk_score` (float), `summary`, `context`, `detected_at`

## API Endpoints

- `GET /api/healthz` — Health check
- `POST /api/analyze/prompt` — Prompt injection detection (12 pattern rules + caching)
- `POST /api/analyze/phishing` — Phishing detection (phrase matching + indicator rules)
- `POST /api/analyze/url` — URL risk analysis (8 suspicious URL patterns)
- `GET /api/analyze/stats` — Aggregate detection statistics
- `GET /api/analyze/recent` — Recent threat events feed (last 20)

## Dashboard Pages

- `/` — System Overview: live stats + recent threat feed
- `/threats` — Threat Log: filterable full event list
- `/analyzer` — Manual Analyzer: paste text/URL and analyze on-demand
- `/extension` — Extension Setup: install instructions for Chrome/Firefox/Safari

## Browser Extension (`artifacts/aurora-shield-ext/`)

Extension files ready to load in developer mode. Before using:
1. In `content.js` and `background.js`, replace `API_BASE` with your deployed API URL
2. In `popup.js`, update the dashboard link URL
3. Add icons in `icons/` directory (16, 32, 48, 128 px PNGs)

Files: `manifest.json`, `content.js`, `background.js`, `popup.html`, `popup.css`, `popup.js`

See `artifacts/aurora-shield-ext/README.md` for full installation instructions.

## Detection Engines

All detection runs server-side with in-memory LRU caching:
- **Prompt injection**: 12 regex patterns (ignore instructions, role override, jailbreaks, token injection, prompt extraction, etc.)
- **Phishing**: 23 phrase matches + 6 indicator patterns (lookalike domains, urgency timers, sensitive data requests)
- **URL analysis**: 8 suspicious patterns (raw IPs, shorteners, long subdomains, lookalike brands, suspicious TLDs, URL encoding)

Risk levels: `safe` → `low` → `medium` → `high` → `critical`
