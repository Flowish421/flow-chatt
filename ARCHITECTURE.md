# Quiver — varifrån vi hämtat allt

## Context

Du vill ha en överblick över alla externa tekniker, browser-API:er, libraries och tjänster som Quiver bygger på. Det här är ett **referensdokument** — inga kodändringar planeras. Syftet är att du ska kunna svara på "vad är detta byggt av?" snabbt, och se varifrån varje feature kommer.

Stack i ett ord: **stdlib-first**. Ingen Node, ingen React, inga frontend-libraries. Backend = Python 3.14 stdlib. Frontend = vanilla HTML/CSS/JS. Allt vi inte själva skrivit pekar på en konkret extern tjänst.

---

## 1. Frontend-features → vilket Web API

| Feature | Web API | Var i `static/chat.html` |
|---|---|---|
| Skärmdelning | `navigator.mediaDevices.getDisplayMedia()` | ~rad 6219 |
| Kamera (webcam overlay) | `navigator.mediaDevices.getUserMedia({video})` | ~rad 5996, 6312 |
| Mikrofon | `navigator.mediaDevices.getUserMedia({audio})` | ~rad 3593 |
| Voice-mesh | `RTCPeerConnection` + offer/answer/ICE | ~rad 5803-6658 |
| Brusreducering | Web Audio API (AudioContext, BiquadFilter, GainNode, AnalyserNode) | ~rad 5865-5934 |
| Real-time meddelanden | `WebSocket` (primär) | ~rad 3472-3484 |
| Real-time fallback | `EventSource` (SSE) | ~rad 3532-3537 |
| Avatar-upload + resize | `FileReader.readAsDataURL()` + `<canvas>` 2D, 128×128 | ~rad 1419, 1430 |
| Drag & drop bilder | dragenter/dragleave/dragover/drop events | ~rad 3700-3719 |
| Klistra in bild | clipboard paste event | inline |
| Kopiera invite-länk | `navigator.clipboard.writeText()` | ~rad 5113, 5246, 5251, 5726 |
| Inkommande-samtal-notis | `Notification.requestPermission()` + `new Notification(...)` | ~rad 3285, 3466 |
| Lagring av token, avatar, settings | `localStorage` | ~rad 1353-1406 |
| HTTP-anrop till backend | `fetch()` | hela filen |
| Lightbox / spel-canvas | `<canvas>` 2D | ~rad 5524, 5545 |

**Inga externa JS-libraries.** Allt är native browser-APIer.

---

## 2. WebRTC-infrastruktur

**Arkitektur:** Mesh — varje deltagare öppnar en `RTCPeerConnection` mot varje annan. Skalar OK upp till ~6-8 deltagare per voice-kanal.

**STUN-servrar (Google Public — gratis):**
- `stun:stun.l.google.com:19302`
- `stun:stun1.l.google.com:19302`

**TURN-server (OpenRelay / Metered — gratis tier):**
- `turn:staticauth.openrelay.metered.ca:80` (UDP + TCP)
- `turn:staticauth.openrelay.metered.ca:443` (för restriktiva nät)
- Användarnamn `openrelayproject`, credential `openrelayprojectsecret`

**Codec / audio-tuning:** Opus 64 kbps, FEC, DTX, VBR (sätts via SDP-munging på offer/answer).

**Audio-pipeline efter mic-input:**
mic → highpass 80 Hz → lowpass 8 kHz → noise-gate (GainNode med Analyser-driven threshold) → peer

**Signaling-transport:** Vår egen `/api/signal`-endpoint via WebSocket (primärt) eller HTTP POST (fallback). Inga tredjeparts-signaling-server.

---

## 3. Backend-beroenden

**`requirements.txt`:**
- `psycopg[binary]` — PostgreSQL-driver för Render-produktion. Det är enda externa pip-paketet.

**Python stdlib (allt annat):**
- `http.server` + `socketserver.ThreadingMixIn` — HTTP-servern
- `sqlite3` — lokal DB-default
- `hashlib` — PBKDF2-SHA256 för lösenord (600k iterations)
- `hmac` — HMAC-SHA256 för highscore-sessioner och admin-token-jämförelse
- `secrets` — slumpmässiga tokens, nonces, reset-koder
- `uuid` — UUIDv4 för message-IDs, user-tokens, invite-koder
- `urllib.request` / `urllib.error` — utgående anrop till OpenAI, Anthropic, Resend
- `socket`, `struct`, `base64` — egen WebSocket-frame-parser
- `threading` — en tråd per WebSocket-/SSE-klient
- `re`, `json`, `gzip`, `time`, `os`, `sys`, `random`, `copy`

**Inget Flask, FastAPI, Django, websockets-pkg, requests, eller liknande.** Vi bygger HTTP/WebSocket från råa socketar.

---

## 4. Databaser

| Miljö | DB | Hur väljs |
|---|---|---|
| Lokalt | SQLite (fil `chat.db`) | default |
| Render | PostgreSQL via `psycopg3` | när `DATABASE_URL` env är satt |

`server.py:38-43` — auto-translaterar `postgres://` → `postgresql://` (Render ger gamla URL-formatet, psycopg3 vill ha nya).

`PgConnection`-klassen i `server.py:455` är en wrapper som översätter SQLite-syntax (`?`, `INSERT OR IGNORE/REPLACE`) till PostgreSQL-motsvarigheter — så samma kod kör på båda.

---

## 5. Externa tjänster (allt vi pratar med över nätet)

| Tjänst | Vad | Endpoint | Auth |
|---|---|---|---|
| **OpenAI** | AI-genererade spel/sajter via `/spawn` | `https://api.openai.com/v1/chat/completions` | `OPENAI_API_KEY` env |
| **Anthropic** | Alternativ AI-provider | `https://api.anthropic.com/v1/messages` | `ANTHROPIC_API_KEY` env |
| **Resend** | Email-verifieringskoder | `https://api.resend.com/emails` | `RESEND_API_KEY` env |
| **Render** | Hosting + PostgreSQL | — | platform |
| **OpenRelay** | TURN-server (NAT traversal) | `staticauth.openrelay.metered.ca` | inbakad i klient |
| **Google Fonts** | JetBrains Mono + DM Sans | `fonts.googleapis.com` / `fonts.gstatic.com` | publik |
| **Google STUN** | NAT-discovery för WebRTC | `stun.l.google.com:19302` | publik |

---

## 6. Säkerhet — vilka primitiver

- **PBKDF2-SHA256, 600k iter** (hashlib) — lösenord
- **HMAC-SHA256** (hmac) — highscore-sessions, admin-token-compare
- **`secrets.token_hex(32)`** — server-secret för HMAC, default per process
- **`secrets.randbelow()`** — 8-siffrig reset-kod
- **`hmac.compare_digest()`** — timing-safe admin-jämförelse
- **CSP via HTTP-header**, X-Content-Type-Options nosniff, X-Frame-Options DENY
- **CORS allowlist** — `CORS_ORIGIN` env, default same-origin

---

## 7. Real-time — egen vs externa

| Lager | Implementation |
|---|---|
| WebSocket-server | Egen, `WebSocketConnection`-klass i `server.py:985` (RFC 6455 hand-rolled — sec-key, frame-parsing, masking) |
| WebSocket-klient | Native `WebSocket` |
| SSE-server | Egen, i `do_GET` för `/api/events` |
| SSE-klient | Native `EventSource` |
| Voice-signaling | Vår `/api/signal` ovanpå WebSocket eller HTTP |
| Voice-media | Direkt peer-to-peer via WebRTC (Google STUN + OpenRelay TURN) |

**Inga Socket.IO, ingen ws-pkg, ingen Pusher, inget Ably.** Allt skrivet från scratch på socket-nivå.

---

## 8. AI-spawn (Game Studios)

- **Provider-switch:** `SPAWN_PROVIDER` env väljer `openai` eller `anthropic`
- **12 system-prompts** definierade i `chat.html:3837` (`SPAWN_AI_TYPES`) — GameAI, PlatformerAI, ArcadeAI, PuzzleAI, RPGAI, ShooterAI, RacerAI, StrategyAI, WebAI, ArtAI, CodeAI, SoundAI
- **MDA-framework** (Mechanics/Dynamics/Aesthetics) bakat in i alla speltyper
- **Game-output:** AI returnerar komplett HTML-fil, vi visar via iframe (sandbox `allow-scripts allow-same-origin`)
- **QuiverAPI** injiceras automatiskt i iframen → `submitScore()`, `getScores()`, `user`
- **Highscore-flow:** `/api/highscore/start` → HMAC-signerad session → `/api/highscore` med signaturen → DB

---

## 9. Spel: Among Us

- **Helt egen logik** i `server.py:191-274` (sanitize_game, broadcast_game, check_game_win, resolve_votes)
- In-memory state per grupp
- Roller: impostor vs crewmate, random assign
- Voting → majority-eject
- Win-condition: alla impostors voteade ut, eller impostors ≥ crew

---

## 10. Fonter & typografi

```html
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500&family=DM+Sans:wght@400;500;600&display=swap">
```

- **JetBrains Mono** — monospace för UI/headers
- **DM Sans** — sans-serif för body
- Preconnect-hint till `fonts.googleapis.com`

---

## 11. UI-komponenter — alla egen-byggda

- **Emoji picker** — egen, `chat.html:376-407`
- **Lightbox** — egen, `chat.html:278-283`
- **Drag-overlay** — egen, `chat.html:464-470`
- **Mobil-nav** — CSS media queries
- **Modaler** — CSS toggle på `.on`-klass
- **Spawn-popup** — egen kategoriserad meny

**Inga Tailwind, Bootstrap, MUI, eller liknande.** Custom CSS i `<style>`-blocket.

---

## 12. Deployment

- **Repo:** https://github.com/Flowish421/flow-chatt (master)
- **Hosting:** Render free tier — auto-deploy vid push till master
- **Build:** `build.sh` → `pip install -r requirements.txt`
- **Run:** `python server.py` (läser `PORT` env)
- **Persistens:** PostgreSQL på Render (gratis), SQLite lokalt
- **Konfig:** Allt via env-variabler (`OPENAI_API_KEY`, `ADMIN_PASS`, `CORS_ORIGIN`, `HIGHSCORE_SECRET`, etc)

---

## TL;DR — beroendekarta

```
Webbläsare (vanilla JS)
  ├─ WebRTC → Google STUN + OpenRelay TURN → andra peers
  ├─ WebSocket / SSE → vår Python-server
  ├─ getUserMedia / getDisplayMedia → vår mesh
  ├─ Web Audio API → brusreducering lokalt
  ├─ Google Fonts (JetBrains Mono + DM Sans)
  └─ fetch → vår REST API

Vår Python-server (stdlib + psycopg)
  ├─ SQLite (lokalt) eller PostgreSQL (Render)
  ├─ Egen WebSocket-implementation (RFC 6455 från grunden)
  ├─ Egen SSE-implementation
  ├─ → OpenAI / Anthropic (för /spawn)
  └─ → Resend (för email-verify)

Render (host)
  └─ auto-deploy från GitHub master
```

---

## Verifiering

För att bekräfta att en specifik teknologi används som beskrivet:

- **Browser-APIer:** sök efter API-namnet i `static/chat.html` med Grep, t.ex. `getDisplayMedia`, `RTCPeerConnection`, `EventSource`
- **STUN/TURN:** `grep -n "stun:\|turn:" static/chat.html`
- **Externa endpoints:** `grep -n "api.openai\|api.anthropic\|api.resend\|fonts.googleapis" -r .`
- **Stdlib-användning:** `grep -n "^import\|^from" server.py`
- **DB-driver:** öppna `requirements.txt`
- **Render-deploy:** öppna `render.yaml`, `Dockerfile`, `build.sh`

Inget av det här kräver att man kör koden — det är ren kodläsning.
