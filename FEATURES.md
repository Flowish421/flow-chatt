# Quiver — Feature List

## Byggt och fungerar

### Autentisering
- Registrering med nickname + losenord (PBKDF2 600k iterationer)
- Login med nickname + losenord
- Token-baserad session (localStorage)
- Logga ut-knapp i sidebar
- Losenordsaterstallning: anvandare begar → admin genererar 8-siffrig resetkod → anvandare loggar in med koden → tvingas byta losenord
- Auto-logout vid ogiltig token
- Min 6 teckens losenord
- Token rotation vid losenordsbyte

### Grupper (Discord-stil)
- Skapa grupper (publik/privat) med auto-genererad #general kanal
- Collapsible grupper i sidebar med text/voice kanaler
- "Upptack grupper" sektion for publika grupper man inte ar med i
- Join request-system for privata grupper
- Owner kan radera grupp (cascade delete allt)
- Ownership transfer vid leave

### Invite-system (Discord-stil)
- Bjud in vanner-modal med sokbar anvandarlista
- Visar avatarer, online-status, bios
- Ett klick for att bjuda in
- Generera invite-lank (25 anvandningar, auto-kopieras)
- URL-format: /?invite=KOD&group=ID
- Invite-knapp pa varje gruppheader i sidebar
- "Bjud in vanner"-knapp i gruppinstallningar

### Custom Roller (Discord-stil)
- Owner skapar roller med namn + farg
- Default-roller: "Moderator" (rod) + "Medlem" (gra) per grupp
- Tilldela roller via toggle-knappar i grupp-installningar
- Flera roller per anvandare
- Rollkrav pa kanaler (gomda for anvandare utan rollen)
- Voice join enforce:ar rollkrav

### Anvandarprofiler
- Profilbild (upload, client-side resize till 128x128 JPEG)
- Avatar-farg (10 preset-farger)
- Banner-farg (10 preset-farger)
- Bio (max 200 tecken)
- Profilkort: klicka pa anvandarnamn → popup med banner, avatar, bio, roller
- Avatar-cirklar i chattmeddelanden

### Voice Channels (WebRTC mesh)
- Brusreducering toggle (highpass 80Hz + lowpass 18kHz + noise gate)
- Opus codec tuning: 64kbps, FEC, DTX, VBR
- ICE candidate buffering + ICE restart
- Voice-medlemmar med avatarer i sidebar
- Mikrofon/hogtalare-valjare
- Mikrofon-nivaindikator

### Skarmdelning
- Dela skarm-knapp i voice-overlayen (monitorikon)
- Video visas i resizable flytande fonster
- WebRTC video track addas till befintlig mesh
- Auto-stoppar nar browsern "Sluta dela" klickas
- Visar vem som delar i fonstret

### Meddelanden + Real-time
- Text, bilder, emojis, reactions
- Forsvinnande meddelanden (1-30s timer)
- Typing indicator ("X skriver..." med animerade dots)
- Notifikation-dots (gron puls) pa olasta kanaler
- Username-farger (konsistent hash, 20 farger)
- Roll-badges i chat
- WebSocket + SSE dual-mode
- Optimistic rendering

### Allmant (Global chatt)
- Oppen kanal for alla inloggade — chatta direkt utan att skapa grupp
- Valkomstmeddelande fran system

### UI/UX
- Vibrant fargschema (GitHub dark inspired)
- Smooth animationer (modaler, sidebar, scroll)
- Q-logga (bla cirkel med Q) pa login + favicon
- Mobil-responsivt
- Klickbara anvandarnamn → profilkort
- Emoji picker med kategorier
- Lightbox for bilder
- Drag & drop + paste for bilder

### Sakerhet (fullstandig audit)
- PBKDF2 losenordshashing (600k iterationer, backward compat)
- secrets-modul for alla sakerhetskodar
- Token-auth pa alla endpoints + WS + SSE
- Rate limiting 200/min
- XSS-skydd: safeUrl(), safeColor(), esc() overallt
- CSP via HTTP header
- WebSocket signaling identity enforcement
- localStorage crash protection
- X-Content-Type-Options: nosniff
- Minneslakar-skydd (user_msg_times cap)

### Admin-panel (/admin)
- Dashboard: users, online, kanaler, meddelanden
- Losenordsaterstallningar: se pending requests, generera resetkoder
- Kicka/radera anvandare med audit logging

---

## Nasta steg / Kan byggas

### Kort sikt
- [ ] DM (direktmeddelanden mellan anvandare)
- [ ] Notifikationer (push-notiser via Service Worker)
- [ ] Meddelande-redigering och radering
- [ ] Trad/reply-funktion (som Discord threads)
- [ ] Pinnacle meddelanden (pin messages)
- [ ] Fildelning (PDF, dokument, inte bara bilder)
- [ ] Sokfunktion (sok i meddelanden)

### Mellansikt
- [ ] Extern DB (PostgreSQL/Turso) for persistent data (Render free tier forlorar data)
- [ ] Egen doman → aktivera email-verifiering via Resend
- [ ] TURN-server for NAT traversal (voice bakom symmetric NAT)
- [ ] Video-samtal (kamera, inte bara skarmdelning)
- [ ] Roll-hierarki med drag-to-reorder
- [ ] Byta Render service name till "quiver" → quiver.onrender.com
- [ ] Anvandarstatus (online/away/DND/offline)
- [ ] Typing bubbles i DM

### Lang sikt
- [ ] End-to-end kryptering (E2EE) for DMs
- [ ] Bot/webhook-system (integrationer)
- [ ] Anpassade emojis per grupp
- [ ] Server-side rendering for SEO/preview
- [ ] Mobilapp (PWA eller React Native)
- [ ] Admin-dashboard: statistik, grafer, moderation-log
- [ ] Multi-server federation (Quiver ↔ Quiver)

---

## Teknik

- **Backend:** Python 3.14, stdlib only (http.server + ThreadingMixIn + SQLite)
- **Frontend:** Vanilla JS/HTML/CSS, single-file (chat.html ~4200 rader)
- **Voice:** WebRTC mesh med Opus codec tuning
- **Deploy:** Render free tier (auto-deploy vid push till GitHub)
- **Repo:** https://github.com/Flowish421/flow-chatt
- **Live:** https://cortex-chat.onrender.com
