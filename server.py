"""
Cortex Chat — Lightweight real-time chat server.
Python 3.10+, zero external dependencies (stdlib only).
Deploy anywhere: Render, Railway, Fly.io, or localhost.
"""

import json
import os
import sqlite3
import uuid
import time
import threading
import re
import hashlib
import hmac
import struct
import base64
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote
from pathlib import Path
from datetime import datetime, timezone
from queue import Queue, Empty
from socketserver import ThreadingMixIn

DB_PATH = os.environ.get("CHAT_DB", "chat.db")
PORT = int(os.environ.get("PORT", "8080"))
HOST = os.environ.get("HOST", "0.0.0.0")
MAX_BODY = 5 * 1024 * 1024  # 5MB max for image uploads
MAX_ATTACHMENT_SIZE = 2 * 1024 * 1024  # 2MB per image base64
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")  # Set for delete protection
CORS_ORIGIN = os.environ.get("CORS_ORIGIN", "*")  # Set to your domain in prod
ADMIN_USER = os.environ.get("ADMIN_USER", "Flow")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "tnd421")

WELCOME_TEXT = """Valkommen till Flow Chatt!

Hur det fungerar:
- Offentliga rum: alla kan se och lasa. Klicka "Ga med" for att skriva.
- Privata rum: bara inbjudna kan se och skriva. Skaparen bjuder in via namn eller kod.
- Skapa rum: klicka "+ Skapa rum" i sidofaltet.
- Emojis: klicka emoji-knappen eller reagera pa meddelanden med +
- Bilder: klistra in, dra & slapp, eller klicka gem-ikonen.

Regler:
- Var schysst mot varandra
- Inget spam
- Admins kan kicka/radera konton

Det har rummet ar skrivskyddat."""

# --- Membership cache (in-memory for fast SSE filtering) ---
membership_cache = {}  # room_name -> set(username)
membership_lock = threading.Lock()
# Channel visibility cache
visibility_cache = {}  # room_name -> 'public'|'private'|'system'
visibility_lock = threading.Lock()


def load_caches():
    """Load membership and visibility caches from DB."""
    db = get_db()
    # Membership
    rows = db.execute("SELECT room, username FROM room_members").fetchall()
    cache = {}
    for r in rows:
        cache.setdefault(r["room"], set()).add(r["username"])
    with membership_lock:
        membership_cache.clear()
        membership_cache.update(cache)
    # Visibility
    rows = db.execute("SELECT name, visibility FROM channels").fetchall()
    vcache = {}
    for r in rows:
        vcache[r["name"]] = r["visibility"] or "public"
    with visibility_lock:
        visibility_cache.clear()
        visibility_cache.update(vcache)
    db.close()


def cache_add_member(room, username):
    with membership_lock:
        membership_cache.setdefault(room, set()).add(username)


def cache_remove_member(room, username):
    with membership_lock:
        if room in membership_cache:
            membership_cache[room].discard(username)


def cache_set_visibility(room, vis):
    with visibility_lock:
        visibility_cache[room] = vis


def is_member(room, username):
    with membership_lock:
        return username in membership_cache.get(room, set())


def check_room_access(db, room_name, username=None):
    """Returns (room_row, access_level) or (None, None).
    access_level: 'system' | 'read' | 'write' | 'owner'
    """
    room = db.execute("SELECT * FROM channels WHERE name = ?", (room_name,)).fetchone()
    if not room:
        return None, None
    vis = room["visibility"] or "public"
    if vis == "system":
        return room, "system"
    if vis == "public":
        if not username:
            return room, "read"
        member = db.execute("SELECT role FROM room_members WHERE room = ? AND username = ?", (room_name, username)).fetchone()
        if member:
            return room, "owner" if member["role"] == "owner" else "write"
        return room, "read"
    if vis == "private":
        if not username:
            return None, None
        member = db.execute("SELECT role FROM room_members WHERE room = ? AND username = ?", (room_name, username)).fetchone()
        if not member:
            return None, None
        return room, "owner" if member["role"] == "owner" else "write"
    return None, None


# --- DoS protection limits ---
MAX_USERS = 500               # Max registered users
MAX_CHANNELS = 50             # Max channels
MAX_MESSAGES = 50000          # Max total messages before pruning oldest
MAX_MESSAGES_PER_USER_PER_MIN = 10  # Spam protection per user
MAX_ADMIN_SESSIONS = 10       # Cap admin session tokens
SSE_CLIENT_TIMEOUT = 3600     # SSE connections killed after 1 hour
MAX_THREADS = 50              # Max concurrent threads (prevents thread exhaustion)
REQUEST_TIMEOUT = 30          # Socket timeout for slow clients (anti-Slowloris)
MAX_SSE_PER_IP = 3            # Max SSE connections per IP
MAX_QUEUE_SIZE = 50           # Max queued SSE events per client
MAX_RATE_LIMIT_ENTRIES = 10000  # Cap rate_limits dict size to prevent memory leak
user_msg_times = {}           # author -> [timestamps] for per-user spam limiting
user_msg_lock = threading.Lock()


def check_user_spam(author):
    """Returns True if allowed, False if user is sending too fast."""
    now_t = time.time()
    with user_msg_lock:
        if author not in user_msg_times:
            user_msg_times[author] = []
        user_msg_times[author] = [t for t in user_msg_times[author] if now_t - t < 60]
        if len(user_msg_times[author]) >= MAX_MESSAGES_PER_USER_PER_MIN:
            return False
        user_msg_times[author].append(now_t)
        return True


def prune_old_messages(db):
    """Delete oldest messages if over MAX_MESSAGES. Keeps DB from growing forever."""
    count = db.execute("SELECT COUNT(*) as c FROM messages").fetchone()["c"]
    if count > MAX_MESSAGES:
        delete_count = count - int(MAX_MESSAGES * 0.9)
        db.execute("""
            DELETE FROM messages WHERE id IN (
                SELECT id FROM messages ORDER BY created_at ASC LIMIT ?
            )
        """, (delete_count,))
        db.commit()


# --- Database ---

def _harden_conn(conn):
    """Disable dangerous SQLite features on a connection."""
    try:
        conn.execute("PRAGMA trusted_schema=OFF")
    except sqlite3.OperationalError:
        pass
    def _authorizer(action, arg1, arg2, db_name, trigger):
        SQLITE_ATTACH = 24
        SQLITE_DETACH = 25
        SQLITE_DENY = 1
        SQLITE_OK = 0
        if action in (SQLITE_ATTACH, SQLITE_DETACH):
            return SQLITE_DENY
        return SQLITE_OK
    conn.set_authorizer(_authorizer)


def init_db():
    conn = sqlite3.connect(DB_PATH)
    _harden_conn(conn)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            channel TEXT NOT NULL DEFAULT 'general',
            author TEXT NOT NULL,
            content TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            attachments TEXT DEFAULT '[]',
            created_at TEXT NOT NULL
        )
    """)
    try:
        conn.execute("ALTER TABLE messages ADD COLUMN attachments TEXT DEFAULT '[]'")
    except sqlite3.OperationalError:
        pass
    conn.execute("""
        CREATE TABLE IF NOT EXISTS channels (
            name TEXT PRIMARY KEY,
            display_name TEXT,
            topic TEXT DEFAULT '',
            visibility TEXT NOT NULL DEFAULT 'public',
            owner TEXT,
            created_by TEXT,
            created_at TEXT NOT NULL
        )
    """)
    # Migration: add visibility/owner columns if missing
    for col, default in [("visibility", "'public'"), ("owner", "NULL")]:
        try:
            conn.execute(f"ALTER TABLE channels ADD COLUMN {col} TEXT DEFAULT {default}")
        except sqlite3.OperationalError:
            pass
    conn.execute("CREATE INDEX IF NOT EXISTS idx_msg_channel ON messages(channel, created_at)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS room_members (
            room TEXT NOT NULL,
            username TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'member',
            joined_at TEXT NOT NULL,
            PRIMARY KEY (room, username)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_members_user ON room_members(username)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS invites (
            code TEXT PRIMARY KEY,
            room TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            uses_left INTEGER DEFAULT 1,
            expires_at TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_invites_room ON invites(room)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS reactions (
            id TEXT PRIMARY KEY,
            message_id TEXT NOT NULL,
            emoji TEXT NOT NULL,
            author TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(message_id, emoji, author)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_react_msg ON reactions(message_id)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            token TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL
        )
    """)
    # Seed the system room "allmant" (read-only instructions)
    conn.execute("""
        INSERT OR IGNORE INTO channels (name, display_name, topic, visibility, owner, created_by, created_at)
        VALUES ('allmant', 'Allmant', 'Instruktioner och regler', 'system', 'system', 'system', ?)
    """, (now(),))
    # Seed welcome message in allmant if empty
    existing = conn.execute("SELECT id FROM messages WHERE channel = 'allmant' LIMIT 1").fetchone()
    if not existing:
        conn.execute(
            "INSERT INTO messages (id, channel, author, content, role, created_at) VALUES (?, 'allmant', 'system', ?, 'system', ?)",
            (uuid.uuid4().hex, WELCOME_TEXT, now())
        )
    conn.commit()
    conn.close()


def now():
    return datetime.now(timezone.utc).isoformat()


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    _harden_conn(conn)
    return conn


# --- Rate limiting ---
rate_limits = {}  # ip -> [timestamps]
rate_lock = threading.Lock()
MAX_REQUESTS_PER_MIN = 60
MAX_SSE_CLIENTS = 100


def check_rate_limit(ip):
    """Returns True if allowed, False if rate limited."""
    now_t = time.time()
    with rate_lock:
        # Prevent unbounded memory growth from spoofed IPs
        if len(rate_limits) > MAX_RATE_LIMIT_ENTRIES:
            sorted_ips = sorted(rate_limits.keys(), key=lambda k: rate_limits[k][-1] if rate_limits[k] else 0)
            for old_ip in sorted_ips[:len(sorted_ips) // 2]:
                del rate_limits[old_ip]
        if ip not in rate_limits:
            rate_limits[ip] = []
        rate_limits[ip] = [t for t in rate_limits[ip] if now_t - t < 60]
        if len(rate_limits[ip]) >= MAX_REQUESTS_PER_MIN:
            return False
        rate_limits[ip].append(now_t)
        return True


# --- Online tracking ---
online_users = {}
online_lock = threading.Lock()


def touch_online(username, ip="", channel=""):
    with online_lock:
        online_users[username] = {
            "last_seen": time.time(),
            "ip": ip,
            "channel": channel,
        }


def get_online(timeout=120):
    """Users seen in last 2 minutes."""
    now_t = time.time()
    with online_lock:
        return {u: info for u, info in online_users.items() if now_t - info["last_seen"] < timeout}


# --- Admin sessions ---
admin_sessions = set()


def check_admin(headers):
    token = headers.get("X-Admin-Token", "")
    return token in admin_sessions


# --- SSE Clients ---
sse_clients = []  # list of (queue, channel_filter, username, ip, connected_at)
sse_lock = threading.Lock()


def broadcast(event_data, channel=None):
    """Send event to SSE clients. For private rooms, only send to members."""
    # Check if this is a private channel
    filter_members = None
    if channel:
        with visibility_lock:
            vis = visibility_cache.get(channel, "public")
        if vis == "private":
            with membership_lock:
                filter_members = membership_cache.get(channel, set())

    with sse_lock:
        dead = []
        for i, entry in enumerate(sse_clients):
            # Filter: private rooms only go to members
            if filter_members is not None:
                sse_user = entry[2] if len(entry) > 2 else ""
                if sse_user not in filter_members:
                    continue
            try:
                if entry[0].qsize() < MAX_QUEUE_SIZE:
                    entry[0].put_nowait(event_data)
            except:
                dead.append(i)
        for i in reversed(dead):
            sse_clients.pop(i)


# --- WebSocket Clients ---
ws_clients = []  # list of WebSocketConnection
ws_lock = threading.Lock()

WS_MAGIC_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class WebSocketConnection:
    """A single WebSocket client connection."""

    def __init__(self, handler, username="anonymous", ip=""):
        self.handler = handler
        self.username = username
        self.ip = ip
        self.connected_at = time.time()
        self.alive = True
        self.write_lock = threading.Lock()

    def read_frame(self):
        """Read one WebSocket frame. Returns (opcode, payload) or (None, None)."""
        try:
            header = self.handler.rfile.read(2)
            if len(header) < 2:
                return None, None
            b0, b1 = header[0], header[1]
            opcode = b0 & 0x0F
            masked = (b1 & 0x80) != 0
            payload_len = b1 & 0x7F

            if payload_len == 126:
                ext = self.handler.rfile.read(2)
                if len(ext) < 2: return None, None
                payload_len = struct.unpack("!H", ext)[0]
            elif payload_len == 127:
                ext = self.handler.rfile.read(8)
                if len(ext) < 8: return None, None
                payload_len = struct.unpack("!Q", ext)[0]

            if payload_len > 1024 * 1024:  # 1MB max frame
                return None, None

            if masked:
                mask_key = self.handler.rfile.read(4)
                if len(mask_key) < 4: return None, None
                raw = self.handler.rfile.read(payload_len)
                if len(raw) < payload_len: return None, None
                payload = bytes(raw[i] ^ mask_key[i % 4] for i in range(len(raw)))
            else:
                payload = self.handler.rfile.read(payload_len)
                if len(payload) < payload_len: return None, None

            return opcode, payload
        except (socket.timeout, OSError, ValueError):
            return None, None

    def send_frame(self, opcode, payload):
        """Send a WebSocket frame (unmasked, from server)."""
        try:
            with self.write_lock:
                frame = bytearray()
                frame.append(0x80 | opcode)  # FIN + opcode
                plen = len(payload)
                if plen < 126:
                    frame.append(plen)
                elif plen < 65536:
                    frame.append(126)
                    frame.extend(struct.pack("!H", plen))
                else:
                    frame.append(127)
                    frame.extend(struct.pack("!Q", plen))
                frame.extend(payload)
                self.handler.wfile.write(bytes(frame))
                self.handler.wfile.flush()
                return True
        except (socket.timeout, OSError, BrokenPipeError):
            self.alive = False
            return False

    def send_json(self, data):
        """Send a JSON text frame."""
        return self.send_frame(0x1, json.dumps(data).encode("utf-8"))

    def send_close(self, code=1000):
        """Send close frame."""
        self.send_frame(0x8, struct.pack("!H", code))
        self.alive = False

    def run(self):
        """Main WebSocket event loop."""
        while self.alive:
            opcode, payload = self.read_frame()
            if opcode is None:
                break
            if opcode == 0x8:  # Close
                self.send_close(1000)
                break
            if opcode == 0x9:  # Ping → Pong
                self.send_frame(0xA, payload)
                continue
            if opcode == 0xA:  # Pong
                continue
            if opcode == 0x1:  # Text
                try:
                    msg = json.loads(payload.decode("utf-8"))
                    # Client can send ping-type messages to keep alive
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass
        self.alive = False


def broadcast(event_data, channel=None):
    """Send event to ALL clients (SSE + WebSocket). Filter private rooms."""
    filter_members = None
    if channel:
        with visibility_lock:
            vis = visibility_cache.get(channel, "public")
        if vis == "private":
            with membership_lock:
                filter_members = membership_cache.get(channel, set())

    # SSE clients
    with sse_lock:
        dead = []
        for i, entry in enumerate(sse_clients):
            if filter_members is not None:
                sse_user = entry[2] if len(entry) > 2 else ""
                if sse_user not in filter_members:
                    continue
            try:
                if entry[0].qsize() < MAX_QUEUE_SIZE:
                    entry[0].put_nowait(event_data)
            except:
                dead.append(i)
        for i in reversed(dead):
            sse_clients.pop(i)

    # WebSocket clients
    with ws_lock:
        dead = []
        for i, ws in enumerate(ws_clients):
            if not ws.alive:
                dead.append(i)
                continue
            if filter_members is not None and ws.username not in filter_members:
                continue
            if not ws.send_json(event_data):
                dead.append(i)
        for i in reversed(dead):
            ws_clients.pop(i)


# --- HTTP Handler ---

class ChatHandler(BaseHTTPRequestHandler):
    timeout = REQUEST_TIMEOUT

    def setup(self):
        """Set socket timeout to prevent Slowloris attacks."""
        super().setup()
        self.request.settimeout(REQUEST_TIMEOUT)

    def real_ip(self):
        """Get real client IP with validation."""
        forwarded = self.headers.get("X-Forwarded-For", "")
        if forwarded:
            ip = forwarded.split(",")[0].strip()
            if re.match(r'^[\d.:a-fA-F]+$', ip):
                return ip
        return self.client_address[0] if self.client_address else "unknown"

    def log_message(self, format, *args):
        if args and '/api/events' not in str(args[0]):
            import sys
            sys.stderr.write(f"{self.real_ip()} - {format % args}\n")

    def send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", CORS_ORIGIN)
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, path):
        try:
            resolved = Path(path).resolve()
            allowed = Path("static").resolve()
            if not str(resolved).startswith(str(allowed)):
                self.send_error(403)
                return
            content = resolved.read_bytes()
            self.send_response(200)
            ctype = "text/html" if path.endswith(".html") else "text/css" if path.endswith(".css") else "application/javascript"
            self.send_header("Content-Type", f"{ctype}; charset=utf-8")
            self.send_header("Content-Length", len(content))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-XSS-Protection", "1; mode=block")
            self.end_headers()
            self.wfile.write(content)
        except FileNotFoundError:
            self.send_error(404)

    def send_static_file(self, path, content_type):
        try:
            resolved = Path(path).resolve()
            allowed = Path("static").resolve()
            if not str(resolved).startswith(str(allowed)):
                self.send_error(403)
                return
            content = resolved.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", len(content))
            self.send_header("Cache-Control", "public, max-age=86400")
            self.end_headers()
            self.wfile.write(content)
        except FileNotFoundError:
            self.send_error(404)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", CORS_ORIGIN)
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        # Rate limit API GET requests (not static files)
        if path.startswith("/api/"):
            client_ip = self.real_ip()
            if not check_rate_limit(client_ip):
                self.send_json({"ok": False, "error": "rate limited"}, 429)
                return

        # Static files
        if path == "/" or path == "/chat.html":
            self.send_html("static/chat.html")
            return

        if path == "/admin" or path == "/admin.html":
            self.send_html("static/admin.html")
            return

        if path == "/intro.mp4":
            self.send_static_file("static/intro.mp4", "video/mp4")
            return

        # WebSocket upgrade
        if path == "/ws":
            upgrade = self.headers.get("Upgrade", "").lower()
            if upgrade != "websocket":
                self.send_error(400)
                return
            sec_key = self.headers.get("Sec-WebSocket-Key", "")
            if not sec_key:
                self.send_error(400)
                return

            # Compute accept key
            accept = base64.b64encode(
                hashlib.sha1((sec_key + WS_MAGIC_GUID).encode()).digest()
            ).decode()

            # Send 101 Switching Protocols
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.end_headers()
            self.wfile.flush()

            # Parse username from query
            ws_user = params.get("user", ["anonymous"])[0][:20]
            client_ip = self.real_ip()
            touch_online(ws_user, client_ip, "ws")

            ws_conn = WebSocketConnection(self, ws_user, client_ip)
            with ws_lock:
                if len(ws_clients) >= MAX_SSE_CLIENTS:
                    ws_conn.send_close(1013)  # Try again later
                    return
                ws_clients.append(ws_conn)

            try:
                # Send ping every 20s to keep connection alive
                def ws_ping_loop():
                    while ws_conn.alive:
                        time.sleep(20)
                        if ws_conn.alive:
                            ws_conn.send_frame(0x9, b"")
                ping_thread = threading.Thread(target=ws_ping_loop, daemon=True)
                ping_thread.start()

                ws_conn.run()
            finally:
                ws_conn.alive = False
                with ws_lock:
                    ws_clients[:] = [c for c in ws_clients if c is not ws_conn]
            return

        # API: health
        if path == "/api/health":
            self.send_json({"ok": True})
            return

        # API: channels — filtered by visibility + membership
        if path == "/api/channels":
            req_user = params.get("user", [None])[0]
            req_token = params.get("token", [None])[0]
            # Verify token if provided
            authenticated_user = None
            if req_user and req_token:
                db = get_db()
                valid = db.execute("SELECT username FROM users WHERE username = ? AND token = ?", (req_user, req_token)).fetchone()
                db.close()
                if valid:
                    authenticated_user = req_user

            db = get_db()
            rows = db.execute("SELECT * FROM channels ORDER BY created_at").fetchall()
            # Get user's memberships
            user_rooms = {}
            if authenticated_user:
                members = db.execute("SELECT room, role FROM room_members WHERE username = ?", (authenticated_user,)).fetchall()
                user_rooms = {m["room"]: m["role"] for m in members}
            db.close()

            channels = []
            for r in rows:
                ch = dict(r)
                vis = ch.get("visibility", "public")
                ch["is_member"] = ch["name"] in user_rooms
                ch["user_role"] = user_rooms.get(ch["name"], None)
                # Private rooms: show name but mark as locked if not member
                if vis == "private" and not ch["is_member"]:
                    ch["locked"] = True
                    # Don't expose topic/owner to non-members
                    ch["topic"] = ""
                channels.append(ch)

            # Count unique online SSE users
            with sse_lock:
                online_names = set(c[2] for c in sse_clients if len(c) > 2 and c[2] != "anonymous")
            with ws_lock:
                online_names |= set(c.username for c in ws_clients if c.alive and c.username != "anonymous")
            self.send_json({"ok": True, "channels": channels, "online_count": len(online_names)})
            return

        # API: messages for a channel (access controlled)
        if path.startswith("/api/channel/") and path.endswith("/messages"):
            parts = path.split("/")
            channel = parts[3]
            try:
                limit = min(int(params.get("limit", ["100"])[0]), 500)
            except (ValueError, IndexError):
                limit = 100

            # Access check: private rooms require membership
            req_user = params.get("user", [None])[0]
            req_token = params.get("token", [None])[0]
            auth_user = None
            if req_user and req_token:
                db_v = get_db()
                valid = db_v.execute("SELECT username FROM users WHERE username = ? AND token = ?", (req_user, req_token)).fetchone()
                db_v.close()
                if valid:
                    auth_user = req_user

            db = get_db()
            room, access = check_room_access(db, channel, auth_user)
            if room is None:
                db.close()
                self.send_error(404)
                return
            rows = db.execute(
                "SELECT id, channel, author, content, role, attachments, created_at FROM messages WHERE channel = ? ORDER BY created_at DESC LIMIT ?",
                (channel, limit)
            ).fetchall()
            msg_ids = [r["id"] for r in rows]
            react_map = {}
            if msg_ids:
                placeholders = ",".join("?" * len(msg_ids))
                reacts = db.execute(
                    f"SELECT message_id, emoji, author FROM reactions WHERE message_id IN ({placeholders})",
                    msg_ids
                ).fetchall()
                for rx in reacts:
                    mid = rx["message_id"]
                    if mid not in react_map:
                        react_map[mid] = []
                    react_map[mid].append({"emoji": rx["emoji"], "author": rx["author"]})
            db.close()
            messages = []
            for r in rows:
                m = dict(r)
                try:
                    m["attachments"] = json.loads(m.get("attachments") or "[]")
                except:
                    m["attachments"] = []
                m["reactions"] = react_map.get(m["id"], [])
                messages.append(m)
            self.send_json({
                "ok": True,
                "channel": channel,
                "count": len(messages),
                "messages": messages
            })
            return

        # API: SSE events
        if path == "/api/events":
            client_ip = self.real_ip()

            # Per-IP SSE limit to prevent one attacker from consuming all slots
            with sse_lock:
                ip_count = sum(1 for c in sse_clients if len(c) > 3 and c[3] == client_ip)
                if ip_count >= MAX_SSE_PER_IP:
                    self.send_error(429)
                    return
                if len(sse_clients) >= MAX_SSE_CLIENTS:
                    self.send_error(503)
                    return

            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("Access-Control-Allow-Origin", CORS_ORIGIN)
            self.end_headers()

            q = Queue(maxsize=MAX_QUEUE_SIZE)
            sse_user = params.get("user", ["anonymous"])[0][:20]
            connected_at = time.time()
            touch_online(sse_user, client_ip, "connected")
            with sse_lock:
                sse_clients.append((q, None, sse_user, client_ip, connected_at))

            try:
                self.wfile.write(b": connected\n\n")
                self.wfile.flush()

                while True:
                    # Kill connections older than SSE_CLIENT_TIMEOUT
                    if time.time() - connected_at > SSE_CLIENT_TIMEOUT:
                        break
                    try:
                        data = q.get(timeout=15)
                        self.wfile.write(f"data: {json.dumps(data)}\n\n".encode())
                        self.wfile.flush()
                    except Empty:
                        self.wfile.write(b"data: {\"event_type\":\"ping\"}\n\n")
                        self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                with sse_lock:
                    sse_clients[:] = [c for c in sse_clients if c[0] is not q]
            return

        self.send_error(404)

    def do_POST(self):
        client_ip = self.real_ip()
        if not check_rate_limit(client_ip):
            self.send_json({"ok": False, "error": "rate limited"}, 429)
            return

        parsed = urlparse(self.path)
        path = parsed.path

        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            self.send_json({"ok": False, "error": "bad content-length"}, 400)
            return
        if content_length > MAX_BODY:
            self.send_json({"ok": False, "error": "payload too large (max 5MB)"}, 413)
            return
        try:
            body = json.loads(self.rfile.read(content_length)) if content_length > 0 else {}
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            self.send_json({"ok": False, "error": "invalid JSON"}, 400)
            return

        # API: admin login
        if path == "/api/admin/login":
            u = body.get("username", "")
            p = body.get("password", "")
            if not ADMIN_PASS:
                self.send_json({"ok": False, "error": "admin not configured"}, 403)
                return
            if u == ADMIN_USER and hmac.compare_digest(p, ADMIN_PASS):
                if len(admin_sessions) >= MAX_ADMIN_SESSIONS:
                    admin_sessions.clear()
                session = uuid.uuid4().hex
                admin_sessions.add(session)
                self.send_json({"ok": True, "token": session})
            else:
                time.sleep(0.5)  # Slow down brute force
                self.send_json({"ok": False, "error": "Fel losenord"}, 401)
            return

        # API: admin dashboard
        if path == "/api/admin/dashboard":
            if not check_admin(self.headers):
                self.send_json({"ok": False, "error": "unauthorized"}, 401)
                return
            db = get_db()
            users = [dict(r) for r in db.execute("SELECT username, created_at FROM users ORDER BY created_at DESC").fetchall()]
            channels = [dict(r) for r in db.execute("SELECT * FROM channels ORDER BY created_at DESC").fetchall()]
            msg_count = db.execute("SELECT COUNT(*) as c FROM messages").fetchone()["c"]
            user_stats = {}
            for row in db.execute("SELECT author, COUNT(*) as c FROM messages GROUP BY author ORDER BY c DESC").fetchall():
                user_stats[row["author"]] = row["c"]
            recent = [dict(r) for r in db.execute("SELECT id, channel, author, content, created_at FROM messages ORDER BY created_at DESC LIMIT 50").fetchall()]
            db.close()
            online = get_online()
            sse_count = len(sse_clients)
            self.send_json({
                "ok": True,
                "users": users,
                "channels": channels,
                "total_messages": msg_count,
                "user_stats": user_stats,
                "recent_messages": recent,
                "online": {u: {"last_seen": info["last_seen"], "ip": info["ip"], "channel": info["channel"]} for u, info in online.items()},
                "sse_connections": sse_count,
            })
            return

        # API: admin delete user
        if path == "/api/admin/delete-user":
            if not check_admin(self.headers):
                self.send_json({"ok": False, "error": "unauthorized"}, 401)
                return
            uname = body.get("username", "")
            if not uname:
                self.send_json({"ok": False, "error": "username required"}, 400)
                return
            db = get_db()
            try:
                db.execute("DELETE FROM users WHERE username = ?", (uname,))
                db.execute("DELETE FROM messages WHERE author = ?", (uname,))
                db.execute("DELETE FROM reactions WHERE author = ?", (uname,))
                db.commit()
            finally:
                db.close()
            self.send_json({"ok": True, "deleted": uname})
            return

        # API: admin kick user
        if path == "/api/admin/kick-user":
            if not check_admin(self.headers):
                self.send_json({"ok": False, "error": "unauthorized"}, 401)
                return
            uname = body.get("username", "")
            if not uname:
                self.send_json({"ok": False, "error": "username required"}, 400)
                return
            db = get_db()
            try:
                db.execute("DELETE FROM users WHERE username = ?", (uname,))
                db.commit()
            finally:
                db.close()
            with online_lock:
                online_users.pop(uname, None)
            self.send_json({"ok": True, "kicked": uname})
            return

        # API: register username
        if path == "/api/register":
            uname = body.get("username", "").strip()[:20]
            if not uname or len(uname) < 2:
                self.send_json({"ok": False, "error": "Namn maste vara 2-20 tecken"}, 400)
                return
            if not re.match(r'^[a-zA-Z0-9\u00e5\u00e4\u00f6\u00c5\u00c4\u00d6_-]{2,20}$', uname):
                self.send_json({"ok": False, "error": "Bara bokstaver, siffror, - och _"}, 400)
                return

            db = get_db()
            try:
                user_count = db.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]
                if user_count >= MAX_USERS:
                    self.send_json({"ok": False, "error": "Max antal anvandare uppnatt"}, 403)
                    return
                token = uuid.uuid4().hex
                db.execute(
                    "INSERT INTO users (username, token, created_at) VALUES (?, ?, ?)",
                    (uname, token, now())
                )
                db.commit()
            except sqlite3.IntegrityError:
                db.close()
                self.send_json({"ok": False, "error": "Namnet ar redan taget"}, 409)
                return
            db.close()
            self.send_json({"ok": True, "username": uname, "token": token})
            return

        # API: verify token
        if path == "/api/verify":
            uname = body.get("username", "").strip()
            token = body.get("token", "").strip()
            if not uname or not token:
                self.send_json({"ok": False, "error": "missing fields"}, 400)
                return
            db = get_db()
            row = db.execute(
                "SELECT username FROM users WHERE username = ? AND token = ?",
                (uname, token)
            ).fetchone()
            db.close()
            if row:
                self.send_json({"ok": True, "username": uname})
            else:
                self.send_json({"ok": False, "error": "invalid token"}, 401)
            return

        # API: check if username is available
        if path == "/api/check-name":
            uname = body.get("username", "").strip()
            if not uname:
                self.send_json({"ok": False, "available": False})
                return
            db = get_db()
            row = db.execute("SELECT username FROM users WHERE username = ?", (uname,)).fetchone()
            db.close()
            self.send_json({"ok": True, "available": row is None, "username": uname})
            return

        # API: send message (requires valid token)
        if path.startswith("/api/channel/") and path.endswith("/message"):
            parts = path.split("/")
            channel = parts[3][:50]
            if not re.match(r'^[a-z0-9\u00e5\u00e4\u00f6][a-z0-9\u00e5\u00e4\u00f6_-]{0,48}$', channel):
                self.send_json({"ok": False, "error": "invalid channel name"}, 400)
                return
            content = body.get("content", "").strip()[:5000]
            author = body.get("author", "anonymous").strip()[:20]
            token = body.get("token", "").strip()

            if token:
                db_check = get_db()
                valid = db_check.execute(
                    "SELECT username FROM users WHERE username = ? AND token = ?",
                    (author, token)
                ).fetchone()
                db_check.close()
                if not valid:
                    self.send_json({"ok": False, "error": "invalid token"}, 401)
                    return
            else:
                self.send_json({"ok": False, "error": "token required"}, 401)
                return

            # Room access check
            db_ac = get_db()
            room, access = check_room_access(db_ac, channel, author)
            db_ac.close()
            if room is None:
                self.send_error(404)
                return
            if access == "system":
                self.send_json({"ok": False, "error": "det har rummet ar skrivskyddat"}, 403)
                return
            if access == "read":
                self.send_json({"ok": False, "error": "du maste ga med i rummet forst"}, 403)
                return

            # Per-user spam limit
            if not check_user_spam(author):
                self.send_json({"ok": False, "error": "du skickar for snabbt, vanta lite"}, 429)
                return

            role = "user"
            attachments = body.get("attachments", [])[:5]
            total_att_size = 0
            for att in attachments:
                att_size = len(att.get("dataUrl", ""))
                if att_size > MAX_ATTACHMENT_SIZE:
                    self.send_json({"ok": False, "error": "attachment too large (max 2MB)"}, 400)
                    return
                total_att_size += att_size
            if total_att_size > MAX_BODY:
                self.send_json({"ok": False, "error": "total attachments too large"}, 400)
                return

            if not content and not attachments:
                self.send_json({"ok": False, "error": "empty message"}, 400)
                return

            if not content and attachments:
                content = "[bild]" if len(attachments) == 1 else f"[{len(attachments)} bilder]"

            touch_online(author, client_ip, channel)

            # Ephemeral mode: message is NOT saved, only broadcast + auto-expires
            ephemeral = body.get("ephemeral", 0)
            if ephemeral:
                ephemeral = max(1, min(30, int(ephemeral)))  # 1-30 seconds
                msg_id = "eph-" + uuid.uuid4().hex[:12]
                ts = now()
                broadcast_data = {
                    "event_type": "chat_message",
                    "id": msg_id,
                    "channel": channel,
                    "author": author,
                    "content": content,
                    "role": role,
                    "ephemeral": ephemeral,
                    "attachments": attachments,  # Send full data for ephemeral (not saved)
                    "created_at": ts,
                }
                broadcast(broadcast_data, channel)
                self.send_json({"ok": True, "id": msg_id, "channel": channel, "ephemeral": ephemeral})
                return

            msg_id = str(uuid.uuid4())
            ts = now()
            att_json = json.dumps(attachments) if attachments else "[]"

            db = get_db()
            try:
                db.execute(
                    "INSERT INTO messages (id, channel, author, content, role, attachments, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (msg_id, channel, author, content, role, att_json, ts)
                )
                db.commit()
                prune_old_messages(db)
            finally:
                db.close()

            broadcast_data = {
                "event_type": "chat_message",
                "id": msg_id,
                "channel": channel,
                "author": author,
                "content": content,
                "role": role,
                "attachments": [{"name": a.get("name", ""), "type": a.get("type", "")} for a in attachments] if attachments else [],
                "has_attachments": bool(attachments),
                "created_at": ts,
            }
            broadcast(broadcast_data, channel)

            self.send_json({"ok": True, "id": msg_id, "channel": channel})
            return

        # API: delete own message — POST /api/message/:id/delete { author, token }
        if path.startswith("/api/message/") and path.endswith("/delete"):
            parts = path.split("/")
            message_id = parts[3]
            author = body.get("author", "").strip()[:20]
            token = body.get("token", "").strip()
            if not author or not token:
                self.send_json({"ok": False, "error": "token required"}, 401)
                return
            db = get_db()
            try:
                valid = db.execute("SELECT username FROM users WHERE username = ? AND token = ?", (author, token)).fetchone()
                if not valid:
                    self.send_json({"ok": False, "error": "invalid token"}, 401)
                    return
                msg = db.execute("SELECT author, channel FROM messages WHERE id = ?", (message_id,)).fetchone()
                if not msg:
                    self.send_json({"ok": False, "error": "meddelandet finns inte"}, 404)
                    return
                # Only the author or room owner can delete
                is_author = msg["author"] == author
                is_room_owner = False
                owner_row = db.execute("SELECT role FROM room_members WHERE room = ? AND username = ?", (msg["channel"], author)).fetchone()
                if owner_row and owner_row["role"] == "owner":
                    is_room_owner = True
                if not is_author and not is_room_owner:
                    self.send_json({"ok": False, "error": "du kan bara radera dina egna meddelanden"}, 403)
                    return
                db.execute("DELETE FROM messages WHERE id = ?", (message_id,))
                db.execute("DELETE FROM reactions WHERE message_id = ?", (message_id,))
                db.commit()
            finally:
                db.close()
            broadcast({"event_type": "message_deleted", "id": message_id, "channel": msg["channel"]}, msg["channel"])
            self.send_json({"ok": True})
            return

        # API: create channel (requires token)
        if path == "/api/channel":
            name = body.get("name", "").strip().lower().replace(" ", "-")[:50]
            if not name:
                self.send_json({"ok": False, "error": "name required"}, 400)
                return
            if not re.match(r'^[a-z0-9\u00e5\u00e4\u00f6][a-z0-9\u00e5\u00e4\u00f6_-]{0,48}$', name):
                self.send_json({"ok": False, "error": "invalid channel name"}, 400)
                return
            display = body.get("display_name", name)[:100]
            topic = body.get("topic", "")[:200]
            creator = body.get("created_by", "anonymous")[:20]
            token = body.get("token", "").strip()

            if token:
                db_v = get_db()
                valid = db_v.execute("SELECT username FROM users WHERE username = ? AND token = ?", (creator, token)).fetchone()
                db_v.close()
                if not valid:
                    self.send_json({"ok": False, "error": "invalid token"}, 401)
                    return
            else:
                self.send_json({"ok": False, "error": "token required"}, 401)
                return

            visibility = body.get("visibility", "public")
            if visibility not in ("public", "private"):
                visibility = "public"

            db = get_db()
            try:
                ch_count = db.execute("SELECT COUNT(*) as c FROM channels").fetchone()["c"]
                if ch_count >= MAX_CHANNELS:
                    self.send_json({"ok": False, "error": "max antal kanaler uppnatt"}, 403)
                    return
                ts = now()
                db.execute(
                    "INSERT OR IGNORE INTO channels (name, display_name, topic, visibility, owner, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (name, display, topic, visibility, creator, creator, ts)
                )
                # Auto-join creator as owner
                db.execute(
                    "INSERT OR IGNORE INTO room_members (room, username, role, joined_at) VALUES (?, ?, 'owner', ?)",
                    (name, creator, ts)
                )
                db.commit()
            finally:
                db.close()
            # Update caches
            cache_set_visibility(name, visibility)
            cache_add_member(name, creator)
            self.send_json({"ok": True, "channel": name, "visibility": visibility})
            return

        # API: react to a message
        if path.startswith("/api/message/") and path.endswith("/react"):
            parts = path.split("/")
            message_id = parts[3]
            emoji = body.get("emoji", "").strip()[:10]
            author = body.get("author", "anonymous").strip()[:20]
            token = body.get("token", "").strip()

            if not emoji:
                self.send_json({"ok": False, "error": "emoji required"}, 400)
                return

            if token:
                db_v = get_db()
                valid = db_v.execute("SELECT username FROM users WHERE username = ? AND token = ?", (author, token)).fetchone()
                db_v.close()
                if not valid:
                    self.send_json({"ok": False, "error": "invalid token"}, 401)
                    return
            else:
                self.send_json({"ok": False, "error": "token required"}, 401)
                return

            db = get_db()
            try:
                existing = db.execute(
                    "SELECT id FROM reactions WHERE message_id = ? AND emoji = ? AND author = ?",
                    (message_id, emoji, author)
                ).fetchone()

                if existing:
                    db.execute("DELETE FROM reactions WHERE id = ?", (existing["id"],))
                    action = "removed"
                else:
                    react_id = str(uuid.uuid4())
                    db.execute(
                        "INSERT INTO reactions (id, message_id, emoji, author, created_at) VALUES (?, ?, ?, ?, ?)",
                        (react_id, message_id, emoji, author, now())
                    )
                    action = "added"
                db.commit()

                reacts = db.execute(
                    "SELECT emoji, author FROM reactions WHERE message_id = ?",
                    (message_id,)
                ).fetchall()
            finally:
                db.close()

            react_list = [{"emoji": rx["emoji"], "author": rx["author"]} for rx in reacts]
            broadcast({
                "event_type": "reaction",
                "message_id": message_id,
                "reactions": react_list,
            })
            self.send_json({"ok": True, "action": action, "reactions": react_list})
            return

        # API: delete channel — owner or admin only
        if path.startswith("/api/channel/") and path.count("/") == 3:
            parts = path.split("/")
            channel = parts[3]
            if channel == "allmant":
                self.send_json({"ok": False, "error": "kan inte ta bort allmant"}, 400)
                return
            # Check: admin session, admin bearer, or room owner
            is_admin = check_admin(self.headers)
            if not is_admin and ADMIN_TOKEN:
                auth = self.headers.get("Authorization", "")
                if hmac.compare_digest(auth, f"Bearer {ADMIN_TOKEN}"):
                    is_admin = True
            is_owner = False
            del_user = body.get("author", "")
            del_token = body.get("token", "")
            if del_user and del_token:
                db_v = get_db()
                valid = db_v.execute("SELECT username FROM users WHERE username = ? AND token = ?", (del_user, del_token)).fetchone()
                if valid:
                    owner_row = db_v.execute("SELECT role FROM room_members WHERE room = ? AND username = ?", (channel, del_user)).fetchone()
                    if owner_row and owner_row["role"] == "owner":
                        is_owner = True
                db_v.close()
            if not is_admin and not is_owner:
                self.send_json({"ok": False, "error": "unauthorized"}, 401)
                return
            db = get_db()
            try:
                db.execute("DELETE FROM messages WHERE channel = ?", (channel,))
                db.execute("DELETE FROM reactions WHERE message_id IN (SELECT id FROM messages WHERE channel = ?)", (channel,))
                db.execute("DELETE FROM room_members WHERE room = ?", (channel,))
                db.execute("DELETE FROM invites WHERE room = ?", (channel,))
                db.execute("DELETE FROM channels WHERE name = ?", (channel,))
                db.commit()
            finally:
                db.close()
            # Clear caches
            with membership_lock:
                membership_cache.pop(channel, None)
            with visibility_lock:
                visibility_cache.pop(channel, None)
            self.send_json({"ok": True})
            return

        # API: request access to private room — notifies the owner via SSE
        if path.startswith("/api/channel/") and path.endswith("/request-access"):
            parts = path.split("/")
            room_name = parts[3]
            author = body.get("author", "").strip()[:20]
            token = body.get("token", "").strip()
            if not author or not token:
                self.send_json({"ok": False, "error": "token required"}, 401)
                return
            db = get_db()
            try:
                valid = db.execute("SELECT username FROM users WHERE username = ? AND token = ?", (author, token)).fetchone()
                if not valid:
                    self.send_json({"ok": False, "error": "invalid token"}, 401)
                    return
                room = db.execute("SELECT * FROM channels WHERE name = ?", (room_name,)).fetchone()
                if not room:
                    self.send_error(404)
                    return
                owner = str(room["owner"] or "")
                display = str(room["display_name"] or room_name)
            finally:
                db.close()
            # Broadcast to ALL clients — owner filters client-side
            import sys
            sys.stderr.write(f"ACCESS_REQUEST: {author} -> {room_name} (owner: {owner}), SSE clients: {len(sse_clients)}\n")
            broadcast({
                "event_type": "access_request",
                "room": room_name,
                "display_name": display,
                "from": author,
                "owner": owner,
            })
            self.send_json({"ok": True, "message": "Forfragan skickad till agaren"})
            return

        # API: join a room
        if path.startswith("/api/channel/") and path.endswith("/join"):
            parts = path.split("/")
            room_name = parts[3]
            author = body.get("author", "").strip()[:20]
            token = body.get("token", "").strip()
            if not author or not token:
                self.send_json({"ok": False, "error": "token required"}, 401)
                return
            db = get_db()
            try:
                valid = db.execute("SELECT username FROM users WHERE username = ? AND token = ?", (author, token)).fetchone()
                if not valid:
                    self.send_json({"ok": False, "error": "invalid token"}, 401)
                    return
                room, access = check_room_access(db, room_name, author)
                if room is None:
                    self.send_error(404)
                    return
                vis = room["visibility"] or "public"
                if vis == "system":
                    self.send_json({"ok": False, "error": "kan inte ga med i systemrum"}, 400)
                    return
                if vis == "private":
                    self.send_error(404)  # Can't join private without invite
                    return
                # Public: join as member
                db.execute(
                    "INSERT OR IGNORE INTO room_members (room, username, role, joined_at) VALUES (?, ?, 'member', ?)",
                    (room_name, author, now())
                )
                db.commit()
            finally:
                db.close()
            cache_add_member(room_name, author)
            self.send_json({"ok": True, "room": room_name})
            return

        # API: leave a room
        if path.startswith("/api/channel/") and path.endswith("/leave"):
            parts = path.split("/")
            room_name = parts[3]
            author = body.get("author", "").strip()[:20]
            token = body.get("token", "").strip()
            if not author or not token:
                self.send_json({"ok": False, "error": "token required"}, 401)
                return
            db = get_db()
            try:
                valid = db.execute("SELECT username FROM users WHERE username = ? AND token = ?", (author, token)).fetchone()
                if not valid:
                    self.send_json({"ok": False, "error": "invalid token"}, 401)
                    return
                member = db.execute("SELECT role FROM room_members WHERE room = ? AND username = ?", (room_name, author)).fetchone()
                if not member:
                    self.send_json({"ok": True})
                    return
                db.execute("DELETE FROM room_members WHERE room = ? AND username = ?", (room_name, author))
                # If owner left, transfer to oldest member or delete room
                if member["role"] == "owner":
                    next_member = db.execute("SELECT username FROM room_members WHERE room = ? ORDER BY joined_at ASC LIMIT 1", (room_name,)).fetchone()
                    if next_member:
                        db.execute("UPDATE room_members SET role = 'owner' WHERE room = ? AND username = ?", (room_name, next_member["username"]))
                        db.execute("UPDATE channels SET owner = ? WHERE name = ?", (next_member["username"], room_name))
                    else:
                        # No members left — delete room
                        db.execute("DELETE FROM messages WHERE channel = ?", (room_name,))
                        db.execute("DELETE FROM invites WHERE room = ?", (room_name,))
                        db.execute("DELETE FROM channels WHERE name = ?", (room_name,))
                db.commit()
            finally:
                db.close()
            cache_remove_member(room_name, author)
            self.send_json({"ok": True})
            return

        # API: invite to a room (owner only)
        if path.startswith("/api/channel/") and path.endswith("/invite"):
            parts = path.split("/")
            room_name = parts[3]
            author = body.get("author", "").strip()[:20]
            token = body.get("token", "").strip()
            if not author or not token:
                self.send_json({"ok": False, "error": "token required"}, 401)
                return
            db = get_db()
            try:
                valid = db.execute("SELECT username FROM users WHERE username = ? AND token = ?", (author, token)).fetchone()
                if not valid:
                    self.send_json({"ok": False, "error": "invalid token"}, 401)
                    return
                room, access = check_room_access(db, room_name, author)
                if room is None or access != "owner":
                    self.send_json({"ok": False, "error": "bara agaren kan bjuda in"}, 403)
                    return

                invitee = body.get("username", "").strip()
                generate_code = body.get("generate_code", False)

                if invitee:
                    # Direct invite: add to members
                    user_exists = db.execute("SELECT username FROM users WHERE username = ?", (invitee,)).fetchone()
                    if not user_exists:
                        self.send_json({"ok": False, "error": "anvandaren finns inte"}, 404)
                        return
                    db.execute(
                        "INSERT OR IGNORE INTO room_members (room, username, role, joined_at) VALUES (?, ?, 'member', ?)",
                        (room_name, invitee, now())
                    )
                    db.commit()
                    cache_add_member(room_name, invitee)
                    # Notify via SSE
                    broadcast({"event_type": "invited", "room": room_name, "username": invitee, "display_name": room["display_name"] or room_name})
                    self.send_json({"ok": True, "invited": invitee})
                    return

                if generate_code:
                    # Check invite limit
                    invite_count = db.execute("SELECT COUNT(*) as c FROM invites WHERE room = ?", (room_name,)).fetchone()["c"]
                    if invite_count >= 10:
                        self.send_json({"ok": False, "error": "max 10 inbjudningskoder per rum"}, 400)
                        return
                    code = uuid.uuid4().hex[:16]
                    uses = int(body.get("uses", 10))
                    db.execute(
                        "INSERT INTO invites (code, room, created_by, created_at, uses_left) VALUES (?, ?, ?, ?, ?)",
                        (code, room_name, author, now(), uses)
                    )
                    db.commit()
                    self.send_json({"ok": True, "code": code, "uses": uses})
                    return

                self.send_json({"ok": False, "error": "ange username eller generate_code"}, 400)
            finally:
                db.close()
            return

        # API: accept an invite code
        if path.startswith("/api/invite/") and path.endswith("/accept"):
            parts = path.split("/")
            code = parts[3]
            author = body.get("author", "").strip()[:20]
            token = body.get("token", "").strip()
            if not author or not token:
                self.send_json({"ok": False, "error": "token required"}, 401)
                return
            db = get_db()
            try:
                valid = db.execute("SELECT username FROM users WHERE username = ? AND token = ?", (author, token)).fetchone()
                if not valid:
                    self.send_json({"ok": False, "error": "invalid token"}, 401)
                    return
                invite = db.execute("SELECT * FROM invites WHERE code = ?", (code,)).fetchone()
                if not invite:
                    self.send_json({"ok": False, "error": "ogiltig inbjudningskod"}, 404)
                    return
                if invite["uses_left"] == 0:
                    self.send_json({"ok": False, "error": "inbjudningskoden har forbrukats"}, 410)
                    return
                room_name = invite["room"]
                # Add member
                db.execute(
                    "INSERT OR IGNORE INTO room_members (room, username, role, joined_at) VALUES (?, ?, 'member', ?)",
                    (room_name, author, now())
                )
                # Decrement uses
                if invite["uses_left"] > 0:
                    new_uses = invite["uses_left"] - 1
                    if new_uses <= 0:
                        db.execute("DELETE FROM invites WHERE code = ?", (code,))
                    else:
                        db.execute("UPDATE invites SET uses_left = ? WHERE code = ?", (new_uses, code))
                db.commit()
            finally:
                db.close()
            cache_add_member(room_name, author)
            self.send_json({"ok": True, "room": room_name})
            return

        # API: kick member (owner only)
        if path.startswith("/api/channel/") and path.endswith("/kick"):
            parts = path.split("/")
            room_name = parts[3]
            author = body.get("author", "").strip()[:20]
            token = body.get("token", "").strip()
            target = body.get("username", "").strip()
            if not author or not token:
                self.send_json({"ok": False, "error": "token required"}, 401)
                return
            if not target or target == author:
                self.send_json({"ok": False, "error": "ogiltig anvandare"}, 400)
                return
            db = get_db()
            try:
                valid = db.execute("SELECT username FROM users WHERE username = ? AND token = ?", (author, token)).fetchone()
                if not valid:
                    self.send_json({"ok": False, "error": "invalid token"}, 401)
                    return
                room, access = check_room_access(db, room_name, author)
                if room is None or access != "owner":
                    self.send_json({"ok": False, "error": "bara agaren kan kicka"}, 403)
                    return
                db.execute("DELETE FROM room_members WHERE room = ? AND username = ?", (room_name, target))
                db.commit()
            finally:
                db.close()
            cache_remove_member(room_name, target)
            broadcast({"event_type": "kicked", "room": room_name, "username": target})
            self.send_json({"ok": True, "kicked": target})
            return

        # API: list room members
        if path.startswith("/api/channel/") and path.endswith("/members"):
            parts = path.split("/")
            room_name = parts[3]
            req_user = params.get("user", [None])[0] if hasattr(params, 'get') else None
            # For POST, get from body
            if not req_user:
                req_user = body.get("author", "")
                req_token = body.get("token", "")
            else:
                req_token = params.get("token", [None])[0]
            auth_user = None
            if req_user and req_token:
                db_v = get_db()
                valid = db_v.execute("SELECT username FROM users WHERE username = ? AND token = ?", (req_user, req_token)).fetchone()
                db_v.close()
                if valid:
                    auth_user = req_user
            db = get_db()
            room, access = check_room_access(db, room_name, auth_user)
            if room is None:
                db.close()
                self.send_error(404)
                return
            members = [dict(r) for r in db.execute("SELECT username, role, joined_at FROM room_members WHERE room = ? ORDER BY joined_at", (room_name,)).fetchall()]
            db.close()
            self.send_json({"ok": True, "room": room_name, "members": members})
            return

        self.send_json({"ok": False, "error": "not found"}, 404)

    def do_DELETE(self):
        self.do_POST()


# --- Threaded server with limits ---

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    _thread_count = 0
    _thread_lock = threading.Lock()

    def process_request(self, request, client_address):
        """Enforce max thread limit and set socket timeout."""
        request.settimeout(REQUEST_TIMEOUT)
        with self._thread_lock:
            if self._thread_count >= MAX_THREADS:
                try:
                    request.close()
                except:
                    pass
                return
            self._thread_count += 1
        try:
            super().process_request(request, client_address)
        except:
            with self._thread_lock:
                self._thread_count -= 1

    def process_request_thread(self, request, client_address):
        """Decrement thread count when request completes."""
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._thread_lock:
                self._thread_count -= 1


if __name__ == "__main__":
    init_db()
    load_caches()
    server = ThreadedHTTPServer((HOST, PORT), ChatHandler)
    print(f"Cortex Chat running on http://{HOST}:{PORT}")
    print(f"Share with friends: open the URL above")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()
