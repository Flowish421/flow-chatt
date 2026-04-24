"""
Quiver — Lightweight real-time chat server.
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
import signal
import sys
import gzip
import urllib.request
import urllib.error
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
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
EMAIL_FROM = os.environ.get("EMAIL_FROM", "onboarding@resend.com")

DISPOSABLE_DOMAINS = {
    "mailinator.com","guerrillamail.com","guerrillamail.de","tempmail.com","throwaway.email",
    "yopmail.com","10minutemail.com","trashmail.com","fakeinbox.com","sharklasers.com",
    "guerrillamailblock.com","grr.la","dispostable.com","mailnesia.com","maildrop.cc",
    "discard.email","tmpmail.net","tmpmail.org","bupmail.com","emailondeck.com",
    "tempr.email","temp-mail.org","mohmal.com","burnermail.io","inboxbear.com",
    "mailcatch.com","mintemail.com","tempinbox.com","getnada.com","emailfake.com",
    "crazymailing.com","tmail.ws","tempmailo.com","luxusmail.org","trashmail.me",
    "harakirimail.com","spamgourmet.com","mytemp.email","mailsac.com","mailtemp.net",
    "guerrillamail.info","mailexpire.com","throwam.com","filzmail.com","getairmail.com",
    "meltmail.com","spamavert.com","trashmail.net","mailnull.com","spamfree24.org",
    "jetable.org","trashinbox.com","tempail.com","receiveee.com","temp-mail.io",
    "minutemail.com","tempmailer.com","fakemailgenerator.com",
}
EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

def hash_password(password):
    salt = uuid.uuid4().hex[:16]
    hashed = hashlib.sha256((salt + password).encode()).hexdigest()
    return salt + ":" + hashed

def verify_password(stored, password):
    if ":" not in stored:
        return False
    salt, hashed = stored.split(":", 1)
    return hashlib.sha256((salt + password).encode()).hexdigest() == hashed

WELCOME_TEXT = """Valkommen till Quiver! Borja chatta direkt har, eller skapa en grupp med "+ Skapa grupp" i sidofaltet."""

# --- Membership cache (in-memory for fast SSE filtering) ---
membership_cache = {}  # room_name -> set(username)
membership_lock = threading.Lock()
# Channel visibility cache
visibility_cache = {}  # room_name -> 'public'|'private'|'system'
visibility_lock = threading.Lock()

# --- Group membership cache ---
group_membership_cache = {}  # group_id -> set(username)
group_membership_lock = threading.Lock()
group_visibility_cache = {}  # group_id -> 'public'|'private'
group_visibility_lock = threading.Lock()


def group_cache_add_member(group_id, username):
    with group_membership_lock:
        group_membership_cache.setdefault(group_id, set()).add(username)


def group_cache_remove_member(group_id, username):
    with group_membership_lock:
        if group_id in group_membership_cache:
            group_membership_cache[group_id].discard(username)


def is_group_member(group_id, username):
    with group_membership_lock:
        return username in group_membership_cache.get(group_id, set())


def cache_set_group_visibility(group_id, vis):
    with group_visibility_lock:
        group_visibility_cache[group_id] = vis


def load_caches():
    """Load membership and visibility caches from DB."""
    db = get_db()
    try:
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
        # Group membership
        rows = db.execute("SELECT group_id, username FROM group_members").fetchall()
        gcache = {}
        for r in rows:
            gcache.setdefault(r["group_id"], set()).add(r["username"])
        with group_membership_lock:
            group_membership_cache.clear()
            group_membership_cache.update(gcache)
        # Group visibility
        rows = db.execute("SELECT id, visibility FROM groups").fetchall()
        gvcache = {}
        for r in rows:
            gvcache[r["id"]] = r["visibility"] or "public"
        with group_visibility_lock:
            group_visibility_cache.clear()
            group_visibility_cache.update(gvcache)
    finally:
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


def _group_role_level(role):
    """Role hierarchy: owner > admin > member."""
    return {"owner": 3, "admin": 2, "member": 1}.get(role, 0)


def check_room_access(db, room_name, username=None):
    """Returns (room_row, access_level) or (None, None).
    access_level: 'system' | 'read' | 'write' | 'owner'
    """
    room = db.execute("SELECT * FROM channels WHERE name = ?", (room_name,)).fetchone()
    if not room:
        return None, None
    vis = room["visibility"] or "public"

    # Group channel access
    group_id = room["group_id"] if "group_id" in room.keys() else None
    if group_id:
        if vis == "system":
            return room, "system"
        if not username:
            # For group channels in public groups, allow read; private groups deny
            with group_visibility_lock:
                gvis = group_visibility_cache.get(group_id, "public")
            if gvis == "private":
                return None, None
            return room, "read"
        # Check group membership
        gm = db.execute("SELECT role FROM group_members WHERE group_id = ? AND username = ?", (group_id, username)).fetchone()
        if not gm:
            # Not a group member
            with group_visibility_lock:
                gvis = group_visibility_cache.get(group_id, "public")
            if gvis == "private":
                return None, None
            return room, "read"
        # Group member — check required_role for the channel
        user_role = gm["role"]
        required_role = room["required_role"] if "required_role" in room.keys() else "member"
        if not required_role:
            required_role = "member"
        # Owner and admin always bypass role requirements
        if user_role in ("owner", "admin"):
            return room, "owner" if user_role == "owner" else "write"
        # Check built-in roles first
        if _group_role_level(user_role) >= _group_role_level(required_role):
            return room, "write"
        # Check custom role: required_role might be a custom role ID
        if required_role not in ("member", "admin", "owner"):
            has_custom = db.execute(
                "SELECT 1 FROM user_roles WHERE group_id = ? AND username = ? AND role_id = ?",
                (group_id, username, required_role)
            ).fetchone()
            if has_custom:
                return room, "write"
            # User does NOT have the required custom role — hide channel entirely
            return None, None
        return room, "read"

    if vis == "system":
        return room, "system"
    if vis == "public":
        if not username:
            return room, "read"
        member = db.execute("SELECT role FROM room_members WHERE room = ? AND username = ?", (room_name, username)).fetchone()
        if member:
            return room, "owner" if member["role"] == "owner" else "write"
        # All logged-in users can write in public non-group channels
        return room, "write"
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
MAX_GROUPS = 20               # Max groups (servers)
MAX_CHANNELS_PER_GROUP = 20   # Max channels per group
MAX_GROUP_MEMBERS = 200       # Max members per group
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
    # Migration: add columns if missing
    for col, default in [("visibility", "'public'"), ("owner", "NULL"), ("channel_type", "'text'")]:
        try:
            conn.execute(f"ALTER TABLE channels ADD COLUMN {col} TEXT DEFAULT {default}")
        except sqlite3.OperationalError:
            pass
    conn.execute("""
        CREATE TABLE IF NOT EXISTS voice_state (
            channel TEXT NOT NULL,
            username TEXT NOT NULL,
            joined_at TEXT NOT NULL,
            PRIMARY KEY (channel, username)
        )
    """)
    # Clear stale voice state on startup
    conn.execute("DELETE FROM voice_state")
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
    # --- Groups (Discord-like servers) ---
    conn.execute("""
        CREATE TABLE IF NOT EXISTS groups (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            display_name TEXT,
            description TEXT DEFAULT '',
            visibility TEXT NOT NULL DEFAULT 'public',
            owner TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS group_members (
            group_id TEXT NOT NULL,
            username TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'member',
            joined_at TEXT NOT NULL,
            PRIMARY KEY (group_id, username)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS join_requests (
            id TEXT PRIMARY KEY,
            group_id TEXT NOT NULL,
            username TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL,
            resolved_by TEXT,
            resolved_at TEXT,
            UNIQUE(group_id, username)
        )
    """)
    # Migration: add group columns to channels
    for col, default in [("group_id", "NULL"), ("required_role", "'member'")]:
        try:
            conn.execute(f"ALTER TABLE channels ADD COLUMN {col} TEXT DEFAULT {default}")
        except sqlite3.OperationalError:
            pass
    # Migration: add group_id to invites
    try:
        conn.execute("ALTER TABLE invites ADD COLUMN group_id TEXT DEFAULT NULL")
    except sqlite3.OperationalError:
        pass
    # --- Custom roles tables ---
    conn.execute("""
        CREATE TABLE IF NOT EXISTS group_roles (
            id TEXT PRIMARY KEY,
            group_id TEXT NOT NULL,
            name TEXT NOT NULL,
            display_name TEXT,
            color TEXT DEFAULT '#99aab5',
            position INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            UNIQUE(group_id, name)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS user_roles (
            group_id TEXT NOT NULL,
            username TEXT NOT NULL,
            role_id TEXT NOT NULL,
            assigned_at TEXT NOT NULL,
            PRIMARY KEY (group_id, username, role_id)
        )
    """)
    # Group indexes
    conn.execute("CREATE INDEX IF NOT EXISTS idx_channels_group ON channels(group_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members(username)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_join_requests_group ON join_requests(group_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_group_roles_group ON group_roles(group_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_user_roles_group ON user_roles(group_id, username)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_msg_author ON messages(author)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles(role_id)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            token TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL
        )
    """)
    # Migration: add email column to users
    try:
        conn.execute("ALTER TABLE users ADD COLUMN email TEXT")
    except sqlite3.OperationalError:
        pass
    # Migration: add password column to users
    try:
        conn.execute("ALTER TABLE users ADD COLUMN password TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass
    # Migration: add profile columns to users
    for col, default in [("bio", "''"), ("avatar_color", "'#4f8ff7'"), ("banner_color", "'#1a1e26'")]:
        try:
            conn.execute(f"ALTER TABLE users ADD COLUMN {col} TEXT DEFAULT {default}")
        except sqlite3.OperationalError:
            pass
    # Migration: add avatar (profile picture) column to users
    try:
        conn.execute("ALTER TABLE users ADD COLUMN avatar TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email)")
    except sqlite3.OperationalError:
        pass
    # Pending verification codes table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS pending_codes (
            email TEXT PRIMARY KEY,
            code TEXT NOT NULL,
            username TEXT NOT NULL,
            expires_at REAL NOT NULL,
            attempts INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        )
    """)
    # Password resets table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS password_resets (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            reset_code TEXT NOT NULL,
            created_at TEXT NOT NULL,
            used INTEGER DEFAULT 0
        )
    """)
    # Seed the global chat room "allmant" (public, writable by all)
    conn.execute("""
        INSERT OR IGNORE INTO channels (name, display_name, topic, visibility, owner, created_by, created_at)
        VALUES ('allmant', 'Allmant', 'Oppen chatt for alla', 'public', 'system', 'system', ?)
    """, (now(),))
    # Migration: convert old system/Guide channel to writable public channel
    conn.execute("UPDATE channels SET display_name = 'Allmant', topic = 'Oppen chatt for alla', visibility = 'public' WHERE name = 'allmant' AND visibility = 'system'")
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
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    _harden_conn(conn)
    return conn


# --- Rate limiting ---
rate_limits = {}  # ip -> [timestamps]
rate_lock = threading.Lock()
MAX_REQUESTS_PER_MIN = 200
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


# --- Email verification rate limiting ---
email_rate = {}  # email -> last_send_timestamp
email_rate_lock = threading.Lock()
ip_email_rate = {}  # ip -> [timestamps] for hourly cap
ip_email_rate_lock = threading.Lock()


def is_disposable_email(email):
    domain = email.rsplit("@", 1)[-1].lower()
    return domain in DISPOSABLE_DOMAINS


def send_verification_email(to_email, code):
    if not RESEND_API_KEY:
        print(f"RESEND_API_KEY not configured. Code for {to_email}: {code}", file=sys.stderr)
        return False
    try:
        html = f"""<div style="font-family:monospace;background:#1a1a2e;color:#e0e0e0;padding:40px;border-radius:12px;max-width:400px;margin:0 auto">
            <h2 style="color:#4f8ff7;margin:0 0 20px">Quiver</h2>
            <p>Din verifieringskod:</p>
            <div style="background:#16213e;padding:20px;border-radius:8px;text-align:center;font-size:32px;letter-spacing:8px;color:#34d399;font-weight:bold;margin:20px 0">{code}</div>
            <p style="color:#888;font-size:12px">Koden gar ut om 10 minuter. Om du inte begarde detta kan du ignorera mailet.</p>
        </div>"""
        payload = json.dumps({
            "from": EMAIL_FROM,
            "to": [to_email],
            "subject": "Quiver - Verifieringskod",
            "html": html,
        }).encode()
        req = urllib.request.Request(
            "https://api.resend.com/emails",
            data=payload,
            headers={
                "Authorization": f"Bearer {RESEND_API_KEY}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
        print(f"Email sent to {to_email}: {result.get('id', 'ok')}", file=sys.stderr)
        return True
    except Exception as e:
        print(f"Resend email error: {e}", file=sys.stderr)
        return False


def check_email_rate(email, ip):
    """Returns (allowed, error_message). Enforces 1 per 60s per email, 5 per hour per IP."""
    now_t = time.time()
    with email_rate_lock:
        last = email_rate.get(email, 0)
        if now_t - last < 60:
            return False, "Vanta minst 60 sekunder mellan kodforskningar"
    with ip_email_rate_lock:
        if ip not in ip_email_rate:
            ip_email_rate[ip] = []
        ip_email_rate[ip] = [t for t in ip_email_rate[ip] if now_t - t < 3600]
        if len(ip_email_rate[ip]) >= 5:
            return False, "For manga kodforfragan fran denna IP, forsok igen senare"
    return True, ""


def record_email_send(email, ip):
    """Record that a code was sent."""
    now_t = time.time()
    with email_rate_lock:
        email_rate[email] = now_t
    with ip_email_rate_lock:
        ip_email_rate.setdefault(ip, []).append(now_t)


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


admin_login_attempts = {}  # ip -> [timestamps] for brute-force protection
admin_login_lock = threading.Lock()
MAX_ADMIN_LOGIN_ATTEMPTS = 20  # per 15 minutes


def check_admin_lockout(ip):
    """Returns True if the IP is locked out from admin login attempts."""
    now_t = time.time()
    with admin_login_lock:
        if ip not in admin_login_attempts:
            return False
        admin_login_attempts[ip] = [t for t in admin_login_attempts[ip] if now_t - t < 900]
        return len(admin_login_attempts[ip]) >= MAX_ADMIN_LOGIN_ATTEMPTS


def record_admin_failure(ip):
    """Record a failed admin login attempt."""
    with admin_login_lock:
        if ip not in admin_login_attempts:
            admin_login_attempts[ip] = []
        admin_login_attempts[ip].append(time.time())


def clear_admin_failures(ip):
    """Clear failed login attempts on successful login."""
    with admin_login_lock:
        admin_login_attempts.pop(ip, None)


def check_admin(headers):
    token = headers.get("X-Admin-Token", "")
    if not token:
        return False
    return token in admin_sessions


# --- SSE Clients ---
sse_clients = []  # list of (queue, channel_filter, username, ip, connected_at)
sse_lock = threading.Lock()


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
                    # Typing indicator — broadcast to channel members, not stored
                    if msg.get("type") == "typing":
                        msg["from"] = self.username  # Force sender identity
                        channel = msg.get("channel", "")
                        if channel:
                            broadcast({"event_type": "typing", "username": self.username, "channel": channel}, channel=channel)
                    # WebRTC signaling relay — send to specific user
                    elif msg.get("type") in ("call_offer", "call_answer", "ice_candidate", "call_reject", "call_hangup"):
                        send_to_user(msg.get("to"), msg)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass
        self.alive = False


def broadcast(event_data, channel=None):
    """Send event to ALL clients (SSE + WebSocket). Filter private rooms and private group channels.
    Collects targets under lock, sends outside lock to avoid holding locks during I/O."""
    filter_members = None
    if channel:
        with visibility_lock:
            vis = visibility_cache.get(channel, "public")
        if vis == "private":
            with membership_lock:
                filter_members = membership_cache.get(channel, set()).copy()
        # For group channels in private groups, filter by group membership
        if filter_members is None:
            # Check if channel belongs to a private group
            db_bc = get_db()
            try:
                ch_row = db_bc.execute("SELECT group_id FROM channels WHERE name = ?", (channel,)).fetchone()
                if ch_row and ch_row["group_id"]:
                    gid = ch_row["group_id"]
                    with group_visibility_lock:
                        gvis = group_visibility_cache.get(gid, "public")
                    if gvis == "private":
                        with group_membership_lock:
                            filter_members = group_membership_cache.get(gid, set()).copy()
            finally:
                db_bc.close()

    # SSE clients — collect targets under lock, enqueue is fast (no I/O)
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

    # WebSocket clients — collect targets under lock, send outside lock
    with ws_lock:
        ws_targets = []
        dead = []
        for i, ws in enumerate(ws_clients):
            if not ws.alive:
                dead.append(i)
                continue
            if filter_members is not None and ws.username not in filter_members:
                continue
            ws_targets.append(ws)
        for i in reversed(dead):
            ws_clients.pop(i)

    # Send outside lock to avoid holding ws_lock during I/O
    ws_dead = []
    for ws in ws_targets:
        if not ws.send_json(event_data):
            ws_dead.append(ws)
    if ws_dead:
        with ws_lock:
            ws_clients[:] = [c for c in ws_clients if c not in ws_dead]


def send_to_user(target_username, event_data):
    """Send an event to a specific user (WebSocket + SSE)."""
    if not target_username:
        return
    # WebSocket clients
    with ws_lock:
        for ws in ws_clients:
            if ws.alive and ws.username == target_username:
                ws.send_json(event_data)
    # SSE clients
    with sse_lock:
        for entry in sse_clients:
            if len(entry) > 2 and entry[2] == target_username:
                try:
                    entry[0].put_nowait(event_data)
                except:
                    pass


# --- HTTP Handler ---

class ChatHandler(BaseHTTPRequestHandler):
    timeout = REQUEST_TIMEOUT

    def setup(self):
        """Set socket timeout to prevent Slowloris attacks."""
        super().setup()
        self.request.settimeout(REQUEST_TIMEOUT)

    def send_error(self, code, message=None, explain=None):
        """Override to return JSON errors with CORS headers."""
        error_msg = message or self.responses.get(code, ("Error",))[0]
        body = json.dumps({"ok": False, "error": error_msg}).encode()
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", CORS_ORIGIN)
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

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
        raw = json.dumps(data).encode()
        # Gzip if client supports it and response is large enough
        accept_enc = self.headers.get("Accept-Encoding", "")
        if "gzip" in accept_enc and len(raw) > 512:
            body = gzip.compress(raw)
            self.send_response(status)
            self.send_header("Content-Encoding", "gzip")
        else:
            body = raw
            self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", CORS_ORIGIN)
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Admin-Token, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
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
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; media-src 'self' data:; connect-src 'self' ws: wss:;")
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
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Admin-Token, Authorization")
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

        # Favicon — inline SVG chat bubble to avoid 404 spam
        if path == "/favicon.ico":
            svg = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="50" fill="#58a6ff"/><text x="50" y="68" text-anchor="middle" font-family="sans-serif" font-size="60" font-weight="700" fill="#0d1117">Q</text></svg>'
            self.send_response(200)
            self.send_header("Content-Type", "image/svg+xml")
            self.send_header("Content-Length", len(svg))
            self.send_header("Cache-Control", "public, max-age=604800")
            self.end_headers()
            self.wfile.write(svg)
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

            # Parse username and verify token from query
            ws_user = params.get("user", ["anonymous"])[0][:20]
            ws_token = params.get("token", [""])[0]
            client_ip = self.real_ip()
            if ws_user != "anonymous" and ws_token:
                db_ws = get_db()
                try:
                    valid = db_ws.execute("SELECT username FROM users WHERE username = ? AND token = ?", (ws_user, ws_token)).fetchone()
                finally:
                    db_ws.close()
                if not valid:
                    ws_user = "anonymous"
            elif ws_user != "anonymous":
                ws_user = "anonymous"  # No token provided — demote to anonymous
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

        # API: health (verifies DB connectivity)
        if path == "/api/health":
            try:
                db_h = get_db()
                try:
                    db_h.execute("SELECT 1").fetchone()
                finally:
                    db_h.close()
                self.send_json({"ok": True})
            except Exception as e:
                self.send_json({"ok": False, "error": "db unreachable"}, 503)
            return

        # API: channels — filtered by visibility + membership
        if path == "/api/channels":
            req_user = params.get("user", [None])[0]
            req_token = params.get("token", [None])[0]
            # Verify token if provided
            authenticated_user = None
            if req_user and req_token:
                db = get_db()
                try:
                    valid = db.execute("SELECT username FROM users WHERE username = ? AND token = ?", (req_user, req_token)).fetchone()
                finally:
                    db.close()
                if valid:
                    authenticated_user = req_user

            db = get_db()
            try:
                rows = db.execute("SELECT * FROM channels ORDER BY created_at").fetchall()
                # Get user's memberships
                user_rooms = {}
                if authenticated_user:
                    members = db.execute("SELECT room, role FROM room_members WHERE username = ?", (authenticated_user,)).fetchall()
                    user_rooms = {m["room"]: m["role"] for m in members}
                # Get voice state — who's in each voice channel
                voice_rows = db.execute("SELECT channel, username FROM voice_state").fetchall()
                voice_map = {}
                for vr in voice_rows:
                    voice_map.setdefault(vr["channel"], []).append(vr["username"])
            finally:
                db.close()

            channels = []
            for r in rows:
                ch = dict(r)
                vis = ch.get("visibility", "public")
                ch["channel_type"] = ch.get("channel_type", "text")
                ch["group_id"] = ch.get("group_id", None)
                ch["required_role"] = ch.get("required_role", "member")
                ch["is_member"] = ch["name"] in user_rooms
                ch["user_role"] = user_rooms.get(ch["name"], None)
                if vis == "private" and not ch["is_member"]:
                    ch["locked"] = True
                    ch["topic"] = ""
                # Voice channels: include who's in the room
                if ch["channel_type"] == "voice":
                    ch["voice_members"] = voice_map.get(ch["name"], [])
                channels.append(ch)

            with sse_lock:
                online_names = set(c[2] for c in sse_clients if len(c) > 2 and c[2] != "anonymous")
            with ws_lock:
                online_names |= set(c.username for c in ws_clients if c.alive and c.username != "anonymous")
            self.send_json({"ok": True, "channels": channels, "online_count": len(online_names)})
            return

        # API: messages for a channel (access controlled)
        if path.startswith("/api/channel/") and path.endswith("/messages"):
            parts = path.split("/")
            # Validate channel name from URL path (same regex as message POST)
            parts[3] = unquote(parts[3])[:50]
            if not re.match(r'^[a-z0-9\u00e5\u00e4\u00f6][a-z0-9\u00e5\u00e4\u00f6_-]{0,48}$', parts[3]):
                self.send_json({"ok": False, "error": "invalid channel name"}, 400)
                return
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
                try:
                    valid = db_v.execute("SELECT username FROM users WHERE username = ? AND token = ?", (req_user, req_token)).fetchone()
                finally:
                    db_v.close()
                if valid:
                    auth_user = req_user

            before = params.get("before", [None])[0]  # cursor: ISO timestamp for pagination

            db = get_db()
            try:
                room, access = check_room_access(db, channel, auth_user)
                if room is None:
                    self.send_error(404)
                    return
                if before:
                    rows = db.execute(
                        "SELECT id, channel, author, content, role, attachments, created_at FROM messages WHERE channel = ? AND created_at < ? ORDER BY created_at DESC LIMIT ?",
                        (channel, before, limit)
                    ).fetchall()
                else:
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

                # Build author avatar_color + avatar map
                author_avatar_map = {}  # username -> avatar_color
                author_avatar_img_map = {}  # username -> avatar (data URL)
                unique_msg_authors = set(r["author"] for r in rows)
                if unique_msg_authors:
                    auth_ph = ",".join("?" * len(unique_msg_authors))
                    avatar_rows = db.execute(
                        f"SELECT username, avatar_color, avatar FROM users WHERE username IN ({auth_ph})",
                        list(unique_msg_authors)
                    ).fetchall()
                    for ar in avatar_rows:
                        author_avatar_map[ar["username"]] = ar["avatar_color"] or "#4f8ff7"
                        if ar["avatar"]:
                            author_avatar_img_map[ar["username"]] = ar["avatar"]

                # Build author roles map for this channel's group
                author_roles_map = {}  # username -> [{"role_id", "name", "display_name", "color"}]
                group_id = room["group_id"] if "group_id" in room.keys() else None
                if group_id:
                    unique_authors = set(r["author"] for r in rows)
                    if unique_authors:
                        role_defs = {}
                        for gr in db.execute("SELECT id, name, display_name, color FROM group_roles WHERE group_id = ?", (group_id,)).fetchall():
                            role_defs[gr["id"]] = {"role_id": gr["id"], "name": gr["name"], "display_name": gr["display_name"], "color": gr["color"]}
                        auth_placeholders = ",".join("?" * len(unique_authors))
                        ur_rows = db.execute(
                            f"SELECT username, role_id FROM user_roles WHERE group_id = ? AND username IN ({auth_placeholders})",
                            [group_id] + list(unique_authors)
                        ).fetchall()
                        for ur in ur_rows:
                            rd = role_defs.get(ur["role_id"])
                            if rd:
                                author_roles_map.setdefault(ur["username"], []).append(rd)
            finally:
                db.close()
            messages = []
            for r in rows:
                m = dict(r)
                try:
                    m["attachments"] = json.loads(m.get("attachments") or "[]")
                except:
                    m["attachments"] = []
                m["reactions"] = react_map.get(m["id"], [])
                m["author_roles"] = author_roles_map.get(m["author"], [])
                m["avatar_color"] = author_avatar_map.get(m["author"], "#4f8ff7")
                m["avatar"] = author_avatar_img_map.get(m["author"], "")
                messages.append(m)
            self.send_json({
                "ok": True,
                "channel": channel,
                "count": len(messages),
                "has_more": len(messages) == limit,
                "messages": messages
            })
            return

        # API: SSE events
        if path == "/api/events":
            client_ip = self.real_ip()

            # Verify token for SSE connection
            sse_user = params.get("user", ["anonymous"])[0][:20]
            sse_token = params.get("token", [""])[0]
            if sse_user != "anonymous" and sse_token:
                db_sse = get_db()
                try:
                    valid = db_sse.execute("SELECT username FROM users WHERE username = ? AND token = ?", (sse_user, sse_token)).fetchone()
                finally:
                    db_sse.close()
                if not valid:
                    sse_user = "anonymous"
            elif sse_user != "anonymous":
                sse_user = "anonymous"

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
            self.send_header("X-Accel-Buffering", "no")
            self.send_header("Access-Control-Allow-Origin", CORS_ORIGIN)
            self.end_headers()

            q = Queue(maxsize=MAX_QUEUE_SIZE)
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

        # API: list groups — public + private groups user belongs to
        if path == "/api/groups":
            req_user = params.get("user", [None])[0]
            req_token = params.get("token", [None])[0]
            authenticated_user = None
            if req_user and req_token:
                db = get_db()
                try:
                    valid = db.execute("SELECT username FROM users WHERE username = ? AND token = ?", (req_user, req_token)).fetchone()
                finally:
                    db.close()
                if valid:
                    authenticated_user = req_user

            db = get_db()
            try:
                if authenticated_user:
                    # Public groups + private groups user is member of
                    rows = db.execute("""
                        SELECT g.* FROM groups g
                        WHERE g.visibility = 'public'
                        OR g.id IN (SELECT group_id FROM group_members WHERE username = ?)
                        ORDER BY g.created_at
                    """, (authenticated_user,)).fetchall()
                else:
                    rows = db.execute("SELECT * FROM groups WHERE visibility = 'public' ORDER BY created_at").fetchall()

                groups = []
                for r in rows:
                    g = dict(r)
                    gid = g["id"]
                    # Member count
                    g["member_count"] = db.execute("SELECT COUNT(*) as c FROM group_members WHERE group_id = ?", (gid,)).fetchone()["c"]
                    # User's role in this group
                    if authenticated_user:
                        gm = db.execute("SELECT role FROM group_members WHERE group_id = ? AND username = ?", (gid, authenticated_user)).fetchone()
                        g["user_role"] = gm["role"] if gm else None
                        g["is_member"] = gm is not None
                    else:
                        g["user_role"] = None
                        g["is_member"] = False
                    # Channels in this group (filtered by user's role)
                    ch_rows = db.execute("SELECT * FROM channels WHERE group_id = ? ORDER BY created_at", (gid,)).fetchall()
                    # Voice state for this group's channels
                    voice_rows = db.execute("SELECT channel, username FROM voice_state WHERE channel IN (SELECT name FROM channels WHERE group_id = ?)", (gid,)).fetchall()
                    voice_map = {}
                    for vr in voice_rows:
                        voice_map.setdefault(vr["channel"], []).append(vr["username"])
                    # Load user's custom roles for this group
                    user_custom_role_ids = set()
                    if authenticated_user:
                        ur_rows = db.execute("SELECT role_id FROM user_roles WHERE group_id = ? AND username = ?", (gid, authenticated_user)).fetchall()
                        user_custom_role_ids = {r["role_id"] for r in ur_rows}
                    channels = []
                    for ch in ch_rows:
                        chd = dict(ch)
                        chd["channel_type"] = chd.get("channel_type", "text")
                        chd["required_role"] = chd.get("required_role", "member")
                        req_role = chd["required_role"] or "member"
                        user_role = g["user_role"]
                        # Owner/admin always have access
                        if user_role in ("owner", "admin"):
                            chd["accessible"] = True
                            chd["is_member"] = True
                            chd["user_role"] = user_role
                        # If user has sufficient built-in role level
                        elif user_role and _group_role_level(user_role) >= _group_role_level(req_role):
                            chd["accessible"] = True
                            chd["is_member"] = True
                            chd["user_role"] = user_role
                        # Check custom role requirement
                        elif req_role not in ("member", "admin", "owner") and req_role in user_custom_role_ids:
                            chd["accessible"] = True
                            chd["is_member"] = True
                            chd["user_role"] = user_role
                        elif req_role not in ("member", "admin", "owner"):
                            # Channel requires a custom role the user doesn't have — hide it
                            continue
                        elif g["visibility"] == "public":
                            chd["accessible"] = False
                            chd["is_member"] = False
                            chd["user_role"] = None
                        else:
                            continue  # Private group, user doesn't have access to this channel
                        # Voice channels: include who's in the room
                        if chd["channel_type"] == "voice":
                            chd["voice_members"] = voice_map.get(chd["name"], [])
                        channels.append(chd)
                    g["channels"] = channels
                    # Include custom roles for this group
                    role_rows = db.execute("SELECT id, name, display_name, color, position FROM group_roles WHERE group_id = ? ORDER BY position DESC", (gid,)).fetchall()
                    g["roles"] = [dict(rr) for rr in role_rows]
                    # Include avatar_colors and avatars for group members
                    member_rows = db.execute(
                        "SELECT u.username, u.avatar_color, u.avatar FROM users u INNER JOIN group_members gm ON u.username = gm.username WHERE gm.group_id = ?",
                        (gid,)
                    ).fetchall()
                    g["member_colors"] = {mr["username"]: (mr["avatar_color"] or "#4f8ff7") for mr in member_rows}
                    g["member_avatars"] = {mr["username"]: (mr["avatar"] or "") for mr in member_rows if mr["avatar"]}
                    groups.append(g)

                # Global channels (no group — pinned at top of sidebar)
                system_rows = db.execute("SELECT * FROM channels WHERE (group_id IS NULL OR group_id = '') ORDER BY created_at").fetchall()
                system_channels = []
                if authenticated_user:
                    user_global_rooms = {m["room"]: m["role"] for m in db.execute("SELECT room, role FROM room_members WHERE username = ?", (authenticated_user,)).fetchall()}
                else:
                    user_global_rooms = {}
                for r in system_rows:
                    sc = dict(r)
                    vis = sc.get("visibility", "public")
                    sc["is_member"] = sc["name"] in user_global_rooms or vis == "public"
                    sc["user_role"] = user_global_rooms.get(sc["name"], "member" if vis == "public" else None)
                    if vis == "private" and not sc["name"] in user_global_rooms:
                        continue  # Hide private channels user isn't in
                    system_channels.append(sc)

                # Compute online usernames for per-group online counts
                online_info = get_online()
                online_names_set = set(online_info.keys()) - {"anonymous"}
                # Add online_count per group
                for g in groups:
                    gid = g["id"]
                    with group_membership_lock:
                        g_members = group_membership_cache.get(gid, set())
                    g["online_count"] = len(online_names_set & g_members)

                # Discover groups: public groups where user is NOT a member
                discover_groups = []
                if authenticated_user:
                    disc_rows = db.execute("""
                        SELECT g.id, g.name, g.display_name, g.visibility FROM groups g
                        WHERE g.visibility = 'public'
                        AND g.id NOT IN (SELECT group_id FROM group_members WHERE username = ?)
                        ORDER BY g.created_at
                    """, (authenticated_user,)).fetchall()
                    for dr in disc_rows:
                        dg = dict(dr)
                        dg["member_count"] = db.execute("SELECT COUNT(*) as c FROM group_members WHERE group_id = ?", (dg["id"],)).fetchone()["c"]
                        discover_groups.append(dg)

                online_count = len(online_info)
            finally:
                db.close()
            self.send_json({"ok": True, "groups": groups, "system_channels": system_channels, "discover_groups": discover_groups, "online_count": online_count})
            return

        # API: list custom roles in group — GET /api/group/{id}/roles
        if re.match(r'^/api/group/[a-f0-9]+/roles$', path):
            group_id = path.split("/")[3]
            db = get_db()
            try:
                group = db.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
                if not group:
                    self.send_json({"ok": False, "error": "gruppen finns inte"}, 404)
                    return
                rows = db.execute("SELECT id, name, display_name, color, position, created_at FROM group_roles WHERE group_id = ? ORDER BY position DESC", (group_id,)).fetchall()
                roles = []
                for r in rows:
                    rd = dict(r)
                    members = db.execute("SELECT username FROM user_roles WHERE group_id = ? AND role_id = ?", (group_id, rd["id"])).fetchall()
                    rd["members"] = [m["username"] for m in members]
                    roles.append(rd)
                # Build user assignments map
                user_assignments = {}
                all_assignments = db.execute("SELECT username, role_id FROM user_roles WHERE group_id = ?", (group_id,)).fetchall()
                for a in all_assignments:
                    user_assignments.setdefault(a["username"], []).append(a["role_id"])
            finally:
                db.close()
            self.send_json({"ok": True, "roles": roles, "user_assignments": user_assignments})
            return

        # API: get profile — GET /api/profile/{username}
        if re.match(r'^/api/profile/[a-zA-Z0-9\u00e5\u00e4\u00f6\u00c5\u00c4\u00d6_-]+$', path):
            profile_user = unquote(path.split("/")[3])[:20]
            db = get_db()
            try:
                row = db.execute("SELECT username, bio, avatar_color, banner_color, avatar, created_at FROM users WHERE username = ?", (profile_user,)).fetchone()
                if not row:
                    self.send_json({"ok": False, "error": "user not found"}, 404)
                    return
                self.send_json({
                    "ok": True,
                    "username": row["username"],
                    "bio": row["bio"] or "",
                    "avatar_color": row["avatar_color"] or "#4f8ff7",
                    "banner_color": row["banner_color"] or "#1a1e26",
                    "avatar": row["avatar"] or "",
                    "created_at": row["created_at"],
                })
            finally:
                db.close()
            return

        # API: list registered users (for invite search)
        if path == "/api/users":
            req_user = params.get("user", [None])[0]
            req_token = params.get("token", [None])[0]
            search = params.get("q", [None])[0]
            if not req_user or not req_token:
                self.send_json({"ok": False, "error": "auth required"}, 401)
                return
            db = get_db()
            try:
                valid = db.execute("SELECT username FROM users WHERE username = ? AND token = ?", (req_user, req_token)).fetchone()
                if not valid:
                    self.send_json({"ok": False, "error": "invalid token"}, 401)
                    return
                if search:
                    rows = db.execute("SELECT username, avatar_color, avatar, bio FROM users WHERE username LIKE ? LIMIT 50", ('%' + search + '%',)).fetchall()
                else:
                    rows = db.execute("SELECT username, avatar_color, avatar, bio FROM users ORDER BY username LIMIT 50").fetchall()
            finally:
                db.close()
            users = []
            for r in rows:
                users.append({"username": r["username"], "avatar_color": r["avatar_color"] or "#4f8ff7", "avatar": r["avatar"] or "", "bio": r["bio"] or ""})
            with sse_lock:
                online_names = set(c[2] for c in sse_clients if len(c) > 2 and c[2] != "anonymous")
            with ws_lock:
                online_names |= set(c.username for c in ws_clients if c.alive and c.username != "anonymous")
            for u in users:
                u["online"] = u["username"] in online_names
            self.send_json({"ok": True, "users": users})
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
            if check_admin_lockout(client_ip):
                self.send_json({"ok": False, "error": "for manga felaktiga forsok, forsok igen senare"}, 429)
                return
            if hmac.compare_digest(u, ADMIN_USER) and hmac.compare_digest(p, ADMIN_PASS):
                clear_admin_failures(client_ip)
                if len(admin_sessions) >= MAX_ADMIN_SESSIONS:
                    admin_sessions.clear()
                session = uuid.uuid4().hex
                admin_sessions.add(session)
                self.send_json({"ok": True, "token": session})
            else:
                record_admin_failure(client_ip)
                time.sleep(1)  # Slow down brute force
                self.send_json({"ok": False, "error": "Fel losenord"}, 401)
            return

        # API: admin dashboard
        if path == "/api/admin/dashboard":
            if not check_admin(self.headers):
                self.send_json({"ok": False, "error": "unauthorized"}, 401)
                return
            db = get_db()
            try:
                users = [dict(r) for r in db.execute("SELECT username, created_at FROM users ORDER BY created_at DESC").fetchall()]
                channels = [dict(r) for r in db.execute("SELECT * FROM channels ORDER BY created_at DESC").fetchall()]
                msg_count = db.execute("SELECT COUNT(*) as c FROM messages").fetchone()["c"]
                user_stats = {}
                for row in db.execute("SELECT author, COUNT(*) as c FROM messages GROUP BY author ORDER BY c DESC").fetchall():
                    user_stats[row["author"]] = row["c"]
                recent = [dict(r) for r in db.execute("SELECT id, channel, author, content, created_at FROM messages ORDER BY created_at DESC LIMIT 50").fetchall()]
                pending_resets = [dict(r) for r in db.execute("SELECT id, username, reset_code, created_at FROM password_resets WHERE used = 0").fetchall()]
            finally:
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
                "password_resets": pending_resets,
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
                db.execute("DELETE FROM room_members WHERE username = ?", (uname,))
                db.execute("DELETE FROM invites WHERE created_by = ?", (uname,))
                db.execute("DELETE FROM voice_state WHERE username = ?", (uname,))
                db.commit()
            finally:
                db.close()
            import sys; sys.stderr.write(f"ADMIN_ACTION: delete-user '{uname}' from {client_ip}\n")
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
                db.execute("DELETE FROM room_members WHERE username = ?", (uname,))
                db.execute("DELETE FROM voice_state WHERE username = ?", (uname,))
                db.commit()
            finally:
                db.close()
            with online_lock:
                online_users.pop(uname, None)
            import sys; sys.stderr.write(f"ADMIN_ACTION: kick-user '{uname}' from {client_ip}\n")
            self.send_json({"ok": True, "kicked": uname})
            return

        # API: admin generate password reset code
        if path == "/api/admin/generate-reset":
            if not check_admin(self.headers):
                self.send_json({"ok": False, "error": "unauthorized"}, 401)
                return
            uname = body.get("username", "")
            if not uname:
                self.send_json({"ok": False, "error": "username required"}, 400)
                return
            import random
            reset_code = f"{random.randint(0, 99999999):08d}"
            db = get_db()
            try:
                row = db.execute("SELECT username FROM users WHERE username = ?", (uname,)).fetchone()
                if not row:
                    self.send_json({"ok": False, "error": "Anvandaren finns inte"}, 404)
                    return
                db.execute(
                    "INSERT INTO password_resets (id, username, reset_code, created_at) VALUES (?, ?, ?, ?)",
                    (uuid.uuid4().hex, uname, reset_code, now())
                )
                db.commit()
            finally:
                db.close()
            self.send_json({"ok": True, "reset_code": reset_code})
            return

        # API: register username with password
        if path == "/api/register":
            uname = body.get("username", "").strip()[:20]
            password = body.get("password", "")
            if not uname or len(uname) < 2:
                self.send_json({"ok": False, "error": "Namn maste vara 2-20 tecken"}, 400)
                return
            if not re.match(r'^[a-zA-Z0-9\u00e5\u00e4\u00f6\u00c5\u00c4\u00d6_-]{2,20}$', uname):
                self.send_json({"ok": False, "error": "Bara bokstaver, siffror, - och _"}, 400)
                return
            if len(password) < 4:
                self.send_json({"ok": False, "error": "Losenord maste vara minst 4 tecken"}, 400)
                return

            hashed_pw = hash_password(password)
            db = get_db()
            try:
                user_count = db.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]
                if user_count >= MAX_USERS:
                    self.send_json({"ok": False, "error": "Max antal anvandare uppnatt"}, 403)
                    return
                token = uuid.uuid4().hex
                db.execute(
                    "INSERT INTO users (username, token, password, created_at) VALUES (?, ?, ?, ?)",
                    (uname, token, hashed_pw, now())
                )
                db.commit()
            except sqlite3.IntegrityError:
                self.send_json({"ok": False, "error": "Namnet ar redan taget"}, 409)
                return
            finally:
                db.close()
            self.send_json({"ok": True, "username": uname, "token": token})
            return

        # API: send verification code (step 1 of email registration)
        if path == "/api/register/send-code":
            email = body.get("email", "").strip().lower()[:254]
            uname = body.get("username", "").strip()[:20]
            if not email or not EMAIL_RE.match(email):
                self.send_json({"ok": False, "error": "Ogiltig e-postadress"}, 400)
                return
            if is_disposable_email(email):
                self.send_json({"ok": False, "error": "Engangsmailadresser ar inte tillatna"}, 400)
                return
            if not uname or len(uname) < 2:
                self.send_json({"ok": False, "error": "Namn maste vara 2-20 tecken"}, 400)
                return
            if not re.match(r'^[a-zA-Z0-9\u00e5\u00e4\u00f6\u00c5\u00c4\u00d6_-]{2,20}$', uname):
                self.send_json({"ok": False, "error": "Bara bokstaver, siffror, - och _"}, 400)
                return

            # Rate limit check
            allowed, err_msg = check_email_rate(email, client_ip)
            if not allowed:
                self.send_json({"ok": False, "error": err_msg}, 429)
                return

            db = get_db()
            try:
                # Check user count
                user_count = db.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]
                if user_count >= MAX_USERS:
                    self.send_json({"ok": False, "error": "Max antal anvandare uppnatt"}, 403)
                    return
                # Check if username already taken
                existing_user = db.execute("SELECT username FROM users WHERE username = ?", (uname,)).fetchone()
                if existing_user:
                    self.send_json({"ok": False, "error": "Namnet ar redan taget"}, 409)
                    return
                # Check if email already used
                existing_email = db.execute("SELECT username FROM users WHERE email = ?", (email,)).fetchone()
                if existing_email:
                    self.send_json({"ok": False, "error": "E-postadressen ar redan registrerad"}, 409)
                    return

                # Generate 6-digit code
                import random
                code = f"{random.randint(0, 999999):06d}"
                expires_at = time.time() + 600  # 10 minutes

                # Upsert pending code
                db.execute("DELETE FROM pending_codes WHERE email = ?", (email,))
                db.execute(
                    "INSERT INTO pending_codes (email, code, username, expires_at, attempts, created_at) VALUES (?, ?, ?, ?, 0, ?)",
                    (email, code, uname, expires_at, now())
                )
                db.commit()
            finally:
                db.close()

            # Send email
            send_verification_email(email, code)
            record_email_send(email, client_ip)

            self.send_json({"ok": True, "message": "Kod skickad"})
            return

        # API: verify code and complete registration (step 2)
        if path == "/api/register/verify":
            email = body.get("email", "").strip().lower()[:254]
            code = body.get("code", "").strip()[:10]
            uname = body.get("username", "").strip()[:20]
            if not email or not code or not uname:
                self.send_json({"ok": False, "error": "Alla falt kravs"}, 400)
                return

            db = get_db()
            try:
                row = db.execute("SELECT * FROM pending_codes WHERE email = ?", (email,)).fetchone()
                if not row:
                    self.send_json({"ok": False, "error": "Ingen kod hittades, begare en ny"}, 404)
                    return

                # Check expiry
                if time.time() > row["expires_at"]:
                    db.execute("DELETE FROM pending_codes WHERE email = ?", (email,))
                    db.commit()
                    self.send_json({"ok": False, "error": "Koden har gatt ut, begare en ny"}, 410)
                    return

                # Check attempts
                if row["attempts"] >= 5:
                    db.execute("DELETE FROM pending_codes WHERE email = ?", (email,))
                    db.commit()
                    self.send_json({"ok": False, "error": "For manga forsok, begare en ny kod"}, 429)
                    return

                # Verify code
                if row["code"] != code:
                    db.execute("UPDATE pending_codes SET attempts = attempts + 1 WHERE email = ?", (email,))
                    db.commit()
                    remaining = 4 - row["attempts"]
                    self.send_json({"ok": False, "error": f"Fel kod, {remaining} forsok kvar"}, 401)
                    return

                # Check username matches
                if row["username"] != uname:
                    self.send_json({"ok": False, "error": "Anvandarnamnet matchar inte"}, 400)
                    return

                # Create user
                user_count = db.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]
                if user_count >= MAX_USERS:
                    self.send_json({"ok": False, "error": "Max antal anvandare uppnatt"}, 403)
                    return

                token = uuid.uuid4().hex
                try:
                    db.execute(
                        "INSERT INTO users (username, token, email, created_at) VALUES (?, ?, ?, ?)",
                        (uname, token, email, now())
                    )
                except sqlite3.IntegrityError:
                    self.send_json({"ok": False, "error": "Namnet eller e-postadressen ar redan tagen"}, 409)
                    return

                # Clean up pending code
                db.execute("DELETE FROM pending_codes WHERE email = ?", (email,))
                db.commit()
            finally:
                db.close()

            self.send_json({"ok": True, "username": uname, "token": token})
            return

        # API: login with username + password
        if path == "/api/login":
            uname = body.get("username", "").strip()[:20]
            password = body.get("password", "")
            reset_code = body.get("reset_code", "").strip()
            if not uname:
                self.send_json({"ok": False, "error": "Fyll i alla falt"}, 400)
                return
            db = get_db()
            try:
                row = db.execute(
                    "SELECT username, token, password FROM users WHERE username = ?",
                    (uname,)
                ).fetchone()
                if not row:
                    time.sleep(0.5)
                    self.send_json({"ok": False, "error": "Felaktigt anvandarnamn eller losenord"}, 401)
                    return

                # Check if logging in with a reset code
                if reset_code:
                    reset_row = db.execute(
                        "SELECT id FROM password_resets WHERE username = ? AND reset_code = ? AND used = 0",
                        (uname, reset_code)
                    ).fetchone()
                    if reset_row:
                        db.execute("UPDATE password_resets SET used = 1 WHERE id = ?", (reset_row["id"],))
                        db.commit()
                        self.send_json({"ok": True, "username": row["username"], "token": row["token"], "must_change_password": True})
                        return
                    else:
                        time.sleep(0.5)
                        self.send_json({"ok": False, "error": "Ogiltig aterstallningskod"}, 401)
                        return

                # Normal password login
                stored_pw = row["password"] or ""
                if not stored_pw:
                    # Legacy account without password — allow login and set password
                    if password:
                        db.execute("UPDATE users SET password = ? WHERE username = ?", (hash_password(password), uname))
                        db.commit()
                elif not verify_password(stored_pw, password):
                    # Password wrong — check if it's a reset code
                    reset_row = db.execute(
                        "SELECT id FROM password_resets WHERE username = ? AND reset_code = ? AND used = 0",
                        (uname, password)
                    ).fetchone()
                    if reset_row:
                        db.execute("UPDATE password_resets SET used = 1 WHERE id = ?", (reset_row["id"],))
                        db.commit()
                        self.send_json({"ok": True, "username": row["username"], "token": row["token"], "must_change_password": True})
                        return
                    time.sleep(0.5)
                    self.send_json({"ok": False, "error": "Felaktigt anvandarnamn eller losenord"}, 401)
                    return
                self.send_json({"ok": True, "username": row["username"], "token": row["token"]})
            finally:
                db.close()
            return

        # API: change password
        if path == "/api/change-password":
            uname = body.get("username", "").strip()
            token = body.get("token", "").strip()
            old_password = body.get("old_password", "")
            new_password = body.get("new_password", "")
            if not uname or not token or not new_password:
                self.send_json({"ok": False, "error": "Alla falt kravs"}, 400)
                return
            if len(new_password) < 4:
                self.send_json({"ok": False, "error": "Losenord maste vara minst 4 tecken"}, 400)
                return
            db = get_db()
            try:
                row = db.execute(
                    "SELECT username, password FROM users WHERE username = ? AND token = ?",
                    (uname, token)
                ).fetchone()
                if not row:
                    self.send_json({"ok": False, "error": "Ogiltig token"}, 401)
                    return
                stored_pw = row["password"] or ""
                # If old password exists and old_password provided, verify it
                if stored_pw and old_password:
                    if not verify_password(stored_pw, old_password):
                        self.send_json({"ok": False, "error": "Fel nuvarande losenord"}, 401)
                        return
                hashed_new = hash_password(new_password)
                db.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_new, uname))
                db.commit()
            finally:
                db.close()
            self.send_json({"ok": True})
            return

        # API: request password reset
        if path == "/api/request-reset":
            uname = body.get("username", "").strip()
            if not uname:
                self.send_json({"ok": False, "error": "Anvandarnamn kravs"}, 400)
                return
            db = get_db()
            try:
                row = db.execute("SELECT username FROM users WHERE username = ?", (uname,)).fetchone()
                if row:
                    import random
                    reset_code = f"{random.randint(0, 99999999):08d}"
                    db.execute(
                        "INSERT INTO password_resets (id, username, reset_code, created_at) VALUES (?, ?, ?, ?)",
                        (uuid.uuid4().hex, uname, reset_code, now())
                    )
                    db.commit()
            finally:
                db.close()
            # Always return success to not reveal if user exists
            self.send_json({"ok": True, "message": "Begaran skickad till admin"})
            return

        # API: verify token
        if path == "/api/verify":
            uname = body.get("username", "").strip()
            token = body.get("token", "").strip()
            if not uname or not token:
                self.send_json({"ok": False, "error": "missing fields"}, 400)
                return
            db = get_db()
            try:
                row = db.execute(
                    "SELECT username FROM users WHERE username = ? AND token = ?",
                    (uname, token)
                ).fetchone()
            finally:
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
            try:
                row = db.execute("SELECT username FROM users WHERE username = ?", (uname,)).fetchone()
            finally:
                db.close()
            self.send_json({"ok": True, "available": row is None, "username": uname})
            return

        # API: send message (requires valid token)
        if path.startswith("/api/channel/") and path.endswith("/message"):
            parts = path.split("/")
            channel = unquote(parts[3])[:50]
            if not re.match(r'^[a-z0-9\u00e5\u00e4\u00f6][a-z0-9\u00e5\u00e4\u00f6_-]{0,48}$', channel):
                self.send_json({"ok": False, "error": "invalid channel name"}, 400)
                return
            content = body.get("content", "").strip()[:5000]
            author = body.get("author", "anonymous").strip()[:20]
            token = body.get("token", "").strip()

            if token:
                db_check = get_db()
                try:
                    valid = db_check.execute(
                        "SELECT username FROM users WHERE username = ? AND token = ?",
                        (author, token)
                    ).fetchone()
                finally:
                    db_check.close()
                if not valid:
                    self.send_json({"ok": False, "error": "invalid token"}, 401)
                    return
            else:
                self.send_json({"ok": False, "error": "token required"}, 401)
                return

            # Room access check
            db_ac = get_db()
            try:
                room, access = check_room_access(db_ac, channel, author)
            finally:
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
            ALLOWED_IMAGE_MIMES = ("data:image/png;", "data:image/jpeg;", "data:image/gif;", "data:image/webp;", "data:image/bmp;")
            total_att_size = 0
            for att in attachments:
                if not isinstance(att, dict):
                    self.send_json({"ok": False, "error": "invalid attachment format"}, 400)
                    return
                data_url = att.get("dataUrl", "")
                if data_url and not data_url.startswith(ALLOWED_IMAGE_MIMES):
                    self.send_json({"ok": False, "error": "only image attachments allowed (png, jpeg, gif, webp, bmp)"}, 400)
                    return
                att_size = len(data_url)
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

            # Fetch author's avatar_color and avatar for broadcast
            db_ac = get_db()
            try:
                ac_row = db_ac.execute("SELECT avatar_color, avatar FROM users WHERE username = ?", (author,)).fetchone()
                author_avatar_color = ac_row["avatar_color"] if ac_row and ac_row["avatar_color"] else "#4f8ff7"
                author_avatar_img = ac_row["avatar"] if ac_row and ac_row["avatar"] else ""
            finally:
                db_ac.close()

            # Ephemeral mode: message is NOT saved, only broadcast + auto-expires
            try:
                ephemeral = int(body.get("ephemeral", 0))
            except (ValueError, TypeError):
                ephemeral = 0
            if ephemeral:
                ephemeral = max(1, min(30, ephemeral))  # 1-30 seconds
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
                    "avatar_color": author_avatar_color,
                    "avatar": author_avatar_img,
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
                "avatar_color": author_avatar_color,
                "avatar": author_avatar_img,
            }
            broadcast(broadcast_data, channel)

            self.send_json({"ok": True, "id": msg_id, "channel": channel})
            return

        # API: WebRTC signaling relay — POST /api/signal { type, to, from, ... }
        if path == "/api/signal":
            sig_type = body.get("type", "")
            to_user = body.get("to", "")
            from_user = body.get("from", "")
            token = body.get("token", "")
            if not to_user or not from_user or not token:
                self.send_json({"ok": False, "error": "missing fields"}, 400)
                return
            # Verify sender token
            db = get_db()
            try:
                valid = db.execute("SELECT username FROM users WHERE username = ? AND token = ?", (from_user, token)).fetchone()
            finally:
                db.close()
            if not valid:
                self.send_json({"ok": False, "error": "invalid token"}, 401)
                return
            # Relay signal to target user
            signal = {k: v for k, v in body.items() if k != "token"}
            send_to_user(to_user, signal)
            self.send_json({"ok": True})
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
            # Protect system room names from being created/overwritten
            if name == "allmant":
                self.send_json({"ok": False, "error": "det namnet ar reserverat"}, 400)
                return
            display = body.get("display_name", name)[:100]
            topic = body.get("topic", "")[:200]
            creator = body.get("created_by", "anonymous")[:20]
            token = body.get("token", "").strip()

            if token:
                db_v = get_db()
                try:
                    valid = db_v.execute("SELECT username FROM users WHERE username = ? AND token = ?", (creator, token)).fetchone()
                finally:
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
            channel_type = body.get("channel_type", "text")
            if channel_type not in ("text", "voice"):
                channel_type = "text"

            db = get_db()
            try:
                ch_count = db.execute("SELECT COUNT(*) as c FROM channels").fetchone()["c"]
                if ch_count >= MAX_CHANNELS:
                    self.send_json({"ok": False, "error": "max antal kanaler uppnatt"}, 403)
                    return
                # Check if channel name already exists
                if db.execute("SELECT 1 FROM channels WHERE name = ?", (name,)).fetchone():
                    self.send_json({"ok": False, "error": "kanalen finns redan"}, 409)
                    return
                ts = now()
                db.execute(
                    "INSERT INTO channels (name, display_name, topic, visibility, owner, channel_type, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (name, display, topic, visibility, creator, channel_type, creator, ts)
                )
                # Auto-join creator as owner
                db.execute(
                    "INSERT INTO room_members (room, username, role, joined_at) VALUES (?, ?, 'owner', ?)",
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
            # Reject plain ASCII text as reactions — must contain emoji (non-ASCII)
            if all(ord(c) < 0x200 for c in emoji):
                self.send_json({"ok": False, "error": "only emoji reactions allowed"}, 400)
                return

            if token:
                db_v = get_db()
                try:
                    valid = db_v.execute("SELECT username FROM users WHERE username = ? AND token = ?", (author, token)).fetchone()
                finally:
                    db_v.close()
                if not valid:
                    self.send_json({"ok": False, "error": "invalid token"}, 401)
                    return
            else:
                self.send_json({"ok": False, "error": "token required"}, 401)
                return

            db = get_db()
            try:
                # Verify message exists
                msg_row = db.execute("SELECT id, channel FROM messages WHERE id = ?", (message_id,)).fetchone()
                if not msg_row:
                    self.send_json({"ok": False, "error": "meddelandet finns inte"}, 404)
                    return

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
                try:
                    valid = db_v.execute("SELECT username FROM users WHERE username = ? AND token = ?", (del_user, del_token)).fetchone()
                    if valid:
                        owner_row = db_v.execute("SELECT role FROM room_members WHERE room = ? AND username = ?", (channel, del_user)).fetchone()
                        if owner_row and owner_row["role"] == "owner":
                            is_owner = True
                finally:
                    db_v.close()
            if not is_admin and not is_owner:
                self.send_json({"ok": False, "error": "unauthorized"}, 401)
                return
            db = get_db()
            try:
                db.execute("DELETE FROM reactions WHERE message_id IN (SELECT id FROM messages WHERE channel = ?)", (channel,))
                db.execute("DELETE FROM messages WHERE channel = ?", (channel,))
                db.execute("DELETE FROM room_members WHERE room = ?", (channel,))
                db.execute("DELETE FROM invites WHERE room = ?", (channel,))
                db.execute("DELETE FROM voice_state WHERE channel = ?", (channel,))
                db.execute("DELETE FROM channels WHERE name = ?", (channel,))
                db.commit()
            finally:
                db.close()
            # Clear caches
            with membership_lock:
                membership_cache.pop(channel, None)
            with visibility_lock:
                visibility_cache.pop(channel, None)
            broadcast({"event_type": "channel_deleted", "channel": channel})
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
            # Send only to the room owner — not to all clients
            send_to_user(owner, {
                "event_type": "access_request",
                "room": room_name,
                "display_name": display,
                "from": author,
                "owner": owner,
            })
            self.send_json({"ok": True, "message": "Forfragan skickad till agaren"})
            return

        # API: join voice channel — POST /api/channel/{name}/voice/join
        if path.startswith("/api/channel/") and path.endswith("/voice/join"):
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
                ch = db.execute("SELECT * FROM channels WHERE name = ? AND channel_type = 'voice'", (room_name,)).fetchone()
                if not ch:
                    self.send_json({"ok": False, "error": "voice-kanalen finns inte"}, 404)
                    return
                # Access check: use check_room_access for full role/group verification
                _, access = check_room_access(db, room_name, author)
                if access is None or access in ("read", "locked", "system"):
                    self.send_json({"ok": False, "error": "du har inte tillgang till den har kanalen"}, 403)
                    return
                # Leave any other voice channel first
                db.execute("DELETE FROM voice_state WHERE username = ?", (author,))
                # Join this one
                db.execute("INSERT OR REPLACE INTO voice_state (channel, username, joined_at) VALUES (?, ?, ?)", (room_name, author, now()))
                db.commit()
                # Get current members
                members = [r["username"] for r in db.execute("SELECT username FROM voice_state WHERE channel = ?", (room_name,)).fetchall()]
            finally:
                db.close()
            broadcast({"event_type": "voice_joined", "channel": room_name, "username": author, "members": members}, room_name)
            self.send_json({"ok": True, "channel": room_name, "members": members})
            return

        # API: leave voice channel — POST /api/channel/{name}/voice/leave
        if path.startswith("/api/channel/") and path.endswith("/voice/leave"):
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
                db.execute("DELETE FROM voice_state WHERE channel = ? AND username = ?", (room_name, author))
                db.commit()
                members = [r["username"] for r in db.execute("SELECT username FROM voice_state WHERE channel = ?", (room_name,)).fetchall()]
            finally:
                db.close()
            broadcast({"event_type": "voice_left", "channel": room_name, "username": author, "members": members}, room_name)
            self.send_json({"ok": True})
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
                        # No members left — delete room and all associated data
                        db.execute("DELETE FROM reactions WHERE message_id IN (SELECT id FROM messages WHERE channel = ?)", (room_name,))
                        db.execute("DELETE FROM messages WHERE channel = ?", (room_name,))
                        db.execute("DELETE FROM invites WHERE room = ?", (room_name,))
                        db.execute("DELETE FROM voice_state WHERE channel = ?", (room_name,))
                        db.execute("DELETE FROM channels WHERE name = ?", (room_name,))
                        with visibility_lock:
                            visibility_cache.pop(room_name, None)
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
                    # Notify only the invited user
                    send_to_user(invitee, {"event_type": "invited", "room": room_name, "username": invitee, "display_name": room["display_name"] or room_name})
                    self.send_json({"ok": True, "invited": invitee})
                    return

                if generate_code:
                    # Check invite limit
                    invite_count = db.execute("SELECT COUNT(*) as c FROM invites WHERE room = ?", (room_name,)).fetchone()["c"]
                    if invite_count >= 10:
                        self.send_json({"ok": False, "error": "max 10 inbjudningskoder per rum"}, 400)
                        return
                    code = uuid.uuid4().hex[:16]
                    try:
                        uses = max(1, min(100, int(body.get("uses", 10))))
                    except (ValueError, TypeError):
                        uses = 10
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
                invite_group_id = invite["group_id"] if "group_id" in invite.keys() else None
                # Add member
                db.execute(
                    "INSERT OR IGNORE INTO room_members (room, username, role, joined_at) VALUES (?, ?, 'member', ?)",
                    (room_name, author, now())
                )
                # If invite has group_id, also add to group_members
                if invite_group_id:
                    db.execute(
                        "INSERT OR IGNORE INTO group_members (group_id, username, role, joined_at) VALUES (?, ?, 'member', ?)",
                        (invite_group_id, author, now())
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
            if invite_group_id:
                group_cache_add_member(invite_group_id, author)
            self.send_json({"ok": True, "room": room_name, "group_id": invite_group_id})
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
            send_to_user(target, {"event_type": "kicked", "room": room_name, "username": target})
            self.send_json({"ok": True, "kicked": target})
            return

        # API: list room members
        if path.startswith("/api/channel/") and path.endswith("/members"):
            parts = path.split("/")
            room_name = parts[3]
            # Parse query params for GET-style calls via do_DELETE->do_POST
            qs = parse_qs(urlparse(self.path).query)
            req_user = qs.get("user", [None])[0]
            req_token = qs.get("token", [None])[0]
            # For POST, get from body if not in query
            if not req_user:
                req_user = body.get("author", "")
                req_token = body.get("token", "")
            auth_user = None
            if req_user and req_token:
                db_v = get_db()
                try:
                    valid = db_v.execute("SELECT username FROM users WHERE username = ? AND token = ?", (req_user, req_token)).fetchone()
                finally:
                    db_v.close()
                if valid:
                    auth_user = req_user
            db = get_db()
            try:
                room, access = check_room_access(db, room_name, auth_user)
                if room is None:
                    self.send_error(404)
                    return
                members = [dict(r) for r in db.execute("SELECT username, role, joined_at FROM room_members WHERE room = ? ORDER BY joined_at", (room_name,)).fetchall()]
            finally:
                db.close()
            self.send_json({"ok": True, "room": room_name, "members": members})
            return

        # ===== GROUP ENDPOINTS =====

        # API: create group — POST /api/group
        if path == "/api/group":
            name = body.get("name", "").strip().lower().replace(" ", "-")[:50]
            if not name:
                self.send_json({"ok": False, "error": "name required"}, 400)
                return
            if not re.match(r'^[a-z0-9\u00e5\u00e4\u00f6][a-z0-9\u00e5\u00e4\u00f6_-]{0,48}$', name):
                self.send_json({"ok": False, "error": "invalid group name"}, 400)
                return
            display_name = body.get("display_name", name)[:100]
            description = body.get("description", "")[:500]
            visibility = body.get("visibility", "public")
            if visibility not in ("public", "private"):
                visibility = "public"
            creator = body.get("created_by", "").strip()[:20]
            token = body.get("token", "").strip()
            if not creator or not token:
                self.send_json({"ok": False, "error": "token required"}, 401)
                return
            db = get_db()
            try:
                valid = db.execute("SELECT username FROM users WHERE username = ? AND token = ?", (creator, token)).fetchone()
                if not valid:
                    self.send_json({"ok": False, "error": "invalid token"}, 401)
                    return
                # Check limit
                group_count = db.execute("SELECT COUNT(*) as c FROM groups").fetchone()["c"]
                if group_count >= MAX_GROUPS:
                    self.send_json({"ok": False, "error": "max antal grupper uppnatt"}, 403)
                    return
                # Check unique name
                if db.execute("SELECT 1 FROM groups WHERE name = ?", (name,)).fetchone():
                    self.send_json({"ok": False, "error": "gruppnamnet finns redan"}, 409)
                    return
                group_id = uuid.uuid4().hex
                ts = now()
                db.execute(
                    "INSERT INTO groups (id, name, display_name, description, visibility, owner, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (group_id, name, display_name, description, visibility, creator, ts)
                )
                # Add creator as owner
                db.execute(
                    "INSERT INTO group_members (group_id, username, role, joined_at) VALUES (?, ?, 'owner', ?)",
                    (group_id, creator, ts)
                )
                # Auto-create #general channel
                general_name = f"g-{name}-general"[:50]
                db.execute(
                    "INSERT INTO channels (name, display_name, topic, visibility, owner, channel_type, created_by, created_at, group_id, required_role) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (general_name, "General", "", "public", creator, "text", creator, ts, group_id, "member")
                )
                # Auto-create default custom roles
                for role_name, role_display, role_color, role_pos in [("moderator", "Moderator", "#e74c3c", 2), ("medlem", "Medlem", "#99aab5", 1)]:
                    db.execute(
                        "INSERT INTO group_roles (id, group_id, name, display_name, color, position, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (uuid.uuid4().hex, group_id, role_name, role_display, role_color, role_pos, ts)
                    )
                db.commit()
            finally:
                db.close()
            # Update caches
            cache_set_group_visibility(group_id, visibility)
            group_cache_add_member(group_id, creator)
            cache_set_visibility(general_name, "public")
            broadcast({"event_type": "group_created", "group_id": group_id, "name": name, "display_name": display_name, "visibility": visibility})
            self.send_json({"ok": True, "group_id": group_id, "name": name, "general_channel": general_name})
            return

        # API: delete group — DELETE /api/group/{id}
        if re.match(r'^/api/group/[a-f0-9]+$', path) and self.command == "DELETE":
            group_id = path.split("/")[3]
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
                group = db.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
                if not group:
                    self.send_json({"ok": False, "error": "gruppen finns inte"}, 404)
                    return
                if group["owner"] != author:
                    self.send_json({"ok": False, "error": "bara agaren kan ta bort gruppen"}, 403)
                    return
                # Cascade delete: get all channels in this group
                ch_names = [r["name"] for r in db.execute("SELECT name FROM channels WHERE group_id = ?", (group_id,)).fetchall()]
                for ch_name in ch_names:
                    db.execute("DELETE FROM reactions WHERE message_id IN (SELECT id FROM messages WHERE channel = ?)", (ch_name,))
                    db.execute("DELETE FROM messages WHERE channel = ?", (ch_name,))
                    db.execute("DELETE FROM voice_state WHERE channel = ?", (ch_name,))
                db.execute("DELETE FROM channels WHERE group_id = ?", (group_id,))
                db.execute("DELETE FROM group_members WHERE group_id = ?", (group_id,))
                db.execute("DELETE FROM group_roles WHERE group_id = ?", (group_id,))
                db.execute("DELETE FROM user_roles WHERE group_id = ?", (group_id,))
                db.execute("DELETE FROM invites WHERE group_id = ?", (group_id,))
                db.execute("DELETE FROM join_requests WHERE group_id = ?", (group_id,))
                db.execute("DELETE FROM groups WHERE id = ?", (group_id,))
                db.commit()
            finally:
                db.close()
            # Clear caches
            with group_membership_lock:
                group_membership_cache.pop(group_id, None)
            with group_visibility_lock:
                group_visibility_cache.pop(group_id, None)
            for ch_name in ch_names:
                with membership_lock:
                    membership_cache.pop(ch_name, None)
                with visibility_lock:
                    visibility_cache.pop(ch_name, None)
            broadcast({"event_type": "group_deleted", "group_id": group_id})
            self.send_json({"ok": True})
            return

        # API: join public group — POST /api/group/{id}/join
        if re.match(r'^/api/group/[a-f0-9]+/join$', path):
            group_id = path.split("/")[3]
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
                group = db.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
                if not group:
                    self.send_json({"ok": False, "error": "gruppen finns inte"}, 404)
                    return
                if group["visibility"] == "private":
                    self.send_json({"ok": False, "error": "gruppen ar privat, begara tillgang istallet"}, 403)
                    return
                # Check member limit
                member_count = db.execute("SELECT COUNT(*) as c FROM group_members WHERE group_id = ?", (group_id,)).fetchone()["c"]
                if member_count >= MAX_GROUP_MEMBERS:
                    self.send_json({"ok": False, "error": "gruppen ar full"}, 403)
                    return
                db.execute(
                    "INSERT OR IGNORE INTO group_members (group_id, username, role, joined_at) VALUES (?, ?, 'member', ?)",
                    (group_id, author, now())
                )
                db.commit()
            finally:
                db.close()
            group_cache_add_member(group_id, author)
            broadcast({"event_type": "group_member_joined", "group_id": group_id, "username": author})
            self.send_json({"ok": True, "group_id": group_id})
            return

        # API: leave group — POST /api/group/{id}/leave
        if re.match(r'^/api/group/[a-f0-9]+/leave$', path):
            group_id = path.split("/")[3]
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
                group = db.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
                if not group:
                    self.send_json({"ok": False, "error": "gruppen finns inte"}, 404)
                    return
                member = db.execute("SELECT role FROM group_members WHERE group_id = ? AND username = ?", (group_id, author)).fetchone()
                if not member:
                    self.send_json({"ok": True})
                    return
                db.execute("DELETE FROM group_members WHERE group_id = ? AND username = ?", (group_id, author))
                if member["role"] == "owner":
                    # Transfer ownership: oldest admin, then oldest member
                    next_owner = db.execute("SELECT username FROM group_members WHERE group_id = ? AND role = 'admin' ORDER BY joined_at ASC LIMIT 1", (group_id,)).fetchone()
                    if not next_owner:
                        next_owner = db.execute("SELECT username FROM group_members WHERE group_id = ? ORDER BY joined_at ASC LIMIT 1", (group_id,)).fetchone()
                    if next_owner:
                        db.execute("UPDATE group_members SET role = 'owner' WHERE group_id = ? AND username = ?", (group_id, next_owner["username"]))
                        db.execute("UPDATE groups SET owner = ? WHERE id = ?", (next_owner["username"], group_id))
                    else:
                        # No members left — delete group and all data
                        ch_names = [r["name"] for r in db.execute("SELECT name FROM channels WHERE group_id = ?", (group_id,)).fetchall()]
                        for ch_name in ch_names:
                            db.execute("DELETE FROM reactions WHERE message_id IN (SELECT id FROM messages WHERE channel = ?)", (ch_name,))
                            db.execute("DELETE FROM messages WHERE channel = ?", (ch_name,))
                            db.execute("DELETE FROM voice_state WHERE channel = ?", (ch_name,))
                        db.execute("DELETE FROM channels WHERE group_id = ?", (group_id,))
                        db.execute("DELETE FROM invites WHERE group_id = ?", (group_id,))
                        db.execute("DELETE FROM join_requests WHERE group_id = ?", (group_id,))
                        db.execute("DELETE FROM groups WHERE id = ?", (group_id,))
                        with group_visibility_lock:
                            group_visibility_cache.pop(group_id, None)
                        for ch_name in ch_names:
                            with visibility_lock:
                                visibility_cache.pop(ch_name, None)
                            with membership_lock:
                                membership_cache.pop(ch_name, None)
                db.commit()
            finally:
                db.close()
            group_cache_remove_member(group_id, author)
            self.send_json({"ok": True})
            return

        # API: create channel in group — POST /api/group/{id}/channel
        if re.match(r'^/api/group/[a-f0-9]+/channel$', path):
            group_id = path.split("/")[3]
            name = body.get("name", "").strip().lower().replace(" ", "-")[:50]
            if not name:
                self.send_json({"ok": False, "error": "name required"}, 400)
                return
            if not re.match(r'^[a-z0-9\u00e5\u00e4\u00f6][a-z0-9\u00e5\u00e4\u00f6_-]{0,48}$', name):
                self.send_json({"ok": False, "error": "invalid channel name"}, 400)
                return
            display_name = body.get("display_name", name)[:100]
            channel_type = body.get("channel_type", "text")
            if channel_type not in ("text", "voice"):
                channel_type = "text"
            required_role = body.get("required_role", "member")
            # Accept built-in roles or custom role IDs (hex strings)
            if required_role not in ("member", "admin", "owner") and not re.match(r'^[a-f0-9]{32}$', required_role):
                required_role = "member"
            creator = body.get("created_by", "").strip()[:20]
            token = body.get("token", "").strip()
            if not creator or not token:
                self.send_json({"ok": False, "error": "token required"}, 401)
                return
            db = get_db()
            try:
                valid = db.execute("SELECT username FROM users WHERE username = ? AND token = ?", (creator, token)).fetchone()
                if not valid:
                    self.send_json({"ok": False, "error": "invalid token"}, 401)
                    return
                group = db.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
                if not group:
                    self.send_json({"ok": False, "error": "gruppen finns inte"}, 404)
                    return
                # Auth: admin or owner only
                gm = db.execute("SELECT role FROM group_members WHERE group_id = ? AND username = ?", (group_id, creator)).fetchone()
                if not gm or gm["role"] not in ("admin", "owner"):
                    self.send_json({"ok": False, "error": "bara admin eller agare kan skapa kanaler"}, 403)
                    return
                # Check channel limit
                ch_count = db.execute("SELECT COUNT(*) as c FROM channels WHERE group_id = ?", (group_id,)).fetchone()["c"]
                if ch_count >= MAX_CHANNELS_PER_GROUP:
                    self.send_json({"ok": False, "error": "max antal kanaler i gruppen uppnatt"}, 403)
                    return
                # Prefix channel name with group name for uniqueness
                full_name = f"g-{group['name']}-{name}"[:50]
                if db.execute("SELECT 1 FROM channels WHERE name = ?", (full_name,)).fetchone():
                    self.send_json({"ok": False, "error": "kanalen finns redan"}, 409)
                    return
                ts = now()
                db.execute(
                    "INSERT INTO channels (name, display_name, topic, visibility, owner, channel_type, created_by, created_at, group_id, required_role) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (full_name, display_name, "", "public", creator, channel_type, creator, ts, group_id, required_role)
                )
                db.commit()
            finally:
                db.close()
            cache_set_visibility(full_name, "public")
            broadcast({"event_type": "group_channel_created", "group_id": group_id, "channel": full_name, "display_name": display_name})
            self.send_json({"ok": True, "channel": full_name, "group_id": group_id})
            return

        # API: update channel settings — POST /api/group/{id}/channel/{name}/settings
        if re.match(r'^/api/group/[a-f0-9]+/channel/.+/settings$', path):
            parts = path.split("/")
            group_id = parts[3]
            channel_name = unquote(parts[5])
            author = body.get("author", "").strip()[:20]
            token = body.get("token", "").strip()
            required_role = body.get("required_role", "").strip()
            if not author or not token:
                self.send_json({"ok": False, "error": "token required"}, 401)
                return
            db = get_db()
            try:
                valid = db.execute("SELECT username FROM users WHERE username = ? AND token = ?", (author, token)).fetchone()
                if not valid:
                    self.send_json({"ok": False, "error": "invalid token"}, 401)
                    return
                group = db.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
                if not group:
                    self.send_json({"ok": False, "error": "gruppen finns inte"}, 404)
                    return
                gm = db.execute("SELECT role FROM group_members WHERE group_id = ? AND username = ?", (group_id, author)).fetchone()
                if not gm or gm["role"] not in ("admin", "owner"):
                    self.send_json({"ok": False, "error": "bara admin eller agare"}, 403)
                    return
                ch = db.execute("SELECT * FROM channels WHERE name = ? AND group_id = ?", (channel_name, group_id)).fetchone()
                if not ch:
                    self.send_json({"ok": False, "error": "kanalen finns inte"}, 404)
                    return
                # Validate required_role: empty string means 'member' (all members)
                if not required_role:
                    required_role = "member"
                elif required_role not in ("member", "admin", "owner"):
                    # Check if it's a valid custom role ID
                    custom = db.execute("SELECT 1 FROM group_roles WHERE id = ? AND group_id = ?", (required_role, group_id)).fetchone()
                    if not custom:
                        self.send_json({"ok": False, "error": "ogiltig roll"}, 400)
                        return
                db.execute("UPDATE channels SET required_role = ? WHERE name = ? AND group_id = ?", (required_role, channel_name, group_id))
                db.commit()
            finally:
                db.close()
            broadcast({"event_type": "group_updated", "group_id": group_id})
            self.send_json({"ok": True})
            return

        # API: delete channel in group — DELETE /api/group/{id}/channel/{channel_name}
        if re.match(r'^/api/group/[a-f0-9]+/channel/.+$', path) and self.command == "DELETE":
            parts = path.split("/")
            group_id = parts[3]
            channel_name = unquote(parts[5])
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
                group = db.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
                if not group:
                    self.send_json({"ok": False, "error": "gruppen finns inte"}, 404)
                    return
                ch = db.execute("SELECT * FROM channels WHERE name = ? AND group_id = ?", (channel_name, group_id)).fetchone()
                if not ch:
                    self.send_json({"ok": False, "error": "kanalen finns inte"}, 404)
                    return
                # Auth: admin/owner or channel creator
                gm = db.execute("SELECT role FROM group_members WHERE group_id = ? AND username = ?", (group_id, author)).fetchone()
                is_admin_or_owner = gm and gm["role"] in ("admin", "owner")
                is_creator = ch["created_by"] == author
                if not is_admin_or_owner and not is_creator:
                    self.send_json({"ok": False, "error": "unauthorized"}, 403)
                    return
                # Delete channel and its data
                db.execute("DELETE FROM reactions WHERE message_id IN (SELECT id FROM messages WHERE channel = ?)", (channel_name,))
                db.execute("DELETE FROM messages WHERE channel = ?", (channel_name,))
                db.execute("DELETE FROM voice_state WHERE channel = ?", (channel_name,))
                db.execute("DELETE FROM channels WHERE name = ?", (channel_name,))
                db.commit()
            finally:
                db.close()
            with visibility_lock:
                visibility_cache.pop(channel_name, None)
            with membership_lock:
                membership_cache.pop(channel_name, None)
            broadcast({"event_type": "channel_deleted", "channel": channel_name, "group_id": group_id})
            self.send_json({"ok": True})
            return

        # API: change member role — POST /api/group/{id}/members/{username}/role
        if re.match(r'^/api/group/[a-f0-9]+/members/.+/role$', path):
            parts = path.split("/")
            group_id = parts[3]
            target_user = unquote(parts[5])
            new_role = body.get("role", "").strip()
            author = body.get("author", "").strip()[:20]
            token = body.get("token", "").strip()
            if not author or not token:
                self.send_json({"ok": False, "error": "token required"}, 401)
                return
            if new_role not in ("member", "admin", "owner"):
                self.send_json({"ok": False, "error": "ogiltig roll"}, 400)
                return
            db = get_db()
            try:
                valid = db.execute("SELECT username FROM users WHERE username = ? AND token = ?", (author, token)).fetchone()
                if not valid:
                    self.send_json({"ok": False, "error": "invalid token"}, 401)
                    return
                group = db.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
                if not group:
                    self.send_json({"ok": False, "error": "gruppen finns inte"}, 404)
                    return
                # Only owner can promote/demote
                if group["owner"] != author:
                    self.send_json({"ok": False, "error": "bara agaren kan andra roller"}, 403)
                    return
                target_member = db.execute("SELECT role FROM group_members WHERE group_id = ? AND username = ?", (group_id, target_user)).fetchone()
                if not target_member:
                    self.send_json({"ok": False, "error": "anvandaren ar inte medlem"}, 404)
                    return
                if new_role == "owner":
                    # Transfer ownership
                    db.execute("UPDATE group_members SET role = 'admin' WHERE group_id = ? AND username = ?", (group_id, author))
                    db.execute("UPDATE groups SET owner = ? WHERE id = ?", (target_user, group_id))
                db.execute("UPDATE group_members SET role = ? WHERE group_id = ? AND username = ?", (new_role, group_id, target_user))
                db.commit()
            finally:
                db.close()
            broadcast({"event_type": "group_role_changed", "group_id": group_id, "username": target_user, "role": new_role})
            self.send_json({"ok": True, "username": target_user, "role": new_role})
            return

        # API: kick from group — POST /api/group/{id}/kick
        if re.match(r'^/api/group/[a-f0-9]+/kick$', path):
            group_id = path.split("/")[3]
            target = body.get("username", "").strip()[:20]
            author = body.get("author", "").strip()[:20]
            token = body.get("token", "").strip()
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
                group = db.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
                if not group:
                    self.send_json({"ok": False, "error": "gruppen finns inte"}, 404)
                    return
                author_member = db.execute("SELECT role FROM group_members WHERE group_id = ? AND username = ?", (group_id, author)).fetchone()
                if not author_member or author_member["role"] not in ("admin", "owner"):
                    self.send_json({"ok": False, "error": "bara admin eller agare kan kicka"}, 403)
                    return
                target_member = db.execute("SELECT role FROM group_members WHERE group_id = ? AND username = ?", (group_id, target)).fetchone()
                if not target_member:
                    self.send_json({"ok": False, "error": "anvandaren ar inte medlem"}, 404)
                    return
                # Admins can't kick other admins or owner
                if author_member["role"] == "admin" and target_member["role"] in ("admin", "owner"):
                    self.send_json({"ok": False, "error": "admins kan inte kicka andra admins eller agaren"}, 403)
                    return
                db.execute("DELETE FROM group_members WHERE group_id = ? AND username = ?", (group_id, target))
                db.commit()
            finally:
                db.close()
            group_cache_remove_member(group_id, target)
            send_to_user(target, {"event_type": "group_kicked", "group_id": group_id, "username": target})
            self.send_json({"ok": True, "kicked": target})
            return

        # API: invite to group — POST /api/group/{id}/invite
        if re.match(r'^/api/group/[a-f0-9]+/invite$', path):
            group_id = path.split("/")[3]
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
                group = db.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
                if not group:
                    self.send_json({"ok": False, "error": "gruppen finns inte"}, 404)
                    return
                # Check author is member (any role can invite)
                gm = db.execute("SELECT role FROM group_members WHERE group_id = ? AND username = ?", (group_id, author)).fetchone()
                if not gm:
                    self.send_json({"ok": False, "error": "du ar inte medlem i gruppen"}, 403)
                    return

                invitee = body.get("username", "").strip()
                generate_code = body.get("generate_code", False)

                if invitee:
                    # Direct invite: add to members
                    user_exists = db.execute("SELECT username FROM users WHERE username = ?", (invitee,)).fetchone()
                    if not user_exists:
                        self.send_json({"ok": False, "error": "anvandaren finns inte"}, 404)
                        return
                    member_count = db.execute("SELECT COUNT(*) as c FROM group_members WHERE group_id = ?", (group_id,)).fetchone()["c"]
                    if member_count >= MAX_GROUP_MEMBERS:
                        self.send_json({"ok": False, "error": "gruppen ar full"}, 403)
                        return
                    db.execute(
                        "INSERT OR IGNORE INTO group_members (group_id, username, role, joined_at) VALUES (?, ?, 'member', ?)",
                        (group_id, invitee, now())
                    )
                    db.commit()
                    group_cache_add_member(group_id, invitee)
                    send_to_user(invitee, {"event_type": "group_invited", "group_id": group_id, "group_name": group["name"], "display_name": group["display_name"] or group["name"], "username": invitee})
                    self.send_json({"ok": True, "invited": invitee})
                    return

                if generate_code:
                    invite_count = db.execute("SELECT COUNT(*) as c FROM invites WHERE group_id = ?", (group_id,)).fetchone()["c"]
                    if invite_count >= 10:
                        self.send_json({"ok": False, "error": "max 10 inbjudningskoder per grupp"}, 400)
                        return
                    code = uuid.uuid4().hex[:16]
                    try:
                        uses = max(1, min(100, int(body.get("uses", 10))))
                    except (ValueError, TypeError):
                        uses = 10
                    # Use the group's general channel as room placeholder, set group_id
                    general_ch = db.execute("SELECT name FROM channels WHERE group_id = ? ORDER BY created_at LIMIT 1", (group_id,)).fetchone()
                    room_name = general_ch["name"] if general_ch else group["name"]
                    db.execute(
                        "INSERT INTO invites (code, room, created_by, created_at, uses_left, group_id) VALUES (?, ?, ?, ?, ?, ?)",
                        (code, room_name, author, now(), uses, group_id)
                    )
                    db.commit()
                    self.send_json({"ok": True, "code": code, "uses": uses})
                    return

                self.send_json({"ok": False, "error": "ange username eller generate_code"}, 400)
            finally:
                db.close()
            return

        # API: request to join private group — POST /api/group/{id}/request-join
        if re.match(r'^/api/group/[a-f0-9]+/request-join$', path):
            group_id = path.split("/")[3]
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
                group = db.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
                if not group:
                    self.send_json({"ok": False, "error": "gruppen finns inte"}, 404)
                    return
                # Check if already a member
                existing_member = db.execute("SELECT 1 FROM group_members WHERE group_id = ? AND username = ?", (group_id, author)).fetchone()
                if existing_member:
                    self.send_json({"ok": False, "error": "du ar redan medlem"}, 400)
                    return
                # Check for existing pending request
                existing_req = db.execute("SELECT 1 FROM join_requests WHERE group_id = ? AND username = ? AND status = 'pending'", (group_id, author)).fetchone()
                if existing_req:
                    self.send_json({"ok": False, "error": "du har redan en aktiv forfragan"}, 400)
                    return
                req_id = uuid.uuid4().hex
                db.execute(
                    "INSERT OR REPLACE INTO join_requests (id, group_id, username, status, created_at) VALUES (?, ?, ?, 'pending', ?)",
                    (req_id, group_id, author, now())
                )
                db.commit()
            finally:
                db.close()
            # Notify group owner
            send_to_user(group["owner"], {
                "event_type": "group_join_request",
                "group_id": group_id,
                "group_name": group["name"],
                "request_id": req_id,
                "from": author,
            })
            self.send_json({"ok": True, "request_id": req_id})
            return

        # API: resolve join request — POST /api/group/{id}/request/{req_id}/resolve
        if re.match(r'^/api/group/[a-f0-9]+/request/[a-f0-9]+/resolve$', path):
            parts = path.split("/")
            group_id = parts[3]
            req_id = parts[5]
            action = body.get("action", "").strip()
            author = body.get("author", "").strip()[:20]
            token = body.get("token", "").strip()
            if not author or not token:
                self.send_json({"ok": False, "error": "token required"}, 401)
                return
            if action not in ("accept", "reject"):
                self.send_json({"ok": False, "error": "action must be accept or reject"}, 400)
                return
            db = get_db()
            try:
                valid = db.execute("SELECT username FROM users WHERE username = ? AND token = ?", (author, token)).fetchone()
                if not valid:
                    self.send_json({"ok": False, "error": "invalid token"}, 401)
                    return
                group = db.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
                if not group:
                    self.send_json({"ok": False, "error": "gruppen finns inte"}, 404)
                    return
                # Only owner or admin can resolve
                gm = db.execute("SELECT role FROM group_members WHERE group_id = ? AND username = ?", (group_id, author)).fetchone()
                if not gm or gm["role"] not in ("admin", "owner"):
                    self.send_json({"ok": False, "error": "bara admin eller agare kan hantera forfragningar"}, 403)
                    return
                req = db.execute("SELECT * FROM join_requests WHERE id = ? AND group_id = ?", (req_id, group_id)).fetchone()
                if not req:
                    self.send_json({"ok": False, "error": "forfragningen finns inte"}, 404)
                    return
                if req["status"] != "pending":
                    self.send_json({"ok": False, "error": "forfragningen ar redan hanterad"}, 400)
                    return
                ts = now()
                db.execute("UPDATE join_requests SET status = ?, resolved_by = ?, resolved_at = ? WHERE id = ?",
                           (action + "ed", author, ts, req_id))
                if action == "accept":
                    member_count = db.execute("SELECT COUNT(*) as c FROM group_members WHERE group_id = ?", (group_id,)).fetchone()["c"]
                    if member_count >= MAX_GROUP_MEMBERS:
                        self.send_json({"ok": False, "error": "gruppen ar full"}, 403)
                        return
                    db.execute(
                        "INSERT OR IGNORE INTO group_members (group_id, username, role, joined_at) VALUES (?, ?, 'member', ?)",
                        (group_id, req["username"], ts)
                    )
                    group_cache_add_member(group_id, req["username"])
                db.commit()
            finally:
                db.close()
            # Notify the requester
            send_to_user(req["username"], {
                "event_type": "group_join_resolved",
                "group_id": group_id,
                "group_name": group["name"],
                "action": action,
            })
            self.send_json({"ok": True, "action": action, "username": req["username"]})
            return

        # API: list group members — POST /api/group/{id}/members
        if re.match(r'^/api/group/[a-f0-9]+/members$', path):
            parts = path.split("/")
            group_id = parts[3]
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
                group = db.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
                if not group:
                    self.send_json({"ok": False, "error": "gruppen finns inte"}, 404)
                    return
                # Check user is a member
                gm = db.execute("SELECT role FROM group_members WHERE group_id = ? AND username = ?", (group_id, author)).fetchone()
                if not gm:
                    self.send_json({"ok": False, "error": "du ar inte medlem"}, 403)
                    return
                rows = db.execute("SELECT username, role, joined_at FROM group_members WHERE group_id = ? ORDER BY joined_at", (group_id,)).fetchall()
                members = []
                for r in rows:
                    md = dict(r)
                    roles = db.execute("SELECT role_id FROM user_roles WHERE group_id = ? AND username = ?", (group_id, md["username"])).fetchall()
                    md["custom_roles"] = [cr["role_id"] for cr in roles]
                    members.append(md)
            finally:
                db.close()
            self.send_json({"ok": True, "members": members})
            return

        # API: list pending join requests — POST /api/group/{id}/requests
        if re.match(r'^/api/group/[a-f0-9]+/requests$', path):
            parts = path.split("/")
            group_id = parts[3]
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
                group = db.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
                if not group:
                    self.send_json({"ok": False, "error": "gruppen finns inte"}, 404)
                    return
                # Only owner or admin can view requests
                gm = db.execute("SELECT role FROM group_members WHERE group_id = ? AND username = ?", (group_id, author)).fetchone()
                if not gm or gm["role"] not in ("admin", "owner"):
                    self.send_json({"ok": False, "error": "bara admin eller agare kan se forfragningar"}, 403)
                    return
                rows = db.execute("SELECT id, username, status, created_at FROM join_requests WHERE group_id = ? AND status = 'pending' ORDER BY created_at", (group_id,)).fetchall()
                requests = [dict(r) for r in rows]
            finally:
                db.close()
            self.send_json({"ok": True, "requests": requests})
            return

        # ===== CUSTOM ROLES ENDPOINTS =====

        # API: create custom role — POST /api/group/{id}/role
        if re.match(r'^/api/group/[a-f0-9]+/role$', path):
            group_id = path.split("/")[3]
            role_name = body.get("name", "").strip().lower().replace(" ", "-")[:50]
            if not role_name:
                self.send_json({"ok": False, "error": "name required"}, 400)
                return
            role_display = body.get("display_name", "").strip()[:100] or body.get("name", "").strip()[:100]
            role_color = body.get("color", "#99aab5")[:10]
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
                group = db.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
                if not group:
                    self.send_json({"ok": False, "error": "gruppen finns inte"}, 404)
                    return
                if group["owner"] != author:
                    self.send_json({"ok": False, "error": "bara agaren kan skapa roller"}, 403)
                    return
                # Check for duplicate name
                if db.execute("SELECT 1 FROM group_roles WHERE group_id = ? AND name = ?", (group_id, role_name)).fetchone():
                    self.send_json({"ok": False, "error": "rollen finns redan"}, 409)
                    return
                # Get max position
                max_pos = db.execute("SELECT COALESCE(MAX(position), 0) as m FROM group_roles WHERE group_id = ?", (group_id,)).fetchone()["m"]
                role_id = uuid.uuid4().hex
                ts = now()
                db.execute(
                    "INSERT INTO group_roles (id, group_id, name, display_name, color, position, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (role_id, group_id, role_name, role_display, role_color, max_pos + 1, ts)
                )
                db.commit()
            finally:
                db.close()
            broadcast({"event_type": "group_role_created", "group_id": group_id, "role_id": role_id, "name": role_name, "display_name": role_display, "color": role_color})
            self.send_json({"ok": True, "role_id": role_id, "name": role_name, "display_name": role_display, "color": role_color})
            return

        # API: delete custom role — DELETE /api/group/{id}/role/{role_id}
        if re.match(r'^/api/group/[a-f0-9]+/role/[a-f0-9]+$', path) and self.command == "DELETE":
            parts = path.split("/")
            group_id = parts[3]
            role_id = parts[5]
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
                group = db.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
                if not group:
                    self.send_json({"ok": False, "error": "gruppen finns inte"}, 404)
                    return
                if group["owner"] != author:
                    self.send_json({"ok": False, "error": "bara agaren kan ta bort roller"}, 403)
                    return
                role = db.execute("SELECT * FROM group_roles WHERE id = ? AND group_id = ?", (role_id, group_id)).fetchone()
                if not role:
                    self.send_json({"ok": False, "error": "rollen finns inte"}, 404)
                    return
                db.execute("DELETE FROM group_roles WHERE id = ?", (role_id,))
                db.execute("DELETE FROM user_roles WHERE role_id = ?", (role_id,))
                # Clear required_role on channels that referenced this role
                db.execute("UPDATE channels SET required_role = 'member' WHERE group_id = ? AND required_role = ?", (group_id, role_id))
                db.commit()
            finally:
                db.close()
            broadcast({"event_type": "group_role_deleted", "group_id": group_id, "role_id": role_id})
            self.send_json({"ok": True})
            return

        # API: assign role to user — POST /api/group/{id}/role/{role_id}/assign
        if re.match(r'^/api/group/[a-f0-9]+/role/[a-f0-9]+/assign$', path):
            parts = path.split("/")
            group_id = parts[3]
            role_id = parts[5]
            target = body.get("username", "").strip()[:20]
            author = body.get("author", "").strip()[:20]
            token = body.get("token", "").strip()
            if not author or not token:
                self.send_json({"ok": False, "error": "token required"}, 401)
                return
            if not target:
                self.send_json({"ok": False, "error": "username required"}, 400)
                return
            db = get_db()
            try:
                valid = db.execute("SELECT username FROM users WHERE username = ? AND token = ?", (author, token)).fetchone()
                if not valid:
                    self.send_json({"ok": False, "error": "invalid token"}, 401)
                    return
                group = db.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
                if not group:
                    self.send_json({"ok": False, "error": "gruppen finns inte"}, 404)
                    return
                # Only owner or admin can assign roles
                gm = db.execute("SELECT role FROM group_members WHERE group_id = ? AND username = ?", (group_id, author)).fetchone()
                if not gm or gm["role"] not in ("admin", "owner"):
                    self.send_json({"ok": False, "error": "bara admin eller agare kan tilldela roller"}, 403)
                    return
                # Verify role exists
                role = db.execute("SELECT * FROM group_roles WHERE id = ? AND group_id = ?", (role_id, group_id)).fetchone()
                if not role:
                    self.send_json({"ok": False, "error": "rollen finns inte"}, 404)
                    return
                # Verify target is a group member
                target_member = db.execute("SELECT 1 FROM group_members WHERE group_id = ? AND username = ?", (group_id, target)).fetchone()
                if not target_member:
                    self.send_json({"ok": False, "error": "anvandaren ar inte medlem i gruppen"}, 404)
                    return
                ts = now()
                db.execute(
                    "INSERT OR IGNORE INTO user_roles (group_id, username, role_id, assigned_at) VALUES (?, ?, ?, ?)",
                    (group_id, target, role_id, ts)
                )
                db.commit()
            finally:
                db.close()
            broadcast({"event_type": "user_role_assigned", "group_id": group_id, "username": target, "role_id": role_id})
            self.send_json({"ok": True, "username": target, "role_id": role_id})
            return

        # API: remove role from user — POST /api/group/{id}/role/{role_id}/remove
        if re.match(r'^/api/group/[a-f0-9]+/role/[a-f0-9]+/remove$', path):
            parts = path.split("/")
            group_id = parts[3]
            role_id = parts[5]
            target = body.get("username", "").strip()[:20]
            author = body.get("author", "").strip()[:20]
            token = body.get("token", "").strip()
            if not author or not token:
                self.send_json({"ok": False, "error": "token required"}, 401)
                return
            if not target:
                self.send_json({"ok": False, "error": "username required"}, 400)
                return
            db = get_db()
            try:
                valid = db.execute("SELECT username FROM users WHERE username = ? AND token = ?", (author, token)).fetchone()
                if not valid:
                    self.send_json({"ok": False, "error": "invalid token"}, 401)
                    return
                group = db.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
                if not group:
                    self.send_json({"ok": False, "error": "gruppen finns inte"}, 404)
                    return
                # Only owner or admin can remove roles
                gm = db.execute("SELECT role FROM group_members WHERE group_id = ? AND username = ?", (group_id, author)).fetchone()
                if not gm or gm["role"] not in ("admin", "owner"):
                    self.send_json({"ok": False, "error": "bara admin eller agare kan ta bort roller"}, 403)
                    return
                db.execute("DELETE FROM user_roles WHERE group_id = ? AND username = ? AND role_id = ?", (group_id, target, role_id))
                db.commit()
            finally:
                db.close()
            broadcast({"event_type": "user_role_removed", "group_id": group_id, "username": target, "role_id": role_id})
            self.send_json({"ok": True, "username": target, "role_id": role_id})
            return

        # API: update profile — POST /api/profile/update
        if path == "/api/profile/update":
            uname = body.get("username", "").strip()[:20]
            token = body.get("token", "")
            bio = body.get("bio", "").strip()[:200]
            avatar_color = body.get("avatar_color", "").strip()[:20]
            banner_color = body.get("banner_color", "").strip()[:20]
            avatar = body.get("avatar", "")
            if not uname or not token:
                self.send_json({"ok": False, "error": "username and token required"}, 400)
                return
            # Validate hex colors
            hex_re = re.compile(r'^#[0-9a-fA-F]{6}$')
            if avatar_color and not hex_re.match(avatar_color):
                self.send_json({"ok": False, "error": "invalid avatar_color"}, 400)
                return
            if banner_color and not hex_re.match(banner_color):
                self.send_json({"ok": False, "error": "invalid banner_color"}, 400)
                return
            # Validate avatar (profile picture) if provided
            if avatar:
                if not avatar.startswith("data:image/"):
                    self.send_json({"ok": False, "error": "invalid avatar format"}, 400)
                    return
                # Check allowed image types
                allowed_types = ("data:image/png;", "data:image/jpeg;", "data:image/gif;", "data:image/webp;")
                if not any(avatar.startswith(t) for t in allowed_types):
                    self.send_json({"ok": False, "error": "avatar must be png, jpeg, gif, or webp"}, 400)
                    return
                if len(avatar) > 150000:
                    self.send_json({"ok": False, "error": "avatar too large (max ~100KB)"}, 400)
                    return
            db = get_db()
            try:
                user = db.execute("SELECT username FROM users WHERE username = ? AND token = ?", (uname, token)).fetchone()
                if not user:
                    self.send_json({"ok": False, "error": "unauthorized"}, 401)
                    return
                updates = []
                params_list = []
                if bio is not None:
                    updates.append("bio = ?")
                    params_list.append(bio)
                if avatar_color:
                    updates.append("avatar_color = ?")
                    params_list.append(avatar_color)
                if banner_color:
                    updates.append("banner_color = ?")
                    params_list.append(banner_color)
                if avatar is not None and "avatar" in body:
                    updates.append("avatar = ?")
                    params_list.append(avatar)
                if updates:
                    params_list.append(uname)
                    db.execute(f"UPDATE users SET {', '.join(updates)} WHERE username = ?", params_list)
                    db.commit()
            finally:
                db.close()
            self.send_json({"ok": True})
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
    # Startup warnings
    if not ADMIN_PASS:
        sys.stderr.write("WARNING: ADMIN_PASS not set — admin panel is disabled.\n")
    if CORS_ORIGIN == "*":
        sys.stderr.write("WARNING: CORS_ORIGIN is '*' — set to your domain in production.\n")
    if DB_PATH.startswith("/tmp") or DB_PATH.startswith("\\tmp"):
        sys.stderr.write(f"WARNING: DB_PATH is '{DB_PATH}' — data will be lost on restart in ephemeral environments.\n")
    if not RESEND_API_KEY:
        sys.stderr.write("WARNING: RESEND_API_KEY not set — email verification disabled, direct registration allowed\n")

    init_db()
    load_caches()
    server = ThreadedHTTPServer((HOST, PORT), ChatHandler)

    # Graceful shutdown on SIGTERM (container orchestrators, Render, etc.)
    def _sigterm_handler(signum, frame):
        sys.stderr.write("Received SIGTERM, shutting down gracefully...\n")
        threading.Thread(target=server.shutdown, daemon=True).start()

    try:
        signal.signal(signal.SIGTERM, _sigterm_handler)
    except (OSError, ValueError):
        pass  # SIGTERM not available on some platforms (e.g. Windows services)

    print(f"Quiver running on http://{HOST}:{PORT}")
    print(f"Share with friends: open the URL above")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()
