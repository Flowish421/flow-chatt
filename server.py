"""
Cortex Chat — Lightweight real-time chat server.
Python 3.10+, zero external dependencies (stdlib only).
Deploy anywhere: Render, Railway, Fly.io, or localhost.
"""

import asyncio
import json
import os
import sqlite3
import uuid
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path
from datetime import datetime, timezone

DB_PATH = os.environ.get("CHAT_DB", "chat.db")
PORT = int(os.environ.get("PORT", "8080"))
HOST = os.environ.get("HOST", "0.0.0.0")
MAX_BODY = 5 * 1024 * 1024  # 5MB max for image uploads
MAX_ATTACHMENT_SIZE = 2 * 1024 * 1024  # 2MB per image base64
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")  # Set for delete protection
CORS_ORIGIN = os.environ.get("CORS_ORIGIN", "*")  # Set to your domain in prod
import re

# --- Database ---

def init_db():
    conn = sqlite3.connect(DB_PATH)
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
    # Migration: add attachments column if missing (existing DBs)
    try:
        conn.execute("ALTER TABLE messages ADD COLUMN attachments TEXT DEFAULT '[]'")
    except sqlite3.OperationalError:
        pass  # column already exists
    conn.execute("""
        CREATE TABLE IF NOT EXISTS channels (
            name TEXT PRIMARY KEY,
            display_name TEXT,
            topic TEXT DEFAULT '',
            created_by TEXT,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_msg_channel ON messages(channel, created_at)")
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
    # Seed default channel
    conn.execute("""
        INSERT OR IGNORE INTO channels (name, display_name, topic, created_by, created_at)
        VALUES ('general', 'General', 'Allmän chatt', 'system', ?)
    """, (now(),))
    conn.commit()
    conn.close()

def now():
    return datetime.now(timezone.utc).isoformat()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
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
        if ip not in rate_limits:
            rate_limits[ip] = []
        # Prune old entries
        rate_limits[ip] = [t for t in rate_limits[ip] if now_t - t < 60]
        if len(rate_limits[ip]) >= MAX_REQUESTS_PER_MIN:
            return False
        rate_limits[ip].append(now_t)
        return True

# --- SSE Clients ---

sse_clients = []  # list of (queue, channel_filter)
sse_lock = threading.Lock()

def broadcast(event_data):
    """Send event to all SSE clients."""
    with sse_lock:
        dead = []
        for i, (q, _) in enumerate(sse_clients):
            try:
                q.put_nowait(event_data)
            except:
                dead.append(i)
        for i in reversed(dead):
            sse_clients.pop(i)

# Thread-safe queue for SSE
from queue import Queue, Empty

# --- HTTP Handler ---

class ChatHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Log requests but skip SSE keepalives
        if args and '/api/events' not in str(args[0]):
            import sys
            sys.stderr.write(f"{self.client_address[0]} - {format % args}\n")

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
        # Path traversal protection: resolve and verify it stays within static/
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
            # Security headers
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-XSS-Protection", "1; mode=block")
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

        # Static files
        if path == "/" or path == "/chat.html":
            self.send_html("static/chat.html")
            return

        # API: health
        if path == "/api/health":
            self.send_json({"ok": True})
            return

        # API: channels
        if path == "/api/channels":
            db = get_db()
            rows = db.execute("SELECT * FROM channels ORDER BY created_at").fetchall()
            db.close()
            self.send_json({
                "ok": True,
                "channels": [dict(r) for r in rows]
            })
            return

        # API: messages for a channel
        if path.startswith("/api/channel/") and path.endswith("/messages"):
            parts = path.split("/")
            channel = parts[3]
            try:
                limit = min(int(params.get("limit", ["100"])[0]), 500)
            except (ValueError, IndexError):
                limit = 100
            db = get_db()
            rows = db.execute(
                "SELECT * FROM messages WHERE channel = ? ORDER BY created_at DESC LIMIT ?",
                (channel, limit)
            ).fetchall()
            msg_ids = [r["id"] for r in rows]
            # Fetch reactions for all messages in one query
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
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("Access-Control-Allow-Origin", CORS_ORIGIN)
            self.end_headers()

            q = Queue()
            with sse_lock:
                if len(sse_clients) >= MAX_SSE_CLIENTS:
                    self.send_error(503)
                    return
                sse_clients.append((q, None))

            try:
                # Send keepalive immediately
                self.wfile.write(b": connected\n\n")
                self.wfile.flush()

                while True:
                    try:
                        data = q.get(timeout=15)
                        self.wfile.write(f"data: {json.dumps(data)}\n\n".encode())
                        self.wfile.flush()
                    except Empty:
                        # Keepalive
                        self.wfile.write(b": ping\n\n")
                        self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                with sse_lock:
                    sse_clients[:] = [(cq, cf) for cq, cf in sse_clients if cq is not q]
            return

        self.send_error(404)

    def do_POST(self):
        # Rate limit
        client_ip = self.client_address[0] if self.client_address else "unknown"
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

        # API: send message
        if path.startswith("/api/channel/") and path.endswith("/message"):
            parts = path.split("/")
            channel = parts[3][:50]
            if not re.match(r'^[a-z0-9\u00e5\u00e4\u00f6][a-z0-9\u00e5\u00e4\u00f6_-]{0,48}$', channel):
                self.send_json({"ok": False, "error": "invalid channel name"}, 400)
                return
            content = body.get("content", "").strip()[:5000]
            author = body.get("author", "anonymous").strip()[:20]
            role = body.get("role", "user")
            if role not in ("user", "assistant"):
                role = "user"
            attachments = body.get("attachments", [])[:5]
            # Validate attachment sizes
            for att in attachments:
                if len(att.get("dataUrl", "")) > MAX_ATTACHMENT_SIZE:
                    self.send_json({"ok": False, "error": "attachment too large (max 2MB)"}, 400)
                    return

            if not content and not attachments:
                self.send_json({"ok": False, "error": "empty message"}, 400)
                return

            if not content and attachments:
                content = "[bild]" if len(attachments) == 1 else f"[{len(attachments)} bilder]"

            msg_id = str(uuid.uuid4())
            ts = now()
            att_json = json.dumps(attachments) if attachments else "[]"

            db = get_db()
            db.execute(
                "INSERT OR IGNORE INTO channels (name, display_name, topic, created_by, created_at) VALUES (?, ?, '', ?, ?)",
                (channel, channel, author, ts)
            )
            db.execute(
                "INSERT INTO messages (id, channel, author, content, role, attachments, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (msg_id, channel, author, content, role, att_json, ts)
            )
            db.commit()
            db.close()

            broadcast({
                "event_type": "chat_message",
                "id": msg_id,
                "channel": channel,
                "author": author,
                "content": content,
                "role": role,
                "attachments": attachments,
                "created_at": ts,
            })

            self.send_json({"ok": True, "id": msg_id, "channel": channel})
            return

        # API: create channel
        if path == "/api/channel":
            name = body.get("name", "").strip().lower().replace(" ", "-")
            if not name:
                self.send_json({"ok": False, "error": "name required"}, 400)
                return
            display = body.get("display_name", name)
            topic = body.get("topic", "")
            creator = body.get("created_by", "anonymous")
            ts = now()

            db = get_db()
            db.execute(
                "INSERT OR IGNORE INTO channels (name, display_name, topic, created_by, created_at) VALUES (?, ?, ?, ?, ?)",
                (name, display, topic, creator, ts)
            )
            db.commit()
            db.close()
            self.send_json({"ok": True, "channel": name})
            return

        # API: react to a message — POST /api/message/:id/react { emoji, author }
        if path.startswith("/api/message/") and path.endswith("/react"):
            parts = path.split("/")
            message_id = parts[3]
            emoji = body.get("emoji", "").strip()
            author = body.get("author", "anonymous").strip()

            if not emoji:
                self.send_json({"ok": False, "error": "emoji required"}, 400)
                return

            db = get_db()
            # Toggle: if already reacted with same emoji, remove it
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

            # Get updated reactions for this message
            reacts = db.execute(
                "SELECT emoji, author FROM reactions WHERE message_id = ?",
                (message_id,)
            ).fetchall()
            db.close()

            react_list = [{"emoji": rx["emoji"], "author": rx["author"]} for rx in reacts]

            broadcast({
                "event_type": "reaction",
                "message_id": message_id,
                "reactions": react_list,
            })

            self.send_json({"ok": True, "action": action, "reactions": react_list})
            return

        # API: delete channel (requires admin token if set)
        if path.startswith("/api/channel/") and path.count("/") == 3:
            parts = path.split("/")
            channel = parts[3]
            if channel == "general":
                self.send_json({"ok": False, "error": "cannot delete general"}, 400)
                return
            if ADMIN_TOKEN:
                auth = self.headers.get("Authorization", "")
                if auth != f"Bearer {ADMIN_TOKEN}":
                    self.send_json({"ok": False, "error": "unauthorized"}, 401)
                    return
            db = get_db()
            try:
                db.execute("DELETE FROM messages WHERE channel = ?", (channel,))
                db.execute("DELETE FROM channels WHERE name = ?", (channel,))
                db.commit()
            finally:
                db.close()
            self.send_json({"ok": True})
            return

        self.send_json({"ok": False, "error": "not found"}, 404)

    def do_DELETE(self):
        self.do_POST()  # Route DELETE through POST handler


# --- Threaded server for SSE support ---

from socketserver import ThreadingMixIn

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    init_db()
    server = ThreadedHTTPServer((HOST, PORT), ChatHandler)
    print(f"Cortex Chat running on http://{HOST}:{PORT}")
    print(f"Share with friends: open the URL above")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()
