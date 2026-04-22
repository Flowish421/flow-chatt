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
            created_at TEXT NOT NULL
        )
    """)
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
        pass  # Quiet logs

    def send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, path):
        try:
            content = Path(path).read_bytes()
            self.send_response(200)
            ctype = "text/html" if path.endswith(".html") else "text/css" if path.endswith(".css") else "application/javascript"
            self.send_header("Content-Type", f"{ctype}; charset=utf-8")
            self.send_header("Content-Length", len(content))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(content)
        except FileNotFoundError:
            self.send_error(404)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
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
            limit = int(params.get("limit", ["100"])[0])
            db = get_db()
            rows = db.execute(
                "SELECT * FROM messages WHERE channel = ? ORDER BY created_at DESC LIMIT ?",
                (channel, limit)
            ).fetchall()
            db.close()
            self.send_json({
                "ok": True,
                "channel": channel,
                "count": len(rows),
                "messages": [dict(r) for r in rows]
            })
            return

        # API: SSE events
        if path == "/api/events":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

            q = Queue()
            with sse_lock:
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
        parsed = urlparse(self.path)
        path = parsed.path

        content_length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(content_length)) if content_length > 0 else {}

        # API: send message
        if path.startswith("/api/channel/") and path.endswith("/message"):
            parts = path.split("/")
            channel = parts[3]
            content = body.get("content", "").strip()
            author = body.get("author", "anonymous").strip()
            role = body.get("role", "user")

            if not content:
                self.send_json({"ok": False, "error": "empty message"}, 400)
                return

            msg_id = str(uuid.uuid4())
            ts = now()

            db = get_db()
            # Auto-create channel if doesn't exist
            db.execute(
                "INSERT OR IGNORE INTO channels (name, display_name, topic, created_by, created_at) VALUES (?, ?, '', ?, ?)",
                (channel, channel, author, ts)
            )
            db.execute(
                "INSERT INTO messages (id, channel, author, content, role, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (msg_id, channel, author, content, role, ts)
            )
            db.commit()
            db.close()

            # Broadcast to SSE clients
            broadcast({
                "event_type": "chat_message",
                "id": msg_id,
                "channel": channel,
                "author": author,
                "content": content,
                "role": role,
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

        # API: delete channel
        if path.startswith("/api/channel/") and path.count("/") == 3:
            parts = path.split("/")
            channel = parts[3]
            if channel == "general":
                self.send_json({"ok": False, "error": "cannot delete general"}, 400)
                return
            db = get_db()
            db.execute("DELETE FROM messages WHERE channel = ?", (channel,))
            db.execute("DELETE FROM channels WHERE name = ?", (channel,))
            db.commit()
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
