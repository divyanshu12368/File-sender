# lan_share_transfer.py
# Single-script: LAN queue transfer (resume + pause) + Share-via-Link HTTP server
# Requires Python 3.8+. Optional: pip install ttkbootstrap for modern theme.
# Save as lan_share_transfer.py and run on both machines.

import os
import sys
import json
import time
import socket
import threading
import hashlib
from collections import deque
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox
    from tkinter import ttk
except Exception as e:
    raise SystemExit("Tkinter not available: " + str(e))

# optional modern UI
USE_TTKB = False
try:
    import ttkbootstrap as tb
    from ttkbootstrap.constants import PRIMARY
    USE_TTKB = True
except Exception:
    tb = None

# ----------------- Config -----------------
TRANSFER_PORT_DEFAULT = 5001
BUFFER_SIZE = 1024 * 1024
HEADER_SEP = "|"
RETRY_DELAY_START = 1.5
RETRY_DELAY_MAX = 12.0
UI_UPDATE_INTERVAL = 0.2
ROLLING_WINDOW = 3.0
HEADER_PREFIX_LEN = 12
STATE_SUFFIX = ".partstate.json"
PART_SUFFIX = ".part"
HTTP_PORT_DEFAULT = 8000

# ----------------- Utilities -----------------
def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def human_size(n: int) -> str:
    n = float(n)
    for unit in ("B","KB","MB","GB","TB"):
        if n < 1024.0:
            return f"{n:.2f} {unit}"
        n /= 1024.0
    return f"{n:.2f} PB"

def safe_target_path(directory: str, relpath: str) -> str:
    out_path = os.path.join(directory, relpath)
    folder = os.path.dirname(out_path)
    os.makedirs(folder, exist_ok=True)
    base, ext = os.path.splitext(os.path.basename(out_path))
    parent = os.path.dirname(out_path)
    candidate = out_path
    i = 1
    while os.path.exists(candidate):
        candidate = os.path.join(parent, f"{base} ({i}){ext}")
        i += 1
    return candidate

def hash_session(files_meta) -> str:
    h = hashlib.sha256()
    for f in files_meta:
        h.update(f["rel"].encode())
        h.update(str(f["size"]).encode())
    return h.hexdigest()[:16]

# ------- header helpers (JSON header prefixed with fixed length) -------
def send_header(sock, data: dict):
    blob = json.dumps(data).encode()
    length = f"{len(blob):0{HEADER_PREFIX_LEN}d}".encode()
    sock.sendall(length + blob)

def recv_header(sock) -> dict:
    need = HEADER_PREFIX_LEN
    buf = b""
    while len(buf) < need:
        chunk = sock.recv(need - len(buf))
        if not chunk:
            raise ConnectionError("Header length missing")
        buf += chunk
    total_len = int(buf.decode())
    blob = b""
    while len(blob) < total_len:
        chunk = sock.recv(min(4096, total_len - len(blob)))
        if not chunk:
            raise ConnectionError("Header JSON truncated")
        blob += chunk
    return json.loads(blob.decode())

# ----------------- HTTP Share Server -----------------
class FileShareHandler(BaseHTTPRequestHandler):
    # class attributes to be set when starting server:
    # FileShareHandler.mapping = {"/file1": "/abs/path/to/file1", ...}
    # FileShareHandler.list_html  = generated HTML
    # supports Range requests for resume
    server_version = "LANShare/1.0"

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(self.list_html.encode())))
            self.end_headers()
            self.wfile.write(self.list_html.encode())
            return

        # path -> file mapping
        if self.path not in self.mapping:
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return
        filepath = self.mapping[self.path]
        try:
            file_size = os.path.getsize(filepath)
            range_header = self.headers.get("Range")
            start = 0
            end = file_size - 1
            if range_header:
                # Example: Range: bytes=1000-
                try:
                    _, rng = range_header.split("=")
                    s, *_ = rng.split("-")
                    start = int(s) if s else 0
                except Exception:
                    start = 0
                if start >= file_size:
                    self.send_error(HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE)
                    return
                self.send_response(HTTPStatus.PARTIAL_CONTENT)
                self.send_header("Content-Range", f"bytes {start}-{end}/{file_size}")
            else:
                self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(file_size - start))
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Content-Disposition", f'attachment; filename="{os.path.basename(filepath)}"')
            self.end_headers()

            with open(filepath, "rb") as f:
                f.seek(start)
                remaining = file_size - start
                while remaining > 0:
                    chunk = f.read(min(BUFFER_SIZE, remaining))
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    remaining -= len(chunk)
        except Exception as e:
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(e))

    def log_message(self, format, *args):
        # silence default logging (or forward to UI)
        return


class HttpShareServer:
    def __init__(self, mapping, port=HTTP_PORT_DEFAULT):
        # mapping: {"/name": "/abs/path"} ; list_html is generated
        self.mapping = mapping
        self.port = port
        self.httpd = None
        self.thread = None

    def start(self, ip):
        # build list HTML
        items = []
        for path, absfile in self.mapping.items():
            display = os.path.basename(absfile)
            items.append(f'<li><a href="{path}">{display}</a> <small>{human_size(os.path.getsize(absfile))}</small></li>')
        html = "<html><head><meta charset='utf-8'><title>Files</title></head><body>"
        html += "<h3>Files available for download</h3><ul>"
        html += "\n".join(items)
        html += "</ul><p>Open in browser to download. Supports resume if your browser uses Range.</p></body></html>"

        FileShareHandler.mapping = self.mapping
        FileShareHandler.list_html = html

        server_address = (ip, self.port)
        try:
            self.httpd = ThreadingHTTPServer(server_address, FileShareHandler)
        except OSError as e:
            raise

        def run():
            try:
                self.httpd.serve_forever()
            except Exception:
                pass

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()

    def stop(self):
        if self.httpd:
            try:
                self.httpd.shutdown()
                self.httpd.server_close()
            except Exception:
                pass
            self.httpd = None

# ----------------- Sender (queue-mode) -----------------
class Sender:
    def __init__(self, ui):
        self.ui = ui
        self.file_queue = []  # {abs, rel, size}
        self.total_size = 0
        self.session_id = None
        self.stop_flag = False
        self.pause_event = threading.Event()
        self.pause_event.clear()
        self.http_server = None

    def pick_files(self):
        paths = self.ui.ask_files()
        if not paths:
            return
        self._set_queue_from_list(paths)

    def pick_folder(self):
        folder, files = self.ui.ask_folder_files()
        if not files:
            return
        self._set_queue_from_list(files, base_folder=folder)

    def _set_queue_from_list(self, paths, base_folder=None):
        self.file_queue.clear()
        self.total_size = 0
        base = os.path.abspath(base_folder) if base_folder else None
        for p in paths:
            ap = os.path.abspath(p)
            rel = os.path.relpath(ap, base) if base and ap.startswith(base) else os.path.basename(ap)
            size = os.path.getsize(ap)
            self.file_queue.append({"abs": ap, "rel": rel, "size": size})
            self.total_size += size
        meta = [{"rel": f["rel"], "size": f["size"]} for f in self.file_queue]
        self.session_id = hash_session(meta)
        self.ui.set_sender_queue(self.file_queue, self.total_size, self.session_id)

    def start_server(self):
        if not self.file_queue:
            self.ui.alert("Pick files or a folder first")
            return
        threading.Thread(target=self._serve_loop, daemon=True).start()

    def _serve_loop(self):
        local_ip = get_local_ip()
        port = self.ui.get_port()
        secret = self.ui.get_secret()
        files_meta = [{"rel": f["rel"], "size": f["size"]} for f in self.file_queue]
        header = {"session": self.session_id, "files": files_meta, "total": self.total_size, "port": port}
        self.ui.log(f"Waiting for receiver… IP: {local_ip}, Port: {port}")
        sent_total_confirmed = 0
        last_ui = 0.0

        while (sent_total_confirmed < self.total_size):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
                    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    server.bind(("0.0.0.0", port))
                    server.listen(1)
                    conn, addr = server.accept()
                    with conn:
                        self.ui.log(f"Connected: {addr}. Handshaking…")
                        # simple hello auth
                        hello = conn.recv(256).decode(errors='ignore')
                        if not hello.startswith("HELLO" + HEADER_SEP):
                            self.ui.log("Bad hello; dropping")
                            continue
                        recv_secret = hello.split(HEADER_SEP, 1)[1]
                        if secret and recv_secret != secret:
                            self.ui.log("Secret mismatch; dropping")
                            continue
                        send_header(conn, header)
                        hint = conn.recv(128).decode(errors='ignore')
                        try:
                            parts = hint.split(HEADER_SEP)
                            idx = int(parts[1]); off = int(parts[3])
                        except Exception:
                            idx, off = 0, 0
                        sent_total_confirmed = sum(f["size"] for f in self.file_queue[:idx]) + off
                        t0 = time.time()
                        history = deque()
                        for i in range(idx, len(self.file_queue)):
                            fmeta = self.file_queue[i]
                            with open(fmeta["abs"], "rb") as fh:
                                if i == idx and off:
                                    fh.seek(off)
                                pos = off
                                off = 0
                                while pos < fmeta["size"]:
                                    if self.pause_event.is_set():
                                        time.sleep(0.05); continue
                                    chunk = fh.read(BUFFER_SIZE)
                                    if not chunk:
                                        break
                                    conn.sendall(chunk)
                                    now = time.time()
                                    sent = len(chunk)
                                    pos += sent
                                    sent_total_confirmed += sent
                                    history.append((now, sent))
                                    while history and (now - history[0][0]) > ROLLING_WINDOW:
                                        history.popleft()
                                    duration = max(1e-6, history[-1][0] - history[0][0]) if history else 1e-6
                                    bps = sum(b for _, b in history) / duration
                                    mbps = bps / (1024*1024)
                                    if now - last_ui >= UI_UPDATE_INTERVAL:
                                        pct_total = (sent_total_confirmed / self.total_size) * 100
                                        remaining = self.total_size - sent_total_confirmed
                                        eta = remaining / max(1e-6, bps)
                                        self.ui.set_sender_progress(i, len(self.file_queue), pos, fmeta["size"], pct_total, mbps, eta)
                                        last_ui = now
                        # if loop ends, will break outer while to wait for next connection
            except Exception as e:
                self.ui.log(f"Sender: connection error — {e}. Waiting to resume…")
                time.sleep(RETRY_DELAY_START)

        # done
        self.ui.set_sender_done()

    def pause(self):
        self.pause_event.set()
        self.ui.log("Sender paused")

    def resume(self):
        self.pause_event.clear()
        self.ui.log("Sender resumed")

    # HTTP share features
    def share_via_http(self):
        # mapping paths to URL paths
        if not self.file_queue:
            self.ui.alert("Pick files/folder first to share")
            return
        # choose HTTP port
        http_port = self.ui.get_http_port()
        ip = get_local_ip()
        mapping = {}
        # build mapping with unique keys
        for idx, f in enumerate(self.file_queue):
            key = f"/file{idx}_{os.path.basename(f['abs'])}"
            mapping[key] = f["abs"]
        server = HttpShareServer(mapping, port=http_port)
        try:
            server.start(ip)
        except OSError as e:
            self.ui.alert(f"Cannot start HTTP server on {ip}:{http_port}\n{e}")
            return
        self.http_server = server
        link = f"http://{ip}:{http_port}/"
        self.ui.log(f"HTTP share started at {link}")
        self.ui.show_http_link(link)

    def stop_http_share(self):
        if self.http_server:
            self.http_server.stop()
            self.http_server = None
            self.ui.log("HTTP share stopped")
            self.ui.clear_http_link()

# ----------------- Receiver -----------------
class Receiver:
    def __init__(self, ui):
        self.ui = ui
        self.stop_flag = False
        self.pause_event = threading.Event()
        self.pause_event.clear()
        self.session_id = None
        self.files_meta = []
        self.total_size = 0
        self.dest_dir = None
        self.state_path = None
        self.idx = 0
        self.offset = 0
        self.received_total = 0

    def start(self):
        ip = self.ui.get_peer_ip().strip()
        if not ip:
            self.ui.alert("Enter Sender IP")
            return
        self.dest_dir = self.ui.ask_dest_dir()
        if not self.dest_dir:
            return
        self.stop_flag = False
        self.pause_event.clear()
        threading.Thread(target=self._receive_loop, args=(ip, self.ui.get_port()), daemon=True).start()

    def pause(self):
        self.pause_event.set()
        self.ui.log("Receiver paused", sender=False)

    def resume(self):
        self.pause_event.clear()
        self.ui.log("Receiver resumed", sender=False)

    def _state_file_for(self, session_id):
        return os.path.join(self.dest_dir, f"{session_id}{STATE_SUFFIX}")

    def _load_state(self):
        try:
            if self.state_path and os.path.exists(self.state_path):
                with open(self.state_path, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception:
            pass
        return None

    def _save_state(self):
        try:
            if not self.state_path:
                return
            state = {"idx": self.idx, "offset": self.offset, "received_total": self.received_total, "total": self.total_size, "files": self.files_meta}
            with open(self.state_path, "w", encoding="utf-8") as f:
                json.dump(state, f)
        except Exception:
            pass

    def _receive_loop(self, ip: str, port: int):
        delay = RETRY_DELAY_START
        last_ui = 0.0
        secret = self.ui.get_secret()
        self.received_total = 0

        while True:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    self.ui.log(f"Connecting to {ip}:{port}…", sender=False)
                    s.settimeout(10)
                    s.connect((ip, port))
                    s.settimeout(None)
                    s.sendall(f"HELLO{HEADER_SEP}{secret}".encode())
                    header = recv_header(s)
                    if self.session_id is None:
                        self.session_id = header["session"]
                        self.files_meta = header["files"]
                        self.total_size = header["total"]
                        self.state_path = self._state_file_for(self.session_id)
                        st = self._load_state()
                        if st and st.get("files") == self.files_meta:
                            self.idx = int(st.get("idx", 0))
                            self.offset = int(st.get("offset", 0))
                            self.received_total = int(st.get("received_total", 0))
                        else:
                            self.idx = 0; self.offset = 0; self.received_total = 0
                        self.ui.set_receiver_queue(self.files_meta, self.total_size, self.session_id)
                    # send resume hint
                    s.sendall(f"INDEX{HEADER_SEP}{self.idx}{HEADER_SEP}OFFSET{HEADER_SEP}{self.offset}".encode())
                    history = deque()
                    last_ui = 0.0
                    for i in range(self.idx, len(self.files_meta)):
                        meta = self.files_meta[i]
                        rel = meta["rel"]; size = int(meta["size"])
                        part_path = os.path.join(self.dest_dir, rel + PART_SUFFIX)
                        final_path_candidate = safe_target_path(self.dest_dir, rel)
                        os.makedirs(os.path.dirname(part_path), exist_ok=True)
                        pos = 0
                        if i == self.idx and self.offset:
                            pos = self.offset
                        with open(part_path, "ab") as f:
                            if os.path.exists(part_path):
                                cur = os.path.getsize(part_path)
                                if cur != pos:
                                    f.truncate(pos)
                            while pos < size:
                                if self.pause_event.is_set():
                                    time.sleep(0.05); continue
                                chunk = s.recv(BUFFER_SIZE)
                                if not chunk:
                                    break
                                f.write(chunk)
                                now = time.time()
                                got = len(chunk); pos += got; self.received_total += got
                                history.append((now, got))
                                while history and (now - history[0][0]) > ROLLING_WINDOW:
                                    history.popleft()
                                duration = max(1e-6, history[-1][0] - history[0][0]) if history else 1e-6
                                bps = sum(b for _, b in history) / duration
                                mbps = bps / (1024*1024)
                                if now - last_ui >= UI_UPDATE_INTERVAL:
                                    pct_total = (self.received_total / self.total_size) * 100
                                    remaining = self.total_size - self.received_total
                                    eta = remaining / max(1e-6, bps)
                                    self.ui.set_receiver_progress(i, len(self.files_meta), pos, size, pct_total, mbps, eta)
                                    last_ui = now
                                    self.idx = i; self.offset = pos; self._save_state()
                        # if file complete, move to final path
                        if pos >= size:
                            try:
                                os.makedirs(os.path.dirname(final_path_candidate), exist_ok=True)
                                if os.path.exists(final_path_candidate):
                                    os.remove(final_path_candidate)
                                os.replace(part_path, final_path_candidate)
                            except Exception:
                                with open(part_path, 'rb') as src, open(final_path_candidate, 'wb') as dst:
                                    while True:
                                        b = src.read(BUFFER_SIZE)
                                        if not b: break
                                        dst.write(b)
                                try: os.remove(part_path)
                                except Exception: pass
                            self.idx = i + 1; self.offset = 0; self._save_state()
                    # all files done?
                    if self.received_total >= self.total_size:
                        self.ui.set_receiver_done()
                        try:
                            if self.state_path and os.path.exists(self.state_path):
                                os.remove(self.state_path)
                        except Exception:
                            pass
                        return
            except Exception as e:
                self.ui.log(f"Receiver error: {e}. Retrying…", sender=False)
                time.sleep(delay)
                delay = min(RETRY_DELAY_MAX, delay * 2)

# ----------------- UI -----------------
class App:
    def __init__(self, root):
        self.root = root
        title = "LAN Share & Transfer (Queue + Resume)"
        if USE_TTKB:
            self.style = tb.Style("darkly")
            root.title(title)
        else:
            root.title(title)
        root.geometry("980x640")
        root.minsize(880, 580)

        self.port_var = tk.IntVar(value=TRANSFER_PORT_DEFAULT)
        self.http_port_var = tk.IntVar(value=HTTP_PORT_DEFAULT)
        self.secret_var = tk.StringVar(value="")

        self.nb = ttk.Notebook(root); self.nb.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.sender_tab = ttk.Frame(self.nb); self.receiver_tab = ttk.Frame(self.nb)
        self.nb.add(self.sender_tab, text="Sender"); self.nb.add(self.receiver_tab, text="Receiver")

        self._build_sender()
        self._build_receiver()

        footer = ttk.Frame(root); footer.pack(fill=tk.X, padx=10, pady=(0,10))
        self.ip_label = ttk.Label(footer, text=self._footer_text()); self.ip_label.pack(side=tk.LEFT)
        ttk.Button(footer, text="🔄 Recheck IP", command=self.refresh_ip).pack(side=tk.LEFT, padx=8)

        # controller objects
        self.sender = Sender(self)
        self.receiver = Receiver(self)

    # -- build sender UI
    def _build_sender(self):
        top = ttk.Frame(self.sender_tab); top.pack(fill=tk.X, pady=6)
        ttk.Label(top, text="Port:").pack(side=tk.LEFT); ttk.Entry(top, textvariable=self.port_var, width=8).pack(side=tk.LEFT, padx=(4,12))
        ttk.Label(top, text="HTTP Port:").pack(side=tk.LEFT); ttk.Entry(top, textvariable=self.http_port_var, width=6).pack(side=tk.LEFT, padx=(4,12))
        ttk.Label(top, text="Secret (optional):").pack(side=tk.LEFT)
        showchar = "•" if USE_TTKB else "*"
        self.secret_entry = ttk.Entry(top, textvariable=self.secret_var, show=showchar, width=18); self.secret_entry.pack(side=tk.LEFT, padx=6)
        ttk.Button(top, text="📂 Choose Files", command=self.choose_files).pack(side=tk.LEFT, padx=4)
        ttk.Button(top, text="📁 Choose Folder", command=self.choose_folder).pack(side=tk.LEFT, padx=4)
        ttk.Button(top, text="▶ Start Server", command=self.sender_start).pack(side=tk.LEFT, padx=4)
        ttk.Button(top, text="📱 Share via Link", command=self.sender_share_link).pack(side=tk.LEFT, padx=4)
        ttk.Button(top, text="Stop Link", command=self.sender_stop_link).pack(side=tk.LEFT, padx=4)
        ttk.Button(top, text="⏸ Pause", command=self.sender_pause).pack(side=tk.LEFT, padx=4)
        ttk.Button(top, text="▶ Resume", command=self.sender_resume).pack(side=tk.LEFT, padx=4)

        mid = ttk.Frame(self.sender_tab); mid.pack(fill=tk.BOTH, expand=True, pady=6)
        left = ttk.Frame(mid); left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.sender_list = tk.Listbox(left, height=18); self.sender_list.pack(fill=tk.BOTH, expand=True)
        right = ttk.Frame(mid); right.pack(side=tk.LEFT, fill=tk.Y, padx=(8,0))
        self.sender_prog = ttk.Progressbar(self.sender_tab, mode='determinate'); self.sender_prog.pack(fill=tk.X, padx=6, pady=6)
        self.sender_status = ttk.Label(self.sender_tab, text="Idle."); self.sender_status.pack(fill=tk.X, padx=6)
        self.sender_log = tk.Text(self.sender_tab, height=8, state=tk.DISABLED); self.sender_log.pack(fill=tk.BOTH, expand=False, padx=6, pady=(6,6))
        self.http_link_label = ttk.Label(self.sender_tab, text=""); self.http_link_label.pack(padx=6, pady=4)

    # -- build receiver UI
    def _build_receiver(self):
        top = ttk.Frame(self.receiver_tab); top.pack(fill=tk.X, pady=6)
        ttk.Label(top, text="Sender IP:").pack(side=tk.LEFT); self.ip_entry = ttk.Entry(top, width=18); self.ip_entry.pack(side=tk.LEFT, padx=(4,12))
        ttk.Label(top, text="Port:").pack(side=tk.LEFT); ttk.Entry(top, textvariable=self.port_var, width=8).pack(side=tk.LEFT, padx=(4,12))
        ttk.Label(top, text="Secret (optional):").pack(side=tk.LEFT)
        showchar = "•" if USE_TTKB else "*"
        self.secret_entry_r = ttk.Entry(top, textvariable=self.secret_var, show=showchar, width=18); self.secret_entry_r.pack(side=tk.LEFT, padx=(4,12))
        ttk.Button(top, text="📥 Connect & Receive", command=self.receiver_start).pack(side=tk.LEFT)
        ttk.Button(top, text="⏸ Pause", command=self.receiver_pause).pack(side=tk.LEFT, padx=6)
        ttk.Button(top, text="▶ Resume", command=self.receiver_resume).pack(side=tk.LEFT)

        mid = ttk.Frame(self.receiver_tab); mid.pack(fill=tk.BOTH, expand=True, pady=6)
        self.receiver_list = tk.Listbox(mid, height=18); self.receiver_list.pack(fill=tk.BOTH, expand=True)
        self.receiver_prog = ttk.Progressbar(self.receiver_tab, mode='determinate'); self.receiver_prog.pack(fill=tk.X, padx=6, pady=6)
        self.receiver_status = ttk.Label(self.receiver_tab, text="Idle."); self.receiver_status.pack(fill=tk.X, padx=6)
        self.receiver_log = tk.Text(self.receiver_tab, height=8, state=tk.DISABLED); self.receiver_log.pack(fill=tk.BOTH, expand=False, padx=6, pady=(6,6))

    # -- helpers exposed to Sender/Receiver objects
    def get_port(self): 
        try: p = int(self.port_var.get()); return p if 1 <= p <= 65535 else TRANSFER_PORT_DEFAULT
        except: return TRANSFER_PORT_DEFAULT
    def get_http_port(self):
        try: p = int(self.http_port_var.get()); return p if 1 <= p <= 65535 else HTTP_PORT_DEFAULT
        except: return HTTP_PORT_DEFAULT
    def get_secret(self): return self.secret_var.get().strip()
    def get_peer_ip(self): return self.ip_entry.get().strip()

    def ask_files(self): return filedialog.askopenfilenames(title="Choose files to send")
    def ask_folder_files(self):
        folder = filedialog.askdirectory(title="Choose folder to send")
        if not folder: return None, []
        file_list = []
        for root, _, files in os.walk(folder):
            for name in files:
                file_list.append(os.path.join(root, name))
        return folder, file_list
    def ask_dest_dir(self): return filedialog.askdirectory(title="Choose destination folder")

    def alert(self, msg): messagebox.showwarning("Notice", msg)
    def log(self, msg: str, sender=True):
        box = self.sender_log if sender else self.receiver_log
        box.configure(state=tk.NORMAL)
        box.insert(tk.END, msg + "\n"); box.see(tk.END); box.configure(state=tk.DISABLED)
        self.root.update_idletasks()

    # sender UI update calls
    def set_sender_queue(self, queue, total_size, session_id):
        self.sender_list.delete(0, tk.END)
        for f in queue:
            self.sender_list.insert(tk.END, f"{f['rel']} ({human_size(f['size'])})")
        self.sender_status.config(text=f"Session {session_id} | Total: {human_size(total_size)}")
        self.sender_prog['value'] = 0

    def set_sender_progress(self, idx, total_files, pos, size, pct_total, mbps, eta):
        self.sender_prog['value'] = pct_total
        cur = f"Sending [{idx+1}/{total_files}] {human_size(pos)} / {human_size(size)}  @ {mbps:.2f} MB/s  ETA: {eta:.1f}s"
        self.sender_status.config(text=cur)
        self.root.update_idletasks()

    def set_sender_done(self):
        self.sender_prog['value'] = 100
        self.sender_status.config(text="✅ Queue sent successfully")
        self.log("All files sent!", sender=True)
        messagebox.showinfo("Done", "All files sent successfully!")

    # receiver UI update calls
    def set_receiver_queue(self, files_meta, total, session_id):
        self.receiver_list.delete(0, tk.END)
        for f in files_meta:
            self.receiver_list.insert(tk.END, f"{f['rel']} ({human_size(int(f['size']))})")
        self.receiver_status.config(text=f"Session {session_id} | Total: {human_size(total)}")
        self.receiver_prog['value'] = 0

    def set_receiver_progress(self, idx, total_files, pos, size, pct_total, mbps, eta):
        self.receiver_prog['value'] = pct_total
        cur = f"Receiving [{idx+1}/{total_files}] {human_size(pos)} / {human_size(size)}  @ {mbps:.2f} MB/s  ETA: {eta:.1f}s"
        self.receiver_status.config(text=cur)
        self.root.update_idletasks()

    def set_receiver_done(self):
        self.receiver_prog['value'] = 100
        self.receiver_status.config(text="✅ Queue received successfully")
        self.log("All files received!", sender=False)
        messagebox.showinfo("Done", "All files received successfully!")

    # button hooks
    def choose_files(self): self.sender.pick_files()
    def choose_folder(self): self.sender.pick_folder()
    def sender_start(self): self.sender.start_server()
    def sender_pause(self): self.sender.pause()
    def sender_resume(self): self.sender.resume()
    def receiver_start(self): self.receiver.start()
    def receiver_pause(self): self.receiver.pause()
    def receiver_resume(self): self.receiver.resume()

    # HTTP link UI
    def show_http_link(self, link):
        self.http_link_label.config(text=f"Share link: {link}    (open on mobile browser)")
    def clear_http_link(self): self.http_link_label.config(text="")

    def sender_share_link(self): self.sender.share_via_http()
    def sender_stop_link(self): self.sender.stop_http_share()

    def refresh_ip(self):
        self.ip_label.config(text=self._footer_text()); self.root.update_idletasks()

    def _footer_text(self) -> str:
        return f"Your IP: {get_local_ip()}    |    Port: {self.get_port()}"

# ----------------- Entry Point -----------------
def main():
    if USE_TTKB:
        root = tb.Window(themename="darkly")
    else:
        root = tk.Tk()
    app = App(root)
    root.mainloop()

if __name__ == "__main__":
    main()
