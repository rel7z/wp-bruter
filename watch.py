#!/usr/bin/env python3
"""Tail one or more text files into CNC merged, with durable delivery.

Python 3.9+, Linux/macOS, standard library only. See watch_to_merged.md.
"""
import argparse
import base64
import contextlib
import fcntl
import hashlib
import json
import logging
import os
from pathlib import Path
import select
import shlex
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import time
import uuid

LOG = logging.getLogger("watch-to-merged")
READ_SIZE = 64 * 1024
MAX_LINE = 1024 * 1024

# EDIT BAGIAN INI. Setelah disimpan, jalankan: python3 watch_to_merged.py
# Pasangan: (path file sumber, nama file tujuan di merged).
# Path sumber berada di mesin yang menjalankan script ini.
FILES = [
    ("/opt/wp-bruter/results.txt", "wp.txt"),
    # ("/root/lulz/x.txt", "apalah.txt"),
]
MERGED_DIR = "/opt/cnc/merged"
# None jika script dijalankan di controller.
# Dari mesin lain, isi misalnya "root@143.198.214.173" atau "cnc-do-controller".
SSH_TARGET = None
SSH_CONFIG = None  # Misalnya "/Users/fahrel/Documents/GitHub/cnc/.digitalocean/ssh_config"
SSH_IDENTITY = None  # Path private key pada mesin pengirim; tidak dikirim ke server.
STATE_PATH = None  # None = otomatis; atau path SQLite tetap, jangan dihapus saat restart.
INTERVAL_SECONDS = 0.2
FROM_END = False  # False = kirim isi lama juga pada pengamatan pertama.
SERVICE_NAME = "cnc-watch-to-merged"
SERVICE_MEMORY_HIGH = "128M"
SERVICE_MEMORY_MAX = "256M"  # Jika terlampaui: systemd restart, checkpoint tetap ada.


def systemd_argument(value):
    value = str(value)
    if any(c in value for c in "\x00\r\n"):
        raise ValueError("Service arguments cannot contain control characters")
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%').replace('$', '$$') + '"'


def service_unit(program, state, arguments):
    command = [sys.executable, "-u", str(program), "--foreground", *arguments, "--state", str(state)]
    return """[Unit]
Description=CNC durable file watcher to merged
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
UMask=0077
WorkingDirectory=/
ExecStart=""" + " ".join(systemd_argument(a) for a in command) + """
Restart=always
RestartSec=5
TimeoutStopSec=30
KillMode=control-group
OOMPolicy=stop
MemoryAccounting=yes
MemoryHigh=""" + SERVICE_MEMORY_HIGH + "\nMemoryMax=" + SERVICE_MEMORY_MAX + """
TasksMax=32
NoNewPrivileges=yes
StandardOutput=journal
StandardError=journal
SyslogIdentifier=cnc-watch-to-merged
LogRateLimitIntervalSec=30s
LogRateLimitBurst=100

[Install]
WantedBy=multi-user.target
"""


def atomic_file(path, data, mode):
    if path.is_symlink():
        raise RuntimeError("Refusing symlink installation path")
    temporary = path.with_name(path.name + ".new")
    fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data); output.flush(); os.fsync(output.fileno())
        temporary.chmod(mode)
        os.replace(temporary, path)
        directory_fd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()


def install_service(state, arguments):
    if not sys.platform.startswith("linux") or not Path('/run/systemd/system').is_dir() or not shutil.which('systemctl'):
        raise RuntimeError("Automatic installation requires Linux with systemd; use --foreground otherwise")
    if os.geteuid() != 0:
        raise RuntimeError("Install once as root: sudo python3 " + shlex.quote(str(Path(__file__).resolve())))
    if not SERVICE_NAME or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in SERVICE_NAME):
        raise ValueError("SERVICE_NAME must contain only lowercase letters, digits and hyphens")
    directory = Path('/opt') / SERVICE_NAME
    if directory.is_symlink():
        raise RuntimeError("Service installation directory must not be a symlink")
    directory.mkdir(mode=0o700, exist_ok=True)
    directory.chmod(0o700)
    program = directory / 'watch_to_merged.py'
    unit = Path('/etc/systemd/system') / (SERVICE_NAME + '.service')
    source = Path(__file__).read_bytes()
    unit_data = service_unit(program, state, arguments).encode()
    changed = False
    for path, data, mode in [(program, source, 0o700), (unit, unit_data, 0o644)]:
        if path.is_symlink():
            raise RuntimeError("Service installation file must not be a symlink")
        if not path.exists() or path.read_bytes() != data:
            if path.exists():
                atomic_file(path.with_name(path.name + '.previous'), path.read_bytes(), mode)
            atomic_file(path, data, mode)
            changed = True
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'enable', SERVICE_NAME + '.service'], check=True)
    active = subprocess.run(['systemctl', 'is-active', '--quiet', SERVICE_NAME + '.service']).returncode == 0
    if changed or not active:
        subprocess.run(['systemctl', 'restart' if active else 'start', SERVICE_NAME + '.service'], check=True)
    subprocess.run(['systemctl', 'is-active', '--quiet', SERVICE_NAME + '.service'], check=True)
    print('Watcher service active and enabled at boot: ' + SERVICE_NAME)
    print('Checkpoint retained: ' + str(state))
    print('Status: systemctl status ' + SERVICE_NAME + ' --no-pager')
    print('Logs: journalctl -u ' + SERVICE_NAME + ' -f')


def database(path):
    path = Path(path).expanduser().absolute()
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    if path.is_symlink():
        raise RuntimeError("State database must not be a symlink")
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    os.close(fd)
    path.chmod(0o600)
    db = sqlite3.connect(str(path), timeout=30)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    return db


def output_name(name):
    if (not name or name.startswith(".") or not name.endswith(".txt")
            or any(c in name for c in "/\\\x00\r\n") or len(name.encode()) > 200):
        raise ValueError("Merged filename must be a visible, flat .txt filename")
    return name


@contextlib.contextmanager
def exclusive_lock(path, nonblocking=False):
    fd = os.open(str(path), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | (fcntl.LOCK_NB if nonblocking else 0))
        yield
    finally:
        os.close(fd)


class Receiver:
    """Serialize watcher writers and journal appends before acknowledging them."""
    def __init__(self, directory):
        self.root = Path(directory).expanduser().absolute()
        if self.root.is_symlink():
            raise RuntimeError("Merged directory must not be a symlink")
        self.root.mkdir(parents=True, mode=0o700, exist_ok=True)
        self.state = self.root / ".watch-to-merged"
        if self.state.is_symlink():
            raise RuntimeError("Receiver state directory must not be a symlink")
        self.state.mkdir(mode=0o700, exist_ok=True)
        self.db = database(self.state / "receipts.sqlite3")
        self.db.execute("CREATE TABLE IF NOT EXISTS receipts (id TEXT PRIMARY KEY, filename TEXT, data BLOB, start INTEGER, device INTEGER, inode INTEGER, done INTEGER NOT NULL, digest BLOB)")
        self.db.commit()

    def _finish(self, batch_id, row):
        name, data, start, device, inode = row[:5]
        target = self.root / output_name(name)
        if target.is_symlink():
            raise RuntimeError("Destination must not be a symlink")
        fd = os.open(str(target), os.O_CREAT | os.O_RDWR | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != (device, inode) or info.st_size < start:
                raise RuntimeError("Pending destination changed; retain state and inspect before retrying")
            os.lseek(fd, start, os.SEEK_SET)
            existing = os.read(fd, len(data))
            if existing != data[:len(existing)]:
                raise RuntimeError("Uncertain interrupted append: destination has a conflicting write; queued data retained")
            if len(existing) < len(data):
                if os.fstat(fd).st_size != start + len(existing):
                    raise RuntimeError("Destination changed during recovery; queued data retained")
                remaining = memoryview(data)[len(existing):]
                while remaining:
                    written = os.write(fd, remaining)
                    if written <= 0:
                        raise OSError("Append made no progress")
                    remaining = remaining[written:]
            os.fsync(fd)
            directory_fd = os.open(str(self.root), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            with self.db:
                self.db.execute("UPDATE receipts SET data=NULL,done=1 WHERE id=?", (batch_id,))
        finally:
            os.close(fd)

    def apply(self, packet):
        batch_id = packet["id"]
        if not isinstance(batch_id, str) or len(batch_id) > 100:
            raise ValueError("Invalid batch identifier")
        name = output_name(packet["filename"])
        data = base64.b64decode(packet["data"], validate=True)
        if not data or len(data) > MAX_LINE + READ_SIZE or not data.endswith(b"\n"):
            raise ValueError("Packet must contain complete lines within the size limit")
        data.decode("utf-8")
        target = self.root / name
        with exclusive_lock(self.state / "append.lock"):
            # Recover any interrupted append before another watcher can write.
            for pending in self.db.execute("SELECT id,filename,data,start,device,inode,done,digest FROM receipts WHERE done=0").fetchall():
                self._finish(pending[0], pending[1:])
            row = self.db.execute("SELECT filename,data,start,device,inode,done,digest FROM receipts WHERE id=?", (batch_id,)).fetchone()
            if row:
                if row[0] != name or bytes(row[6]) != hashlib.sha256(data).digest():
                    raise RuntimeError("Batch identifier reused with different content")
                return {"id": batch_id, "ok": True, "replayed": True}
            if target.is_symlink():
                raise RuntimeError("Destination must not be a symlink")
            fd = os.open(str(target), os.O_CREAT | os.O_RDWR | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode):
                    raise RuntimeError("Destination must be a regular file")
                start = info.st_size
                # Preserve line boundaries if the merged file predates us and
                # its previous final line did not include a newline.
                actual = data
                if start:
                    os.lseek(fd, start - 1, os.SEEK_SET)
                    if os.read(fd, 1) != b"\n":
                        actual = b"\n" + data
                with self.db:
                    self.db.execute("INSERT INTO receipts VALUES(?,?,?,?,?,?,0,?)", (batch_id, name, actual, start, info.st_dev, info.st_ino, hashlib.sha256(data).digest()))
            finally:
                os.close(fd)
            self._finish(batch_id, (name, actual, start, info.st_dev, info.st_ino, 0, hashlib.sha256(data).digest()))
        return {"id": batch_id, "ok": True, "lines": data.count(b"\n")}

    def close(self):
        self.db.close()


class Tailer:
    def __init__(self, state, mappings, from_end=False):
        self.path = Path(state).expanduser().absolute()
        self.db = database(self.path)
        self.mappings = mappings
        self.from_end = from_end
        self.handles = {}
        self.hashes = {}
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY,value TEXT);
        CREATE TABLE IF NOT EXISTS sources (key TEXT PRIMARY KEY,device INTEGER,inode INTEGER,position INTEGER,pending BLOB,digest TEXT,mtime INTEGER,discard INTEGER);
        CREATE TABLE IF NOT EXISTS outbox (id INTEGER PRIMARY KEY AUTOINCREMENT,filename TEXT,data BLOB);
        CREATE TABLE IF NOT EXISTS fragments (source TEXT,data BLOB,created REAL);
        """)
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO metadata VALUES('identity',?)", (uuid.uuid4().hex,))
        self.identity = self.db.execute("SELECT value FROM metadata WHERE key='identity'").fetchone()[0]

    def _capture(self, key, name, handle, row):
        info = os.fstat(handle.fileno())
        if row is None:
            position = info.st_size if self.from_end else 0
            pending, discard = b"", False
            if position:
                handle.seek(position - 1)
                discard = handle.read(1) != b"\n"
            row = (info.st_dev, info.st_ino, position, pending, "", info.st_mtime_ns, discard)
        position, pending, discard = row[2], bytes(row[3]), row[6]
        cached = self.hashes.get(key)
        # Verify the entire already-read prefix when a writer changes the file.
        # This also detects same-inode rewrites that do not shrink the file.
        if not cached or cached[0] != position or info.st_mtime_ns != row[5] or info.st_size < position:
            handle.seek(0)
            prefix = hashlib.sha256()
            left = position
            while left:
                chunk = handle.read(min(left, READ_SIZE))
                if not chunk:
                    break
                prefix.update(chunk)
                left -= len(chunk)
            changed = left != 0 or (row[4] and prefix.hexdigest() != row[4])
            if changed:
                if pending:
                    with self.db:
                        self.db.execute("INSERT INTO fragments VALUES(?,?,?)", (key, pending, time.time()))
                position, pending, discard = 0, b"", False
                prefix = hashlib.sha256()
                LOG.warning("Source truncated or rewritten; rereading current complete lines")
        else:
            prefix = cached[1].copy()
        handle.seek(position)
        chunk = handle.read(READ_SIZE)
        if not chunk and row[4] and position == row[2] and info.st_mtime_ns == row[5]:
            return
        prefix.update(chunk)
        position += len(chunk)
        combined = pending + chunk
        boundary = combined.rfind(b"\n")
        complete, pending = (combined[:boundary + 1], combined[boundary + 1:]) if boundary >= 0 else (b"", combined)
        if discard and complete:
            complete = complete.split(b"\n", 1)[1]
            discard = False
        if len(pending) > MAX_LINE:
            raise RuntimeError("Source line exceeds 1 MiB; checkpoint retained, split the line before continuing")
        complete.decode("utf-8")
        with self.db:
            if complete:
                self.db.execute("INSERT INTO outbox(filename,data) VALUES(?,?)", (name, complete))
            self.db.execute("INSERT OR REPLACE INTO sources VALUES(?,?,?,?,?,?,?,?)", (key, info.st_dev, info.st_ino, position, pending, prefix.hexdigest(), info.st_mtime_ns, discard))
        self.hashes[key] = (position, prefix.copy())
        if complete:
            LOG.info("Queued %d line(s) for %s", complete.count(b"\n"), name)

    def capture(self):
        for source, name in self.mappings:
            key = json.dumps([str(source), name])
            row = self.db.execute("SELECT device,inode,position,pending,digest,mtime,discard FROM sources WHERE key=?", (key,)).fetchone()
            handle = self.handles.get(key)
            try:
                current = source.stat() if source.exists() else None
                if source.is_symlink():
                    raise RuntimeError("Watch source must not be a symlink")
                if handle and current and (current.st_dev, current.st_ino) != (os.fstat(handle.fileno()).st_dev, os.fstat(handle.fileno()).st_ino):
                    # Drain the old open inode before following a replacement.
                    self._capture(key, name, handle, row)
                    row = self.db.execute("SELECT device,inode,position,pending,digest,mtime,discard FROM sources WHERE key=?", (key,)).fetchone()
                    if os.fstat(handle.fileno()).st_size > row[2]:
                        continue
                    handle.close(); del self.handles[key]; self.hashes.pop(key, None)
                    handle = None
                if handle is None:
                    if current is None:
                        # A file first created after startup is entirely new,
                        # including when --from-end was selected.
                        if row is None:
                            with self.db:
                                self.db.execute("INSERT OR IGNORE INTO sources VALUES(?, -1, -1, 0, ?, '', 0, 0)", (key, b""))
                        continue
                    if not stat.S_ISREG(current.st_mode):
                        raise RuntimeError("Watch source must be a regular file")
                    handle = source.open("rb"); self.handles[key] = handle
                    info = os.fstat(handle.fileno())
                    if row and (info.st_dev, info.st_ino) != (row[0], row[1]):
                        if row[3]:
                            with self.db:
                                self.db.execute("INSERT INTO fragments VALUES(?,?,?)", (key, row[3], time.time()))
                        row = (info.st_dev, info.st_ino, 0, b"", "", info.st_mtime_ns, False)
                self._capture(key, name, handle, row)
            except OSError as error:
                LOG.warning("Cannot read %s (%s); will retry", source, type(error).__name__)

    def deliver(self, transport, limit=100):
        sent = 0
        while sent < limit:
            row = self.db.execute("SELECT id,filename,data FROM outbox ORDER BY id LIMIT 1").fetchone()
            if row is None:
                break
            packet = {"id": self.identity + ":" + str(row[0]), "filename": row[1], "data": base64.b64encode(row[2]).decode("ascii")}
            reply = transport.apply(packet)
            if not reply.get("ok") or reply.get("id") != packet["id"]:
                raise RuntimeError("Receiver did not acknowledge this batch")
            with self.db:
                self.db.execute("DELETE FROM outbox WHERE id=?", (row[0],))
            LOG.info("Delivered %d line(s) to %s", bytes(row[2]).count(b"\n"), row[1])
            sent += 1
        return sent

    def close(self):
        for handle in self.handles.values():
            handle.close()
        self.db.close()


class SSHReceiver:
    def __init__(self, host, directory, config=None, identity=None, log_path=None, command=None):
        if not host or host.startswith("-") or any(c.isspace() for c in host):
            raise ValueError("Invalid SSH target")
        self.command = command
        if command is None:
            program = Path(__file__).read_text()
            self.command = ["ssh", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=8", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3"]
            if config:
                self.command += ["-F", str(Path(config).expanduser())]
            if identity:
                self.command += ["-i", str(Path(identity).expanduser()), "-o", "IdentitiesOnly=yes"]
            self.command += [host, "python3 -u -c " + shlex.quote(program) + " --receive --merged-dir " + shlex.quote(str(directory))]
        self.log_path = log_path
        self.process = None
        self.log = None

    def apply(self, packet):
        if self.process is None or self.process.poll() is not None:
            self.close()
            self.log = open(self.log_path, "ab") if self.log_path else open(os.devnull, "ab")
            if self.log_path:
                os.chmod(self.log_path, 0o600)
            self.process = subprocess.Popen(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.log)
        try:
            self.process.stdin.write(json.dumps(packet).encode() + b"\n"); self.process.stdin.flush()
            deadline = time.monotonic() + 30
            data = b""
            while b"\n" not in data:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([self.process.stdout], [], [], remaining)[0]:
                    raise TimeoutError("Receiver acknowledgement timed out")
                chunk = os.read(self.process.stdout.fileno(), 65536)
                if not chunk:
                    raise ConnectionError("SSH receiver closed; check SSH access and receiver log")
                data += chunk
                if len(data) > 65536:
                    raise RuntimeError("Invalid receiver response")
            reply = json.loads(data)
            if not reply.get("ok"):
                raise RuntimeError(reply.get("error", "Receiver rejected batch"))
            return reply
        except Exception:
            self.close()
            raise

    def close(self):
        if self.process:
            if self.process.stdin:
                with contextlib.suppress(OSError):
                    self.process.stdin.close()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.process.kill(); self.process.wait()
            if self.process.stdout:
                self.process.stdout.close()
            self.process = None
        if self.log:
            self.log.close(); self.log = None


def receive(directory):
    receiver = Receiver(directory)
    try:
        for raw in sys.stdin.buffer:
            try:
                if len(raw) > 2 * 1024 * 1024:
                    raise ValueError("Packet too large")
                packet = json.loads(raw)
                reply = receiver.apply(packet)
            except Exception as error:
                reply = {"ok": False, "error": str(error)}
            print(json.dumps(reply), flush=True)
    finally:
        receiver.close()


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", action="append", default=[], metavar="SOURCE[=MERGED.txt]")
    parser.add_argument("--merged-dir", default=MERGED_DIR)
    parser.add_argument("--ssh", default=SSH_TARGET, help="Existing SSH alias or user@controller; omit on the controller")
    parser.add_argument("--ssh-config", default=SSH_CONFIG)
    parser.add_argument("--identity", default=SSH_IDENTITY, help="Existing authorized SSH private key path")
    parser.add_argument("--state", default=STATE_PATH, help="Private SQLite checkpoint and outbox path")
    parser.add_argument("--interval", type=float, default=INTERVAL_SECONDS, help="Check interval in seconds")
    parser.add_argument("--from-end", action="store_true", default=FROM_END, help="On first observation, skip existing bytes")
    parser.add_argument("--from-start", dest="from_end", action="store_false", help="Override FROM_END and include existing bytes")
    parser.add_argument("--once", action="store_true", help="One capture/delivery pass; useful for checks")
    parser.add_argument("--receive", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--foreground", action="store_true", help="Run directly without installing a service")
    parser.add_argument("--install", action="store_true", help="Install/update and start the systemd service")
    args = parser.parse_args(argv)
    if not args.file:
        args.file = [source + "=" + name for source, name in FILES]
    if not args.receive and (not args.file or args.interval < 0.05):
        parser.error("Configure FILES or use --file; --interval must be >= 0.05")
    return args


def main():
    args = parse_args()
    os.umask(0o077)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if args.receive:
        receive(args.merged_dir); return
    mappings = []
    for spec in args.file:
        source, separator, name = spec.rpartition("=")
        if not separator:
            source, name = spec, Path(spec).name
        source = Path(source).expanduser().absolute()
        name = output_name(name)
        if not args.ssh and source.resolve() == (Path(args.merged_dir).expanduser() / name).resolve():
            raise ValueError("Source and merged destination must be different files")
        if (source, name) not in mappings:
            mappings.append((source, name))
    fingerprint = hashlib.sha256(json.dumps([[str(p), n] for p, n in mappings] + [args.ssh, args.merged_dir]).encode()).hexdigest()[:16]
    state = Path(args.state).expanduser() if args.state else Path.home() / ".local/state/cnc-watch-to-merged" / (fingerprint + ".sqlite3")
    state = state.absolute()
    if args.install or (sys.platform.startswith('linux') and not sys.argv[1:]):
        arguments = [a for a in sys.argv[1:] if a != '--install']
        install_service(state, arguments)
        return 0
    state.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    running = True
    def stop(*_):
        nonlocal running
        running = False
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, stop)
    with exclusive_lock(str(state) + ".lock", nonblocking=True):
        tailer = Tailer(state, mappings, args.from_end)
        transport = SSHReceiver(args.ssh, args.merged_dir, args.ssh_config, args.identity, str(state) + ".ssh.log") if args.ssh else Receiver(args.merged_dir)
        retry_at, failures = 0, 0
        try:
            while running:
                tailer.capture()
                if time.monotonic() >= retry_at:
                    try:
                        tailer.deliver(transport)
                        failures = 0
                    except Exception as error:
                        failures += 1
                        delay = min(30, 2 ** min(failures, 5))
                        retry_at = time.monotonic() + delay
                        LOG.warning("Delivery failed (%s): %s. Retained in outbox; retry in %ss", type(error).__name__, error, delay)
                        if args.once:
                            return 1
                if args.once:
                    return 0
                time.sleep(args.interval)
        finally:
            tailer.close(); transport.close()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main() or 0)
    except (RuntimeError, ValueError, OSError) as error:
        LOG.error("%s", error)
        sys.exit(1)
