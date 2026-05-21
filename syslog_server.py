"""
syslog_server.py — minimal TCP syslog receiver (RFC 5424 + RFC 6587 octet-count framing).

Listens on TCP :5514, parses octet-counted frames sent by syslog_handler.py,
writes each message to stdout and to /var/log/syslog/cortex.log.
"""
import os
import socket
import threading
from datetime import datetime, timezone

LOG_FILE = "/var/log/syslog/cortex.log"
PORT     = 5514


def emit(msg: str) -> None:
    ts   = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = f"{ts} {msg}"
    print(line, flush=True)
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def parse_frames(buf: bytes) -> tuple[list[str], bytes]:
    """
    Extract all complete RFC 6587 octet-counted frames from buf.
    Returns (list of decoded messages, remaining incomplete bytes).
    """
    messages = []
    while buf:
        space = buf.find(b" ")
        if space == -1:
            break
        try:
            length = int(buf[:space])
        except ValueError:
            # Fallback: newline-delimited (not expected but safe)
            nl = buf.find(b"\n")
            if nl == -1:
                break
            messages.append(buf[:nl].decode("utf-8", errors="replace").strip())
            buf = buf[nl + 1:]
            continue

        start = space + 1
        if len(buf) < start + length:
            break  # incomplete frame — wait for more data

        messages.append(buf[start : start + length].decode("utf-8", errors="replace"))
        buf = buf[start + length:]

    return messages, buf


def handle_client(conn: socket.socket, addr) -> None:
    buf = b""
    with conn:
        while True:
            chunk = conn.recv(8192)
            if not chunk:
                break
            buf += chunk
            messages, buf = parse_frames(buf)
            for msg in messages:
                emit(msg)


def main() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", PORT))
    server.listen(10)
    print(f"[syslog-server] TCP listening on :{PORT}", flush=True)

    while True:
        conn, addr = server.accept()
        print(f"[syslog-server] Connection from {addr[0]}:{addr[1]}", flush=True)
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
