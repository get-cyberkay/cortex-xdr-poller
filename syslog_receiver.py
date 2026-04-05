#!/usr/bin/env python3
"""
syslog_receiver.py — Simple RFC 5424 TCP syslog receiver.

Uses RFC 6587 octet-count framing: each message is prefixed with
"<byte-length> " before the syslog payload.

Writes every received message as one line to /logs/received.log and
also prints it to stdout (visible via docker logs).

Run inside Docker:
  python3 /syslog_receiver.py
"""
import os
import socket
import threading

HOST     = "0.0.0.0"
PORT     = 5514
LOG_PATH = "/logs/received.log"
_write_lock = threading.Lock()

os.makedirs("/logs", exist_ok=True)
try:
    os.chmod("/logs", 0o777)
except OSError:
    pass


def _write(msg: str) -> None:
    line = msg.strip()
    if not line:
        return
    with _write_lock:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
        try:
            os.chmod(LOG_PATH, 0o666)
        except OSError:
            pass
    print(line, flush=True)


def handle_client(conn: socket.socket, addr) -> None:
    buf = b""
    with conn:
        while True:
            try:
                chunk = conn.recv(8192)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            # RFC 6587 octet-count framing: "<len> <syslog-msg>"
            while buf:
                sp = buf.find(b" ")
                if sp == -1:
                    break
                try:
                    msg_len = int(buf[:sp])
                except ValueError:
                    # Not a length prefix — discard up to next space
                    buf = buf[sp + 1:]
                    continue
                end = sp + 1 + msg_len
                if len(buf) < end:
                    break  # wait for more data
                msg = buf[sp + 1:end].decode("utf-8", errors="replace")
                _write(msg)
                buf = buf[end:]


def main() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(20)
    print(f"[syslog-receiver] listening on tcp:{PORT}  →  {LOG_PATH}", flush=True)

    while True:
        try:
            conn, addr = srv.accept()
        except OSError:
            break
        print(f"[syslog-receiver] connection from {addr}", flush=True)
        t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        t.start()


if __name__ == "__main__":
    main()
