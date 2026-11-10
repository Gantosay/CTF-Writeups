"""
Buffered I/O wrapper for both a local subprocess and a remote (TCP/TLS)
socket. Fixes the bug in the earlier conn.py: a naive recv_until() that
reads raw socket/pipe chunks and throws away everything after the marker
loses data whenever the server's bytes arrive coalesced in one packet
(extremely common over a real network / through TLS). This version keeps
an internal buffer, like pwntools' tubes do, so nothing is ever dropped.
"""
import subprocess, socket, ssl, time, os


class BufferedIO:
    """Base class: subclasses implement _raw_recv(n) -> bytes (b'' on EOF/timeout)."""

    def __init__(self):
        self._buf = b""

    # ---- override in subclasses ----
    def _raw_recv(self, n, timeout):
        raise NotImplementedError

    def _raw_send(self, data):
        raise NotImplementedError

    def alive(self):
        raise NotImplementedError

    def close(self):
        raise NotImplementedError

    # ---- shared buffered logic ----
    def send(self, data):
        if isinstance(data, str):
            data = data.encode()
        self._raw_send(data)

    def sendline(self, data):
        if isinstance(data, str):
            data = data.encode()
        self.send(data + b"\n")

    def recv_until(self, marker, timeout=10):
        if isinstance(marker, str):
            marker = marker.encode()
        start = time.time()
        while marker not in self._buf:
            remaining = timeout - (time.time() - start)
            if remaining <= 0:
                break
            chunk = self._raw_recv(4096, min(remaining, 1.0))
            if chunk:
                self._buf += chunk
            elif not self.alive():
                break
        idx = self._buf.find(marker)
        if idx == -1:
            # timed out / EOF before marker showed up - return & clear what we have
            out, self._buf = self._buf, b""
            return out
        end = idx + len(marker)
        out, self._buf = self._buf[:end], self._buf[end:]
        return out

    def recv(self, n=4096, timeout=0.5):
        start = time.time()
        while len(self._buf) < n:
            remaining = timeout - (time.time() - start)
            if remaining <= 0:
                break
            chunk = self._raw_recv(4096, min(remaining, 1.0))
            if chunk:
                self._buf += chunk
            else:
                break
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def recv_exact(self, n, timeout=10):
        """Block (up to timeout) until exactly n bytes are available."""
        start = time.time()
        while len(self._buf) < n:
            remaining = timeout - (time.time() - start)
            if remaining <= 0:
                break
            chunk = self._raw_recv(4096, min(remaining, 1.0))
            if chunk:
                self._buf += chunk
            elif not self.alive():
                break
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def recv_line(self, timeout=10):
        return self.recv_until(b"\n", timeout).rstrip(b"\n")

    def interactive(self):
        """Drop into a live, two-way terminal <-> socket/pipe proxy, like
        pwntools' p.interactive(). Flushes anything already buffered first,
        then loops: print whatever the remote sends, send whatever you type.
        Ctrl+D (or Ctrl+C) to leave."""
        import sys, select

        if self._buf:
            sys.stdout.buffer.write(self._buf)
            sys.stdout.flush()
            self._buf = b""

        print("\n[*] switching to interactive mode (Ctrl+D or Ctrl+C to quit)\n")
        fd = self._select_fd()
        try:
            while self.alive():
                r, _, _ = select.select([sys.stdin, fd], [], [], 0.2)
                if fd in r:
                    chunk = self._raw_recv(4096, 0.1)
                    if chunk:
                        sys.stdout.buffer.write(chunk)
                        sys.stdout.flush()
                    elif not self.alive():
                        print("\n[*] connection closed")
                        break
                if sys.stdin in r:
                    line = sys.stdin.readline()
                    if not line:          # EOF (Ctrl+D)
                        break
                    self._raw_send(line.encode())
        except KeyboardInterrupt:
            pass
        print("\n[*] leaving interactive mode")

    def _select_fd(self):
        raise NotImplementedError


class ProcIO(BufferedIO):
    def __init__(self, path):
        super().__init__()
        self.p = subprocess.Popen([path], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, bufsize=0)
        os.set_blocking(self.p.stdout.fileno(), False)

    def _raw_send(self, data):
        self.p.stdin.write(data)
        self.p.stdin.flush()

    def _raw_recv(self, n, timeout):
        end = time.time() + timeout
        while time.time() < end:
            try:
                chunk = self.p.stdout.read(n)
                if chunk:
                    return chunk
            except Exception:
                pass
            if self.p.poll() is not None:
                return b""
            time.sleep(0.01)
        return b""

    def alive(self):
        return self.p.poll() is None

    def close(self):
        try:
            self.p.stdin.close()
        except Exception:
            pass
        self.p.terminate()

    def _select_fd(self):
        return self.p.stdout


class RemoteIO(BufferedIO):
    def __init__(self, host, port, use_ssl=False):
        super().__init__()
        raw = socket.create_connection((host, port))
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self.s = ctx.wrap_socket(raw, server_hostname=host)
        else:
            self.s = raw
        self._closed = False

    def _raw_send(self, data):
        self.s.sendall(data)

    def _raw_recv(self, n, timeout):
        self.s.settimeout(timeout)
        try:
            chunk = self.s.recv(n)
            if not chunk:
                self._closed = True
            return chunk
        except socket.timeout:
            return b""
        except OSError:
            self._closed = True
            return b""

    def alive(self):
        return not self._closed

    def close(self):
        self.s.close()

    def _select_fd(self):
        return self.s
