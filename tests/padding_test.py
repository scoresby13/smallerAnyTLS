#!/usr/bin/env python3
"""
Mock AnyTLS server that checks anytls-tiny's padding scheme implementation.

It terminates TLS itself (asyncio + ssl.MemoryBIO) so it can see the size of
every TLS record the client sends, and checks those sizes against a model of
writeConn() from anytls-go's proxy/session/session.go. It also sends
cmdUpdatePaddingScheme, injects cmdWaste frames into the downstream, and
relays real SOCKS5 / DNS traffic to local echo servers.

Usage: python3 tests/padding_test.py [path/to/anytls-tiny]
"""
import asyncio
import hashlib
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile

DEFAULT = (b"stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n"
           b"3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000")
CUSTOM = (b"stop=6\n0=100-120\n1=200-200\n2=300-350,c,600-600\n3=9-9,700-800\n"
          b"4=50-50,c,60-60,70-70\n5=1000-1000")
PASSWORD = "test-password"
HDR = 7

failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)
        print("  FAIL:", msg)


def md5hex(b):
    return hashlib.md5(b).hexdigest()


class Scheme:
    def __init__(self, raw):
        self.m = dict(l.split("=", 1) for l in raw.decode().split("\n") if "=" in l)
        self.stop = int(self.m["stop"])

    def entries(self, pkt):
        out = []
        for e in self.m.get(str(pkt), "").split(","):
            if e == "c":
                out.append(None)
            elif "-" in e:
                a, b = map(int, e.split("-"))
                out.append((min(a, b), max(a, b)))
        return out


def in_range(l, rng):
    lo, hi = rng
    return l == lo if lo == hi else lo <= l < hi  # anytls-go samples [lo, hi)


def check_packet(name, recs, size, scheme, pkt):
    """Consume the records of one packet with `size` payload bytes from recs."""
    got = []

    def take():
        r = recs.pop(0) if recs else None
        got.append(r)
        return r

    remain = size
    if pkt < scheme.stop:
        for e in scheme.entries(pkt):
            if e is None:
                if remain == 0:
                    break
                continue
            r = take()
            if r is None:
                check(False, f"{name}: missing record")
                return
            if remain > 0 and r < remain:      # record is all payload
                check(in_range(r, e), f"{name}: payload record {r} not in {e}")
                remain -= r
            elif remain > 0 and r == remain:   # payload tail, too little room for cmdWaste
                check(any(in_range(l, e) for l in range(remain, remain + HDR + 1)),
                      f"{name}: tail record {r} not in {e}")
                remain = 0
            elif remain > 0:                   # payload tail + cmdWaste
                check(r >= remain + HDR + 1 and in_range(r, e), f"{name}: padded record {r} not in {e}")
                remain = 0
            else:                              # all cmdWaste
                check(in_range(r - HDR, e), f"{name}: waste record {r} (data {r - HDR}) not in {e}")
    while remain > 0:
        r = take()
        if r is None or r > remain:
            check(False, f"{name}: leftover record {r}, expected <= {remain}")
            return
        remain -= r
    print(f"  {name} ({size} B): records {got}")


class Session:
    def __init__(self, server, reader, writer):
        self.server, self.reader, self.writer = server, reader, writer
        self.records = []        # plaintext size of each client TLS record
        self.buf = b""
        self.authed = False
        self.pad0 = None
        self.settings = None
        self.waste_frames = 0
        self.waste_bytes = 0
        self.streams = {}
        self.closed = asyncio.Event()

    def send(self, data):
        self.obj.write(data)
        self.flush()

    def flush(self):
        out = self.out.read()
        if out and not self.writer.is_closing():
            self.writer.write(out)

    def frame(self, cmd, sid, data=b""):
        return struct.pack(">BIH", cmd, sid, len(data)) + data

    def send_frame(self, cmd, sid, data=b""):
        # Prefix downstream frames with cmdWaste the client has to skip
        w = os.urandom(len(data) % 300)
        self.send(self.frame(0, 0, w))
        self.send(self.frame(cmd, sid, data))

    async def run(self):
        inc, self.out = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.obj = self.server.ctx.wrap_bio(inc, self.out, server_side=True)
        raw, handshaken = b"", False
        try:
            while True:
                data = await self.reader.read(65536)
                if not data:
                    break
                raw += data
                while len(raw) >= 5:
                    ln = struct.unpack(">H", raw[3:5])[0]
                    if len(raw) < 5 + ln:
                        break
                    rec, raw = raw[:5 + ln], raw[5 + ln:]
                    inc.write(rec)   # one TLS record at a time, so each read() is one record
                    if not handshaken:
                        try:
                            self.obj.do_handshake()
                            handshaken = True
                        except ssl.SSLWantReadError:
                            pass
                        self.flush()
                        continue
                    pt = b""
                    while True:
                        try:
                            pt += self.obj.read(65536)
                        except ssl.SSLWantReadError:
                            break
                    self.flush()
                    if pt:
                        self.records.append(len(pt))
                        self.feed(pt)
        except (ssl.SSLError, ConnectionError) as e:
            print("  server: connection error", e)
        finally:
            for st in self.streams.values():
                if st.get("w"):
                    st["w"].close()
            self.writer.close()
            self.closed.set()

    def feed(self, pt):
        self.buf += pt
        if not self.authed:
            if len(self.buf) < 34:
                return
            plen = struct.unpack(">H", self.buf[32:34])[0]
            if len(self.buf) < 34 + plen:
                return
            check(self.buf[:32] == hashlib.sha256(PASSWORD.encode()).digest(), "bad password hash")
            self.pad0 = plen
            self.buf = self.buf[34 + plen:]
            self.authed = True
            self.server.new_session.set()
        while len(self.buf) >= HDR:
            cmd, sid, ln = struct.unpack(">BIH", self.buf[:HDR])
            if len(self.buf) < HDR + ln:
                return
            data, self.buf = self.buf[HDR:HDR + ln], self.buf[HDR + ln:]
            self.handle(cmd, sid, data)

    def handle(self, cmd, sid, data):
        if cmd == 0:
            self.waste_frames += 1
            self.waste_bytes += len(data)
            check(sid == 0 and data == bytes(len(data)), "cmdWaste with nonzero stream id or data")
        elif cmd == 4:
            self.settings = dict(l.split("=", 1) for l in data.decode().split("\n") if "=" in l)
            if self.settings.get("padding-md5") != md5hex(self.server.scheme):
                self.send_frame(6, 0, self.server.scheme)
            if self.server.bogus_update:
                self.send_frame(6, 0, b"foo=bar\n1=10-20")   # no stop=, client must ignore it
            self.send_frame(10, 0, b"v=2")
        elif cmd == 1:
            check(self.settings is not None, "cmdSYN before cmdSettings")
            self.streams[sid] = {"addr": None, "w": None, "pending": b""}
        elif cmd == 2:
            st = self.streams.get(sid)
            if st is None:
                return
            if st["addr"] is None:
                check(data[0] == 1 and len(data) == 7, f"unexpected address {data!r}")
                st["addr"] = (socket.inet_ntoa(data[1:5]), struct.unpack(">H", data[5:7])[0])
                asyncio.ensure_future(self.connect(sid, st))
            elif st["w"]:
                st["w"].write(data)
            else:
                st["pending"] += data
        elif cmd == 3:
            st = self.streams.pop(sid, None)
            if st and st["w"]:
                st["w"].close()
        elif cmd == 8:
            self.send_frame(9, sid)
        elif cmd != 9:
            check(False, f"unexpected command {cmd}")

    async def connect(self, sid, st):
        try:
            r, w = await asyncio.open_connection(*st["addr"])
        except OSError as e:
            self.send_frame(7, sid, str(e).encode())
            return
        self.send_frame(7, sid)
        if sid not in self.streams:
            w.close()
            return
        st["w"] = w
        if st["pending"]:
            w.write(st["pending"])
        while True:
            data = await r.read(16000)
            if not data:
                break
            self.send_frame(2, sid, data)
        if self.streams.pop(sid, None) is not None:
            self.send_frame(3, sid)
        w.close()


class MockServer:
    def __init__(self, ctx, scheme, bogus_update=False):
        self.ctx, self.scheme, self.bogus_update = ctx, scheme, bogus_update
        self.sessions = []
        self.new_session = asyncio.Event()

    async def start(self):
        self.srv = await asyncio.start_server(self.accept, "127.0.0.1", 0)
        return self.srv.sockets[0].getsockname()[1]

    async def accept(self, reader, writer):
        s = Session(self, reader, writer)
        self.sessions.append(s)
        await s.run()

    async def wait_session(self, n):
        while len([s for s in self.sessions if s.authed]) < n:
            self.new_session.clear()
            await asyncio.wait_for(self.new_session.wait(), 40)
        return self.sessions[n - 1]


async def echo_server():
    async def h(r, w):
        while data := await r.read(65536):
            w.write(data)
            await w.drain()
        w.close()
    srv = await asyncio.start_server(h, "127.0.0.1", 0)
    return srv, srv.sockets[0].getsockname()[1]


async def dns_tcp_server():
    async def h(r, w):
        try:
            while True:
                ln = struct.unpack(">H", await r.readexactly(2))[0]
                q = await r.readexactly(ln)
                w.write(struct.pack(">H", len(q)) + q[:2] + b"\x81\x80" + q[4:])
                await w.drain()
        except asyncio.IncompleteReadError:
            w.close()
    srv = await asyncio.start_server(h, "127.0.0.1", 0)
    return srv, srv.sockets[0].getsockname()[1]


async def socks_open(port, target_port):
    for _ in range(50):   # the client may still be reconnecting
        try:
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write(b"\x05\x01\x00")
            if await r.readexactly(2) != b"\x05\x00":
                raise ConnectionError
            w.write(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", target_port))
            rep = await r.readexactly(10)
            if rep[1] == 0:
                return r, w
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        await asyncio.sleep(0.2)
    raise RuntimeError("SOCKS5 connect failed")


async def echo_flow(port, target_port, writes):
    """One SOCKS5 stream; each write waits for its echo so it is its own packet."""
    r, w = await socks_open(port, target_port)
    await asyncio.sleep(0.3)   # let cmdServerSettings / cmdUpdatePaddingScheme arrive
    for n in writes:
        data = os.urandom(n)
        w.write(data)
        await w.drain()
        check(await asyncio.wait_for(r.readexactly(n), 10) == data, f"echo mismatch ({n} B)")
    w.close()
    await asyncio.sleep(0.3)   # FIN goes out as its own packet


async def bulk_flow(port, target_port, size):
    r, w = await socks_open(port, target_port)
    data = os.urandom(size)

    async def sender():
        for i in range(0, size, 50000):
            w.write(data[i:i + 50000])
            await w.drain()
    t = asyncio.ensure_future(sender())
    got = await asyncio.wait_for(r.readexactly(size), 60)
    await t
    w.close()
    check(got == data, f"bulk echo of {size} B corrupted")


def validate(name, sess, first, later, writes, addr_len=7):
    """first: scheme the session started with; later: scheme after any update."""
    print(f" {name}: padding-md5={sess.settings.get('padding-md5')} pad0={sess.pad0} "
          f"waste frames={sess.waste_frames} ({sess.waste_bytes} B)")
    check(sess.settings.get("padding-md5") == md5hex(first), f"{name}: padding-md5 is not md5 of scheme")
    recs = list(sess.records)
    r0 = recs.pop(0)
    check(r0 == 34 + sess.pad0, f"{name}: auth record {r0} != 34 + padding0 {sess.pad0}")
    check(in_range(sess.pad0, Scheme(first).entries(0)[0]), f"{name}: padding0 {sess.pad0} out of range")
    settings_len = HDR + len("v=2\nclient=anytls/0.0.1\npadding-md5=\n") + 32
    sizes = [settings_len + HDR + HDR + addr_len] + [HDR + n for n in writes] + [HDR]
    for i, size in enumerate(sizes):
        pkt = i + 1
        check_packet(f"pkt {pkt}", recs, size, Scheme(first if pkt <= 1 else later), pkt)


async def main():
    binary = sys.argv[1] if len(sys.argv) > 1 else "./anytls-tiny"
    tmp = tempfile.mkdtemp()
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                    "-nodes", "-keyout", f"{tmp}/k.pem", "-out", f"{tmp}/c.pem", "-days", "1",
                    "-subj", "/CN=localhost"], check=True, capture_output=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(f"{tmp}/c.pem", f"{tmp}/k.pem")

    _, echo_port = await echo_server()
    _, dns_port = await dns_tcp_server()

    async def run_client(server, label, body):
        port = await server.start()
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        socks_port = s.getsockname()[1]
        s.close()
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.bind(("127.0.0.1", 0))
        udp_port = u.getsockname()[1]
        u.close()
        log = open(f"{tmp}/{label}.log", "w+")
        proc = subprocess.Popen([binary, "-s", "127.0.0.1", "-p", str(port), "-k", PASSWORD, "-h", "localhost",
                                 "-b", "127.0.0.1", "-l", str(socks_port), "-r", "0", "-u", str(udp_port),
                                 "-n", f"127.0.0.1:{dns_port}"], stdout=log, stderr=subprocess.STDOUT)
        try:
            await body(server, socks_port, udp_port)
        finally:
            proc.terminate()
            proc.wait()
            server.srv.close()
            log.seek(0)
            out = log.read()
        check("ERROR: AddressSanitizer" not in out and "runtime error" not in out, f"{label}: sanitizer report")
        return out

    # A: server uses the default scheme, so no update is sent
    print("A: default scheme")

    async def run_a(server, socks_port, udp_port):
        writes = [50, 50, 1200, 50, 50, 50, 50, 50, 100]
        await echo_flow(socks_port, echo_port, writes)
        sess = await server.wait_session(1)
        validate("session 1", sess, DEFAULT, DEFAULT, writes)
        # Normal traffic after the padded packets: bulk + concurrent streams
        await asyncio.gather(bulk_flow(socks_port, echo_port, 4 << 20),
                             *[echo_flow(socks_port, echo_port, [1000, 20000, 5]) for _ in range(3)])
        print("  bulk 4 MB + 3 concurrent streams echoed OK")
        # New session whose first stream is a DNS query
        sess.writer.close()
        await server.wait_session(2)
        loop = asyncio.get_running_loop()
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.setblocking(False)
        q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
        await loop.sock_sendto(u, q, ("127.0.0.1", udp_port))
        resp = await asyncio.wait_for(loop.sock_recv(u, 2048), 10)
        check(resp[:2] == q[:2] and resp[4:] == q[4:], "DNS reply mismatch")
        print("  DNS query as first stream of a session answered OK")
        # Bulk traffic while this session is still in its padded packets
        await asyncio.gather(bulk_flow(socks_port, echo_port, 2 << 20),
                             *[echo_flow(socks_port, echo_port, [30000, 7]) for _ in range(4)])
        print("  bulk 2 MB + 4 concurrent streams during padded packets echoed OK")

    out = await run_client(MockServer(ctx, DEFAULT), "a", run_a)
    check("Padding scheme updated" not in out, "A: client reported an update")

    # B: server pushes CUSTOM; later packets and the next session must use it
    print("B: server sends cmdUpdatePaddingScheme")

    async def run_b(server, socks_port, udp_port):
        w1 = [3000, 50, 1200, 50, 50, 50, 50]
        await echo_flow(socks_port, echo_port, w1)
        s1 = await server.wait_session(1)
        validate("session 1", s1, DEFAULT, CUSTOM, w1)
        server.bogus_update = True
        s1.writer.close()
        s2 = await server.wait_session(2)
        w2 = [50, 50, 50, 50, 50, 50, 50]
        await echo_flow(socks_port, echo_port, w2)
        validate("session 2", s2, CUSTOM, CUSTOM, w2)

    out = await run_client(MockServer(ctx, CUSTOM), "b", run_b)
    check(out.count("Padding scheme updated") == 1, "B: expected exactly one accepted update")
    check(md5hex(CUSTOM) in out, "B: update log lacks the new md5")

    print("FAILED" if failures else "ALL CHECKS PASSED")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
