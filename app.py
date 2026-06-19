#!/usr/bin/env python3
"""
X3Tunnel Server for Render
"""
import os, asyncio, websockets, struct, hashlib, random, zlib

# === Keys (exactly as before) ===
KEY1 = os.environ.get("CAT_KEY1", "default_alpha_key_2024").encode()
KEY2 = os.environ.get("CAT_KEY2", "default_omega_key_2024").encode()

if os.path.exists("phrases.txt"):
    with open("phrases.txt") as f:
        lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    if len(lines) >= 2:
        KEY1, KEY2 = lines[0].encode(), lines[1].encode()

PORT = int(os.environ.get("PORT", 10000))
WS_PATH = "/tunnel"

# === Protocol constants ===
MAX_MTU = 1497
MAX_PAYLOAD = 1350
MAGIC = 0xCA
VER = 0x01
F_DATA = 0x01
F_CLOSE = 0x02
F_RESYNC = 0x08
F_HB = 0x10
F_ACK = 0x20
F_FRAG = 0x04


# === Lorenz (exactly as before) ===
class Lorenz:
    def __init__(self, key):
        h = hashlib.sha256(key).digest()
        self.x = (int.from_bytes(h[0:4], "big") % 2000) / 100.0 + 0.1
        self.y = (int.from_bytes(h[4:8], "big") % 2000) / 100.0 + 0.1
        self.z = (int.from_bytes(h[8:12], "big") % 2000) / 100.0 + 25.0
        self.s, self.r, self.b, self.dt = 10.0, 28.0, 8.0 / 3.0, 0.01

    def crypt(self, d):
        x, y, z = self.x, self.y, self.z
        out = bytearray()
        for _ in range(len(d)):
            x += self.s * (y - x) * self.dt
            y += (x * (self.r - z) - y) * self.dt
            z += (x * y - self.b * z) * self.dt
            out.append(int(abs(x) % 256))
        self.x, self.y, self.z = x, y, z
        return bytes(a ^ b for a, b in zip(d, bytes(out)))


class DualKey:
    def __init__(self, k1, k2):
        self.p = Lorenz(k1)
        self.s = Lorenz(k2)
        self.a = self.p

    def resync(self):
        self.a = self.s if self.a == self.p else self.p

    def crypt(self, d):
        return self.a.crypt(d)


# === Frame codec (exactly as before) ===
def make_frame(sid, data, flags, cipher, pad_min=16):
    L = len(data)
    if L > MAX_PAYLOAD:
        raise ValueError("payload too big")
    max_pad = MAX_MTU - 3 - 8 - L - 4
    pad = max(0, random.randint(pad_min, max_pad) if max_pad > pad_min else max_pad)
    p = bytes(random.randint(0, 255) for _ in range(pad))
    inner = struct.pack("!BIBH", VER, sid, flags, L) + data + p
    inner += struct.pack("!I", zlib.crc32(inner) & 0xFFFFFFFF)
    if cipher:
        inner = cipher.crypt(inner)
    f = struct.pack("!HB", 3 + len(inner), MAGIC) + inner
    if len(f) > MAX_MTU:
        raise ValueError("exceeds MTU")
    return f


def parse_frame(raw, cipher):
    try:
        if len(raw) < 3:
            return None, 0
        fl = struct.unpack("!H", raw[0:2])[0]
        if len(raw) < fl or raw[2] != MAGIC:
            return None, 0
        inner = raw[3:fl]
        if cipher:
            inner = cipher.crypt(inner)
        if len(inner) < 8:
            return None, 0
        if inner[0] != VER:
            return None, 0
        sid, flags, L = struct.unpack("!IBH", inner[1:8])
        if len(inner) < 8 + L + 4:
            return None, 0
        d = inner[8 : 8 + L]
        cks = struct.unpack("!I", inner[-4:])[0]
        if cks != (zlib.crc32(inner[:-4]) & 0xFFFFFFFF):
            return None, 0
        return (sid, flags, d), fl
    except Exception:
        return None, 0


class Mux:
    def __init__(self, cipher):
        self.c = cipher
        self.st = {}

    def close(self, sid):
        self.st.pop(sid, None)

    def enc(self, sid, data, flags=F_DATA):
        if len(data) > MAX_PAYLOAD:
            r = b""
            chunks = [data[i:i+MAX_PAYLOAD] for i in range(0, len(data), MAX_PAYLOAD)]
            for i, ch in enumerate(chunks):
                if i < len(chunks) - 1:
                    f = F_DATA | F_FRAG
                else:
                    f = flags | F_DATA
                r += make_frame(sid, ch, f, self.c)
            return r
        return make_frame(sid, data, flags | F_DATA, self.c)

    def dec(self, raw):
        res, off = [], 0
        while off < len(raw):
            r, c = parse_frame(raw[off:], self.c)
            if r is None:
                break
            sid, flags, d = r
            if sid not in self.st and flags not in (F_RESYNC, F_HB, F_ACK):
                self.st[sid] = bytearray()

            if flags & F_DATA:
                try:
                    self.st[sid].extend(d)
                except KeyError:
                    pass

            if flags & F_CLOSE:
                try:
                    res.append((sid, "close", bytes(self.st[sid])))
                except KeyError:
                    res.append((sid, "close", b""))
                self.close(sid)
            elif flags & F_RESYNC:
                res.append((sid, "resync", d))
            elif flags & F_HB:
                res.append((sid, "hb", d))
            elif flags & F_ACK:
                res.append((sid, "ack", d))
            elif flags & F_DATA and not (flags & F_FRAG):
                try:
                    res.append((sid, "data", bytes(self.st[sid])))
                    self.st[sid] = bytearray()
                except KeyError:
                    res.append((sid, "data", b""))
            off += c
        return res


# === Health check for Render (websockets 14+) ===
async def process_request(connection, request):
    if request.path == "/":
        return connection.respond(200, "CAT OK")
    return None


class Server:
    def __init__(self):
        self.dk = DualKey(KEY1, KEY2)
        self.clients = {}

    async def handler(self, ws):
        p = getattr(ws, "path", None)
        if p != WS_PATH:
            await ws.close()
            return

        cid = id(ws)
        mux = Mux(self.dk.a)
        self.clients[cid] = {"ws": ws, "mux": mux, "socks": {}, "tasks": {}}
        print(f"[+] Client {cid} connected")

        # heartbeat every 30s
        hb_task = asyncio.create_task(self._heartbeat(cid))

        try:
            async for msg in ws:
                if isinstance(msg, str):
                    continue
                try:
                    for sid, typ, d in mux.dec(msg):
                        if typ == "resync":
                            self.dk.resync()
                            mux.c = self.dk.a
                            for cl in self.clients.values():
                                cl["mux"].c = self.dk.a
                        elif typ == "hb":
                            await ws.send(make_frame(0, b"PONG", F_ACK, self.dk.a))
                        elif typ == "ack":
                            pass
                        elif typ in ("data", "close"):
                            await self._stream(cid, sid, typ, d, ws)
                except Exception as e:
                    print(f"[!] {cid} decode error: {e}")
        except websockets.exceptions.ConnectionClosed:
            pass
        except Exception as e:
            print(f"[!] {cid} handler error: {e}")
        finally:
            hb_task.cancel()
            try:
                await hb_task
            except asyncio.CancelledError:
                pass

            client = self.clients.pop(cid, None)
            if client:
                for sid, task in list(client.get("tasks", {}).items()):
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
                for sid, (reader, writer) in list(client.get("socks", {}).items()):
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass
            print(f"[-] Client {cid} disconnected")

    async def _heartbeat(self, cid):
        while True:
            await asyncio.sleep(30)
            client = self.clients.get(cid)
            if not client:
                return
            try:
                await client["ws"].send(make_frame(0, b"PING", F_HB, self.dk.a))
            except Exception:
                return

    async def _stream(self, cid, sid, typ, d, ws):
        c = self.clients.get(cid)
        if not c:
            return

        # First packet for new stream = "host:port"
        if sid not in c["socks"] and typ == "data":
            try:
                dest = d.decode("utf-8", errors="ignore").strip()
                if ":" not in dest:
                    raise ValueError("invalid dest")
                host, port_str = dest.rsplit(":", 1)
                port = int(port_str)

                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=10
                )
                c["socks"][sid] = (reader, writer)
                task = asyncio.create_task(self._tcp2ws(cid, sid, reader, writer, ws))
                c["tasks"][sid] = task
                print(f"[+] Stream {sid} -> {host}:{port}")
            except Exception as e:
                print(f"[!] Stream {sid} connect error: {e}")
                try:
                    await ws.send(make_frame(sid, b"", F_CLOSE, self.dk.a))
                except Exception:
                    pass
                return

        if sid not in c["socks"]:
            return

        try:
            if typ == "close":
                reader, writer = c["socks"][sid]
                if d:
                    writer.write(d)
                    await writer.drain()
                writer.close()
                await writer.wait_closed()
                del c["socks"][sid]
                if sid in c.get("tasks", {}):
                    c["tasks"][sid].cancel()
                    try:
                        await c["tasks"][sid]
                    except asyncio.CancelledError:
                        pass
                    del c["tasks"][sid]
                print(f"[-] Stream {sid} closed")
            else:
                _, writer = c["socks"][sid]
                writer.write(d)
                await writer.drain()
        except Exception as e:
            print(f"[!] Stream {sid} io error: {e}")
            if sid in c["socks"]:
                try:
                    _, writer = c["socks"][sid]
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
                del c["socks"][sid]
            if sid in c.get("tasks", {}):
                c["tasks"][sid].cancel()
                del c["tasks"][sid]

    async def _tcp2ws(self, cid, sid, reader, writer, ws):
        c = self.clients.get(cid)
        if not c:
            return
        try:
            while True:
                d = await reader.read(MAX_PAYLOAD)
                if not d:
                    break
                await ws.send(c["mux"].enc(sid, d, F_DATA))
        except asyncio.CancelledError:
            return
        except Exception as e:
            print(f"[!] tcp2ws {sid} error: {e}")
        finally:
            try:
                await ws.send(c["mux"].enc(sid, b"", F_CLOSE))
            except Exception:
                pass
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            if cid in self.clients:
                self.clients[cid]["socks"].pop(sid, None)
                self.clients[cid]["tasks"].pop(sid, None)

    async def run(self):
        print(f"[*] Server on port {PORT} | path {WS_PATH}")
        async with websockets.serve(
            self.handler, "0.0.0.0", PORT, process_request=process_request
        ):
            await asyncio.Future()


if __name__ == "__main__":
    print("CAT Server starting...")
    asyncio.run(Server().run())
