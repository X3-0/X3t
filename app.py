#!/usr/bin/env python3
# CAT Server — ChaCha20-Poly1305 AEAD variant (per-frame random nonce)
# Requires: pip install cryptography websockets
import asyncio, os, websockets, struct, hashlib, random, socket, ipaddress, sys
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# === Config ===
PORT = int(os.environ.get("PORT", "10000"))
MAX_MTU = int(os.environ.get("MAX_MTU", 1497))
MAX_PAYLOAD = int(os.environ.get("MAX_PAYLOAD", 1350))
MAGIC, VER = 0xCA, 0x01
F_DATA, F_CLOSE, F_RESYNC = 0x01, 0x02, 0x08

# Keys: prefer phrases.txt if present, else env vars.
def load_keys():
    k1 = os.environ.get("CAT_KEY1")
    k2 = os.environ.get("CAT_KEY2")
    if os.path.exists("phrases.txt"):
        lines = [l.strip() for l in open("phrases.txt") if l.strip() and not l.startswith("#")]
        if len(lines) >= 2:
            return lines[0].encode(), lines[1].encode()
    if not k1 or not k2:
        print("[!] WARNING: CAT_KEY1/CAT_KEY2 not set — using default weak keys. Set secrets via env or phrases.txt for production.", file=sys.stderr)
    return ((k1 or "default_alpha_key_2024").encode(), (k2 or "default_omega_key_2024").encode())

KEY1, KEY2 = load_keys()
# AEAD symmetric key derived as SHA256(KEY1 || KEY2)
AEAD_KEY = hashlib.sha256(KEY1 + KEY2).digest()  # 32 bytes

# Outbound rules / auth
AUTH_TOKEN = os.environ.get("AUTH_TOKEN")  # if not set, allows connections but warns
ALLOW_PRIVATE_OUTBOUND = os.environ.get("ALLOW_PRIVATE_OUTBOUND", "false").lower() in ("1","true","yes")

# === AEAD wrapper (per-connection instance, stateless aside from key) ===
class AEADCipher:
    def __init__(self, key: bytes):
        self.key = key
        self.aead = ChaCha20Poly1305(key)
    def encrypt_frame(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(12)  # per-frame random nonce; must be included with ciphertext
        ct = self.aead.encrypt(nonce, plaintext, None)
        return nonce + ct
    def decrypt_frame(self, blob: bytes) -> bytes:
        if len(blob) < 12 + 16:
            # nonce(12) + tag(16) minimal
            raise ValueError("ciphertext too short")
        nonce = blob[:12]; ct = blob[12:]
        return self.aead.decrypt(nonce, ct, None)

# === Frame protocol (inner encrypted with AEAD; no CRC) ===
def make_frame(sid: int, data: bytes, flags: int, cipher: AEADCipher, pad_min=8) -> bytes:
    L = len(data)
    if L > MAX_PAYLOAD:
        raise ValueError("payload too big")
    max_pad = MAX_MTU - 2 - 9 - L - 4  # keep some variable pad to vary fingerprint; 4 bytes reserved historically but now just a pad heuristic
    if max_pad < 0:
        max_pad = 0
    pad = max(0, random.randint(pad_min, max_pad) if max_pad > pad_min else max_pad)
    p = bytes(random.randint(0,255) for _ in range(pad))
    inner_plain = struct.pack("!BIBH", VER, sid, flags, L) + data + p
    # AEAD encrypt inner
    inner_enc = cipher.encrypt_frame(inner_plain) if cipher else inner_plain
    fl = 3 + len(inner_enc)  # total length field as before
    f = struct.pack("!HB", fl, MAGIC) + inner_enc
    if len(f) > MAX_MTU:
        raise ValueError("mtu exceeded")
    return f

def parse_frame(raw: bytes, cipher: AEADCipher):
    try:
        if len(raw) < 3: return None, 0
        fl = struct.unpack("!H", raw[0:2])[0]
        if fl < 3 or len(raw) < fl or raw[2] != MAGIC: return None, 0
        inner_enc = raw[3:fl]
        inner = cipher.decrypt_frame(inner_enc) if cipher else inner_enc
        if len(inner) < 8: return None, 0
        if inner[0] != VER: return None, 0
        sid, flags, L = struct.unpack("!IBH", inner[1:8])
        if len(inner) < 8 + L: return None, 0
        d = inner[8:8+L]
        return (sid, flags, d), fl
    except Exception:
        return None, 0

# === Mux (with earlier payload-fix on fragment finalization) ===
class Mux:
    def __init__(self, cipher: AEADCipher):
        self.c = cipher
        self.st = {}
        self.n = 1
    def open(self):
        self.n += 1
        self.st[self.n] = bytearray()
        return self.n
    def close(self, sid):
        self.st.pop(sid, None)
    def enc(self, sid, data, flags=F_DATA):
        if len(data) > MAX_PAYLOAD:
            r = b""
            chunks = [data[i:i+MAX_PAYLOAD] for i in range(0, len(data), MAX_PAYLOAD)]
            for i, ch in enumerate(chunks):
                f = (flags if i == len(chunks) - 1 else F_DATA)
                r += make_frame(sid, ch, f, self.c)
            return r
        return make_frame(sid, data, flags, self.c)
    def dec(self, raw: bytes):
        res, off = [], 0
        while off < len(raw):
            r, c = parse_frame(raw[off:], self.c)
            if r is None: break
            sid, flags, d = r
            if sid not in self.st and flags not in (F_RESYNC,):
                self.st[sid] = bytearray()
            # Always append any payload bytes (if present)
            if d:
                try: self.st[sid].extend(d)
                except KeyError: pass
            if flags & F_CLOSE:
                buf = bytes(self.st.pop(sid, bytearray()))
                res.append((sid, "close", buf))
            elif flags & F_RESYNC:
                res.append((sid, "resync", d))
            else:
                buf = bytes(self.st.pop(sid, bytearray()))
                res.append((sid, "data", buf))
            off += c
        return res

# === Helpers for host parsing / safety ===
def parse_hostport(s: str) -> Tuple[str,int]:
    s = s.strip()
    if s.startswith("["):
        if "]" not in s:
            raise ValueError("invalid IPv6 address format")
        host = s[1:s.index("]")]
        rest = s[s.index("]")+1:]
        if not rest.startswith(":"):
            raise ValueError("missing port")
        port = int(rest[1:])
        return host, port
    if ":" not in s:
        raise ValueError("missing port")
    host, port_str = s.rsplit(":", 1)
    return host, int(port_str)

async def resolve_and_check(host: str) -> list:
    infos = await asyncio.get_running_loop().getaddrinfo(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    addrs = []
    for fam, _, _, _, sockaddr in infos:
        addr = sockaddr[0]
        addrs.append(addr)
        ip = ipaddress.ip_address(addr)
        if not ALLOW_PRIVATE_OUTBOUND and (ip.is_private or ip.is_loopback or ip.is_link_local):
            raise ValueError(f"refusing to connect to non-public address {addr}")
    return list(dict.fromkeys(addrs))

# === Server ===
class Server:
    def __init__(self):
        self.clients = {}
        self.lock = asyncio.Lock()

    async def handler(self, websocket):
        cid = id(websocket)
        headers = getattr(websocket, "request_headers", {})
        token = headers.get("X-Auth-Token") or headers.get("Authorization")
        if AUTH_TOKEN:
            if token is None:
                await websocket.close(code=4001, reason="missing auth token")
                print(f"[!] {cid} rejected: no token")
                return
            if token.startswith("Bearer "):
                token = token.split(" ",1)[1]
            if token != AUTH_TOKEN:
                await websocket.close(code=4003, reason="invalid token")
                print(f"[!] {cid} rejected: invalid token")
                return
        else:
            print("[!] AUTH_TOKEN not set — allowing unauthenticated connections (not recommended)", file=sys.stderr)

        # per-client AEAD instance (stateless except key)
        client_cipher = AEADCipher(AEAD_KEY)
        mux = Mux(client_cipher)
        self.clients[cid] = {"ws": websocket, "mux": mux, "socks": {}, "cipher": client_cipher}
        print(f"[+] Client {cid}")
        try:
            async for msg in websocket:
                if isinstance(msg, str):
                    continue
                try:
                    for sid, typ, d in mux.dec(msg):
                        if typ == "resync":
                            # nothing to resync for stateless AEAD with random nonce; keep behavior for compatibility
                            # but flip some ephemeral state if you want — here we just log
                            print(f"[*] Client {cid} requested resync (no-op for AEAD)")
                        elif typ in ("data", "close"):
                            await self.stream(cid, sid, typ, d, websocket)
                except Exception as e:
                    print(f"[!] {cid} decode err: {e}")
        except websockets.exceptions.ConnectionClosed:
            pass
        except Exception as e:
            print(f"[!] {cid} ws err: {e}")
        finally:
            c = self.clients.pop(cid, None)
            if c:
                for s in list(c.get("socks", {})).values():
                    try: s.close()
                    except: pass
            print(f"[-] Client {cid}")

    async def stream(self, cid, sid, typ, d, ws):
        c = self.clients.get(cid)
        if not c: return
        if sid not in c["socks"] and typ == "data":
            try:
                connect_info = d.decode("utf-8", errors="replace")
                host, port = parse_hostport(connect_info)
                await resolve_and_check(host)
                print(f"[*] Stream {sid} -> {host}:{port}")
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(10)
                await asyncio.to_thread(s.connect, (host, port))
                c["socks"][sid] = s
                print(f"[+] Stream {sid} connected")
                asyncio.create_task(self.tcp2ws(cid, sid, s, ws))
            except Exception as e:
                print(f"[!] Stream {sid} err: {e}")
                try:
                    await ws.send(make_frame(sid, b"", F_CLOSE, c["cipher"]))
                except: pass
                return
        elif sid in c["socks"]:
            try:
                if typ == "close":
                    try: c["socks"][sid].close()
                    except: pass
                    del c["socks"][sid]
                else:
                    await asyncio.to_thread(c["socks"][sid].sendall, d)
            except Exception as e:
                print(f"[!] Stream {sid} send err: {e}")
                c["socks"].pop(sid, None)

    async def tcp2ws(self, cid, sid, sock, ws):
        c = self.clients.get(cid)
        if not c: return
        try:
            while True:
                d = await asyncio.to_thread(sock.recv, MAX_PAYLOAD)
                if not d: break
                try:
                    await ws.send(c["mux"].enc(sid, d, F_DATA))
                except Exception as e:
                    print(f"[!] tcp2ws send failed {sid}: {e}")
                    break
        except Exception as e:
            print(f"[!] tcp2ws {sid}: {e}")
        finally:
            try:
                await ws.send(c["mux"].enc(sid, b"", F_CLOSE))
            except: pass
            try: sock.close()
            except: pass
            if cid in self.clients and sid in self.clients[cid]["socks"]:
                del self.clients[cid]["socks"][sid]
            print(f"[-] Stream {sid}")

    async def run(self):
        print(f"[*] Tunnel WS on port {PORT}")
        async with websockets.serve(self.handler, "0.0.0.0", PORT, ping_interval=20, ping_timeout=10, compression=None):
            await asyncio.Future()

if __name__ == "__main__":
    print("CAT Server starting...")
    asyncio.run(Server().run()) 
