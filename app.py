#!/usr/bin/env python3
import os, asyncio, websockets, socket, struct, hashlib, random, zlib

KEY1 = os.environ.get("CAT_KEY1","default_alpha_key_2024").encode()
KEY2 = os.environ.get("CAT_KEY2","default_omega_key_2024").encode()
if os.path.exists("phrases.txt"):
    lines=[l.strip() for l in open("phrases.txt") if l.strip() and not l.startswith("#")]
    if len(lines)>=2: KEY1,KEY2 = lines[0].encode(), lines[1].encode()

PORT = int(os.environ.get("PORT",10000))
MAX_MTU, MAX_PAYLOAD = 1497, 1350
MAGIC, VER = 0xCA, 0x01
F_DATA, F_CLOSE, F_RESYNC, F_HB, F_ACK = 0x01, 0x02, 0x08, 0x10, 0x20

class Lorenz:
    def __init__(self, key):
        h = hashlib.sha256(key).digest()
        self.x = (int.from_bytes(h[0:4],"big")%2000)/100.0+0.1
        self.y = (int.from_bytes(h[4:8],"big")%2000)/100.0+0.1
        self.z = (int.from_bytes(h[8:12],"big")%2000)/100.0+25.0
        self.s, self.r, self.b, self.dt = 10.0, 28.0, 8.0/3.0, 0.01
    def crypt(self, d):
        x,y,z,out = self.x,self.y,self.z,bytearray()
        for _ in range(len(d)):
            x += (self.s*(y-x)*self.dt)
            y += (x*(self.r-z)-y)*self.dt
            z += (x*y-self.b*z)*self.dt
            out.append(int(abs(x)%256))
        self.x, self.y, self.z = x, y, z
        return bytes(a^b for a,b in zip(d,bytes(out)))

class DualKey:
    def __init__(self,k1,k2):
        self.p, self.s = Lorenz(k1), Lorenz(k2)
        self.a = self.p
    def resync(self): self.a = self.s if self.a==self.p else self.p
    def crypt(self,d): return self.a.crypt(d)

def make_frame(sid, data, flags, cipher, pad_min=16):
    L = len(data)
    if L > MAX_PAYLOAD: raise ValueError("payload too big")
    max_pad = MAX_MTU - 2 - 9 - L - 4
    pad = max(0, random.randint(pad_min, max_pad) if max_pad>pad_min else max_pad)
    p = bytes(random.randint(0,255) for _ in range(pad))
    inner = struct.pack("!BIBH", VER, sid, flags, L) + data + p
    inner += struct.pack("!I", zlib.crc32(inner)&0xFFFFFFFF)
    if cipher: inner = cipher.crypt(inner)
    return struct.pack("!HB", 3+len(inner), MAGIC) + inner

def parse_frame(raw, cipher):
    try:
        if len(raw) < 3: return None, 0
        fl = struct.unpack("!H", raw[0:2])[0]
        if len(raw) < fl or raw[2] != MAGIC: return None, 0
        inner = raw[3:fl]
        if cipher: inner = cipher.crypt(inner)
        if len(inner) < 8: return None, 0
        if inner[0] != VER: return None, 0
        sid, flags, L = struct.unpack("!IBH", inner[1:8])
        if len(inner) < 8+L+4: return None, 0
        d = inner[8:8+L]
        cks = struct.unpack("!I", inner[-4:])[0]
        if cks != (zlib.crc32(inner[:-4]) & 0xFFFFFFFF): return None, 0
        return (sid, flags, d), fl
    except: return None, 0

class Mux:
    def __init__(self, cipher): self.cipher, self.st, self.n = cipher, {}, 1
    def open(self): self.n += 1; self.st[self.n] = bytearray(); return self.n
    def close(self, sid):
        try: del self.st[sid]
        except: pass

    def enc(self, sid, data, flags=F_DATA):
        base = flags & ~F_DATA
        if len(data) > MAX_PAYLOAD:
            chunks = [data[i:i+MAX_PAYLOAD] for i in range(0, len(data), MAX_PAYLOAD)]
            r = b""
            for i, ch in enumerate(chunks):
                f = F_DATA if i < len(chunks)-1 else base
                r += make_frame(sid, ch, f, self.cipher)
            return r
        return make_frame(sid, data, base, self.cipher)

    def dec(self, raw):
        res, off = [], 0
        while off < len(raw):
            r, c = parse_frame(raw[off:], self.cipher)
            if r is None: break
            sid, flags, d = r
            if sid not in self.st and flags not in (F_RESYNC, F_HB, F_ACK):
                self.st[sid] = bytearray()
            if flags & F_DATA:
                try: self.st[sid].extend(d)
                except: pass
            if flags & F_CLOSE:
                try: res.append((sid, "close", bytes(self.st[sid]))); self.close(sid)
                except: res.append((sid, "close", b""))
            elif flags & F_RESYNC: res.append((sid, "resync", d))
            elif flags & F_HB: res.append((sid, "hb", d))
            elif flags & F_ACK: res.append((sid, "ack", d))
            else:
                try:
                    buf = bytes(self.st[sid]) + d
                    res.append((sid, "data", buf))
                    self.st[sid] = bytearray()
                except: res.append((sid, "data", d))
            off += c
        return res

class Server:
    def __init__(self):
        self.dk = DualKey(KEY1, KEY2)
        self.clients = {}

    async def handler(self, websocket):
        cid = id(websocket)
        mux = Mux(self.dk.a)
        self.clients[cid] = {"ws": websocket, "mux": mux, "socks": {}}
        print(f"[+] Client {cid}")
        try:
            async for msg in websocket:
                if isinstance(msg, str): continue
                try:
                    for sid, typ, d in mux.dec(msg):
                        if typ == "resync":
                            self.dk.resync()
                            mux.cipher = self.dk.a
                            for c in self.clients.values(): c["mux"].cipher = self.dk.a
                        elif typ == "hb":
                            await websocket.send(make_frame(0, b"PONG", F_ACK, self.dk.a))
                        elif typ == "ack": pass
                        elif typ in ("data", "close"):
                            await self.stream(cid, sid, typ, d, websocket)
                except Exception as e:
                    print(f"[!] {cid} err: {e}")
                    if self.dk.a == self.dk.p:
                        self.dk.resync()
                        mux.cipher = self.dk.a
        except: pass
        for info in list(self.clients.get(cid, {}).get("socks", {}).values()):
            try:
                info['writer'].close()
                await info['writer'].wait_closed()
            except: pass
        if cid in self.clients: del self.clients[cid]
        print(f"[-] Client {cid}")

    async def stream(self, cid, sid, typ, d, ws):
        c = self.clients.get(cid)
        if not c: return

        if sid not in c["socks"] and typ == "data":
            try:
                connect_info = d.decode('utf-8', errors='replace')
                host, port_str = connect_info.rsplit(':', 1)
                port = int(port_str)
                print(f"[*] [{cid}] Stream {sid} -> {host}:{port}")

                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=10
                )
                c["socks"][sid] = {"reader": reader, "writer": writer}
                print(f"[+] [{cid}] Stream {sid} connected")

                asyncio.create_task(self.tcp2ws(cid, sid, reader, writer, ws))
            except Exception as e:
                print(f"[!] [{cid}] Stream {sid} connect failed: {e}")
                try: await ws.send(make_frame(sid, b"", F_CLOSE, self.dk.a))
                except: pass
                return

        if sid in c["socks"]:
            try:
                if typ == "close":
                    info = c["socks"][sid]
                    info['writer'].close()
                    await info['writer'].wait_closed()
                    del c["socks"][sid]
                    print(f"[-] [{cid}] Stream {sid} closed by client")
                else:
                    c["socks"][sid]['writer'].write(d)
                    await c["socks"][sid]['writer'].drain()
            except Exception as e:
                print(f"[!] [{cid}] Stream {sid} write error: {e}")
                try: await ws.send(make_frame(sid, b"", F_CLOSE, self.dk.a))
                except: pass
                if sid in c["socks"]:
                    try:
                        c["socks"][sid]['writer'].close()
                        await c["socks"][sid]['writer'].wait_closed()
                    except: pass
                    del c["socks"][sid]

    async def tcp2ws(self, cid, sid, reader, writer, ws):
        c = self.clients.get(cid)
        if not c: return
        try:
            while True:
                d = await reader.read(MAX_PAYLOAD)
                if not d: break
                await ws.send(c["mux"].enc(sid, d, F_DATA))
        except asyncio.CancelledError: raise
        except Exception as e:
            print(f"[!] [{cid}] Stream {sid} read error: {e}")
        finally:
            try: await ws.send(c["mux"].enc(sid, b"", F_CLOSE))
            except: pass
            try:
                writer.close()
                await writer.wait_closed()
            except: pass
            if cid in self.clients and sid in self.clients[cid]["socks"]:
                del self.clients[cid]["socks"][sid]
                print(f"[-] [{cid}] Stream {sid} closed by remote")

    async def run(self):
        print(f"[*] Tunnel on port {PORT}")
        async with websockets.serve(self.handler, "0.0.0.0", PORT):
            await asyncio.Future()

if __name__ == "__main__":
    print("CAT Server starting...")
    asyncio.run(Server().run())
 
