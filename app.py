#!/usr/bin/env python3
import os, asyncio, ssl, socket, struct, hashlib, random, zlib

KEY1 = os.environ.get("CAT_KEY1","default_alpha_key_2024").encode()
KEY2 = os.environ.get("CAT_KEY2","default_omega_key_2024").encode()
if os.path.exists("phrases.txt"):
    lines=[l.strip() for l in open("phrases.txt") if l.strip() and not l.startswith("#")]
    if len(lines)>=2: KEY1,KEY2 = lines[0].encode(), lines[1].encode()

PORT = int(os.environ.get("PORT",10000))
MAX_MTU, MAX_PAYLOAD = 1497, 1350
MAGIC, VER = 0xCA, 0x01
F_DATA, F_CLOSE = 0x01, 0x02

class Lorenz:
    def __init__(self, key):
        h = hashlib.sha256(key).digest()
        self.x0 = (int.from_bytes(h[0:4],"big")%2000)/100.0+0.1
        self.y0 = (int.from_bytes(h[4:8],"big")%2000)/100.0+0.1
        self.z0 = (int.from_bytes(h[8:12],"big")%2000)/100.0+25.0
        self.s, self.r, self.b, self.dt = 10.0, 28.0, 8.0/3.0, 0.01
    def crypt(self, d):
        x,y,z,out = self.x0,self.y0,self.z0,bytearray()
        for _ in range(len(d)):
            x+=(self.s*(y-x)*self.dt); y+=(x*(self.r-z)-y)*self.dt; z+=(x*y-self.b*z)*self.dt
            out.append(int(abs(x)%256))
        return bytes(a^b for a,b in zip(d,bytes(out)))

class DualKey:
    def __init__(self,k1,k2):
        self.p, self.s = Lorenz(k1), Lorenz(k2)
        self.a = self.p
    def resync(self): self.a = self.s if self.a==self.p else self.p
    def crypt(self,d): return self.a.crypt(d)

def make_frame(data, cipher, pad_min=16):
    L = len(data)
    if L > MAX_PAYLOAD: raise ValueError("payload too big")
    max_pad = MAX_MTU - 2 - 5 - L - 4
    pad = max(0, random.randint(pad_min, max_pad) if max_pad>pad_min else max_pad)
    p = bytes(random.randint(0,255) for _ in range(pad))
    inner = struct.pack("!BBH", VER, 0, L) + data + p
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
        if len(inner) < 7: return None, 0
        if inner[0] != VER: return None, 0
        flags, L = struct.unpack("!BH", inner[1:4])
        if len(inner) < 5+L+4: return None, 0
        d = inner[4:4+L]
        cks = struct.unpack("!I", inner[-4:])[0]
        if cks != (zlib.crc32(inner[:-4]) & 0xFFFFFFFF): return None, 0
        return (flags, d), fl
    except: return None, 0

class FrameReader:
    def __init__(self, cipher): self.cipher, self.buf = cipher, b""
    async def read(self, reader):
        while True:
            r, c = parse_frame(self.buf, self.cipher)
            if r is not None:
                self.buf = self.buf[c:]
                return r
            chunk = await reader.read(4096)
            if not chunk: return None
            self.buf += chunk

async def handle_client(reader, writer, dk):
    cipher = dk.a
    fr = FrameReader(cipher)
    
    r = await fr.read(reader)
    if r is None: 
        writer.close(); await writer.wait_closed(); return
    flags, d = r
    try:
        connect_info = d.decode('utf-8', errors='replace')
        host, port_str = connect_info.rsplit(':', 1)
        port = int(port_str)
    except:
        writer.close(); await writer.wait_closed(); return

    print(f"[*] Connect -> {host}:{port}")
    try:
        target_reader, target_writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=10
        )
    except Exception as e:
        print(f"[!] Connect failed: {e}")
        writer.close(); await writer.wait_closed(); return

    print(f"[+] Connected to {host}:{port}")

    async def client_to_target():
        try:
            while True:
                r = await fr.read(reader)
                if r is None: break
                flags, d = r
                if flags & F_CLOSE: break
                target_writer.write(d)
                await target_writer.drain()
        except: pass
        finally:
            try: target_writer.close(); await target_writer.wait_closed()
            except: pass

    async def target_to_client():
        try:
            while True:
                d = await target_reader.read(MAX_PAYLOAD)
                if not d: break
                writer.write(make_frame(d, cipher))
                await writer.drain()
        except: pass
        finally:
            try: writer.write(make_frame(b"", cipher)); await writer.drain()
            except: pass
            try: writer.close(); await writer.wait_closed()
            except: pass

    await asyncio.gather(client_to_target(), target_to_client())
    print(f"[-] Disconnected from {host}:{port}")

async def main():
    server = await asyncio.start_server(
        lambda r,w: handle_client(r,w, DualKey(KEY1,KEY2)),
        "0.0.0.0", PORT
    )
    print(f"[*] CAT raw TCP on port {PORT}")
    async with server: await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
