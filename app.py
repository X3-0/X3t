#!/usr/bin/env python3
import os, asyncio, websockets, socket, struct, hashlib, random, zlib
from websockets.server import WebSocketServerProtocol

KEY1 = os.environ.get("CAT_KEY1","default_alpha_key_2024").encode()
KEY2 = os.environ.get("CAT_KEY2","default_omega_key_2024").encode()
if os.path.exists("phrases.txt"):
    lines=[l.strip() for l in open("phrases.txt") if l.strip() and not l.startswith("#")]
    if len(lines)>=2: KEY1,KEY2 = lines[0].encode(), lines[1].encode()

PORT = int(os.environ.get("PORT",10000))
WS_PATH = "/tunnel"
MAX_MTU, MAX_PAYLOAD = 1497, 1350
MAGIC, VER = 0xCA, 0x01
F_DATA, F_CLOSE, F_RESYNC, F_HB, F_ACK = 0x01, 0x02, 0x08, 0x10, 0x20

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
        self.p, self.s, self.a = Lorenz(k1), Lorenz(k2), None
        self.a = self.p
    def resync(self): self.a = self.s if self.a==self.p else self.p
    def crypt(self,d): return self.a.crypt(d)

def make_frame(sid, data, flags, cipher, pad_min=16):
    L = len(data)
    if L > MAX_PAYLOAD: raise ValueError("big")
    max_pad = MAX_MTU - 2 - 9 - L - 4
    pad = max(0, random.randint(pad_min, max_pad) if max_pad>pad_min else max_pad)
    p = bytes(random.randint(0,255) for _ in range(pad))
    if cipher: p = cipher.crypt(p)
    inner = struct.pack("!BIBH", VER, sid, flags, L) + data + p
    inner += struct.pack("!I", zlib.crc32(inner)&0xFFFFFFFF)
    if cipher: inner = cipher.crypt(inner)
    f = struct.pack("!HB", 3+len(inner), MAGIC) + inner
    if len(f)>MAX_MTU: raise ValueError("mtu")
    return f

def parse_frame(raw, cipher):
    try:
        if len(raw)<3: return None,0
        fl = struct.unpack("!H",raw[0:2])[0]
        if len(raw)<fl or raw[2]!=MAGIC: return None,0
        inner = raw[3:fl]
        if cipher: inner = cipher.crypt(inner)
        if len(inner)<8: return None,0
        if inner[0]!=VER: return None,0
        sid,flags,L = struct.unpack("!IBH",inner[1:8])
        if len(inner)<8+L+4: return None,0
        d = inner[8:8+L]
        cks = struct.unpack("!I",inner[-4:])[0]
        if cks != (zlib.crc32(inner[:-4])&0xFFFFFFFF): return None,0
        return (sid,flags,d), fl
    except: return None,0

class Mux:
    def __init__(self, c): self.c, self.st, self.n = c, {}, 1
    def open(self): self.n+=1; self.st[self.n]=bytearray(); return self.n
    def close(self, sid):
        try: del self.st[sid]
        except: pass
    def enc(self, sid, data, flags=F_DATA):
        if len(data)>MAX_PAYLOAD:
            r=b""; chunks=[data[i:i+MAX_PAYLOAD] for i in range(0,len(data),MAX_PAYLOAD)]
            for i,ch in enumerate(chunks):
                f = F_DATA if i<len(chunks)-1 else flags|F_DATA
                r+=make_frame(sid,ch,f,self.c)
            return r
        return make_frame(sid,data,flags,self.c)
    def dec(self, raw):
        res,off=[],0
        while off<len(raw):
            r,c = parse_frame(raw[off:],self.c)
            if r is None: break
            sid,flags,d = r
            if sid not in self.st and flags not in (F_RESYNC,F_HB,F_ACK): self.st[sid]=bytearray()
            if flags&F_DATA:
                try: self.st[sid].extend(d)
                except: pass
            if flags&F_CLOSE:
                try: res.append((sid,"close",bytes(self.st[sid]))); self.close(sid)
                except: res.append((sid,"close",b""))
            elif flags&F_RESYNC: res.append((sid,"resync",d))
            elif flags&F_HB: res.append((sid,"hb",d))
            elif flags&F_ACK: res.append((sid,"ack",d))
            else:
                try: res.append((sid,"data",bytes(self.st[sid]))); self.st[sid]=bytearray()
                except: res.append((sid,"data",b""))
            off+=c
        return res

class Server:
    def __init__(self):
        self.dk = DualKey(KEY1,KEY2)
        self.clients = {}
    async def handler(self, ws, path):
        if path != WS_PATH: await ws.close(); return
        cid = id(ws); mux = Mux(self.dk.a)
        self.clients[cid] = {"ws":ws, "mux":mux, "socks":{}}
        print(f"[+] Client {cid}")
        try:
            async for msg in ws:
                if isinstance(msg,str): continue
                try:
                    for sid,typ,d in mux.dec(msg):
                        if typ=="resync":
                            self.dk.resync(); mux.c=self.dk.a
                            for c in self.clients.values(): c["mux"].c=self.dk.a
                        elif typ=="hb": await ws.send(make_frame(0,b"PONG",F_ACK,self.dk.a))
                        elif typ=="ack": pass
                        elif typ in ("data","close"): await self.stream(cid,sid,typ,d,ws)
                except Exception as e:
                    print(f"[!] {cid} err: {e}")
                    if self.dk.a==self.dk.p: self.dk.resync(); mux.c=self.dk.a
        except: pass
        for s in self.clients.get(cid,{}).get("socks",{}).values():
            try: s.close()
            except: pass
        if cid in self.clients: del self.clients[cid]
        print(f"[-] Client {cid}")
    async def stream(self, cid, sid, typ, d, ws):
        c = self.clients.get(cid)
        if not c: return
        if sid not in c["socks"] and typ=="data":
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(10); s.connect(("1.1.1.1",80))
                c["socks"][sid]=s
                asyncio.create_task(self.tcp2ws(cid,sid,s,ws))
            except Exception as e:
                print(f"[!] Stream {sid} err: {e}")
                await ws.send(make_frame(sid,b"",F_CLOSE,self.dk.a)); return
        if sid in c["socks"]:
            try:
                if typ=="close": c["socks"][sid].close(); del c["socks"][sid]
                else: c["socks"][sid].sendall(d); c["mux"].st[sid]=bytearray()
            except: pass
    async def tcp2ws(self, cid, sid, sock, ws):
        c = self.clients.get(cid)
        if not c: return
        try:
            while True:
                d = sock.recv(MAX_PAYLOAD)
                if not d: break
                await ws.send(c["mux"].enc(sid,d,F_DATA))
        except: pass
        finally:
            try: await ws.send(c["mux"].enc(sid,b"",F_CLOSE))
            except: pass
            try: sock.close()
            except: pass
            if cid in self.clients and sid in self.clients[cid]["socks"]:
                del self.clients[cid]["socks"][sid]
    async def run(self):
        print(f"[*] Tunnel on port {PORT}")
        async with websockets.serve(self.handler, "0.0.0.0", PORT):
            await asyncio.Future()

if __name__=="__main__":
    print("CAT Server starting...")
    asyncio.run(Server().run())
