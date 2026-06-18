#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CAT Server - Chaotic Anonymous Tunnel
Render.com deployment. WebSocket over HTTPS (443).
Lorenz cipher + multiplexer + dual-key resync.
"""

import os, sys, asyncio, websockets, socket, struct, hashlib, random, zlib, time, threading, json
from http.server import BaseHTTPRequestHandler, HTTPServer

# ==================== CONFIG ====================
KEY1 = os.environ.get("CAT_KEY1", "default_alpha_key_2024").encode()
KEY2 = os.environ.get("CAT_KEY2", "default_omega_key_2024").encode()

if os.path.exists("phrases.txt"):
    with open("phrases.txt", "r", encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        if len(lines) >= 2:
            KEY1 = lines[0].encode()
            KEY2 = lines[1].encode()

WS_PATH = "/tunnel"
PORT = int(os.environ.get("PORT", 10000))
MAX_MTU = 1497
MAX_PAYLOAD = 1350
MAGIC = 0xCA
VERSION = 0x01
FLAG_DATA = 0x01
FLAG_CLOSE = 0x02
FLAG_RESYNC = 0x08
FLAG_HEARTBEAT = 0x10
FLAG_ACK = 0x20

# ==================== LORENZ CIPHER ====================
class LorenzCipher:
    def __init__(self, key: bytes, sigma=10.0, rho=28.0, beta=8.0/3.0):
        h = hashlib.sha256(key).digest()
        self.sigma = sigma
        self.rho = rho
        self.beta = beta
        self.x0 = (int.from_bytes(h[0:4], "big") % 2000) / 100.0 + 0.1
        self.y0 = (int.from_bytes(h[4:8], "big") % 2000) / 100.0 + 0.1
        self.z0 = (int.from_bytes(h[8:12], "big") % 2000) / 100.0 + 25.0
        self.dt = 0.01

    def _keystream_at(self, start_x, start_y, start_z, n: int):
        x, y, z = start_x, start_y, start_z
        out = bytearray()
        for _ in range(n):
            dx = self.sigma * (y - x) * self.dt
            dy = (x * (self.rho - z) - y) * self.dt
            dz = (x * y - self.beta * z) * self.dt
            x += dx; y += dy; z += dz
            out.append(int(abs(x) % 256))
        return bytes(out), x, y, z

    def encrypt(self, data: bytes) -> bytes:
        ks, _, _, _ = self._keystream_at(self.x0, self.y0, self.z0, len(data))
        return bytes(a ^ b for a, b in zip(data, ks))

    def decrypt(self, data: bytes) -> bytes:
        return self.encrypt(data)

# ==================== DUAL KEY MANAGER ====================
class DualKeyManager:
    def __init__(self, key1: bytes, key2: bytes):
        self.primary = LorenzCipher(key1)
        self.secondary = LorenzCipher(key2)
        self.active = self.primary
        self.resync_count = 0
        self.lock = threading.Lock()

    def get_cipher(self):
        with self.lock:
            return self.active

    def resync(self):
        with self.lock:
            self.resync_count += 1
            self.active = self.secondary if self.active == self.primary else self.primary
            return self.active

    def encrypt(self, data: bytes) -> bytes:
        with self.lock:
            return self.active.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        with self.lock:
            return self.active.decrypt(data)

# ==================== FRAME PROTOCOL ====================
def make_frame(stream_id: int, data: bytes, flags: int = FLAG_DATA, cipher=None, pad_min: int = 16) -> bytes:
    try:
        length = len(data)
        if length > MAX_PAYLOAD:
            raise ValueError(f"Payload {length} > MAX_PAYLOAD {MAX_PAYLOAD}")
        header_size = 1 + 1 + 4 + 1 + 2
        max_pad = MAX_MTU - 2 - header_size - length - 4
        if max_pad < pad_min:
            pad_min = max_pad if max_pad > 0 else 0
        pad_size = random.randint(pad_min, max_pad) if max_pad > pad_min else max(0, pad_min)
        padding = bytes(random.randint(0, 255) for _ in range(pad_size))
        if cipher:
            padding = cipher.encrypt(padding)
        inner = struct.pack("!BIBH", VERSION, stream_id, flags, length) + data + padding
        cksum = zlib.crc32(inner) & 0xFFFFFFFF
        inner += struct.pack("!I", cksum)
        if cipher:
            inner = cipher.encrypt(inner)
        frame = struct.pack("!HB", 3 + len(inner), MAGIC) + inner
        if len(frame) > MAX_MTU:
            raise ValueError(f"Frame {len(frame)} > MTU {MAX_MTU}")
        return frame
    except (struct.error, ValueError) as e:
        raise ValueError(f"Frame creation error: {e}")

def parse_frame(raw: bytes, cipher=None) -> tuple:
    try:
        if len(raw) < 3:
            return None, 0
        frame_len = struct.unpack("!H", raw[0:2])[0]
        if len(raw) < frame_len:
            return None, 0
        if raw[2] != MAGIC:
            return None, 0
        inner = raw[3:frame_len]
        if cipher:
            inner = cipher.decrypt(inner)
        if len(inner) < 8:
            return None, 0
        ver = inner[0]
        if ver != VERSION:
            return None, 0
        stream_id, flags, length = struct.unpack("!IBH", inner[1:8])
        if len(inner) < 8 + length + 4:
            return None, 0
        data = inner[8:8+length]
        checksum_offset = len(inner) - 4
        stored_cksum = struct.unpack("!I", inner[checksum_offset:])[0]
        calc_cksum = zlib.crc32(inner[:checksum_offset]) & 0xFFFFFFFF
        if stored_cksum != calc_cksum:
            return None, 0
        return (stream_id, flags, data), frame_len
    except (struct.error, IndexError, ValueError):
        return None, 0

# ==================== MULTIPLEXER ====================
class Multiplexer:
    def __init__(self, cipher=None):
        self.cipher = cipher
        self.streams = {}
        self.next_id = 1
        self.lock = threading.Lock()

    def open_stream(self) -> int:
        with self.lock:
            sid = self.next_id
            self.next_id += 1
            self.streams[sid] = bytearray()
            return sid

    def close_stream(self, sid: int):
        try:
            with self.lock:
                del self.streams[sid]
        except KeyError:
            pass

    def encode(self, sid: int, data: bytes, flags: int = FLAG_DATA) -> bytes:
        try:
            if len(data) > MAX_PAYLOAD:
                chunks = [data[i:i+MAX_PAYLOAD] for i in range(0, len(data), MAX_PAYLOAD)]
                frames = b""
                for i, chunk in enumerate(chunks):
                    f = FLAG_DATA
                    if i == len(chunks) - 1:
                        f = flags | FLAG_DATA
                    frames += make_frame(sid, chunk, f, self.cipher)
                return frames
            return make_frame(sid, data, flags, self.cipher)
        except ValueError as e:
            raise ValueError(f"Encode error: {e}")

    def decode(self, raw: bytes) -> list:
        results = []
        offset = 0
        while offset < len(raw):
            try:
                result, consumed = parse_frame(raw[offset:], self.cipher)
                if result is None:
                    break
                sid, flags, data = result
                if sid not in self.streams and flags not in (FLAG_RESYNC, FLAG_HEARTBEAT, FLAG_ACK):
                    self.streams[sid] = bytearray()
                if flags & FLAG_DATA:
                    try:
                        self.streams[sid].extend(data)
                    except KeyError:
                        pass
                if flags & FLAG_CLOSE:
                    try:
                        payload = bytes(self.streams[sid])
                        results.append((sid, "close", payload))
                        self.close_stream(sid)
                    except KeyError:
                        results.append((sid, "close", b""))
                elif flags & FLAG_RESYNC:
                    results.append((sid, "resync", data))
                elif flags & FLAG_HEARTBEAT:
                    results.append((sid, "heartbeat", data))
                elif flags & FLAG_ACK:
                    results.append((sid, "ack", data))
                else:
                    try:
                        payload = bytes(self.streams[sid])
                        results.append((sid, "data", payload))
                        self.streams[sid] = bytearray()
                    except KeyError:
                        results.append((sid, "data", b""))
                offset += consumed
            except ValueError:
                break
        return results

# ==================== HTTP HEALTH CHECK ====================
class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"CAT Server OK")

    def log_message(self, format, *args):
        pass

def start_health_server():
    server = HTTPServer(("0.0.0.0", PORT), HealthHandler)
    print(f"[*] Health check on port {PORT}")
    server.serve_forever()

# ==================== WEBSOCKET HANDLER ====================
class TunnelServer:
    def __init__(self):
        self.km = DualKeyManager(KEY1, KEY2)
        self.clients = {}
        self.resync_threshold = 3

    async def handle_client(self, websocket, path):
        if path != WS_PATH:
            await websocket.close()
            return
        
        client_id = id(websocket)
        mux = Multiplexer(self.km.get_cipher())
        self.clients[client_id] = {"ws": websocket, "mux": mux, "sockets": {}}
        print(f"[+] Client {client_id} connected")
        
        try:
            async for msg in websocket:
                if isinstance(msg, str):
                    continue
                try:
                    results = mux.decode(msg)
                    for sid, typ, data in results:
                        if typ == "resync":
                            self.km.resync()
                            mux.cipher = self.km.get_cipher()
                            for c in self.clients.values():
                                c["mux"].cipher = self.km.get_cipher()
                            print(f"[*] Global resync to key #{2 if self.km.active == self.km.secondary else 1}")
                        elif typ == "heartbeat":
                            ack = make_frame(0, b"PONG", FLAG_ACK, self.km.get_cipher())
                            await websocket.send(ack)
                        elif typ == "ack":
                            pass
                        elif typ in ("data", "close"):
                            await self.handle_stream_data(client_id, sid, typ, data, websocket)
                except Exception as e:
                    print(f"[!] Client {client_id} decode error: {e}")
                    if self.km.resync_count < self.resync_threshold:
                        self.km.resync()
                        mux.cipher = self.km.get_cipher()
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            for s in self.clients.get(client_id, {}).get("sockets", {}).values():
                try:
                    s.close()
                except:
                    pass
            if client_id in self.clients:
                del self.clients[client_id]
            print(f"[-] Client {client_id} disconnected")

    async def handle_stream_data(self, client_id, sid, typ, data, ws):
        client = self.clients.get(client_id)
        if not client:
            return
        
        if sid not in client["sockets"] and typ == "data":
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect(("1.1.1.1", 80))
                client["sockets"][sid] = sock
                asyncio.create_task(self.tcp_to_ws(client_id, sid, sock, ws))
            except Exception as e:
                print(f"[!] Stream {sid} connect error: {e}")
                frame = make_frame(sid, b"", FLAG_CLOSE, self.km.get_cipher())
                await ws.send(frame)
                return
        
        if sid in client["sockets"]:
            try:
                if typ == "close":
                    client["sockets"][sid].close()
                    del client["sockets"][sid]
                else:
                    client["sockets"][sid].sendall(data)
                    client["mux"].streams[sid] = bytearray()
            except (OSError, KeyError):
                pass

    async def tcp_to_ws(self, client_id, sid, sock, ws):
        client = self.clients.get(client_id)
        if not client:
            return
        try:
            while True:
                data = sock.recv(MAX_PAYLOAD)
                if not data:
                    break
                try:
                    frame = client["mux"].encode(sid, data, FLAG_DATA)
                    await ws.send(frame)
                except ValueError as e:
                    print(f"[!] Encode error: {e}")
                    break
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        finally:
            try:
                frame = client["mux"].encode(sid, b"", FLAG_CLOSE)
                await ws.send(frame)
            except:
                pass
            try:
                sock.close()
            except:
                pass
            if client_id in self.clients and sid in self.clients[client_id]["sockets"]:
                del self.clients[client_id]["sockets"][sid]

    async def run(self):
        threading.Thread(target=start_health_server, daemon=True).start()
        print(f"[*] WebSocket tunnel on wss://0.0.0.0:{PORT}{WS_PATH}")
        async with websockets.serve(self.handle_client, "0.0.0.0", PORT):
            await asyncio.Future()

# ==================== MAIN ====================
if __name__ == "__main__":
    print("""
    ╔═══════════════════════════════════════╗
    ║     CAT Server - Chaotic Tunnel       ║
    ║         Render.com / WebSocket          ║
    ╚═══════════════════════════════════════╝
    """)
    server = TunnelServer()
    asyncio.run(server.run())
