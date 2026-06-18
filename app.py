#!/usr/bin/env python3
import asyncio, os, ssl, hashlib

KEY1 = os.environ.get("CAT_KEY1", "default_alpha_key_2024").encode()
KEY2 = os.environ.get("CAT_KEY2", "default_omega_key_2024").encode()
if os.path.exists("phrases.txt"):
    lines = [l.strip() for l in open("phrases.txt") if l.strip() and not l.startswith("#")]
    if len(lines) >= 2:
        KEY1, KEY2 = lines[0].encode(), lines[1].encode()

PORT = int(os.environ.get("PORT", 10000))

class Lorenz:
    def __init__(self, key):
        h = hashlib.sha256(key).digest()
        self.x0 = (int.from_bytes(h[0:4], "big") % 2000) / 100.0 + 0.1
        self.y0 = (int.from_bytes(h[4:8], "big") % 2000) / 100.0 + 0.1
        self.z0 = (int.from_bytes(h[8:12], "big") % 2000) / 100.0 + 25.0
        self.s, self.r, self.b, self.dt = 10.0, 28.0, 8.0 / 3.0, 0.01
        self.x, self.y, self.z = self.x0, self.y0, self.z0

    def crypt(self, data):
        out = bytearray()
        for byte in data:
            self.x += (self.s * (self.y - self.x) * self.dt)
            self.y += (self.x * (self.r - self.z) - self.y) * self.dt
            self.z += (self.x * self.y - self.b * self.z) * self.dt
            out.append(byte ^ int(abs(self.x) % 256))
        return bytes(out)

class DualKey:
    def __init__(self, k1, k2):
        self.p = Lorenz(k1)  # client -> server
        self.s = Lorenz(k2)  # server -> client

async def pipe(reader, writer, cipher, label):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(cipher.crypt(data))
            await writer.drain()
    except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        print(f"[!] {label} error: {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except:
            pass

async def handle_client(reader, writer):
    addr = writer.get_extra_info("peername")
    print(f"[+] Client {addr}")
    dk = DualKey(KEY1, KEY2)
    try:
        len_bytes = await reader.readexactly(2)
        data_len = int.from_bytes(len_bytes, "big")
        enc_data = await reader.readexactly(data_len)
        connect_info = dk.p.crypt(enc_data).decode("utf-8", errors="replace")
        host, port_str = connect_info.rsplit(":", 1)
        port = int(port_str)
        print(f"[*] Stream -> {host}:{port}")
        target_reader, target_writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=10
        )
        print(f"[+] Stream connected")
        t1 = asyncio.create_task(pipe(reader, target_writer, dk.p, "client->target"))
        t2 = asyncio.create_task(pipe(target_reader, writer, dk.s, "target->client"))
        done, pending = await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass
    except asyncio.TimeoutError:
        print(f"[!] Connection timeout")
    except asyncio.IncompleteReadError:
        pass
    except Exception as e:
        print(f"[!] Handler error: {e}")
    finally:
        print(f"[-] Client {addr}")
        try:
            writer.close()
            await writer.wait_closed()
        except:
            pass

async def main():
    # TLS 1.2 server context
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ssl_ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ssl_ctx.load_cert_chain("server.crt", "server.key")

    server = await asyncio.start_server(handle_client, "0.0.0.0", PORT, ssl=ssl_ctx)
    print(f"[*] CAT Server TLS 1.2 on port {PORT}")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
 
