import os
import asyncio
import struct
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from ipaddress import ip_address

app = FastAPI()

@app.get("/")
async def root():
    return {"status": "stealth_node_active"}

def is_safe_host(host: str) -> bool:
    dangerous_hosts = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
    if host in dangerous_hosts:
        return False
    try:
        addr = ip_address(host)
        return not (addr.is_private or addr.is_loopback)
    except ValueError:
        return True

@app.websocket("/tunnel")
async def tunnel(websocket: WebSocket):
    await websocket.accept()
    streams = {} 
    
    # ЛОКАЛЬНЫЙ Лоренц ТОЛЬКО для этой сессии (защита от рассинхрона)
    lorenz = [1.0, 1.0, 10.0]

    def step_lorenz_and_get_pad():
        x, y, z = lorenz[0], lorenz[1], lorenz[2]
        dt = 0.01
        dx = 10.0 * (y - x) * dt
        dy = (x * (28.0 - z) - y) * dt
        dz = (x * y - (8.0 / 3.0) * z) * dt
        lorenz[0], lorenz[1], lorenz[2] = x + dx, y + dy, z + dz
        return int(abs(lorenz[0] * 150) % 57) + 8

    async def send_frame(cmd, stream_id, data=b""):
        if len(data) > 65535:  
            data = data[:65535]
        try:
            msg = struct.pack("!BHH", cmd, stream_id, len(data)) + data
            pad_len = step_lorenz_and_get_pad()
            packet = msg + os.urandom(pad_len)
            await websocket.send_bytes(packet)
        except Exception:
            pass

    async def remote_to_ws(reader, stream_id):
        try:
            while True:
                data = await asyncio.wait_for(reader.read(4096), timeout=30)
                if not data:
                    break
                await send_frame(3, stream_id, data)
        except Exception:
            pass
        finally:
            await send_frame(4, stream_id)
            if stream_id in streams:
                try:
                    streams[stream_id].close()
                    await streams[stream_id].wait_closed()
                except Exception:
                    pass
                del streams[stream_id]

    try:
        while True:
            packet = await websocket.receive_bytes()
            if len(packet) < 5:
                continue
            
            cmd, stream_id, payload_len = struct.unpack("!BHH", packet[:5])
            
            # КРИТИЧЕСКИ ВАЖНО: Делаем шаг Лоренца при получении каждого пакета!
            _ = step_lorenz_and_get_pad()

            if len(packet) < 5 + payload_len:
                continue
                
            payload = packet[5:5+payload_len]

            if cmd == 1:  
                if len(payload) < 3:
                    continue
                port = struct.unpack("!H", payload[:2])[0]
                host = payload[2:].decode('utf-8', errors='ignore').strip()
                
                if not host or not (0 < port < 65536) or not is_safe_host(host):
                    await send_frame(2, stream_id, b"\x01")
                    continue
                
                try:
                    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=10)
                    streams[stream_id] = writer
                    await send_frame(2, stream_id, b"\x00")
                    asyncio.create_task(remote_to_ws(reader, stream_id))
                except Exception:
                    await send_frame(2, stream_id, b"\x01")
            
            elif cmd == 3:  
                if stream_id in streams:
                    try:
                        streams[stream_id].write(payload)
                        await asyncio.wait_for(streams[stream_id].drain(), timeout=5)
                    except Exception:
                        pass
            
            elif cmd == 4:  
                if stream_id in streams:
                    try:
                        streams[stream_id].close()
                        await streams[stream_id].wait_closed()
                    except Exception:
                        pass
                    del streams[stream_id]

    except WebSocketDisconnect:
        pass
    finally:
        for writer in list(streams.values()):
            try:
                writer.close()
            except Exception:
                pass
