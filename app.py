import os
import asyncio
import struct
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
import uvicorn

app = FastAPI()

@app.get("/")
async def root():
    return {"status": "tunnel_node_active"}

# Независимый генератор шума Лоренца для направления Сервер -> Клиент
lorenz_state = [1.0, 1.0, 10.0]

def step_lorenz():
    x, y, z = lorenz_state
    dx = 10.0 * (y - x) * 0.01
    dy = (x * (28.0 - z) - y) * 0.01
    dz = (x * y - (8.0 / 3.0) * z) * 0.01
    lorenz_state[0], lorenz_state[1], lorenz_state[2] = x + dx, y + dy, z + dz
    return x

@app.websocket("/tunnel")
async def tunnel(websocket: WebSocket):
    await websocket.accept()
    streams = {}  # Сварка ID потоков и сетевых сокетов (stream_id -> StreamWriter)

    async def send_frame(cmd, stream_id, data=b""):
        try:
            # Структура фрейма: [Команда 1 байт] [ID потока 2 байта] [Длина данных 2 байта] + Данные
            msg = struct.pack("!BHH", cmd, stream_id, len(data)) + data
            x = step_lorenz()
            pad_len = int(abs(x * 100) % 32)
            packet = msg + os.urandom(pad_len)
            await websocket.send_bytes(packet)
        except Exception:
            pass

    async def remote_to_ws(reader, stream_id):
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                await send_frame(3, stream_id, data)  # CMD 3: DATA
        except Exception:
            pass
        finally:
            await send_frame(4, stream_id)  # CMD 4: CLOSE
            if stream_id in streams:
                try:
                    streams[stream_id].close()
                except Exception:
                    pass
                del streams[stream_id]

    try:
        while True:
            packet = await websocket.receive_bytes()
            if len(packet) < 5:
                continue

            cmd, stream_id, payload_len = struct.unpack("!BHH", packet[:5])
            payload = packet[5:5+payload_len]

            if cmd == 1:  # CMD 1: CONNECT (Клиент просит соединить с целевым сайтом)
                if len(payload) < 3:
                    continue
                port = struct.unpack("!H", payload[:2])[0]
                host = payload[2:].decode('utf-8', errors='ignore')
                try:
                    reader, writer = await asyncio.open_connection(host, port)
                    streams[stream_id] = writer
                    await send_frame(2, stream_id, b"\x00")  # Статус 0: Успех
                    asyncio.create_task(remote_to_ws(reader, stream_id))
                except Exception:
                    await send_frame(2, stream_id, b"\x01")  # Статус 1: Провал подключения

            elif cmd == 3:  # CMD 3: DATA (Данные от клиента летят в целевой сайт)
                if stream_id in streams:
                    try:
                        streams[stream_id].write(payload)
                        await streams[stream_id].drain()
                    except Exception:
                        pass

            elif cmd == 4:  # CMD 4: CLOSE (Клиент закрыл вкладку)
                if stream_id in streams:
                    try:
                        streams[stream_id].close()
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

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run(app, host="0.0.0.0", port=port)
