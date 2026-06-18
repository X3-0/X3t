from fastapi import FastAPI, WebSocket
import struct
import asyncio

app = FastAPI()
streams = {}

# Параметры Лоренца
LORENZ = {"x": 1.0, "y": 1.0, "z": 10.0}

def get_pad():
    dt = 0.01
    dx = (10.0 * (LORENZ["y"] - LORENZ["x"])) * dt
    dy = (LORENZ["x"] * (28.0 - LORENZ["z"]) - LORENZ["y"]) * dt
    dz = (LORENZ["x"] * LORENZ["y"] - 8/3 * LORENZ["z"]) * dt
    LORENZ["x"] += dx; LORENZ["y"] += dy; LORENZ["z"] += dz
    return int(abs(LORENZ["x"] * 10)) % 64 + 16 # Паддинг от 16 до 80 байт

@app.websocket("/tunnel")
async def tunnel(websocket: WebSocket):
    await websocket.accept()
    while True:
        try:
            data = await websocket.receive_bytes()
            # Формат: [CMD(1)][ID(2)][LEN(2)]...
            cmd, stream_id, length = struct.unpack("!BHH", data[:5])
            
            if cmd == 0: # SYNC
                LORENZ.update({"x": 1.0, "y": 1.0, "z": 10.0})
            elif cmd == 1: # CONNECT
                streams[stream_id] = asyncio.create_task(handle_stream(websocket, stream_id))
            elif cmd == 3: # DATA
                if stream_id in streams:
                    # Логика обработки данных
                    pass
            elif cmd == 4: # CLOSE
                if stream_id in streams:
                    streams.pop(stream_id, None)
        except: break
