from fastapi import FastAPI, WebSocket
import struct
import asyncio

app = FastAPI()
streams = {}
LORENZ = {"x": 1.0, "y": 1.0, "z": 10.0}

def get_pad():
    dt = 0.01
    dx = (10.0 * (LORENZ["y"] - LORENZ["x"])) * dt
    dy = (LORENZ["x"] * (28.0 - LORENZ["z"]) - LORENZ["y"]) * dt
    dz = (LORENZ["x"] * LORENZ["y"] - 8/3 * LORENZ["z"]) * dt
    LORENZ["x"] += dx; LORENZ["y"] += dy; LORENZ["z"] += dz
    return int(abs(LORENZ["x"] * 10)) % 64 + 16

@app.websocket("/tunnel")
async def tunnel(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_bytes()
            if len(data) < 5: continue
            cmd, sid, length = struct.unpack("!BHH", data[:5])
            
            if cmd == 0: # SYNC
                LORENZ.update({"x": 1.0, "y": 1.0, "z": 10.0})
            elif cmd == 4: # CLOSE
                streams.pop(sid, None)
            elif cmd == 3: # DATA
                # Прямая передача (мультиплексирование)
                pass 
    except:
        pass
    finally:
        streams.clear()
