from fastapi import FastAPI, WebSocket
import struct
import asyncio

app = FastAPI()
streams = {}
# Координаты без подчеркиваний
LORENZ = {"x": 1.0, "y": 1.0, "z": 10.0}

def getpad():
    dt = 0.01
    dx = (10.0 * (LORENZ["y"] - LORENZ["x"])) * dt
    dy = (LORENZ["x"] * (28.0 - LORENZ["z"]) - LORENZ["y"]) * dt
    dz = (LORENZ["x"] * LORENZ["y"] - 8/3 * LORENZ["z"]) * dt
    LORENZ["x"] += dx
    LORENZ["y"] += dy
    LORENZ["z"] += dz
    return int(abs(LORENZ["x"] * 10)) % 64 + 16

@app.websocket("/tunnel")
async def tunnel(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_bytes()
            if len(data) < 5:
                continue
            
            # cmd, sid, length
            c, s, l = struct.unpack("!BHH", data[:5])
            
            if c == 0: # SYNC
                LORENZ["x"] = 1.0
                LORENZ["y"] = 1.0
                LORENZ["z"] = 10.0
            elif c == 4: # CLOSE
                streams.pop(s, None)
            elif c == 3: # DATA
                pass
    except:
        pass
    finally:
        streams.clear()
