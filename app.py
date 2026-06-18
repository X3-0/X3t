from fastapi import FastAPI, WebSocket
import struct
import asyncio
import logging

# Настройка логирования для отладки, если будет ошибка
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()
streams = {}
LORENZ = {"x": 1.0, "y": 1.0, "z": 10.0}

def get_pad():
    # Атомарный расчет, без await, что предотвращает race conditions
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
            # Читаем байты с обработкой ошибок
            data = await websocket.receive_bytes()
            
            # Защита от ValueError: проверяем размер перед распаковкой
            if len(data) < 5:
                continue
                
            cmd, sid, length = struct.unpack("!BHH", data[:5])
            
            if cmd == 0: # SYNC
                LORENZ.update({"x": 1.0, "y": 1.0, "z": 10.0})
                logger.info(f"Sync command received for stream {sid}")

            elif cmd == 4: # CLOSE (Атомарное удаление)
                # .pop(..., None) предотвращает KeyError
                stream_task = streams.pop(sid, None)
                if stream_task:
                    stream_task.cancel() # Останавливаем задачу, если она была
            
            elif cmd == 3: # DATA
                # Здесь должна быть логика передачи данных. 
                # Обязательно добавь try/except при работе с целевым сокетом.
                pass

    except Exception as e:
        logger.error(f"WebSocket connection closed or error: {e}")
    finally:
        # Очистка всех зависших потоков при разрыве WebSocket
        for task in streams.values():
            task.cancel()
        streams.clear()
        logger.info("Tunnel cleaned up.")
