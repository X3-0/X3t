import asyncio
import websockets
import socket

async def proxy_handler(websocket):
    # Просто пересылаем всё, что пришло, в сторону интернета
    # Для теста мы не парсим адрес, а просто ждем поток данных
    async for message in websocket:
        await websocket.send(message) # Echo-тест для начала

start_server = websockets.serve(proxy_handler, "0.0.0.0", 10000)
asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()
