from fastapi import FastAPI, WebSocket, WebSocketDisconnect
import asyncio
import hashlib
import struct

app = FastAPI()

# Константы Лоренца (Базовая система)
SIGMA, RHO, BETA, DT = 10.0, 28.0, 8.0 / 3.0, 0.01
ALLOWED_KEYS = {"ch_1.1", "ch_1.2_backup", "ch_1.3_emergency"}

class ChaoticMultiplexerServer:
    def __init__(self, websocket: WebSocket, secret_key: str):
        self.ws = websocket
        self.active_streams = {}  # Пул активных интернет-соединений: {stream_id: (reader, writer)}
        self.total_packets = 0
        
        # Инициализация координат Лоренца на базе хэша ключа
        hash_bytes = hashlib.sha256(secret_key.encode()).digest()
        self.x = 1.0 + (hash_bytes[0] % 10)
        self.y = 1.0 + (hash_bytes[1] % 10)
        self.z = 10.0 + (hash_bytes[2] % 20)

    def _next_lorenz_step(self):
        """Итерация аттрактора для синхронизации состояния хаоса"""
        self.total_packets += 1
        dx = SIGMA * (self.y - self.x) * DT
        dy = (self.x * (RHO - self.z) - self.y) * DT
        dz = (self.x * self.y - BETA * self.z) * DT
        self.x += dx
        self.y += dy
        self.z += dz
        
        # Безопасное выравнивание округлением каждые 25 шагов
        if self.total_packets % 25 == 0:
            self.x, self.y, self.z = round(self.x, 2), round(self.y, 2), round(self.z, 2)

    async def start_tunnel_loop(self):
        try:
            while True:
                # Получаем бинарный кадр из WebSocket (наш упакованный пакет)
                packet = await self.ws.receive_bytes()
                self._next_lorenz_step()
                
                # ТЕХНИЧЕСКИЙ НЮАНС: Минимум 4 байта заголовка (Stream_ID + Length)
                if len(packet) < 4:
                    continue
                
                # Парсим бинарный заголовок кадра
                stream_id, payload_len = struct.unpack("!HH", packet[:4])
                
                # Извлекаем чистые данные, отсекая Лоренц-паддинг с конца
                clean_data = packet[4:4 + payload_len]
                
                # Если этот Stream_ID прислал данные в первый раз — значит это инициализация нового SOCKS5-канала.
                # Клиент в первой порции данных передает специальный маркер назначения (Host + Port).
                if stream_id not in self.active_streams:
                    await self._init_new_target_stream(stream_id, clean_data)
                else:
                    # Если стрим уже активен, просто пробрасываем чистые данные в сокет целевого сайта
                    _, writer = self.active_streams[stream_id]
                    if clean_data and not writer.is_closing():
                        writer.write(clean_data)
                        await writer.drain()
                        
        except WebSocketDisconnect:
            print("[ИНФО] WebSocket сессия закрыта клиентом.", flush=True)
        finally:
            await self._cleanup_all_streams()

    async def _init_new_target_stream(self, stream_id: int, init_data: bytes):
        """Асинхронное открытие целевого сокета в интернет для нового логического канала"""
        try:
            # Технический нюанс разбора метаданных назначения (хост и порт) из стартового пакета мультиплексора
            # Формат стартового пакета: [1B len_host][Host_string][2B Port]
            host_len = init_data[0]
            host = init_data[1:1 + host_len].decode('utf-8')
            port = struct.unpack("!H", init_data[1 + host_len:3 + host_len])[0]
            
            print(f"[МУЛЬТИПЛЕКСОР] Открытие подканала {stream_id} -> {host}:{port}", flush=True)
            
            reader, writer = await asyncio.open_connection(host, port)
            self.active_streams[stream_id] = (reader, writer)
            
            # Запускаем фоновую задачу (Background Worker) для прослушивания ответов от этого сайта
            asyncio.create_task(self._listen_target_and_reply(stream_id, reader))
            
        except Exception as e:
            print(f"[ОШИБКА МОСТА] Подканал {stream_id} не смог соединиться: {e}", flush=True)

    async def _listen_target_and_reply(self, stream_id: int, reader: asyncio.StreamReader):
        """Слушает целевой сайт и упаковывает ответ обратно в WebSocket для отправки на телефон"""
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                
                # Упаковываем ответ сайта в обратный кадр мультиплексора
                # Формат ответа: [2B Stream_ID][2B Data_Length][Сами данные]
                header = struct.pack("!HH", stream_id, len(data))
                await self.ws.send_bytes(header + data)
        except:
            pass
        finally:
            await self._close_single_stream(stream_id)

    async def _close_single_stream(self, stream_id: int):
        if stream_id in self.active_streams:
            _, writer = self.active_streams.pop(stream_id, (None, None))
            if writer:
                writer.close()
                try: await writer.wait_closed()
                except: pass
            print(f"[МУЛЬТИПЛЕКСОР] Подканал {stream_id} закрыт.", flush=True)

    async def _cleanup_all_streams(self):
        """Полная очистка пула при разрыве основного туннеля"""
        print("[ОЧИСТКА] Закрытие всех активных подканалов...", flush=True)
        for stream_id in list(self.active_streams.keys()):
            await self._close_single_stream(stream_id)


@app.websocket("/tunnel")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    
    try:
        # Фаза авторизации
        secret_key = await websocket.receive_text()
        if secret_key not in ALLOWED_KEYS:
            await websocket.send_text("AUTH_FAILED")
            await websocket.close(code=4001)
            return
            
        await websocket.send_text("AUTH_OK")
        
        # Инициализация ядра хаотического мультиплексирования
        multiplexer = ChaoticMultiplexerServer(websocket, secret_key)
        await multiplexer.start_tunnel_loop()
        
    except Exception as e:
        print(f"[КРИТ] Сбой сессии: {e}", flush=True)
