from fastapi import FastAPI, WebSocket, WebSocketDisconnect
import asyncio
import hashlib

app = FastAPI()

# Константы Лоренца
SIGMA, RHO, BETA, DT = 10.0, 28.0, 8.0 / 3.0, 0.01

# НАША БАЗА КЛЮЧЕЙ (1 основной + 2 резервных)
ALLOWED_KEYS = {
    "ch_1.1",               # Основной ключ сессии
    "ch_1.2_backup",        # Резервный ключ 1
    "ch_1.3_emergency"      # Резервный ключ 2
}

@app.websocket("/tunnel")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    print("[СЕРВЕР] Поступил запрос на подключение к WebSocket...", flush=True)
    
    try:
        # 1. Первая фаза: Ожидаем секретный ключ авторизации от клиента
        secret_key = await websocket.receive_text()
        
        if secret_key not in ALLOWED_KEYS:
            print(f"[КРИТ] Попытка взлома! Неверный ключ сессии: {secret_key}", flush=True)
            await websocket.send_text("AUTH_FAILED: Invalid Secret Key")
            await websocket.close(code=4001)
            return
            
        print(f"[УСПЕХ] Авторизация пройдена по ключу: {secret_key}", flush=True)
        await websocket.send_text("AUTH_OK")
        
        # 2. Инициализация аттрактора Лоренца на основе хэша ключа
        hash_bytes = hashlib.sha256(secret_key.encode()).digest()
        x = 1.0 + (hash_bytes[0] % 10)
        y = 1.0 + (hash_bytes[1] % 10)
        z = 10.0 + (hash_bytes[2] % 20)
        
        total_packets = 0
        
        # 3. Основной цикл приема мультиплексированных SOCKS5-пакетов
        while True:
            packet = await websocket.receive_bytes()
            total_packets += 1
            
            # Шаг Лоренца для расчета динамического паддинга
            dx = SIGMA * (y - x) * DT
            dy = (x * (RHO - z) - y) * DT
            dz = (x * y - BETA * z) * DT
            x, y, z = x + dx, y + dy, z + dz
            
            # Вычисляем длину Лоренц-шума, зашитого в пакет (диапазон общего пакета под MTU)
            padding_len = int(abs(x * 1000) % 50)
            
            # Срезаем паддинг, извлекая чистый трафик
            if padding_len > 0 and len(packet) >= padding_len:
                clean_data = packet[:-padding_len]
            else:
                clean_data = packet
                
            # Безопасное выравнивание координат каждые 25 фреймов
            if total_packets % 25 == 0:
                x, y, z = round(x, 2), round(y, 2), round(z, 2)
                print(f"[СИНХРО] Шаг #{total_packets//25}. Координаты Лоренца выровнены с клиентом.", flush=True)
                
            # Здесь чистый SOCKS5 поток clean_data будет уходить веб-сайтам через транспортный мост
            
    except WebSocketDisconnect:
        print("[ИНФО] Клиент разорвал WebSocket соединение.", flush=True)
    except Exception as e:
        print(f"[ОШИБКА ЯДРА] Сбой в обработке потока: {e}", flush=True)
