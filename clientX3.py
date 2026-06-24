#!/usr/bin/env python3
import asyncio
import struct
import os
import sys

import websockets

SERVER_URL = "wss://x3t.onrender.com/tunnel"

state = {
    "ws": None,
    "streams": {},
    "lorenz_x": 1.0,
    "lorenz_y": 1.0,
    "lorenz_z": 10.0,
    "next_stream_id": 1,
    "total_padded_bytes": 0
}

def step_lorenz_and_get_pad():
    # Классический аттрактор Лоренца (Шаг системы уравнений)
    x = state["lorenz_x"]
    y = state["lorenz_y"]
    z = state["lorenz_z"]

    dt = 0.01
    dx = 10.0 * (y - x) * dt
    dy = (x * (28.0 - z) - y) * dt
    dz = (x * y - (8.0 / 3.0) * z) * dt

    state["lorenz_x"] = x + dx
    state["lorenz_y"] = y + dy
    state["lorenz_z"] = z + dz

    # Пульт управления паддингом: на основе координаты X вычисляем размер мусора (от 8 до 64 байт)
    pad_len = int(abs(state["lorenz_x"] * 150) % 57) + 8
    return pad_len

def print_dashboard(action, stream_id, payload_len, pad_len):
    streams_count = len(state["streams"])
    lx = round(state["lorenz_x"], 2)
    ly = round(state["lorenz_y"], 2)
    lz = round(state["lorenz_z"], 2)

    print(f"[PULSE] {action} | Stream ID: {stream_id} | Data: {payload_len}B")
    print(f"        [LORENZ CHAOS] X: {lx} | Y: {ly} | Z: {lz}")
    print(f"        [PADDING] Added: {pad_len} bytes | [MULTIPLEXER] Active Streams: {streams_count}")
    print("-" * 70)

async def send_frame(cmd, stream_id, data=b""):
    if state["ws"] is None:
        return
    try:
        msg = struct.pack("!BHH", cmd, stream_id, len(data)) + data
        pad_len = step_lorenz_and_get_pad()
        state["total_padded_bytes"] += pad_len
        packet = msg + os.urandom(pad_len)
        cmd_names = {1: "CONNECT_REQ", 3: "DATA_TX", 4: "STREAM_CLOSE"}
        action_name = cmd_names.get(cmd, "UNKNOWN")
        print_dashboard(action_name, stream_id, len(data), pad_len)
        await state["ws"].send(packet)
    except Exception as e:
        print(f"[-] Ошибка отправки: {e}")

async def ws_receive_loop():
    try:
        ws = state["ws"]
        while True:
            packet = await ws.recv()
            if isinstance(packet, str):
                packet = packet.encode('utf-8')
            if not packet or len(packet) < 5:
                continue
            try:
                cmd, stream_id, payload_len = struct.unpack("!BHH", packet[:5])
            except struct.error:
                continue
            payload = packet[5:5+payload_len]
            pad_len = len(packet) - 5 - payload_len
            if stream_id in state["streams"]:
                stream = state["streams"][stream_id]
                if cmd == 2:
                    stream["status"] = payload[0] if payload else 1
                    stream["event"].set()
                    print_dashboard("CONNECT_RESP", stream_id, payload_len, pad_len)
                elif cmd == 3:
                    stream["queue"].put_nowait(payload)
                    print_dashboard("DATA_RX", stream_id, payload_len, pad_len)
                elif cmd == 4:
                    stream["queue"].put_nowait(None)
                    print_dashboard("SERVER_STREAM_CLOSE", stream_id, payload_len, pad_len)
    except Exception as e:
        print(f"[-] Ошибка приема: {e}")
    finally:
        print("[-] Главный туннель закрыт сервером.")
        for sid, stream in list(state["streams"].items()):
            try:
                stream["queue"].put_nowait(None)
            except Exception:
                pass

async def stream_writer_loop(writer, queue):
    try:
        while True:
            data = await queue.get()
            if data is None:
                break
            writer.write(data)
            try:
                await writer.drain()
            except Exception:
                pass
            queue.task_done()
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

async def handle_socks(reader, writer):
    stream_id = None
    try:
        header = await reader.read(2)
        if len(header) < 2 or header[0] != 5:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
            return

        nmeth = header[1]
        await reader.read(nmeth)
        writer.write(b"\x05\x00")
        await writer.drain()

        req = await reader.read(4)
        if len(req) < 4 or req[1] != 1:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
            return

        atyp = req[3]
        if atyp == 1:
            addr_bytes = await reader.read(4)
            if len(addr_bytes) < 4:
                raise Exception("addr read fail")
            dst_addr = ".".join(map(str, addr_bytes))
        elif atyp == 3:
            addr_len_buf = await reader.read(1)
            if not addr_len_buf:
                raise Exception("addr len fail")
            addr_len = addr_len_buf[0]
            addr_bytes = await reader.read(addr_len)
            if len(addr_bytes) < addr_len:
                raise Exception("addr read fail")
            dst_addr = addr_bytes.decode('utf-8', errors='ignore')
        else:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
            return

        port_buf = await reader.read(2)
        if len(port_buf) < 2:
            raise Exception("port read fail")
        dst_port = struct.unpack("!H", port_buf)[0]

        stream_id = state["next_stream_id"]
        state["next_stream_id"] = (state["next_stream_id"] % 65535) + 1

        event = asyncio.Event()
        queue = asyncio.Queue()
        state["streams"][stream_id] = {
            "writer": writer,
            "event": event,
            "queue": queue,
            "status": None
        }

        target_bytes = struct.pack("!H", dst_port) + dst_addr.encode('utf-8')
        await send_frame(1, stream_id, target_bytes)

        try:
            await asyncio.wait_for(event.wait(), timeout=10.0)
        except asyncio.TimeoutError:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
            return

        if state["streams"][stream_id]["status"] != 0:
            try:
                writer.write(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
            except:
                pass
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
            return

        try:
            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
        except:
            pass

        asyncio.create_task(stream_writer_loop(writer, queue))

        while True:
            data = await reader.read(4096)
            if not data:
                break
            await send_frame(3, stream_id, data)

    finally:
        if stream_id is not None:
            try:
                await send_frame(4, stream_id)
            except:
                pass
            if stream_id in state["streams"]:
                try:
                    del state["streams"][stream_id]
                except:
                    pass
        try:
            writer.close()
            await writer.wait_closed()
        except:
            pass

async def main():
    print("[*] Подключение к магистральному WebSocket...")
    try:
        async with websockets.connect(SERVER_URL, open_timeout=20) as ws:
            state["ws"] = ws
            print("[+] Успешная синхронизация с Render!")
            asyncio.create_task(ws_receive_loop())
            socks_server = await asyncio.start_server(handle_socks, '127.0.0.1', 1080)
            print("[+] Стелс-туннель (Лоренц + Мультиплекс) на 127.0.0.1:1080")
            print("=" * 70)
            async with socks_server:
                await socks_server.serve_forever()
    except Exception as e:
        print(f"[-] Ошибка: {e}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nВыход.")
        sys.exit(0)
