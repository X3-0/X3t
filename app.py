from flask import Flask, request
import datetime
import os

app = Flask(__name__)

@app.route('/')
def home():
    # Эти строчки отобразятся в логах Render при тесте X3tunnel
    print(f"[{datetime.datetime.now()}] ВХОДЯЩИЙ ЗАПРОС С IP: {request.remote_addr}", flush=True)
    print(f"Заголовки: {dict(request.headers)}", flush=True)
    return "<h1>X3tunnel Core Socket Active</h1>"

if __name__ == "__main__":
    # Render сам назначит порт через переменную окружения PORT
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
