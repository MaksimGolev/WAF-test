import json
import redis
import threading
import time
from flask import Flask, request, abort

app = Flask(__name__)

# Подключение к Redis (по умолчанию redis:6379 внутри Docker)
r = redis.Redis(host='redis', port=6379, decode_responses=True)

LOG_FILE = "/data/logs.json"
RULES_FILE = "/data/rules.json"

log_queue = []

def log_writer():
    """Поток для записи логов из очереди в файл"""
    while True:
        if log_queue:
            logs = []
            try:
                with open(LOG_FILE, 'r', encoding='utf-8') as f:
                    logs = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                pass

            while log_queue:
                logs.append(log_queue.pop(0))

            with open(LOG_FILE, 'w', encoding='utf-8') as f:
                json.dump(logs, f, indent=2)
        time.sleep(2)

# Запускаем поток логгера
threading.Thread(target=log_writer, daemon=True).start()

def load_rules():
    try:
        with open(RULES_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return []

WAF_RULES = load_rules()

def log_event(event):
    log_queue.append(event)

def is_blocked(ip):
    return r.sismember("blocked_ips", ip)

def block_ip(ip):
    r.sadd("blocked_ips", ip)

def check_rules(data):
    for pattern in WAF_RULES:
        if pattern.lower() in data.lower():
            return True
    return False

@app.before_request
def waf_check():
    ip = request.remote_addr
    if is_blocked(ip):
        abort(403, "Your IP is blocked")

    # Объединяем все данные запроса для проверки
    data = request.path + " " + json.dumps(request.args) + " " + request.get_data(as_text=True)

    if check_rules(data):
        block_ip(ip)
        log_event({"ip": ip, "path": request.path, "event": "blocked by WAF"})
        abort(403, "Blocked by WAF")

    log_event({"ip": ip, "path": request.path, "event": "allowed"})

@app.route("/")
def index():
    return "Hello! This site is protected by simple WAF with Redis blocklist."

@app.route("/search")
def search():
    q = request.args.get('q', '')
    # Уязвимый пример (для теста SQLi)
    return f"Search results for: {q}"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
