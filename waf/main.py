from flask import Flask, request, abort, redirect
import json
import redis
import os

app = Flask(__name__)

# Загрузка правил
rules_path = os.getenv("RULES_FILE", "/data/rules.json")
with open(rules_path) as f:
    rules = json.load(f)

# Подключение к Redis
r = redis.Redis(host="redis", port=6379, decode_responses=True)

logs = []

# Проверка
@app.before_request
def waf_filter():
    ip = request.remote_addr
    ua = request.headers.get("User-Agent", "")
    full_path = request.full_path

    print(f"[WAF] IP: {ip}, UA: {ua}, Path: {full_path}")

    log_entry = {
        "method": request.method,
        "url": request.url,
        "blocked": False
    }

    if r.sismember("blocked_ips", ip):
        print(f"[WAF] BLOCKED IP: {ip}")
        log_entry["blocked"] = True
        logs.append(log_entry)
        save_logs()
        abort(403)

    for rule in rules:
        if rule.lower() in full_path.lower() or rule.lower() in ua.lower():
            r.sadd("blocked_ips", ip)
            print(f"[WAF] BLOCKED by rule '{rule}': {ip}")
            log_entry["blocked"] = True
            logs.append(log_entry)
            save_logs()
            abort(403)
    
    logs.append(log_entry)
    save_logs()

def save_logs():
    with open("logs.json", "w") as file:
        json.dump(logs, file, indent=2)

@app.route("/")
def index():
    # Проксирование запроса на web
    return redirect("http://localhost:8080/", code=302)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
