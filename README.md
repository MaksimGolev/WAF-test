# WAF-test

Simple Dockerized WAF + Web app + Redis example.

How to start
Clone the repository:

```
git clone <this repo>
cd <this repo>
```
Build and run all services:

```
docker compose up --build
```
## Usage
- Open http://localhost:8000 in your browser.
You will be automatically redirected to http://localhost:8080 (the web service).

- If you try to send a request that matches one of the patterns defined in /data/rules.json, your IP will be blocked by the WAF and you'll receive a 403 Forbidden response.

## Unblock yourself
To remove your IP from the block list, connect to Redis and delete the blocked_ips key:
```
docker compose exec redis redis-cli
DEL blocked_ips
```
After that, you can try again to open http://localhost:8000 and get redirected.

## How it works
- waf service inspects requests and blocks IPs based on rules defined in /data/rules.json.

- Blocked IPs are stored in Redis.

- web service is a simple backend running on port 8080.

- Logs are saved to /data/logs.json.