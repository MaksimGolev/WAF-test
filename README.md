# WAF-test
How to start?

```git clone this repo```

```
docker compose up --build
```
try to go link http://localhost:8000 you will redirect to http://localhost:8080

if you try using special from /data/rules.json in your request you will block 

then you need unblock use:
```
docker compose exec redis redis-cli 
DEL blocked_ips
```