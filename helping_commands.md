# 🐳 ERPNext Docker Compose Workflow

This documentation outlines how to manage an ERPNext environment using Docker Compose.

---

## 📦 Pull Docker Images

```bash
docker-compose pull
```

---

## 🛑 Stop and Remove Containers

```bash
docker compose -f pwd.yml down
```

---

## 🚀 Start Containers

Start normally:

```bash
docker compose -f pwd.yml up
```

Start in detached mode and rebuild:

```bash
docker-compose -f pwd.yml up -d --build
```

---

## 📋 List Running Containers

```bash
docker ps
```

---

## 🔍 Access Container Shell

Using container ID:

```bash
docker exec -it <container_id> bash
```

Using service name:

```bash
docker-compose exec backend bash
```

---

## 📂 View Site Data

```bash
docker-compose exec backend ls -la /home/frappe/frappe-bench/sites/
```

---

## 🧾 View Logs

From `site-creator` service:

```bash
docker-compose logs -f site-creator
```

From specific container:

```bash
docker logs --tail 50 docker-15-web-1
```

---

## 💾 Inspect Docker Volume

```bash
docker volume inspect docker-15_sites_volume
```

Edit site config:

```bash
sudo nano /var/lib/docker/volumes/docker-15_sites_volume/_data/site1.local/site_config.json
```

---

## 🛠 Bench Commands

### List Sites

```bash
docker-compose exec backend bench list-sites
```

### Create a New Site

```bash
docker-compose exec backend bench new-site site1.local \
  --mariadb-root-password root \
  --admin-password admin \
  --install-app erpnext
```

---

## 🧾 Full Workflow Example

```bash
# Start containers
docker-compose -f pwd.yml up -d --build

# Create a site
docker-compose exec backend bench new-site site1.local \
  --mariadb-root-password root \
  --admin-password admin \
  --install-app erpnext

# Verify the site
docker-compose exec backend bench list-sites

# Edit site config
sudo nano /var/lib/docker/volumes/docker-15_sites_volume/_data/site1.local/site_config.json

# View logs from Traefik
sudo docker logs -f frappe_cloudbookbd_com-traefik

# View logs from Traefik last 100 line

docker logs frappe_cloudbookbd_com-frontend --tail 100

# docker process list by filter 
docker ps | grep traefik


sudo docker cp 20250602_files.tar pos_com-backend:/home/frappe/


# 🧹 Cleanup Commands Warning: The following will delete all containers, volumes, and networks.
 
sudo docker system prune -a --volumes

sudo docker stop $(docker ps -aq)
sudo docker rm $(docker ps -aq)
sudo docker volume prune -f
sudo docker volume rm $(docker volume ls -q)
sudo docker network prune -f
sudo docker system prune -a --volumes -f









sleep 120; sudo docker logs test20_local-create-site | tail -n 100
sleep 60; sudo docker logs test20_local-app | tail -n 100
sudo docker logs test20_local-create-site | tail -n 200
curl -sS -H 'Host: test20.local' http://localhost:8081/api/method/ping
curl -sS -H 'Host: test20.local' http://localhost:8081/ | head -n 20
curl -sS -o /dev/null -w '%{http_code}\n' -H 'Host: test20.local' http://localhost:8081/
sudo docker logs test20_local-app | grep -i error | tail -n 20
sudo docker exec test20_local-app bash -lc "cd /home/frappe/frappe-bench && bench --site test20.local show-config"
sudo docker exec test20_local-app bash -lc "cd /home/frappe/frappe-bench && bench --site test20.local migrate"
curl -sS -H 'Host: test20.local' http://localhost:8081/ | head -n 10
curl -sS -H 'Host: test20.local' http://localhost:8081/login
curl -sS -H 'Host: test20.local' http://localhost:8081/ | grep -i "login to frappe" | head -n 5

# Restart all processes
sudo docker exec test25_local-app /home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf restart all

# Check status
sudo docker exec test25_local-app /home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf status



