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
```


docker system prune -a --volumes

docker stop $(docker ps -aq)
docker rm $(docker ps -aq)
docker volume prune -f
docker volume rm $(docker volume ls -q)
docker network prune -f
docker system prune -a --volumes -f


