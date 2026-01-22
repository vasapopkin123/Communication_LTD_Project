Alon Marianchick 212345292
nadav mazuz 208752071
ido ben yishay 208837948
Sean fainbrun 209364470

https://github.com/vasapopkin123/Communication_LTD_Project/

# Run From Zero (Secure + Unsecure in parallel)

This guide contains everything needed to run **both systems** (Secure and Unsecure) from scratch using Docker:
- `.env` examples
- ports
- Docker/Compose commands
- troubleshooting

---

## 1) Prerequisites

1. Docker Desktop installed and running.
2. (Optional) Git, if you clone a repo.
3. Make sure these host ports are free:
   - **Secure**: `3000`, `5000`, `3306`
   - **Unsecure**: `3001`, `5001`, `3307`

---

## 2) Recommended folder layout (single root with 2 stacks)

```
project-root/
  secure/
    backend/
      main_secure.py
      security.py
      requirements.txt
      Dockerfile
    frontend/
      index.html
      system.html
      customers.html
      ...
    docker-compose.yml
    .env
  unsecure/
    backend/
      main_unsecure.py
      requirements.txt
      Dockerfile
    frontend/
      index.html
      system.html
      customers.html
      ...
    docker-compose.yml
    .env
```

You can also run everything with **one** central compose file (recommended for parallel run) — see section 5.

---

## 3) `.env` files (what to put there)

### 3.1 Secure: `secure/.env`

Example:

```
# ===== SMTP (optional) =====
# If SMTP_* are empty, the app should fall back to printing the “email” in backend logs.
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=your_user@example.com
SMTP_PASS=your_password_or_app_password
SMTP_FROM=your_user@example.com
```

### 3.2 Unsecure: `unsecure/.env`

Example:

```
# ===== MySQL (unsecure) =====
MYSQL_ROOT_PASSWORD=root_password
MYSQL_DATABASE=my_app_db_not_secure
MYSQL_USER=user
MYSQL_PASSWORD=password

# ===== SMTP (optional) =====
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=your_user@example.com
SMTP_PASS=your_password_or_app_password
SMTP_FROM=your_user@example.com
```

**Important:** If you leave `SMTP_PORT` empty (like `SMTP_PORT=`), Python may crash on `int("")`.
Either set a numeric port (recommended) or ensure your compose uses a default like `${SMTP_PORT:-587}`.

---

## 4) Run each system separately (using each folder’s docker-compose.yml)

### 4.1 Secure
From `secure/`:

```bash
docker compose down
docker compose up -d --build
docker logs -f my_backend_app
```

Open:
- UI: http://localhost:3000
- Swagger: http://localhost:5000/docs

### 4.2 Unsecure
From `unsecure/`:

```bash
docker compose down
docker compose up -d --build
docker logs -f my_backend_app_not_secure
```

Open:
- UI: http://localhost:3001
- Swagger: http://localhost:5001/docs

---

## 5) Run Secure + Unsecure in parallel (recommended)

The most stable setup is one compose file that defines:
- 2 MySQL containers
- 2 backend containers
- 2 frontend containers
with **unique ports and service names**.


### 5.2 Use the same backend Dockerfile for both stacks

In both:
- `secure/backend/Dockerfile`
- `unsecure/backend/Dockerfile`

Use:

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1

CMD ["sh", "-c", "uvicorn ${APP_MODULE}:app --host 0.0.0.0 --port 5000"]
```

### 5.3 Start everything
From `project-root/`:

```bash
cd ./secure/ or cd ./unsecure
docker compose -f docker-compose down
docker compose -f docker-compose up -d --build
```

Open:
- Secure UI: http://localhost:3000
- Secure Docs: http://localhost:5000/docs
- Unsecure UI: http://localhost:3001
- Unsecure Docs: http://localhost:5001/docs

---

## 6) Useful debugging commands

### 6.1 Container status and ports
```bash
docker ps
```

### 6.2 Backend logs
```bash
docker logs -f my_backend_app
docker logs -f my_backend_app_not_secure
```

### 6.3 Inspect env vars inside a container
```bash
docker exec -it my_backend_app sh -c 'printenv | sort'
```

### 6.4 Check MySQL from inside the DB container
```bash
docker exec -it my_mysql_db mysql -uuser -ppassword -e "SHOW DATABASES;"
docker exec -it my_mysql_db_not_secure mysql -uuser -ppassword -e "SHOW DATABASES;"
```

---

## 7) Common issues (quick fixes)

### 7.1 `/docs` not loading + `Could not import module "main"`
Cause: Docker runs `uvicorn main:app` but there is no `main.py`.
Fix: use `APP_MODULE` (section 5.2), or explicitly run:
- `uvicorn main_secure:app` (secure)
- `uvicorn main_unsecure:app` (unsecure)

### 7.2 Forgot Password returns 500 due to SMTP
Cause: invalid/missing `SMTP_HOST`, DNS failure inside container, or empty `SMTP_PORT`.
Fix:
- set SMTP_* in `.env`, or
- leave them empty and rely on the code’s console fallback, and
- in compose use `${SMTP_PORT:-587}` so it never becomes empty.

### 7.3 `Table ... doesn't exist`
Cause: schema not created yet, or backend connects to the wrong MySQL service.
Fix:
- ensure `DB_HOST` matches the compose service name (`mysql_secure` / `mysql_unsecure`)
- ensure the backend runs `ensure_schema()` on startup.

---

## 8) Quick start (TL;DR)

Parallel run:
1. Create `docker-compose.all.yml` in root (section 5.1)
2. Ensure the backend Dockerfile uses `APP_MODULE` (section 5.2)
3. Run:
   ```bash
   docker compose -f docker-compose.all.yml up -d --build
   ```
4. Open:
   - Secure: http://localhost:3000
   - Unsecure: http://localhost:3001

