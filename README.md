## Objetivo
Guía para levantar el proyecto, cargar datos de ejemplo y verificar el estado de la base de datos.

## Prerrequisitos
- Docker Desktop.
- Puertos libres: 3000 (frontend), 5000 (backend), 5432 (Postgres), 8025 (Mailhog)

## Inicio rápido (Docker)
1) Construir y levantar servicios
```
docker compose -f "docker-compose.yaml" up -d --build
```

2) Seed de datos (dentro del contenedor backend)
```
docker compose exec backend npx knex seed:run --knexfile src/knexfile.ts
```

3) Accesos
- Frontend: `http://localhost:3000`
- Backend: `http://localhost:5000`
- Swagger UI: `http://localhost:5000/api-docs`
- Mailhog (SMTP de pruebas): `http://localhost:8025`

## Verificación de base de datos (Postgres)
Conectarse al contenedor y listar tablas:
```
docker compose exec -it postgres psql -U user -d jwt_api
\dt
\d users
\d clinical_histories
\d clinical_history_files
\d invoices
```
Salir con `\q`.

Atajos desde host:
```
docker compose exec postgres psql -U user -d jwt_api -c "\dt"
docker compose exec postgres psql -U user -d jwt_api -c "SELECT table_name FROM information_schema.tables WHERE table_schema='public';"
```

## Troubleshooting
### El frontend no levanta tras el compose
- Revisar logs: `docker compose logs -f frontend` o `docker compose logs -f backend`
- Alternativamente, iniciar el contenedor desde la UI de Docker Desktop puede destrabar si la imagen quedó construida correctamente.

### Correr seed por fuera de Docker
No es necesario si estás usando Docker. Si igual querés hacerlo o te falló el paso de seedear el contenedor:
```
npx knex seed:run --knexfile src/knexfile.ts (Si tira error y hay dependencias que faltan instalar:)
npm install knex pg --save
npm install ts-node typescript @types/node --save-dev
npx tsc
npx ts-node ./node_modules/knex/bin/cli.js seed:run --knexfile src/knexfile.ts
```

### Backend local (sin Docker) + Debug en VS Code

#### Prerrequisitos
- Postgres y Mailhog corriendo en Docker (no levantes el backend en Docker a la vez).
- Node.js 18/20 y npm.

---

#### 1) Levantar Postgres y Mailhog en Docker
```powershell
cd C:\Users\Usuario\Desktop\desarrollo-seguro
docker compose up -d postgres mailhog
```

---

#### 2) Crear `.env` en `services/backend`
```ini
# services/backend/.env
# Usa .env.example como referencia para saber que varibles debes de tener configuradas como variables de entorno. 

---

#### 3) Instalar dependencias y preparar la base
```powershell
cd services\backend
npm ci
npx knex --knexfile src/knexfile.ts migrate:latest
# opcional: datos de ejemplo
npx knex --knexfile src/knexfile.ts seed:run
```

---

#### 4) Ejecutar el backend en modo desarrollo
```powershell
npx ts-node-dev src/index.ts
```
- Servidor en: `http://localhost:5000`

---

#### 5) Debug en VS Code
Creá `C:\Users\Usuario\Desktop\desarrollo-seguro\.vscode\launch.json`:
```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Backend (ts-node-dev)",
      "type": "node",
      "request": "launch",
      "runtimeExecutable": "npx",
      "runtimeArgs": [
        "ts-node-dev",
        "--respawn",
        "--transpile-only",
        "src/index.ts"
      ],
      "cwd": "${workspaceFolder}/services/backend",
      "envFile": "${workspaceFolder}/services/backend/.env",
      "console": "integratedTerminal"
    }
  ]
}
```
- En VS Code: Run and Debug → elegí “Backend (ts-node-dev)” → Play.
- Abrí `services/backend/src/index.ts` para poner breakpoints.

---
