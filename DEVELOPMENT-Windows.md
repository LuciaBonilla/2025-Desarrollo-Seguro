# 🚀 Ambiente de Desarrollo en Windows

## 🎯 Objetivo
Guía para configurar el ambiente, levantar los servicios, cargar datos de ejemplo y verificar la configuración del ambiente de desarollo.

---

## 📋 Prerrequisitos
- **Docker Desktop**
- **Puertos libres**:
  - 3000 → Frontend
  - 5000 → Backend
  - 5432 → PostgreSQL
  - 8025 → Mailhog
  - 1025 → emulador de SMTP

---

## 🐳 Instalación de Docker
Seguir la guía oficial de Windows

---

## 📦 Instalación de NVM, Node.js y npm
Instalar **nvm** (que incluye `npm` y `node`):  
👉 https://github.com/coreybutler/nvm-windows 

Instalar la versión LTS de Node.js:
```PS 
nvm install --lts
```

Verificar la instalación:
```PS
node -v
npm -v
npx -v
```

Instalar las dependencias de los proyectos backend y frontend (ambos relativos
a la raiz del repositorio):
```bash
cd services/backend
npm ci

cd services/frontend
npm ci
```

---

## 🛠️ Backend en el equipo de desarrollo

### 1. Configuración de variables de entorno
Crear el archivo **`services/backend/.env`** con el siguiente contenido:

```env
JWT_SECRET=supersecretkey
PORT=5000
DB_HOST=localhost
DB_USER=user
DB_PASS=password
DB_NAME=jwt_api
DB_PORT=5432
SMTP_HOST=localhost
SMTP_PORT=1025
SMTP_USER=seed
SMTP_PASS=seed
```

> ⚠️ La base de datos se utiliza siempre desde **Docker Compose**.  
> 💡 Se recomienda utilizar **VS Code** para el desarrollo.

---

### 2. Iniciar servicios auxiliares (DB, Mailhog, etc.)
```PS
docker-compose -f docker-compose.yaml up -d --build postgres mailhog master visa
```

---

### 3. Inicializar la base de datos
```PS
cd services/backend
npx knex --knexfile src/knexfile.ts migrate:latest
npx knex seed:run --knexfile src/knexfile.ts
```

---

### 4. Ejecutar el backend
Desde el directorio `services/backend`:
```PS
npm run dev
```

Verificar con un login de prueba:
```PS
Invoke-RestMethod -Uri "http://localhost:5000/auth/login" `
  -Method Post `
  -Headers @{ "Content-Type" = "application/json" } `
  -Body '{ "username": "test", "password": "password" }'
```

---

## 🎨 Frontend

### 1. Configuración de variables de entorno
Crear el archivo **`services/frontend/.env`** con el siguiente contenido:

```env
VITE_API_BASE_URL=http://localhost:5000
```

---

### 2. Ejecutar el frontend
En una nueva terminal (con el backend en ejecución):
```PS
cd services/frontend
npm ci
npm run dev
```

La aplicación estará disponible en 👉 **http://localhost:3000**

---