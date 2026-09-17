# Realidades Financieras — Login demo con 2FA

Demo de login con verificación en dos pasos (TOTP) obligatoria, hecho con Express + SQLite.

## Correr localmente

```bash
npm install
npm start
```

Abre `http://localhost:3000/login`.

Usuario demo: `admin@realidadesfinancieras.com` / `Admin123!`

## Notas de producción

- Cambia `SESSION_SECRET` por una variable de entorno real.
- La base de datos SQLite (`data.sqlite`) es solo para desarrollo; migrar a Postgres antes de tener datos reales de clientes.
- El usuario demo se crea automáticamente al primer arranque; bórralo o cámbiale la contraseña en producción.
