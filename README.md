# Realidades Financieras — Demo de Login + 2FA

Demo visual (sin base de datos) de un flujo de acceso con **usuario/contraseña**
y **verificación en dos pasos (TOTP real)**, con diseño estilo industrial,
lista para presentar a clientes.

## Usuarios de prueba (fijos)

| Correo | Contraseña | Rol |
|---|---|---|
| admin@realidadesfinancieras.com | Admin123! | Administrador |
| gerente@realidadesfinancieras.com | Gerente123! | Gerente |
| contador@realidadesfinancieras.com | Contador123! | Contabilidad |
| auditor@realidadesfinancieras.com | Auditor123! | Auditoría |
| operador@realidadesfinancieras.com | Operador123! | Operaciones |

Cada usuario tiene un secreto TOTP **fijo** (no cambia entre reinicios del
servidor), por lo que puedes configurar Google Authenticator/Authy con
anticipación y el código seguirá funcionando el día de la demo.

## Preparar la demo (antes de presentar)

1. Corre el servidor (ver abajo).
2. Entra a `/setup-2fa`.
3. Elige un usuario y escanea su QR con Google Authenticator/Authy (o
   captura el secreto manualmente).
4. Repite para cada usuario que vayas a usar en la demo.

## Correr en local

```bash
npm install
npm start
```

Abre `http://localhost:3000/login`.

## Flujo de la demo

1. `/login` — usuario y contraseña.
2. `/login/2fa` — código de 6 dígitos de la app autenticadora.
3. `/dashboard` — panel protegido de ejemplo.

No hay base de datos ni persistencia: los usuarios están definidos en
`server.js` para que la demo sea rápida de levantar en cualquier máquina.
