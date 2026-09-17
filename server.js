const path = require('path');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');

// ---------------------------------------------------------------------------
// DEMO: 5 usuarios fijos en memoria (sin base de datos).
// Cada usuario tiene un secreto TOTP fijo para que el QR no cambie entre
// reinicios: se puede configurar Google Authenticator/Authy ANTES de la demo
// y seguirá funcionando el día de la presentación.
// ---------------------------------------------------------------------------
const USERS = [
  {
    id: 1,
    email: 'admin@realidadesfinancieras.com',
    name: 'Administrador General',
    role: 'Administrador',
    password: 'Admin123!',
    totpSecret: 'WTGPMWHLG5P7DR2X',
  },
  {
    id: 2,
    email: 'gerente@realidadesfinancieras.com',
    name: 'Gerente de Cuenta',
    role: 'Gerente',
    password: 'Gerente123!',
    totpSecret: 'JHEIV6ICVT5YUAJS',
  },
  {
    id: 3,
    email: 'contador@realidadesfinancieras.com',
    name: 'Contador General',
    role: 'Contabilidad',
    password: 'Contador123!',
    totpSecret: 'P7CWJYJACN4NEBNB',
  },
  {
    id: 4,
    email: 'auditor@realidadesfinancieras.com',
    name: 'Auditor Interno',
    role: 'Auditoría',
    password: 'Auditor123!',
    totpSecret: '4BUYEF267V5NRCXB',
  },
  {
    id: 5,
    email: 'operador@realidadesfinancieras.com',
    name: 'Operador de Planta',
    role: 'Operaciones',
    password: 'Operador123!',
    totpSecret: 'IXFNLPWIRIPYICER',
  },
];

// Precalcular el hash de cada contraseña una sola vez al arrancar.
USERS.forEach((u) => {
  u.passwordHash = bcrypt.hashSync(u.password, 10);
});

function findUserByEmail(email) {
  return USERS.find((u) => u.email.toLowerCase() === String(email || '').trim().toLowerCase());
}

function findUserById(id) {
  return USERS.find((u) => u.id === Number(id));
}

const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret-solo-para-demo',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 30 * 60 * 1000 },
}));

function requireAuth(req, res, next) {
  if (req.session.userId) return next();
  res.redirect('/login');
}

// ---------- LOGIN: paso 1 (usuario y contraseña) ----------
app.get('/login', (req, res) => {
  if (req.session.userId) return res.redirect('/dashboard');
  res.render('login', { error: null, users: USERS });
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  const user = findUserByEmail(email);

  if (!user || !bcrypt.compareSync(password || '', user.passwordHash)) {
    return res.render('login', { error: 'Usuario o contraseña incorrectos.', users: USERS });
  }

  req.session.pending2faUserId = user.id;
  res.redirect('/login/2fa');
});

// ---------- LOGIN: paso 2 (código de verificación TOTP) ----------
app.get('/login/2fa', (req, res) => {
  const user = findUserById(req.session.pending2faUserId);
  if (!user) return res.redirect('/login');
  res.render('verify', { error: null, email: user.email });
});

app.post('/login/2fa', (req, res) => {
  const user = findUserById(req.session.pending2faUserId);
  if (!user) return res.redirect('/login');

  const { token } = req.body;
  const valid = authenticator.check((token || '').trim(), user.totpSecret);

  if (!valid) {
    return res.render('verify', { error: 'Código incorrecto o expirado. Intenta de nuevo.', email: user.email });
  }

  delete req.session.pending2faUserId;
  req.session.userId = user.id;
  res.redirect('/dashboard');
});

// ---------- CONFIGURACIÓN DE 2FA (para preparar la demo con antelación) ----------
// No requiere sesión iniciada: sirve para que, antes de la demo, se escaneen
// los 5 códigos QR desde una app autenticadora (Google Authenticator / Authy).
app.get('/setup-2fa', (req, res) => {
  res.render('setup-2fa-index', { users: USERS });
});

app.get('/setup-2fa/:id', async (req, res) => {
  const user = findUserById(req.params.id);
  if (!user) return res.redirect('/setup-2fa');

  const otpauth = authenticator.keyuri(user.email, 'Realidades Financieras', user.totpSecret);
  const qrDataUrl = await QRCode.toDataURL(otpauth);

  res.render('setup-2fa', { user, qrDataUrl, secret: user.totpSecret });
});

// ---------- DASHBOARD (protegido) ----------
app.get('/dashboard', requireAuth, (req, res) => {
  const user = findUserById(req.session.userId);
  res.render('dashboard', { user });
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Realidades Financieras (demo) corriendo en http://localhost:${PORT}`));
