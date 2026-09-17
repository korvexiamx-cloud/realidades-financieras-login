const path = require('path');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      totp_secret TEXT,
      totp_enabled BOOLEAN NOT NULL DEFAULT false
    );
  `);

  const { rows } = await pool.query('SELECT id FROM users WHERE email = $1', ['admin@realidadesfinancieras.com']);
  if (rows.length === 0) {
    const hash = bcrypt.hashSync('Admin123!', 12);
    await pool.query('INSERT INTO users (email, password_hash) VALUES ($1, $2)', ['admin@realidadesfinancieras.com', hash]);
  }
}

const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret-cambiar-en-produccion',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 30 * 60 * 1000 }
}));

function requireAuth(req, res, next) {
  if (req.session.userId) return next();
  res.redirect('/login');
}

async function getUserByEmail(email) {
  const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  return rows[0];
}

async function getUserById(id) {
  const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
  return rows[0];
}

// ---------- LOGIN: paso 1 (password) ----------
app.get('/login', (req, res) => {
  if (req.session.userId) return res.redirect('/dashboard');
  res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await getUserByEmail(email);

  if (!user || !bcrypt.compareSync(password || '', user.password_hash)) {
    return res.render('login', { error: 'Correo o contraseña incorrectos.' });
  }

  if (!user.totp_enabled) {
    // Primer login: forzar configuración de 2FA antes de dejarlo entrar
    req.session.setupUserId = user.id;
    return res.redirect('/setup-2fa');
  }

  req.session.pending2faUserId = user.id;
  res.redirect('/login/2fa');
});

// ---------- LOGIN: paso 2 (código TOTP) ----------
app.get('/login/2fa', (req, res) => {
  if (!req.session.pending2faUserId) return res.redirect('/login');
  res.render('verify', { error: null });
});

app.post('/login/2fa', async (req, res) => {
  const userId = req.session.pending2faUserId;
  if (!userId) return res.redirect('/login');

  const user = await getUserById(userId);
  const { token } = req.body;
  const valid = user.totp_secret && authenticator.check((token || '').trim(), user.totp_secret);

  if (!valid) {
    return res.render('verify', { error: 'Código incorrecto o expirado. Intenta de nuevo.' });
  }

  delete req.session.pending2faUserId;
  req.session.userId = user.id;
  res.redirect('/dashboard');
});

// ---------- CONFIGURACIÓN OBLIGATORIA DE 2FA (primer login) ----------
app.get('/setup-2fa', async (req, res) => {
  const userId = req.session.setupUserId;
  if (!userId) return res.redirect('/login');

  const user = await getUserById(userId);

  if (!req.session.tempTotpSecret) {
    req.session.tempTotpSecret = authenticator.generateSecret();
  }
  const secret = req.session.tempTotpSecret;
  const otpauth = authenticator.keyuri(user.email, 'Realidades Financieras', secret);
  const qrDataUrl = await QRCode.toDataURL(otpauth);

  res.render('setup-2fa', { qrDataUrl, secret, error: null });
});

app.post('/setup-2fa', async (req, res) => {
  const userId = req.session.setupUserId;
  const secret = req.session.tempTotpSecret;
  if (!userId || !secret) return res.redirect('/login');

  const { token } = req.body;
  const valid = authenticator.check((token || '').trim(), secret);

  if (!valid) {
    const user = await getUserById(userId);
    const qrDataUrl = await QRCode.toDataURL(authenticator.keyuri(user.email, 'Realidades Financieras', secret));
    return res.render('setup-2fa', { qrDataUrl, secret, error: 'Código incorrecto. Verifica la hora de tu teléfono e intenta de nuevo.' });
  }

  await pool.query('UPDATE users SET totp_secret = $1, totp_enabled = true WHERE id = $2', [secret, userId]);
  delete req.session.tempTotpSecret;
  delete req.session.setupUserId;
  req.session.userId = userId;
  res.redirect('/dashboard');
});

// ---------- DASHBOARD (protegido) ----------
app.get('/dashboard', requireAuth, async (req, res) => {
  const user = await getUserById(req.session.userId);
  res.render('dashboard', { user });
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

const PORT = process.env.PORT || 3000;
initDb()
  .then(() => {
    app.listen(PORT, () => console.log(`Realidades Financieras corriendo en http://localhost:${PORT}`));
  })
  .catch((err) => {
    console.error('Error inicializando la base de datos:', err);
    process.exit(1);
  });
