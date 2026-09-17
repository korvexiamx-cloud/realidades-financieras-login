const path = require('path');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

const INVITE_HOURS_VALID = 72;

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT,
      totp_secret TEXT,
      totp_enabled BOOLEAN NOT NULL DEFAULT false,
      is_admin BOOLEAN NOT NULL DEFAULT false,
      invite_token TEXT,
      invite_expires TIMESTAMPTZ
    );
  `);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT false;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS invite_token TEXT;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS invite_expires TIMESTAMPTZ;`);
  await pool.query(`ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;`);

  const { rows } = await pool.query('SELECT id FROM users WHERE email = $1', ['admin@realidadesfinancieras.com']);
  if (rows.length === 0) {
    const hash = bcrypt.hashSync('Admin123!', 12);
    await pool.query('INSERT INTO users (email, password_hash, is_admin) VALUES ($1, $2, true)', ['admin@realidadesfinancieras.com', hash]);
  } else {
    await pool.query('UPDATE users SET is_admin = true WHERE email = $1', ['admin@realidadesfinancieras.com']);
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

async function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  const user = await getUserById(req.session.userId);
  if (!user || !user.is_admin) return res.status(403).send('No tienes permisos para ver esta página.');
  req.currentUser = user;
  next();
}

async function getUserByEmail(email) {
  const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  return rows[0];
}

async function getUserById(id) {
  const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
  return rows[0];
}

async function listUsers() {
  const { rows } = await pool.query('SELECT id, email, totp_enabled, is_admin, invite_token FROM users ORDER BY id');
  return rows;
}

// ---------- LOGIN: paso 1 (password) ----------
app.get('/login', (req, res) => {
  if (req.session.userId) return res.redirect('/dashboard');
  res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await getUserByEmail(email);

  if (!user || !user.password_hash || !bcrypt.compareSync(password || '', user.password_hash)) {
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

// ---------- INVITACIÓN: el usuario nuevo crea su propia contraseña ----------
app.get('/invite/:token', async (req, res) => {
  const { rows } = await pool.query(
    'SELECT * FROM users WHERE invite_token = $1 AND invite_expires > now()',
    [req.params.token]
  );
  const user = rows[0];
  if (!user) {
    return res.status(400).render('invite-invalid');
  }
  res.render('invite-set-password', { email: user.email, token: req.params.token, error: null });
});

app.post('/invite/:token', async (req, res) => {
  const { rows } = await pool.query(
    'SELECT * FROM users WHERE invite_token = $1 AND invite_expires > now()',
    [req.params.token]
  );
  const user = rows[0];
  if (!user) {
    return res.status(400).render('invite-invalid');
  }

  const { password, confirm } = req.body;
  if (!password || password.length < 8) {
    return res.render('invite-set-password', { email: user.email, token: req.params.token, error: 'La contraseña debe tener al menos 8 caracteres.' });
  }
  if (password !== confirm) {
    return res.render('invite-set-password', { email: user.email, token: req.params.token, error: 'Las contraseñas no coinciden.' });
  }

  const hash = bcrypt.hashSync(password, 12);
  await pool.query(
    'UPDATE users SET password_hash = $1, invite_token = NULL, invite_expires = NULL WHERE id = $2',
    [hash, user.id]
  );

  // Después de crear su contraseña, se le fuerza a configurar 2FA antes de entrar
  req.session.setupUserId = user.id;
  res.redirect('/setup-2fa');
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

// ---------- MI CUENTA: cambiar contraseña ----------
app.get('/account/password', requireAuth, (req, res) => {
  res.render('change-password', { error: null, success: false });
});

app.post('/account/password', requireAuth, async (req, res) => {
  const user = await getUserById(req.session.userId);
  const { currentPassword, newPassword, confirmPassword } = req.body;

  if (!user.password_hash || !bcrypt.compareSync(currentPassword || '', user.password_hash)) {
    return res.render('change-password', { error: 'Tu contraseña actual no es correcta.', success: false });
  }
  if (!newPassword || newPassword.length < 8) {
    return res.render('change-password', { error: 'La nueva contraseña debe tener al menos 8 caracteres.', success: false });
  }
  if (newPassword !== confirmPassword) {
    return res.render('change-password', { error: 'Las contraseñas nuevas no coinciden.', success: false });
  }

  const hash = bcrypt.hashSync(newPassword, 12);
  await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, user.id]);
  res.render('change-password', { error: null, success: true });
});

// ---------- ADMIN: crear y listar usuarios (por invitación, sin mostrar contraseñas) ----------
app.get('/admin/users', requireAdmin, async (req, res) => {
  res.render('admin-users', { users: await listUsers(), inviteLink: null, error: null });
});

app.post('/admin/users', requireAdmin, async (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();

  if (!email) {
    return res.render('admin-users', { users: await listUsers(), inviteLink: null, error: 'El correo es obligatorio.' });
  }

  const existing = await getUserByEmail(email);
  const token = crypto.randomBytes(24).toString('hex');
  const expiresSql = `now() + interval '${INVITE_HOURS_VALID} hours'`;

  if (existing) {
    if (existing.password_hash && existing.totp_enabled) {
      return res.render('admin-users', { users: await listUsers(), inviteLink: null, error: 'Ya existe un usuario activo con ese correo.' });
    }
    // Usuario invitado pero que nunca completó su registro: se le genera un nuevo link
    await pool.query(`UPDATE users SET invite_token = $1, invite_expires = ${expiresSql} WHERE id = $2`, [token, existing.id]);
  } else {
    await pool.query(
      `INSERT INTO users (email, invite_token, invite_expires) VALUES ($1, $2, ${expiresSql})`,
      [email, token]
    );
  }

  const inviteLink = `${req.protocol}://${req.get('host')}/invite/${token}`;
  res.render('admin-users', { users: await listUsers(), inviteLink: { email, url: inviteLink }, error: null });
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
