require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const { Pool } = require('pg');

const app = express();
const port = Number(process.env.PORT || 3000);
const secret = process.env.JWT_SECRET;

if (!secret || secret.length < 32) {
  console.warn('JWT_SECRET devrait contenir au moins 32 caractères.');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 10,
  idleTimeoutMillis: 30000
});

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: process.env.CORS_ORIGIN || true }));
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: true,
  legacyHeaders: false
});
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20
});
app.use('/api', limiter);

const email = (value) => String(value || '').trim().toLowerCase();
const safeUser = (user) => ({
  id: user.id,
  firstName: user.first_name,
  lastName: user.last_name,
  email: user.email,
  role: user.role,
  level: user.level,
  objective: user.objective,
  subscription: user.subscription,
  xp: user.xp
});
const makeToken = (user) => jwt.sign({ id: user.id, role: user.role }, secret, { expiresIn: '7d' });

async function auth(req, res, next) {
  try {
    const header = req.get('authorization') || '';
    if (!header.startsWith('Bearer ')) throw new Error('Missing token');
    req.user = jwt.verify(header.slice(7), secret);
    next();
  } catch {
    res.status(401).json({ success: false, message: 'Session invalide' });
  }
}

function admin(req, res, next) {
  return req.user?.role === 'admin'
    ? next()
    : res.status(403).json({ success: false, message: 'Accès administrateur requis' });
}

app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ success: true, status: 'ok' });
  } catch {
    res.status(503).json({ success: false, status: 'database_unavailable' });
  }
});

app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const firstName = String(req.body.firstName || '').trim();
    const lastName = String(req.body.lastName || '').trim();
    const mail = email(req.body.email);
    const password = String(req.body.password || '');

    if (firstName.length < 2 || !/^\S+@\S+\.\S+$/.test(mail) || password.length < 8) {
      return res.status(400).json({ success: false, message: 'Prénom, email valide et mot de passe de 8 caractères requis.' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      'INSERT INTO users(first_name,last_name,email,password_hash) VALUES($1,$2,$3,$4) RETURNING *',
      [firstName, lastName, mail, passwordHash]
    );

    res.status(201).json({ success: true, token: makeToken(result.rows[0]), user: safeUser(result.rows[0]) });
  } catch (error) {
    res.status(error.code === '23505' ? 409 : 500).json({
      success: false,
      message: error.code === '23505' ? 'Email déjà utilisé' : 'Erreur serveur'
    });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM users WHERE email=$1', [email(req.body.email)]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(String(req.body.password || ''), user.password_hash))) {
      return res.status(401).json({ success: false, message: 'Email ou mot de passe incorrect' });
    }
    res.json({ success: true, token: makeToken(user), user: safeUser(user) });
  } catch {
    res.status(500).json({ success: false, message: 'Erreur serveur' });
  }
});

app.get('/api/me', auth, async (req, res) => {
  const result = await pool.query('SELECT * FROM users WHERE id=$1', [req.user.id]);
  if (!result.rows[0]) return res.status(404).json({ success: false });
  res.json({ success: true, user: safeUser(result.rows[0]) });
});

app.put('/api/me', auth, async (req, res) => {
  const result = await pool.query(
    `UPDATE users SET first_name=COALESCE(NULLIF($1,''),first_name), last_name=COALESCE($2,last_name), level=COALESCE($3,level), objective=COALESCE($4,objective), updated_at=NOW() WHERE id=$5 RETURNING *`,
    [String(req.body.firstName || ''), req.body.lastName, req.body.level, req.body.objective, req.user.id]
  );
  res.json({ success: true, user: safeUser(result.rows[0]) });
});

app.get('/api/courses', auth, async (req, res) => {
  const result = await pool.query(`SELECT c.*, COUNT(l.id)::int AS lesson_count FROM courses c LEFT JOIN lessons l ON l.course_id=c.id AND l.published=true WHERE c.published=true GROUP BY c.id ORDER BY c.id`);
  res.json({ success: true, courses: result.rows });
});

app.get('/api/courses/:id', auth, async (req, res) => {
  const course = await pool.query('SELECT * FROM courses WHERE id=$1 AND published=true', [req.params.id]);
  if (!course.rows[0]) return res.status(404).json({ success: false });
  const lessons = await pool.query('SELECT id,title,description,lesson_number,duration FROM lessons WHERE course_id=$1 AND published=true ORDER BY lesson_number', [req.params.id]);
  res.json({ success: true, course: { ...course.rows[0], lessons: lessons.rows } });
});

app.get('/api/lessons/:id', auth, async (req, res) => {
  const result = await pool.query('SELECT l.*, c.title AS course_title FROM lessons l JOIN courses c ON c.id=l.course_id WHERE l.id=$1 AND l.published=true', [req.params.id]);
  if (!result.rows[0]) return res.status(404).json({ success: false });
  res.json({ success: true, lesson: result.rows[0] });
});

app.post('/api/progress', auth, async (req, res) => {
  const lessonId = Number(req.body.lessonId);
  if (!Number.isInteger(lessonId)) return res.status(400).json({ success: false, message: 'Leçon invalide' });
  const completed = Boolean(req.body.completed);
  await pool.query(`INSERT INTO lesson_progress(user_id,lesson_id,completed,completed_at) VALUES($1,$2,$3,CASE WHEN $3 THEN NOW() ELSE NULL END) ON CONFLICT(user_id,lesson_id) DO UPDATE SET completed=EXCLUDED.completed,completed_at=EXCLUDED.completed_at,updated_at=NOW()`, [req.user.id, lessonId, completed]);
  if (completed) await pool.query('UPDATE users SET xp=xp+10,updated_at=NOW() WHERE id=$1', [req.user.id]);
  res.json({ success: true });
});

app.get('/api/progress', auth, async (req, res) => {
  const result = await pool.query('SELECT lesson_id,completed FROM lesson_progress WHERE user_id=$1', [req.user.id]);
  res.json({ success: true, progress: result.rows });
});

app.get('/api/exercises', auth, async (req, res) => {
  const result = await pool.query('SELECT id,title,question,options,explanation,xp FROM exercises WHERE published=true ORDER BY id');
  res.json({ success: true, exercises: result.rows });
});

app.get('/api/quizzes', auth, async (req, res) => {
  const result = await pool.query('SELECT id,title,description,level,duration,xp FROM quizzes WHERE published=true ORDER BY id');
  res.json({ success: true, quizzes: result.rows });
});

app.get('/api/admin/stats', auth, admin, async (req, res) => {
  const [users, courses, quizzes] = await Promise.all([
    pool.query("SELECT COUNT(*)::int AS count FROM users WHERE role='student'"),
    pool.query('SELECT COUNT(*)::int AS count FROM courses'),
    pool.query('SELECT COUNT(*)::int AS count FROM quizzes')
  ]);
  res.json({ success: true, students: users.rows[0].count, courses: courses.rows[0].count, quizzes: quizzes.rows[0].count });
});

app.get('/api/admin/users', auth, admin, async (req, res) => {
  const result = await pool.query('SELECT id,first_name,last_name,email,role,level,subscription,xp,created_at FROM users ORDER BY created_at DESC');
  res.json({ success: true, users: result.rows });
});

app.use((req, res, next) => {
  if (req.method === 'GET' && !req.path.startsWith('/api')) return res.sendFile(path.join(__dirname, 'public', 'index.html'));
  next();
});

(async () => {
  try {
    await pool.query('SELECT 1');
    const adminEmail = email(process.env.ADMIN_EMAIL);
    if (adminEmail && process.env.ADMIN_PASSWORD) {
      const found = await pool.query('SELECT id FROM users WHERE email=$1', [adminEmail]);
      if (!found.rows[0]) {
        const passwordHash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);
        await pool.query(`INSERT INTO users(first_name,last_name,email,password_hash,role,subscription,level) VALUES('Admin','EL PROF',$1,$2,'admin','premium','Bac')`, [adminEmail, passwordHash]);
      }
    }
    app.listen(port, '127.0.0.1', () => console.log(`EL PROF sur http://localhost:${port}`));
  } catch (error) {
    console.error(error);
    process.exit(1);
  }
})();
