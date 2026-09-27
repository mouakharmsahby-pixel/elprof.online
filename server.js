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

/* =========================================================
   CONFIGURATION
========================================================= */

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.warn(
    '⚠️ JWT_SECRET devrait contenir au moins 32 caractères.'
  );
}

/* =========================================================
   BASE DE DONNÉES
========================================================= */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,

  ssl:
    process.env.NODE_ENV === 'production'
      ? { rejectUnauthorized: false }
      : false,

  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

pool.on('error', (err) => {
  console.error('Erreur PostgreSQL inattendue :', err);
});

/* =========================================================
   APPLICATION EXPRESS
========================================================= */

app.set('trust proxy', 1);

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(
  cors({
    origin: process.env.CORS_ORIGIN || true,
    credentials: true
  })
);

app.use(
  express.json({
    limit: '1mb'
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: '1mb'
  })
);

app.use(
  express.static(path.join(__dirname, 'public'))
);

/* =========================================================
   RATE LIMITING
========================================================= */

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: true,
  legacyHeaders: false,

  message: {
    success: false,
    message: 'Trop de requêtes. Veuillez réessayer plus tard.'
  }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,

  message: {
    success: false,
    message: 'Trop de tentatives. Veuillez patienter quelques minutes.'
  }
});

app.use('/api', apiLimiter);

/* =========================================================
   UTILITAIRES
========================================================= */

function normalizeEmail(value) {
  return String(value || '')
    .trim()
    .toLowerCase();
}

function safeUser(user) {
  if (!user) return null;

  return {
    id: user.id,
    firstName: user.first_name,
    lastName: user.last_name,
    email: user.email,
    role: user.role,
    level: user.level,
    objective: user.objective,
    subscription: user.subscription,
    xp: user.xp
  };
}

function makeToken(user) {
  if (!JWT_SECRET) {
    throw new Error('JWT_SECRET manquant');
  }

  return jwt.sign(
    {
      id: user.id,
      role: user.role
    },
    JWT_SECRET,
    {
      expiresIn: '7d'
    }
  );
}

/* =========================================================
   AUTHENTIFICATION
========================================================= */

async function auth(req, res, next) {
  try {
    const authorization = req.get('authorization') || '';

    if (!authorization.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'Token manquant'
      });
    }

    if (!JWT_SECRET) {
      return res.status(500).json({
        success: false,
        message: 'Configuration serveur incorrecte'
      });
    }

    const token = authorization.slice(7).trim();

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Token invalide'
      });
    }

    req.user = jwt.verify(token, JWT_SECRET);

    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: 'Session invalide ou expirée'
    });
  }
}

/* =========================================================
   ADMIN
========================================================= */

function admin(req, res, next) {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({
      success: false,
      message: 'Accès administrateur requis'
    });
  }

  next();
}

/* =========================================================
   ROUTE DE TEST
========================================================= */

app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');

    res.json({
      success: true,
      status: 'ok',
      database: 'connected'
    });
  } catch (error) {
    console.error('Health check DB:', error);

    res.status(503).json({
      success: false,
      status: 'database_unavailable'
    });
  }
});

/* =========================================================
   INSCRIPTION
========================================================= */

app.post(
  '/api/auth/register',
  authLimiter,
  async (req, res) => {
    try {
      const firstName = String(
        req.body.firstName || ''
      ).trim();

      const lastName = String(
        req.body.lastName || ''
      ).trim();

      const mail = normalizeEmail(req.body.email);

      const password = String(
        req.body.password || ''
      );

      if (
        firstName.length < 2 ||
        !/^\S+@\S+\.\S+$/.test(mail) ||
        password.length < 8
      ) {
        return res.status(400).json({
          success: false,
          message:
            'Prénom, email valide et mot de passe de 8 caractères requis.'
        });
      }

      const existing = await pool.query(
        'SELECT id FROM users WHERE email=$1',
        [mail]
      );

      if (existing.rows.length > 0) {
        return res.status(409).json({
          success: false,
          message: 'Email déjà utilisé'
        });
      }

      const passwordHash = await bcrypt.hash(
        password,
        12
      );

      const result = await pool.query(
        `
        INSERT INTO users
          (first_name, last_name, email, password_hash)
        VALUES
          ($1, $2, $3, $4)
        RETURNING *
        `,
        [
          firstName,
          lastName,
          mail,
          passwordHash
        ]
      );

      const user = result.rows[0];

      res.status(201).json({
        success: true,
        token: makeToken(user),
        user: safeUser(user)
      });
    } catch (error) {
      console.error('Register error:', error);

      if (error.code === '23505') {
        return res.status(409).json({
          success: false,
          message: 'Email déjà utilisé'
        });
      }

      res.status(500).json({
        success: false,
        message: 'Erreur serveur'
      });
    }
  }
);

/* =========================================================
   CONNEXION
========================================================= */

app.post(
  '/api/auth/login',
  authLimiter,
  async (req, res) => {
    try {
      const mail = normalizeEmail(
        req.body.email
      );

      const password = String(
        req.body.password || ''
      );

      if (!mail || !password) {
        return res.status(400).json({
          success: false,
          message: 'Email et mot de passe requis'
        });
      }

      const result = await pool.query(
        'SELECT * FROM users WHERE email=$1',
        [mail]
      );

      const user = result.rows[0];

      if (
        !user ||
        !(await bcrypt.compare(
          password,
          user.password_hash
        ))
      ) {
        return res.status(401).json({
          success: false,
          message: 'Email ou mot de passe incorrect'
        });
      }

      res.json({
        success: true,
        token: makeToken(user),
        user: safeUser(user)
      });
    } catch (error) {
      console.error('Login error:', error);

      res.status(500).json({
        success: false,
        message: 'Erreur serveur'
      });
    }
  }
);

/* =========================================================
   PROFIL UTILISATEUR
========================================================= */

app.get(
  '/api/me',
  auth,
  async (req, res) => {
    try {
      const result = await pool.query(
        'SELECT * FROM users WHERE id=$1',
        [req.user.id]
      );

      const user = result.rows[0];

      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'Utilisateur introuvable'
        });
      }

      res.json({
        success: true,
        user: safeUser(user)
      });
    } catch (error) {
      console.error('Get profile error:', error);

      res.status(500).json({
        success: false,
        message: 'Erreur serveur'
      });
    }
  }
);

/* =========================================================
   MODIFICATION DU PROFIL
========================================================= */

app.put(
  '/api/me',
  auth,
  async (req, res) => {
    try {
      const firstName =
        req.body.firstName !== undefined
          ? String(req.body.firstName).trim()
          : '';

      const lastName =
        req.body.lastName !== undefined
          ? String(req.body.lastName).trim()
          : null;

      const level =
        req.body.level !== undefined
          ? String(req.body.level).trim()
          : null;

      const objective =
        req.body.objective !== undefined
          ? String(req.body.objective).trim()
          : null;

      const result = await pool.query(
        `
        UPDATE users
        SET
          first_name =
            COALESCE(NULLIF($1, ''), first_name),

          last_name =
            COALESCE($2, last_name),

          level =
            COALESCE($3, level),

          objective =
            COALESCE($4, objective),

          updated_at = NOW()

        WHERE id = $5

        RETURNING *
        `,
        [
          firstName,
          lastName,
          level,
          objective,
          req.user.id
        ]
      );

      if (!result.rows[0]) {
        return res.status(404).json({
          success: false,
          message: 'Utilisateur introuvable'
        });
      }

      res.json({
        success: true,
        user: safeUser(result.rows[0])
      });
    } catch (error) {
      console.error('Update profile error:', error);

      res.status(500).json({
        success: false,
        message: 'Erreur serveur'
      });
    }
  }
);

/* =========================================================
   COURS
========================================================= */

app.get(
  '/api/courses',
  auth,
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT
          c.*,
          COUNT(l.id)::int AS lesson_count

        FROM courses c

        LEFT JOIN lessons l
          ON l.course_id = c.id
          AND l.published = true

        WHERE c.published = true

        GROUP BY c.id

        ORDER BY c.id
      `);

      res.json({
        success: true,
        courses: result.rows
      });
    } catch (error) {
      console.error('Courses error:', error);

      res.status(500).json({
        success: false,
        message: 'Erreur lors du chargement des cours'
      });
    }
  }
);

/* =========================================================
   DÉTAIL D'UN COURS
========================================================= */

app.get(
  '/api/courses/:id',
  auth,
  async (req, res) => {
    try {
      const courseId = Number(
        req.params.id
      );

      if (!Number.isInteger(courseId)) {
        return res.status(400).json({
          success: false,
          message: 'ID de cours invalide'
        });
      }

      const course = await pool.query(
        `
        SELECT *
        FROM courses
        WHERE id=$1
          AND published=true
        `,
        [courseId]
      );

      if (!course.rows[0]) {
        return res.status(404).json({
          success: false,
          message: 'Cours introuvable'
        });
      }

      const lessons = await pool.query(
        `
        SELECT
          id,
          title,
          description,
          lesson_number,
          duration

        FROM lessons

        WHERE course_id=$1
          AND published=true

        ORDER BY lesson_number
        `,
        [courseId]
      );

      res.json({
        success: true,
        course: {
          ...course.rows[0],
          lessons: lessons.rows
        }
      });
    } catch (error) {
      console.error('Course detail error:', error);

      res.status(500).json({
        success: false,
        message: 'Erreur lors du chargement du cours'
      });
    }
  }
);

/* =========================================================
   LEÇON
========================================================= */

app.get(
  '/api/lessons/:id',
  auth,
  async (req, res) => {
    try {
      const lessonId = Number(
        req.params.id
      );

      if (!Number.isInteger(lessonId)) {
        return res.status(400).json({
          success: false,
          message: 'ID de leçon invalide'
        });
      }

      const result = await pool.query(
        `
        SELECT
          l.*,
          c.title AS course_title

        FROM lessons l

        JOIN courses c
          ON c.id = l.course_id

        WHERE l.id=$1
          AND l.published=true
          AND c.published=true
        `,
        [lessonId]
      );

      if (!result.rows[0]) {
        return res.status(404).json({
          success: false,
          message: 'Leçon introuvable'
        });
      }

      res.json({
        success: true,
        lesson: result.rows[0]
      });
    } catch (error) {
      console.error('Lesson error:', error);

      res.status(500).json({
        success: false,
        message: 'Erreur lors du chargement de la leçon'
      });
    }
  }
);

/* =========================================================
   PROGRESSION + XP
========================================================= */

app.post(
  '/api/progress',
  auth,
  async (req, res) => {
    const client = await pool.connect();

    try {
      const lessonId = Number(
        req.body.lessonId
      );

      if (!Number.isInteger(lessonId)) {
        return res.status(400).json({
          success: false,
          message: 'Leçon invalide'
        });
      }

      const completed =
        req.body.completed === true;

      await client.query('BEGIN');

      /*
       * Vérifier que la leçon existe
       * et qu'elle est publiée.
       */
      const lesson = await client.query(
        `
        SELECT id
        FROM lessons
        WHERE id=$1
          AND published=true
        `,
        [lessonId]
      );

      if (!lesson.rows[0]) {
        await client.query('ROLLBACK');

        return res.status(404).json({
          success: false,
          message: 'Leçon introuvable'
        });
      }

      /*
       * Récupérer l'état précédent.
       */
      const previous = await client.query(
        `
        SELECT completed
        FROM lesson_progress

        WHERE user_id=$1
          AND lesson_id=$2

        FOR UPDATE
        `,
        [
          req.user.id,
          lessonId
        ]
      );

      const wasCompleted =
        previous.rows[0]?.completed === true;

      /*
       * Enregistrer la progression.
       */
      await client.query(
        `
        INSERT INTO lesson_progress
          (
            user_id,
            lesson_id,
            completed,
            completed_at,
            updated_at
          )

        VALUES
          (
            $1,
            $2,
            $3,
            CASE
              WHEN $3 THEN NOW()
              ELSE NULL
            END,
            NOW()
          )

        ON CONFLICT(user_id, lesson_id)

        DO UPDATE SET
          completed = EXCLUDED.completed,

          completed_at =
            EXCLUDED.completed_at,

          updated_at = NOW()
        `,
        [
          req.user.id,
          lessonId,
          completed
        ]
      );

      /*
       * IMPORTANT :
       * +10 XP uniquement lors du
       * premier passage à terminé.
       */
      let xpAdded = 0;

      if (completed && !wasCompleted) {
        await client.query(
          `
          UPDATE users

          SET
            xp = xp + 10,
            updated_at = NOW()

          WHERE id=$1
          `,
          [req.user.id]
        );

        xpAdded = 10;
      }

      await client.query('COMMIT');

      res.json({
        success: true,
        completed,
        xpAdded
      });
    } catch (error) {
      try {
        await client.query('ROLLBACK');
      } catch {}

      console.error(
        'Progress error:',
        error
      );

      res.status(500).json({
        success: false,
        message:
          'Erreur lors de l’enregistrement de la progression'
      });
    } finally {
      client.release();
    }
  }
);

/* =========================================================
   RÉCUPÉRER LA PROGRESSION
========================================================= */

app.get(
  '/api/progress',
  auth,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          lesson_id,
          completed,
          completed_at,
          updated_at

        FROM lesson_progress

        WHERE user_id=$1

        ORDER BY lesson_id
        `,
        [req.user.id]
      );

      res.json({
        success: true,
        progress: result.rows
      });
    } catch (error) {
      console.error(
        'Progress retrieval error:',
        error
      );

      res.status(500).json({
        success: false,
        message: 'Erreur serveur'
      });
    }
  }
);

/* =========================================================
   EXERCICES
========================================================= */

app.get(
  '/api/exercises',
  auth,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          id,
          course_id,
          title,
          question,
          options,
          explanation,
          xp

        FROM exercises

        WHERE published=true

        ORDER BY id
        `
      );

      res.json({
        success: true,
        exercises: result.rows
      });
    } catch (error) {
      console.error(
        'Exercises error:',
        error
      );

      res.status(500).json({
        success: false,
        message:
          'Erreur lors du chargement des exercices'
      });
    }
  }
);

/* =========================================================
   QUIZ
========================================================= */

app.get(
  '/api/quizzes',
  auth,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          id,
          title,
          description,
          level,
          duration,
          xp

        FROM quizzes

        WHERE published=true

        ORDER BY id
        `
      );

      res.json({
        success: true,
        quizzes: result.rows
      });
    } catch (error) {
      console.error(
        'Quizzes error:',
        error
      );

      res.status(500).json({
        success: false,
        message:
          'Erreur lors du chargement des quiz'
      });
    }
  }
);

/* =========================================================
   ADMIN — STATISTIQUES
========================================================= */

app.get(
  '/api/admin/stats',
  auth,
  admin,
  async (req, res) => {
    try {
      const [
        users,
        courses,
        quizzes
      ] = await Promise.all([
        pool.query(
          `
          SELECT COUNT(*)::int AS count
          FROM users
          WHERE role='student'
          `
        ),

        pool.query(
          `
          SELECT COUNT(*)::int AS count
          FROM courses
          `
        ),

        pool.query(
          `
          SELECT COUNT(*)::int AS count
          FROM quizzes
          `
        )
      ]);

      res.json({
        success: true,
        students:
          users.rows[0].count,
        courses:
          courses.rows[0].count,
        quizzes:
          quizzes.rows[0].count
      });
    } catch (error) {
      console.error(
        'Admin stats error:',
        error
      );

      res.status(500).json({
        success: false,
        message: 'Erreur serveur'
      });
    }
  }
);

/* =========================================================
   ADMIN — UTILISATEURS
========================================================= */

app.get(
  '/api/admin/users',
  auth,
  admin,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          id,
          first_name,
          last_name,
          email,
          role,
          level,
          subscription,
          xp,
          created_at

        FROM users

        ORDER BY created_at DESC
        `
      );

      res.json({
        success: true,
        users: result.rows
      });
    } catch (error) {
      console.error(
        'Admin users error:',
        error
      );

      res.status(500).json({
        success: false,
        message: 'Erreur serveur'
      });
    }
  }
);

/* =========================================================
   ROUTE 404 API
========================================================= */

app.use(
  '/api',
  (req, res) => {
    res.status(404).json({
      success: false,
      message: 'Route API introuvable'
    });
  }
);

/* =========================================================
   FRONTEND
========================================================= */

app.use(
  (req, res, next) => {
    if (
      req.method === 'GET' &&
      !req.path.startsWith('/api')
    ) {
      return res.sendFile(
        path.join(
          __dirname,
          'public',
          'index.html'
        )
      );
    }

    next();
  }
);

/* =========================================================
   GESTIONNAIRE D'ERREUR GLOBAL
========================================================= */

app.use(
  (error, req, res, next) => {
    console.error(
      'Erreur globale:',
      error
    );

    if (res.headersSent) {
      return next(error);
    }

    res.status(500).json({
      success: false,
      message: 'Erreur interne du serveur'
    });
  }
);

/* =========================================================
   CRÉATION AUTOMATIQUE DE L'ADMIN
========================================================= */

async function ensureAdmin() {
  const adminEmail =
    normalizeEmail(
      process.env.ADMIN_EMAIL
    );

  const adminPassword =
    String(
      process.env.ADMIN_PASSWORD || ''
    );

  if (!adminEmail || !adminPassword) {
    console.log(
      'ℹ️ ADMIN_EMAIL / ADMIN_PASSWORD non configurés.'
    );

    return;
  }

  const found = await pool.query(
    `
    SELECT id
    FROM users
    WHERE email=$1
    `,
    [adminEmail]
  );

  if (found.rows[0]) {
    return;
  }

  const passwordHash =
    await bcrypt.hash(
      adminPassword,
      12
    );

  await pool.query(
    `
    INSERT INTO users
      (
        first_name,
        last_name,
        email,
        password_hash,
        role,
        subscription,
        level
      )

    VALUES
      (
        'Admin',
        'EL PROF',
        $1,
        $2,
        'admin',
        'premium',
        'Bac'
      )
    `,
    [
      adminEmail,
      passwordHash
    ]
  );

  console.log(
    `✅ Compte administrateur créé : ${adminEmail}`
  );
}

/* =========================================================
   DÉMARRAGE DU SERVEUR
========================================================= */

async function startServer() {
  try {
    await pool.query('SELECT 1');

    console.log(
      '✅ Connexion PostgreSQL réussie'
    );

    await ensureAdmin();

    app.listen(
      PORT,
      '0.0.0.0',
      () => {
        console.log(
          `🚀 EL PROF démarré sur le port ${PORT}`
        );
      }
    );
  } catch (error) {
    console.error(
      '❌ Impossible de démarrer EL PROF :',
      error
    );

    process.exit(1);
  }
}

/* =========================================================
   ARRÊT PROPRE
========================================================= */

async function shutdown(signal) {
  console.log(
    `\n${signal} reçu. Arrêt du serveur...`
  );

  try {
    await pool.end();

    console.log(
      'PostgreSQL fermé proprement.'
    );

    process.exit(0);
  } catch (error) {
    console.error(
      'Erreur lors de l’arrêt :',
      error
    );

    process.exit(1);
  }
}

process.on(
  'SIGTERM',
  () => shutdown('SIGTERM')
);

process.on(
  'SIGINT',
  () => shutdown('SIGINT')
);

/* =========================================================
   START
========================================================= */

startServer();
