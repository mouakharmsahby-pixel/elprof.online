CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  first_name VARCHAR(100) NOT NULL,
  last_name VARCHAR(100) NOT NULL DEFAULT '',
  email VARCHAR(255) NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role VARCHAR(20) NOT NULL DEFAULT 'student' CHECK (role IN ('student','admin')),
  level VARCHAR(50) NOT NULL DEFAULT 'Débutant',
  objective VARCHAR(255) NOT NULL DEFAULT 'Améliorer mon français',
  subscription VARCHAR(50) NOT NULL DEFAULT 'free',
  xp INTEGER NOT NULL DEFAULT 0 CHECK (xp >= 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS courses (
  id BIGSERIAL PRIMARY KEY,
  title VARCHAR(255) NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  level VARCHAR(50) NOT NULL DEFAULT 'Débutant',
  access VARCHAR(50) NOT NULL DEFAULT 'all',
  duration VARCHAR(50) NOT NULL DEFAULT '3 semaines',
  icon VARCHAR(20) NOT NULL DEFAULT '📚',
  published BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS lessons (
  id BIGSERIAL PRIMARY KEY,
  course_id BIGINT NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
  title VARCHAR(255) NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  lesson_number INTEGER NOT NULL DEFAULT 1,
  duration VARCHAR(50) NOT NULL DEFAULT '20 min',
  content TEXT NOT NULL DEFAULT '',
  published BOOLEAN NOT NULL DEFAULT TRUE,
  UNIQUE(course_id, lesson_number)
);

CREATE TABLE IF NOT EXISTS lesson_progress (
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  lesson_id BIGINT NOT NULL REFERENCES lessons(id) ON DELETE CASCADE,
  completed BOOLEAN NOT NULL DEFAULT FALSE,
  completed_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY(user_id, lesson_id)
);

CREATE TABLE IF NOT EXISTS exercises (
  id BIGSERIAL PRIMARY KEY,
  course_id BIGINT REFERENCES courses(id) ON DELETE SET NULL,
  title VARCHAR(255) NOT NULL,
  question TEXT NOT NULL,
  options JSONB NOT NULL DEFAULT '[]',
  correct_answer TEXT NOT NULL,
  explanation TEXT NOT NULL DEFAULT '',
  xp INTEGER NOT NULL DEFAULT 10,
  published BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS quizzes (
  id BIGSERIAL PRIMARY KEY,
  title VARCHAR(255) NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  level VARCHAR(50) NOT NULL DEFAULT 'Débutant',
  duration VARCHAR(50) NOT NULL DEFAULT '15 min',
  xp INTEGER NOT NULL DEFAULT 25,
  published BOOLEAN NOT NULL DEFAULT TRUE
);

INSERT INTO courses(title,description,level,access,duration,icon)
SELECT * FROM (VALUES
  ('Grammaire','Les règles essentielles pour construire des phrases correctes.','Débutant','all','3 semaines','📘'),
  ('Conjugaison','Les temps et les verbes expliqués simplement.','Intermédiaire','all','4 semaines','🧠'),
  ('Compréhension','Lire, comprendre et analyser un texte.','Intermédiaire','premium','2 semaines','🔎'),
  ('Expression écrite','Rédiger avec méthode et confiance.','Avancé','premium','5 semaines','✍️')
) AS seed(title,description,level,access,duration,icon)
WHERE NOT EXISTS (SELECT 1 FROM courses);

INSERT INTO lessons(course_id,title,description,lesson_number,duration,content)
SELECT c.id, v.title, v.description, v.number, v.duration, v.content
FROM courses c
JOIN (VALUES
  ('Grammaire','Les articles','Les articles définis et indéfinis.',1,'20 min','Un article accompagne le nom et indique son genre et son nombre.'),
  ('Grammaire','Les verbes','Identifier le verbe dans une phrase.',2,'25 min','Le verbe exprime une action ou un état.'),
  ('Conjugaison','Le présent','Conjuguer au présent.',1,'25 min','Le présent exprime une action actuelle ou habituelle.'),
  ('Conjugaison','Le passé composé','Construire le passé composé.',2,'30 min','Le passé composé utilise un auxiliaire et un participe passé.')
) AS v(course,title,description,number,duration,content)
  ON c.title = v.course
WHERE NOT EXISTS (SELECT 1 FROM lessons);

INSERT INTO exercises(course_id,title,question,options,correct_answer,explanation,xp)
SELECT c.id,
       'Présent simple',
       'Je ___ au collège chaque matin.',
       '["vais","va","allons","aller"]',
       'vais',
       'Avec je, on utilise vais.',
       10
FROM courses c
WHERE c.title = 'Grammaire'
  AND NOT EXISTS (SELECT 1 FROM exercises);

INSERT INTO quizzes(title,description,level,duration,xp)
SELECT * FROM (VALUES
  ('Quiz de grammaire','Testez vos bases grammaticales.','Débutant','15 min',25),
  ('Quiz de conjugaison','Présent et passé composé.','Intermédiaire','20 min',30)
) AS v(title,description,level,duration,xp)
WHERE NOT EXISTS (SELECT 1 FROM quizzes);
