
const express = require('express');
const path = require('path');
const { OpenAI } = require('openai');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;
const dbPath = path.resolve(__dirname, 'reichdb.sqlite');

// Initialize SQLite database
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Database connection error:', err);
    } else {
        console.log('Connected to SQLite database');
        // Create users table
        db.run(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT,
    email TEXT,
    full_name TEXT,
    location TEXT,
    title TEXT,
    achievements TEXT,
    stories TEXT,
    role TEXT DEFAULT 'user',
    oath_taken INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
`);
        // Create title_history table
        db.run(`
CREATE TABLE IF NOT EXISTS title_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    old_title TEXT,
    new_title TEXT,
    reason TEXT,
    modified_by INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (modified_by) REFERENCES users(id)
)
`);
    }
});

// Initialize OpenAI
const openai = new OpenAI({
	apiKey: process.env.DEEPSEEK_API_KEY,
	baseURL: "https://api.deepseek.com",
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>

    if (!token) {
        return res.status(401).json({ error: 'Токен не предоставлен' });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'partyreich_secret', (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Недействительный токен' });
        }
        req.user = user;
        next();
    });
};

// Admin Role Middleware
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Требуются права администратора' });
    }
    next();
};

// System prompt in Russian for title generation
const SYSTEM_PROMPT = `Ты - Party Kaiser, великий фюрер вечеринок и повелитель Пати-Райха. Ты командуешь дружбой, созываешь подданных на великие тусовки и даруешь титулы в соответствии с рассказами и достижениями людей.

    Контекст мира:
    - Ты как последний кайзер Германии Вильгельм, но для вечеринок
- В твоем мире есть Коньячные рыцари - любители выпить и потусить
- Есть старший и младший Папа из Ватикана - религиозные проводники
- Система титулов средневековая с графами, подданными, королями
- Священные реликвии: коньячный меч (стеклянный меч с коньяком) и первомеч (кортик)

Примеры титулов:
    "Дарья Первая, законная королева пати-райха, княжна станицы Магнитной, имперская мемелье, обладательница хорошего вкуса, мастер по реставрации, победившая бюрократию, покорительница горных хребтов, законная жена Патикайзера, родом из города Магнитогорск"

Твоя задача: на основе предоставленных достижений, историй и информации о человеке создать торжественный, величественный титул в стиле Пати-Райха. Титул должен:
    1. Быть на русском языке
2. Включать достижения человека
3. Быть торжественным и немного театральным
4. Соответствовать средневековому стилю с элементами вечеринок
5. Упоминать место происхождения если указано

Создай один титул, не более 2-3 строк.`;

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/hall-of-fame', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'hall_of_fame.html'));
});

app.get('/profile', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'profile.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Auth routes
app.post('/api/register', async (req, res) => {
    try {
        const { username, password, email, fullName, tempData } = req.body;

        if (!username || !password || !fullName || !tempData) {
            return res.status(400).json({ error: 'Все поля обязательны' });
        }

        // Check if username exists
        db.get('SELECT username FROM users WHERE username = ?', [username], async (err, row) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            if (row) {
                return res.status(400).json({ error: 'Имя пользователя уже занято' });
            }

            // Hash password
            const passwordHash = await bcrypt.hash(password, 10);

            // Insert user
            db.run(
                `INSERT INTO users (username, password_hash, email, full_name, location, title, achievements, stories, oath_taken)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)`,
                [username, passwordHash, email, fullName, tempData.location, tempData.title, tempData.achievements, tempData.stories],
                function(err) {
                    if (err) {
                        return res.status(500).json({ error: 'Ошибка создания аккаунта' });
                    }

                    const token = jwt.sign(
                        { id: this.lastID, username, role: 'user' },
                        process.env.JWT_SECRET || 'partyreich_secret',
                        { expiresIn: '24h' }
                    );

                    res.json({ success: true, token, user: { id: this.lastID, username, fullName, role: 'user' } });
                }
            );
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/login', (req, res) => {
    try {
        const { username, password } = req.body;

        db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            if (!user) {
                return res.status(401).json({ error: 'Неверное имя пользователя или пароль' });
            }

            const isValidPassword = await bcrypt.compare(password, user.password_hash);
            if (!isValidPassword) {
                return res.status(401).json({ error: 'Неверное имя пользователя или пароль' });
            }

            const token = jwt.sign(
                { id: user.id, username: user.username, role: user.role },
                process.env.JWT_SECRET || 'partyreich_secret',
                { expiresIn: '24h' }
            );

            res.json({
                success: true,
                token,
                user: {
                    id: user.id,
                    username: user.username,
                    fullName: user.full_name,
                    role: user.role
                }
            });
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Title generation (now stores in temp for account creation)
app.post('/generate-title', async (req, res) => {
    try {
        const { name, location, achievements, stories, requestType } = req.body;

        if (!name || !achievements) {
            return res.status(400).json({
                error: 'Имя и достижения обязательны для заполнения'
            });
        }

        // Create user prompt
        let userPrompt = `Даруй титул для: ${name}`;
        if (location) userPrompt += `\nМесто происхождения: ${location}`;
        userPrompt += `\nДостижения: ${achievements}`;
        if (stories) userPrompt += `\nИстории: ${stories}`;
        if (requestType) userPrompt += `\nТип запроса: ${requestType}`;

        // Generate title using OpenAI
        const completion = await openai.chat.completions.create({
            model: "deepseek-chat",
            messages: [
                {
                    role: "system",
                    content: SYSTEM_PROMPT
                },
                {
                    role: "user",
                    content: userPrompt
                }
            ],
            max_tokens: 20000,
            temperature: 0.8
        });

        const generatedTitle = completion.choices[0].message.content.trim();

        res.json({
            success: true,
            title: generatedTitle,
            oath: "Я клянусь быть с тобой мой Пати-кайзер, в радости и печали, болезни и здравии, в богатстве и бедности, любить тебя и оберегать наш союз до конца жизни, а так же клянусь в верности пати райху, обязаюсь верно и добросовестно поддерживать огонь пати харда в своем сердце и сердце своего кайзера.",
            tempData: { name, location, achievements, stories, title: generatedTitle }
        });

    } catch (error) {
        console.error('Error generating title:', error);
        res.status(500).json({
            error: 'Ошибка при генерации титула. Проверьте настройки API.'
        });
    }
});

// Protected routes
app.get('/api/profile', authenticateToken, (req, res) => {
    db.get('SELECT id, username, email, full_name, location, role, title, achievements, stories, created_at FROM users WHERE id = ?',
        [req.user.id], (err, user) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            if (!user) {
                return res.status(404).json({ error: 'User not found' });
            }
            res.json(user);
        }
    );
});

app.put('/api/profile', authenticateToken, (req, res) => {
    const { achievements, stories } = req.body;

    db.run(
        'UPDATE users SET achievements = ?, stories = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
        [achievements, stories, req.user.id],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            res.json({ success: true });
        }
    );
});

app.post('/api/expand-title', authenticateToken, async (req, res) => {
    try {
        const { achievements, stories } = req.body;

        // Get current user data
        db.get('SELECT * FROM users WHERE id = ?', [req.user.id], async (err, user) => {
            if (err || !user) {
                return res.status(500).json({ error: 'User not found' });
            }

            // Create prompt for title expansion
            let userPrompt = `Расширь существующий титул на основе новых достижений:

    Текущий титул: ${user.title}
Имя: ${user.full_name}
Место происхождения: ${user.location || 'Неизвестно'}
Старые достижения: ${user.achievements}
Старые истории: ${user.stories || 'Нет'}

Новые достижения: ${achievements}
Новые истории: ${stories || 'Нет'}

Создай расширенный титул, включающий как старые, так и новые заслуги.`;

            try {
                const completion = await openai.chat.completions.create({
                    model: "gpt-4.1",
                    messages: [
                        { role: "system", content: SYSTEM_PROMPT },
                        { role: "user", content: userPrompt }
                    ],
                    max_tokens: 25000,
                    temperature: 0.8
                });

                const newTitle = completion.choices[0].message.content.trim();

                // Save old title to history
                db.run(
                    'INSERT INTO title_history (user_id, old_title, new_title, reason, modified_by) VALUES (?, ?, ?, ?, ?)',
                    [user.id, user.title, newTitle, 'Расширение титула пользователем', user.id]
                );

                // Update user
                db.run(
                    'UPDATE users SET title = ?, achievements = ?, stories = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
                    [newTitle, user.achievements + '\n\n' + achievements, (user.stories || '') + '\n\n' + stories, user.id],
                    (err) => {
                        if (err) {
                            return res.status(500).json({ error: 'Database error' });
                        }
                        res.json({ success: true, newTitle });
                    }
                );
            } catch (apiError) {
                console.error('OpenAI error:', apiError);
                res.status(500).json({ error: 'Ошибка генерации нового титула' });
            }
        });
    } catch (error) {
        console.error('Expand title error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Hall of Fame
app.get('/api/hall-of-fame', (req, res) => {
    db.all(
        'SELECT id, username, full_name, location, title, created_at FROM users WHERE oath_taken = 1 ORDER BY created_at DESC',
        [],
        (err, users) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            res.json(users);
        }
    );
});

// Admin routes
app.get('/api/admin/users', authenticateToken, requireAdmin, (req, res) => {
    db.all(
        'SELECT id, username, full_name, location, title, role, oath_taken, created_at FROM users ORDER BY created_at DESC',
        [],
        (err, users) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            res.json(users);
        }
    );
});

app.put('/api/admin/users/:id/title', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { title, useAI, achievements, stories } = req.body;
        const userId = req.params.id;

        let finalTitle = title;

        if (useAI && achievements) {
            // Get user data
            const user = await new Promise((resolve, reject) => {
                db.get('SELECT * FROM users WHERE id = ?', [userId], (err, user) => {
                    if (err) reject(err);
                    else resolve(user);
                });
            });

            if (!user) {
                return res.status(404).json({ error: 'User not found' });
            }

            let userPrompt = `Создай новый титул для пользователя:
    Имя: ${user.full_name}
Место происхождения: ${user.location || 'Неизвестно'}
Достижения: ${achievements}`;

            if (stories) userPrompt += `\nИстории: ${stories}`;

            const completion = await openai.chat.completions.create({
                model: "gpt-4.1",
                messages: [
                    { role: "system", content: SYSTEM_PROMPT },
                    { role: "user", content: userPrompt }
                ],
                max_tokens: 20000,
                temperature: 0.8
            });

            finalTitle = completion.choices[0].message.content.trim();
        }

        // Get current title for history
        db.get('SELECT title FROM users WHERE id = ?', [userId], (err, currentUser) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }

            // Save to history
            db.run(
                'INSERT INTO title_history (user_id, old_title, new_title, reason, modified_by) VALUES (?, ?, ?, ?, ?)',
                [userId, currentUser?.title, finalTitle, 'Изменение администратором', req.user.id]
            );

            // Update user
            db.run(
                'UPDATE users SET title = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
                [finalTitle, userId],
                (err) => {
                    if (err) {
                        return res.status(500).json({ error: 'Database error' });
                    }
                    res.json({ success: true, newTitle: finalTitle });
                }
            );
        });
    } catch (error) {
        console.error('Admin title update error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.get('/api/admin/title-history/:id', authenticateToken, requireAdmin, (req, res) => {
    const userId = req.params.id;

    db.all(
        `SELECT th.*, u.username as modified_by_username
FROM title_history th
LEFT JOIN users u ON th.modified_by = u.id
WHERE th.user_id = ?
    ORDER BY th.created_at DESC`,
        [userId],
        (err, history) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            res.json(history);
        }
    );
});

app.listen(port, () => {
    console.log(`Partyreich Title Generator running on http://localhost:${port}`);
    console.log('Make sure to set your OPENAI_API_KEY in .env file');
});
