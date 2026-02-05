Вот мой server.js:
// 🔐 БЕЗОПАСНОСТЬ: Все необходимые импорты
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const bodyParser = require('body-parser');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const CryptoJS = require('crypto-js');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');
const winston = require('winston');
const { v4: uuidv4 } = require('uuid');
const compression = require('compression');
const { lock, unlock } = require('proper-lockfile');
const cookieParser = require('cookie-parser');
const DOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const sqlite3 = require('@journeyapps/sqlcipher');
const util = require('util');

// 🔐 Загружаем секреты из .env файла
require('dotenv').config();

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;

// 🔐 Константы для времени жизни токенов
const ACCESS_TOKEN_EXPIRY = '30m'; // 30 минут
const REFRESH_TOKEN_EXPIRY = '14d'; // 14 дней
const TEMP_TOKEN_EXPIRY = '15m'; // 15 минут для временных токенов (2FA, reset)
const CSRF_TOKEN_EXPIRY = '4h'; // 4 часа для CSRF токенов

// 🔐 Настройка логгера для аудита безопасности
const securityLogger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ 
            filename: 'logs/security.log',
            level: 'warn'
        }),
        new winston.transports.File({ 
            filename: 'logs/crypto-operations.log',
            level: 'info'
        }),
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
            )
        })
    ]
});

// 🔐 Секретные ключи из .env файла
const SECRET_KEY = process.env.SECRET_KEY || crypto.randomBytes(64).toString('hex');
const JWT_SECRET = process.env.JWT_SECRET || SECRET_KEY;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || crypto.randomBytes(64).toString('hex');
const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASSWORD = process.env.EMAIL_PASSWORD;
const DB_ENCRYPTION_KEY = process.env.DB_ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
const CSRF_SECRET = process.env.CSRF_SECRET || crypto.randomBytes(32).toString('hex');

// 🔐 Проверка наличия критических секретов
if (!EMAIL_USER || !EMAIL_PASSWORD) {
    console.error('❌ КРИТИЧЕСКАЯ ОШИБКА: Не настроены email credentials в .env файле');
    process.exit(1);
}

if (!DB_ENCRYPTION_KEY) {
    console.error('❌ КРИТИЧЕСКАЯ ОШИБКА: Не настроен DB_ENCRYPTION_KEY в .env файле');
    process.exit(1);
}

// 🔐 Генерация уникальных ключей для завещаний
const LEGACY_KEY_SECRET = process.env.LEGACY_KEY_SECRET || crypto.randomBytes(32).toString('hex');

// 🔐 Безопасное шифрование паролей
const SALT_ROUNDS = process.env.NODE_ENV === 'production' ? 14 : 10;

// 🔐 SQLCipher подключение
const db = new sqlite3.Database('./data/legacy.db', (err) => {
    if (err) {
        console.error('❌ Ошибка подключения к БД:', err);
        process.exit(1);
    }
    console.log('✅ Подключено к SQLCipher БД');
});

// 🔐 Устанавливаем ключ шифрования для базы данных
db.run(`PRAGMA key = '${DB_ENCRYPTION_KEY}'`);
db.run('PRAGMA cipher_compatibility = 4');
db.run('PRAGMA journal_mode = WAL');
db.run('PRAGMA foreign_keys = ON');

// 🔐 Промисификация методов БД
const dbRun = util.promisify(db.run.bind(db));
const dbGet = util.promisify(db.get.bind(db));
const dbAll = util.promisify(db.all.bind(db));

// 🔐 Создание таблиц при старте
async function initializeDatabase() {
    try {
        // Таблица пользователей
        await dbRun(`
            CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                encrypted TEXT,
                contacts TEXT DEFAULT '[]',
                registration_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login DATETIME,
                last_activity DATETIME,
                subscription TEXT DEFAULT 'free',
                subscription_expiry DATETIME,
                two_factor_enabled BOOLEAN DEFAULT 1,
                two_factor_secret TEXT,
                verification_code TEXT,
                verification_code_expiry DATETIME,
                verification_code_attempts INTEGER DEFAULT 0,
                alive_check_token TEXT,
                is_admin BOOLEAN DEFAULT 0,
                personal_data TEXT DEFAULT '{"isAnonymous":true,"searchMethods":["email"]}',
                activation_methods TEXT DEFAULT '["email_check"]',
                email_check_settings TEXT DEFAULT '{"interval":"30","gracePeriod":"30"}',
                master_password_hash TEXT,
                legacy_encrypted TEXT,
                encryption_method TEXT DEFAULT 'no_encryption',
                legacy_last_updated DATETIME,
                user_salt TEXT,
                token_version INTEGER DEFAULT 0,
                last_alive_check_sent DATETIME,
                last_alive_check_confirmed DATETIME,
                next_alive_check_date DATETIME,
                login_attempts INTEGER DEFAULT 0,
                last_failed_login DATETIME,
                verified BOOLEAN DEFAULT 1,
                banned BOOLEAN DEFAULT 0,
                deceased BOOLEAN DEFAULT 0,
                death_verified_at DATETIME,
                death_verification_id TEXT,
                death_verification_code TEXT,
                trusted_contacts TEXT DEFAULT '[]',
                legacy_key TEXT,
                legacy_migrated BOOLEAN DEFAULT 0,
                legacy_key_secret TEXT
            )
        `);

        // Таблица claims (претензий на завещания)
        await dbRun(`
            CREATE TABLE IF NOT EXISTS claims (
                claim_code TEXT PRIMARY KEY,
                encrypted TEXT NOT NULL,
                encryption_method TEXT NOT NULL,
                method TEXT,
                shared_key TEXT,
                master_password TEXT,
                master_password_hash TEXT,
                contacts TEXT DEFAULT '[]',
                expires BIGINT NOT NULL,
                user_email TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                source TEXT,
                viewed BOOLEAN DEFAULT 0,
                viewed_at DATETIME,
                owner_premium BOOLEAN DEFAULT 0
            )
        `);

        // Таблица death_verifications (подтверждения смерти)
        await dbRun(`
            CREATE TABLE IF NOT EXISTS death_verifications (
                id TEXT PRIMARY KEY,
                user_email TEXT NOT NULL,
                verification_method TEXT NOT NULL,
                verification_details TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                reviewed_at DATETIME,
                reviewed_by TEXT,
                rejection_reason TEXT,
                claim_code TEXT,
                heirs_contacts TEXT DEFAULT '[]'
            )
        `);

        // Таблица support_requests (обращения в поддержку)
        await dbRun(`
            CREATE TABLE IF NOT EXISTS support_requests (
                id TEXT PRIMARY KEY,
                user_email TEXT NOT NULL,
                subject TEXT NOT NULL,
                message TEXT NOT NULL,
                date DATETIME DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'open',
                response TEXT,
                responded_at DATETIME,
                admin_email TEXT
            )
        `);

        // Таблица trusted_contacts (доверенные контакты)
        await dbRun(`
            CREATE TABLE IF NOT EXISTS trusted_contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_email TEXT NOT NULL,
                contact_email TEXT NOT NULL,
                contact_phone TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Таблица token_blacklist (черный список токенов)
        await dbRun(`
            CREATE TABLE IF NOT EXISTS token_blacklist (
                token TEXT PRIMARY KEY,
                expires INTEGER NOT NULL,
                added_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Таблица alive_checks для персистентности проверок активности
        await dbRun(`
            CREATE TABLE IF NOT EXISTS alive_checks (
                email TEXT PRIMARY KEY,
                last_check DATETIME,
                next_check DATETIME,
                token TEXT
            )
        `);

        // Таблица csrf_tokens для хранения CSRF токенов в БД
        await dbRun(`
            CREATE TABLE IF NOT EXISTS csrf_tokens (
                token TEXT PRIMARY KEY,
                user_email TEXT NOT NULL,
                expires INTEGER NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Создаем индексы для оптимизации
        await dbRun('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)');
        await dbRun('CREATE INDEX IF NOT EXISTS idx_claims_expires ON claims(expires)');
        await dbRun('CREATE INDEX IF NOT EXISTS idx_claims_user_email ON claims(user_email)');
        await dbRun('CREATE INDEX IF NOT EXISTS idx_claims_viewed ON claims(viewed)');
        await dbRun('CREATE INDEX IF NOT EXISTS idx_death_verifications_status ON death_verifications(status)');
        await dbRun('CREATE INDEX IF NOT EXISTS idx_token_blacklist_expires ON token_blacklist(expires)');
        await dbRun('CREATE INDEX IF NOT EXISTS idx_csrf_tokens_user ON csrf_tokens(user_email)');
        await dbRun('CREATE INDEX IF NOT EXISTS idx_csrf_tokens_expires ON csrf_tokens(expires)');

        console.log('✅ Все таблицы созданы/проверены с индексами');
    } catch (error) {
        console.error('❌ Ошибка инициализации базы данных:', error);
        process.exit(1);
    }
}

// 🔐 Кэширование для rate limiting
const NodeCache = require('node-cache');
const cache = new NodeCache({ 
    stdTTL: 300, // 5 минут
    checkperiod: 60,
    useClones: false 
});

// 🔐 CSRF токены (сессионные для аутентифицированных пользователей)
const csrfTokens = new NodeCache({
    stdTTL: 4 * 60 * 60, // 4 часа
    checkperiod: 30 * 60 // проверка каждые 30 минут
});

// Хранилище для проверки активности (временное, для токенов подтверждения)
let aliveCheckTokens = {};

// 🔐 Временные данные для регистрации
let pendingRegistrations = {};

// 🔐 Настройка multer для загрузки файлов
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir = './uploads';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const hashedName = crypto.createHash('sha256').update(file.originalname + uniqueSuffix).digest('hex');
    cb(null, hashedName + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/jpg', 'application/pdf'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Разрешены только JPG, PNG и PDF файлы'), false);
    }
  }
});

// 🔐 Функция для защиты от XSS
const window = new JSDOM('').window;
const purify = DOMPurify(window);

function sanitizeInput(input) {
    if (typeof input === 'string') {
        return purify.sanitize(input, {
            ALLOWED_TAGS: [],
            ALLOWED_ATTR: []
        });
    }
    return input;
}

function sanitizeObject(obj) {
    for (let key in obj) {
        if (typeof obj[key] === 'string') {
            obj[key] = sanitizeInput(obj[key]);
        } else if (typeof obj[key] === 'object' && obj[key] !== null) {
            sanitizeObject(obj[key]);
        }
    }
}

// 🔐 Санитизация данных завещания перед отправкой клиенту
const sanitizeLegacyData = (data) => {
    if (!data || typeof data !== 'object') return data;
    
    const sanitized = {};
    
    // Обрабатываем социальные сети
    if (data.social && Array.isArray(data.social)) {
        sanitized.social = data.social.map(account => ({
            name: purify.sanitize(account.name || '', { ALLOWED_TAGS: [] }),
            login: purify.sanitize(account.login || '', { ALLOWED_TAGS: [] }),
            password: purify.sanitize(account.password || '', { ALLOWED_TAGS: [] }),
            instructions: purify.sanitize(account.instructions || '', { ALLOWED_TAGS: [] })
        }));
    }
    
    // Обрабатываем криптокошельки (сид-фразы не санитизируем)
    if (data.crypto && Array.isArray(data.crypto)) {
        sanitized.crypto = data.crypto.map(wallet => ({
            name: purify.sanitize(wallet.name || '', { ALLOWED_TAGS: [] }),
            address: purify.sanitize(wallet.address || '', { ALLOWED_TAGS: [] }),
            seed: wallet.seed || '', // Сид-фразу не санитизируем
            instructions: purify.sanitize(wallet.instructions || '', { ALLOWED_TAGS: [] })
        }));
    }
    
    // Обрабатываем пароли и сообщения
    if (data.credentials) {
        sanitized.credentials = purify.sanitize(data.credentials, { ALLOWED_TAGS: [] });
    }
    
    if (data.messages) {
        sanitized.messages = purify.sanitize(data.messages, { ALLOWED_TAGS: [] });
    }
    
    return sanitized;
};

// 🔐 Middleware для санитизации
app.use((req, res, next) => {
  if (req.body) sanitizeObject(req.body);
  if (req.query) sanitizeObject(req.query);
  if (req.params) sanitizeObject(req.params);
  next();
});

// 🔐 Функции загрузки данных из БД
let users = {};
let supportRequests = {};
let deathVerifications = {};
let trustedContacts = {};
let claims = {};

// ========== 🔐 УСИЛЕННАЯ CSRF ЗАЩИТА ==========

async function loadAllData() {
    try {
        // Загружаем пользователей
        const usersRows = await dbAll('SELECT * FROM users');
        users = {};
        usersRows.forEach(row => {
            users[row.email] = {
                password: row.password,
                encrypted: row.encrypted,
                contacts: JSON.parse(row.contacts || '[]'),
                registrationDate: row.registration_date,
                lastLogin: row.last_login,
                lastActivity: row.last_activity,
                subscription: row.subscription || 'free',
                subscriptionExpiry: row.subscription_expiry,
                twoFactorEnabled: row.two_factor_enabled !== 0,
                twoFactorSecret: row.two_factor_secret,
                verificationCode: row.verification_code,
                verificationCodeExpiry: row.verification_code_expiry,
                verificationCodeAttempts: row.verification_code_attempts || 0,
                aliveCheckToken: row.alive_check_token,
                isAdmin: row.is_admin === 1,
                personalData: JSON.parse(row.personal_data || '{"isAnonymous":true,"searchMethods":["email"]}'),
                activationMethods: JSON.parse(row.activation_methods || '["email_check"]'),
                emailCheckSettings: JSON.parse(row.email_check_settings || '{"interval":"30","gracePeriod":"30"}'),
                masterPasswordHash: row.master_password_hash,
                legacyEncrypted: row.legacy_encrypted,
                encryptionMethod: row.encryption_method || 'no_encryption',
                legacyLastUpdated: row.legacy_last_updated,
                userSalt: row.user_salt,
                tokenVersion: row.token_version || 0,
                lastAliveCheckSent: row.last_alive_check_sent,
                lastAliveCheckConfirmed: row.last_alive_check_confirmed,
                nextAliveCheckDate: row.next_alive_check_date,
                loginAttempts: row.login_attempts || 0,
                lastFailedLogin: row.last_failed_login,
                verified: row.verified === 1,
                banned: row.banned === 1,
                deceased: row.deceased === 1,
                deathVerifiedAt: row.death_verified_at,
                deathVerificationId: row.death_verification_id,
                deathVerificationCode: row.death_verification_code,
                trustedContacts: JSON.parse(row.trusted_contacts || '[]'),
                legacyKey: row.legacy_key,
                legacyMigrated: row.legacy_migrated === 1,
                legacyKeySecret: row.legacy_key_secret
            };
        });

        // Загружаем claims
        const claimsRows = await dbAll('SELECT * FROM claims');
        claims = {};
        claimsRows.forEach(row => {
            claims[row.claim_code] = {
                claimCode: row.claim_code,
                encrypted: row.encrypted,
                encryptionMethod: row.encryption_method,
                method: row.method,
                sharedKey: row.shared_key,
                masterPassword: row.master_password,
                masterPasswordHash: row.master_password_hash,
                contacts: JSON.parse(row.contacts || '[]'), // 🔐 ИСПРАВЛЕНО: парсинг JSON
                expires: row.expires,
                userEmail: row.user_email,
                createdAt: row.created_at,
                source: row.source,
                viewed: row.viewed === 1,
                viewedAt: row.viewed_at,
                ownerPremium: row.owner_premium === 1
            };
        });

        // Загружаем death verifications
        const dvRows = await dbAll('SELECT * FROM death_verifications');
        deathVerifications = {};
        dvRows.forEach(row => {
            deathVerifications[row.id] = {
                id: row.id,
                userEmail: row.user_email,
                verificationMethod: row.verification_method,
                verificationDetails: JSON.parse(row.verification_details || '{}'),
                status: row.status,
                submittedAt: row.submitted_at,
                reviewedAt: row.reviewed_at,
                reviewedBy: row.reviewed_by,
                rejectionReason: row.rejection_reason,
                claimCode: row.claim_code,
                heirsContacts: JSON.parse(row.heirs_contacts || '[]')
            };
        });

        // Загружаем support requests
        const srRows = await dbAll('SELECT * FROM support_requests');
        supportRequests = {};
        srRows.forEach(row => {
            if (!supportRequests[row.user_email]) {
                supportRequests[row.user_email] = [];
            }
            supportRequests[row.user_email].push({
                id: row.id,
                userEmail: row.user_email,
                subject: row.subject,
                message: row.message,
                date: row.date,
                status: row.status,
                response: row.response,
                respondedAt: row.responded_at,
                adminEmail: row.admin_email
            });
        });

        // Загружаем trusted contacts
        const tcRows = await dbAll('SELECT * FROM trusted_contacts');
        trustedContacts = {};
        tcRows.forEach(row => {
            if (!trustedContacts[row.user_email]) {
                trustedContacts[row.user_email] = [];
            }
            trustedContacts[row.user_email].push({
                contactEmail: row.contact_email,
                contactPhone: row.contact_phone
            });
        });

        // Загружаем alive checks
        const acRows = await dbAll('SELECT * FROM alive_checks');
        acRows.forEach(row => {
            if (row.token) {
                aliveCheckTokens[row.token] = {
                    email: row.email,
                    token: row.token,
                    lastCheck: row.last_check,
                    nextCheck: row.next_check
                };
            }
        });

        console.log('✅ Все базы данных загружены из SQLCipher');
    } catch (error) {
        console.error('❌ Ошибка загрузки данных:', error);
        throw error;
    }
}

// 🔐 Инициализация Express с безопасными настройками
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));
app.use(compression());

// 🔐 Helmet с правильной CSP настройкой
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", "https://legacynet.ru"],
            frameSrc: ["'none'"],
            objectSrc: ["'none'"],
            baseUri: ["'self'"],
            formAction: ["'self'"]
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

// 🔐 ДОБАВЛЕНО: cookie-parser middleware
app.use(cookieParser());

// 🔐 Исправленные CORS настройки
const corsOptions = {
    origin: function (origin, callback) {
        // Разрешаем запросы без origin (например, мобильные приложения)
        if (!origin) return callback(null, true);
        
        const allowedOrigins = [
            'https://legacynet.ru',
            'https://www.legacynet.ru',
            'http://localhost:3000' // для локальной разработки
        ];
        
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            console.error('CORS заблокирован для origin:', origin);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
        'Content-Type', 
        'Authorization', 
        'X-CSRF-Token',
        'X-Requested-With',
        'Accept',
        'Cookie',
        'Set-Cookie'
    ],
    exposedHeaders: ['Set-Cookie'],
    maxAge: 86400
};

// 🔐 Обработка preflight OPTIONS запросов
app.options('*', cors(corsOptions));

// 🔐 Дополнительный middleware для установки заголовков
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Origin', 'https://legacynet.ru');
    res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE');
    res.header('Access-Control-Allow-Headers', 'Content-Type, X-CSRF-Token, Authorization');
    
    // Для preflight запросов
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    
    next();
});

app.use(cors(corsOptions));

// 🔐 Middleware для проверки установки cookies - ДОБАВЛЕНО
app.use((req, res, next) => {
    // Логируем только для отладки
    if (req.path.includes('/api/verify_2fa') || req.path.includes('/api/refresh_token')) {
        console.log('Cookies в запросе:', {
            access_token: req.cookies.access_token ? 'ЕСТЬ' : 'НЕТ',
            refresh_token: req.cookies.refresh_token ? 'ЕСТЬ' : 'НЕТ',
            csrf_token: req.cookies.csrf_token ? 'ЕСТЬ' : 'НЕТ',
            path: req.path
        });
    }
    next();
});

// ========== 🔐 УСИЛЕННАЯ CSRF ЗАЩИТА ==========

// 🔐 ФУНКЦИЯ ПРОВЕРКИ CSRF (Double Submit Cookie) - С ДОБАВЛЕННЫМ ОТЛАДОЧНЫМ КОДОМ
async function verifyCsrfDouble(req, userEmail) {
    try {
        // 1. Получаем токены
        const headerToken = req.headers['x-csrf-token'];
        const cookieToken = req.cookies.csrf_token;
        
        // 🔐 ДОБАВЛЕН ОТЛАДОЧНЫЙ КОД ИЗ ИНСТРУКЦИИ
        console.log('🔐 CSRF DEBUG:', {
            path: req.path,
            method: req.method,
            headerToken: headerToken ? headerToken.substring(0, 10) + '...' : 'НЕТ',
            cookieToken: cookieToken ? cookieToken.substring(0, 10) + '...' : 'НЕТ',
            user: userEmail,
            allHeaders: req.headers
        });

        // 2. Проверяем наличие
        if (!headerToken || !cookieToken) {
            console.log('❌ CSRF: Отсутствует токен в заголовке или куке');
            return false;
        }

        // 3. Проверяем совпадение
        if (headerToken !== cookieToken) {
            console.log('❌ CSRF: Токены не совпадают');
            return false;
        }

        // 4. Проверяем в БД и привязку к пользователю
        const row = await dbGet(
            'SELECT * FROM csrf_tokens WHERE token = ? AND user_email = ? AND expires > ?',
            [headerToken, userEmail, Date.now()]
        );

        if (!row) {
            console.log('❌ CSRF: Токен не найден в БД или истек');
            return false;
        }

        console.log('✅ CSRF проверка пройдена');
        return true;
    } catch (error) {
        console.error('Ошибка проверки CSRF:', error);
        return false;
    }
}

// 🔐 УСИЛЕННЫЙ CSRF MIDDLEWARE
app.use(async (req, res, next) => {
    console.log(`[CSRF] ${req.method} ${req.path} - IP: ${req.ip}`);
    
    // 🔐 Пропускаем только READ-ONLY GET запросы
    if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
        const readOnlyGetEndpoints = [
            '/api/profile',
            '/api/get_contacts',
            '/api/activation_settings',
            '/api/alive_check_status',
            '/api/master_password_status',
            '/api/check_premium_status',
            '/api/csrf-token',
            '/api/debug/cookies',
            '/api/check-auth'
        ];
        
        if (readOnlyGetEndpoints.includes(req.path)) {
            console.log(`[CSRF] Пропуск GET запроса: ${req.path}`);
            return next();
        }
    }

    // 🔐 Аутентификационные эндпоинты (не требуют CSRF)
    const authEndpoints = [
        '/api/register',
        '/api/login',
        '/api/verify_2fa',
        '/api/forgot_password',
        '/api/reset_password',
        '/api/csrf-token' // Этот требует verifyToken
    ];

    if (authEndpoints.includes(req.path)) {
        console.log(`[CSRF] Пропуск для auth-роута: ${req.path}`);
        return next();
    }

    // 🔥 ВАЖНО: /api/check_auth НЕ в authEndpoints! Он требует CSRF!

    // 🔐 ОСОБАЯ ОБРАБОТКА ДЛЯ /api/refresh_token
    if (req.path === '/api/refresh_token') {
        const csrfToken = req.headers['x-csrf-token'];
        
        if (!csrfToken) {
            console.log(`[CSRF] Токен отсутствует для refresh_token`);
            return res.status(403).json({ 
                success: false, 
                message: 'CSRF токен обязателен' 
            });
        }
        
        // Проверяем через verifyToken сначала
        // Дальше проверка будет в самом эндпоинте
        console.log(`[CSRF] CSRF токен присутствует для refresh_token`);
        next();
        return;
    }

    // 🔐 ДЛЯ ВСЕХ ОСТАЛЬНЫХ - ТРЕБУЕМ CSRF
    // Но проверка будет в verifyTokenWithCsrf
    console.log(`[CSRF] Требуем CSRF для: ${req.path}`);
    next();
});

// ========== НОВЫЕ ФУНКЦИИ ДЛЯ УПРАВЛЕНИЯ ТОКЕНАМИ ==========

// 🔐 Функция генерации access токена
function generateAccessToken(email, tokenVersion = 0) {
    return jwt.sign({ 
        email: email,
        type: 'access',
        version: tokenVersion,
        iat: Math.floor(Date.now() / 1000)
    }, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRY });
}

// 🔐 Функция генерации refresh токена
function generateRefreshToken(email, tokenVersion = 0) {
    return jwt.sign({ 
        email: email,
        type: 'refresh',
        version: tokenVersion,
        iat: Math.floor(Date.now() / 1000)
    }, JWT_REFRESH_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRY });
}

// 🔐 Функция установки токенов в cookies - ИСПРАВЛЕННАЯ ВЕРСИЯ
function setAuthCookies(res, accessToken, refreshToken) {
    const isProduction = process.env.NODE_ENV === 'production';
    
    // ОСНОВНЫЕ опции для cookies - КРИТИЧЕСКИ ВАЖНО!
    const baseCookieOptions = {
        httpOnly: true,
        secure: true, // ВСЕГДА true для HTTPS!
        sameSite: isProduction ? 'none' : 'lax', // 🔥 ИЗМЕНИЛ 'strict' на 'none'
        path: '/',
        domain: isProduction ? 'legacynet.ru' : undefined // 🔥 УБРАЛ точку в начале
    };
    
    console.log('🔐 Настройки cookies:', baseCookieOptions);
    
    // Access токен - 30 минут
    res.cookie('access_token', accessToken, {
        ...baseCookieOptions,
        maxAge: 30 * 60 * 1000
    });
    
    // Refresh токен - 14 дней
    res.cookie('refresh_token', refreshToken, {
        ...baseCookieOptions,
        maxAge: 14 * 24 * 60 * 60 * 1000
    });
    
    console.log('✅ Cookies установлены для:', {
        domain: baseCookieOptions.domain,
        sameSite: baseCookieOptions.sameSite,
        secure: baseCookieOptions.secure
    });
}

// 🔐 Функция очистки auth cookies - ИСПРАВЛЕННАЯ ВЕРСИЯ
function clearAuthCookies(res) {
    const isProduction = process.env.NODE_ENV === 'production';
    
    const cookieOptions = {
        httpOnly: true,
        secure: true,
        sameSite: isProduction ? 'none' : 'lax',
        path: '/',
        domain: isProduction ? 'legacynet.ru' : undefined
    };
    
    res.clearCookie('access_token', cookieOptions);
    res.clearCookie('refresh_token', cookieOptions);
    res.clearCookie('csrf_token', cookieOptions);
    
    console.log('✅ Cookies очищены');
}

// 🔐 Функция проверки refresh токена в черном списке - ИСПРАВЛЕННАЯ ВЕРСИЯ
async function isRefreshTokenBlacklisted(refreshToken) {
    try {
        const row = await dbGet(
            'SELECT * FROM token_blacklist WHERE token = ? AND expires > ?', 
            [refreshToken, Math.floor(Date.now() / 1000)]
        );
        return !!row;
    } catch (error) {
        console.error('Ошибка проверки черного списка:', error);
        return false;
    }
}

// 🔐 Функция добавления refresh токена в черный список
async function blacklistRefreshToken(refreshToken) {
    try {
        const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
        const expires = decoded.exp;
        
        await dbRun('INSERT OR REPLACE INTO token_blacklist (token, expires) VALUES (?, ?)', 
            [refreshToken, expires]);
        
        console.log(`Refresh токен добавлен в черный список до ${new Date(expires * 1000).toISOString()}`);
        return true;
    } catch (err) {
        console.error('Ошибка при добавлении токена в черный список:', err.message);
        return false;
    }
}

// ========== VERIFY TOKEN ФУНКЦИИ ==========

// 🔐 VERIFY TOKEN БЕЗ ПРОВЕРКИ CSRF (только для get-csrf)
async function verifyTokenWithoutCsrf(req, res, next) {
    try {
        const accessToken = req.cookies.access_token;
        
        if (!accessToken) {
            return res.status(401).json({ 
                success: false, 
                message: 'Access токен отсутствует' 
            });
        }

        const decoded = jwt.verify(accessToken, JWT_SECRET);
        
        if (decoded.type !== 'access') {
            return res.status(401).json({ 
                success: false, 
                message: 'Неверный тип токена' 
            });
        }

        const user = users[decoded.email];
        if (!user) {
            return res.status(401).json({ 
                success: false, 
                message: 'Пользователь не найден' 
            });
        }

        const currentVersion = user.tokenVersion || 0;
        if (decoded.version !== currentVersion) {
            return res.status(401).json({ 
                success: false, 
                message: 'Токен устарел. Пожалуйста, войдите снова.',
                tokenVersionMismatch: true
            });
        }
        
        if (!user.verified) {
            return res.status(403).json({ 
                success: false, 
                message: 'Email не подтверждён. Проверьте вашу почту.' 
            });
        }
        
        if (user.banned) {
            return res.status(403).json({ 
                success: false, 
                message: 'Аккаунт заблокирован' 
            });
        }
        
        req.user = {
            email: decoded.email,
            type: decoded.type,
            version: decoded.version,
            iat: decoded.iat,
            exp: decoded.exp,
            fullData: user
        };

        console.log(`✅ verifyTokenWithoutCsrf пройден для ${decoded.email}`);
        next();
    } catch (err) {
        console.error('❌ Ошибка верификации access токена:', err.message);
        
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ 
                success: false, 
                message: 'Access токен истек. Используйте refresh токен.',
                accessTokenExpired: true
            });
        }
        
        if (err.name === 'JsonWebTokenError') {
            return res.status(401).json({ 
                success: false, 
                message: 'Неверный access токен',
                invalidToken: true
            });
        }
        
        return res.status(401).json({ 
            success: false, 
            message: 'Ошибка аутентификации' 
        });
    }
}

// 🔐 УСИЛЕННЫЙ VERIFY TOKEN С ПРОВЕРКОЙ CSRF
async function verifyTokenWithCsrf(req, res, next) {
    try {
        const accessToken = req.cookies.access_token;
        
        if (!accessToken) {
            return res.status(401).json({ 
                success: false, 
                message: 'Access токен отсутствует',
                requiresLogin: true
            });
        }

        const decoded = jwt.verify(accessToken, JWT_SECRET);
        
        if (decoded.type !== 'access') {
            return res.status(401).json({ 
                success: false, 
                message: 'Неверный тип токена' 
            });
        }

        const user = users[decoded.email];
        if (!user) {
            return res.status(401).json({ 
                success: false, 
                message: 'Пользователь не найден' 
            });
        }

        const currentVersion = user.tokenVersion || 0;
        if (decoded.version !== currentVersion) {
            return res.status(401).json({ 
                success: false, 
                message: 'Токен устарел. Пожалуйста, войдите снова.',
                tokenVersionMismatch: true
            });
        }
        
        if (!user.verified) {
            return res.status(403).json({ 
                success: false, 
                message: 'Email не подтверждён. Проверьте вашу почту.' 
            });
        }
        
        if (user.banned) {
            return res.status(403).json({ 
                success: false, 
                message: 'Аккаунт заблокирован' 
            });
        }
        
        // 2. 🔥 ПРОВЕРЯЕМ CSRF (Double Submit Cookie)
        const csrfValid = await verifyCsrfDouble(req, decoded.email);
        
        if (!csrfValid) {
            console.log(`❌ CSRF проверка не пройдена для ${decoded.email}`);
            return res.status(403).json({ 
                success: false, 
                message: 'Неверный CSRF токен',
                requiresCsrf: true
            });
        }

        // 3. Сохраняем пользователя
        req.user = {
            email: decoded.email,
            type: decoded.type,
            version: decoded.version,
            iat: decoded.iat,
            exp: decoded.exp,
            fullData: user
        };

        console.log(`✅ verifyTokenWithCsrf пройден для ${decoded.email}`);
        next();
    } catch (err) {
        console.error('❌ Ошибка верификации access токена:', err.message);
        
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ 
                success: false, 
                message: 'Access токен истек. Используйте refresh токен.',
                accessTokenExpired: true
            });
        }
        
        if (err.name === 'JsonWebTokenError') {
            return res.status(401).json({ 
                success: false, 
                message: 'Неверный access токен',
                invalidToken: true
            });
        }
        
        return res.status(401).json({ 
            success: false, 
            message: 'Ошибка аутентификации' 
        });
    }
}

// ========== ОСНОВНЫЕ ЭНДПОИНТЫ ==========

// 🔐 Тестовый эндпоинт
app.get('/api/test', (req, res) => {
    res.json({ 
        success: true, 
        message: 'API работает!',
        security: 'Включены все протоколы безопасности',
        token_system: 'Refresh/access token система с 30m/14d сроками',
        database: 'SQLCipher (шифрованная SQLite)'
    });
});

// 🔐 ЭНДПОИНТ ДЛЯ ПОЛУЧЕНИЯ CSRF ТОКЕНА (без CSRF проверки)
app.get('/api/get-csrf', verifyTokenWithoutCsrf, async (req, res) => {
    try {
        const userEmail = req.user.email;
        
        // Генерируем новый CSRF токен
        const csrfToken = crypto.randomBytes(32).toString('hex');
        const csrfExpiry = Date.now() + 4 * 60 * 60 * 1000;

        // Сохраняем в БД
        await dbRun(
            'INSERT INTO csrf_tokens (token, user_email, expires) VALUES (?, ?, ?)',
            [csrfToken, userEmail, csrfExpiry]
        );

        // Устанавливаем HttpOnly cookie
        res.cookie('csrf_token', csrfToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            path: '/',
            maxAge: 4 * 60 * 60 * 1000
        });

        console.log(`✅ Новый CSRF токен для ${userEmail}`);

        res.json({ 
            success: true, 
            csrfToken,
            message: 'CSRF токен обновлен'
        });
    } catch (error) {
        console.error('Ошибка получения CSRF:', error);
        res.status(500).json({ success: false, message: 'Ошибка сервера' });
    }
});

// 🔐 Эндпоинт для обновления токенов - ИСПРАВЛЕННАЯ ВЕРСИЯ
app.post('/api/refresh_token', async (req, res) => {
    try {
        const refreshToken = req.cookies.refresh_token;
        const csrfToken = req.headers['x-csrf-token'];
        
        if (!refreshToken) {
            return res.status(401).json({ 
                success: false, 
                message: 'Refresh токен отсутствует',
                requiresLogin: true
            });
        }
        
        const isBlacklisted = await isRefreshTokenBlacklisted(refreshToken);
        if (isBlacklisted) {
            clearAuthCookies(res);
            return res.status(401).json({ 
                success: false, 
                message: 'Refresh токен отозван. Пожалуйста, войдите снова.',
                tokenRevoked: true
            });
        }
        
        try {
            const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
            
            if (decoded.type !== 'refresh') {
                return res.status(401).json({ 
                    success: false, 
                    message: 'Неверный тип токена' 
                });
            }
            
            const user = users[decoded.email];
            if (!user) {
                return res.status(401).json({ 
                    success: false, 
                    message: 'Пользователь не найден' 
                });
            }
            
            // 🔐 Проверяем CSRF токен
            const csrfValid = await verifyCsrfDouble(req, decoded.email);
            if (!csrfValid) {
                return res.status(403).json({ 
                    success: false, 
                    message: 'Неверный CSRF токен' 
                });
            }
            
            // Проверяем версию токена
            const currentVersion = user.tokenVersion || 0;
            if (decoded.version !== currentVersion) {
                await blacklistRefreshToken(refreshToken);
                clearAuthCookies(res);
                return res.status(401).json({ 
                    success: false, 
                    message: 'Токен устарел. Пожалуйста, войдите снова.',
                    tokenVersionMismatch: true
                });
            }
            
            // Генерируем новую пару токенов
            const newAccessToken = generateAccessToken(decoded.email, currentVersion);
            const newRefreshToken = generateRefreshToken(decoded.email, currentVersion);
            
            // Добавляем старый refresh токен в черный список
            await blacklistRefreshToken(refreshToken);
            
            // Устанавливаем новые токены в cookies
            setAuthCookies(res, newAccessToken, newRefreshToken);
            
            // 🔐 Генерируем НОВЫЙ CSRF токен
            const newCsrfToken = crypto.randomBytes(32).toString('hex');
            const csrfExpiry = Date.now() + 4 * 60 * 60 * 1000;
            
            await dbRun(
                'INSERT INTO csrf_tokens (token, user_email, expires) VALUES (?, ?, ?)',
                [newCsrfToken, decoded.email, csrfExpiry]
            );
            
            // Устанавливаем HttpOnly cookie
            res.cookie('csrf_token', newCsrfToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                path: '/',
                maxAge: 4 * 60 * 60 * 1000
            });
            
            // Обновляем активность
            user.lastActivity = new Date().toISOString();
            await dbRun('UPDATE users SET last_activity = ? WHERE email = ?', 
                [user.lastActivity, decoded.email]);
            
            res.json({ 
                success: true, 
                message: 'Токены успешно обновлены',
                csrfToken: newCsrfToken
            });
            
        } catch (err) {
            if (err.name === 'TokenExpiredError') {
                await blacklistRefreshToken(refreshToken);
                clearAuthCookies(res);
                return res.status(401).json({ 
                    success: false, 
                    message: 'Refresh токен истек. Пожалуйста, войдите снова.',
                    refreshTokenExpired: true
                });
            }
            
            if (err.name === 'JsonWebTokenError') {
                clearAuthCookies(res);
                return res.status(401).json({ 
                    success: false, 
                    message: 'Неверный refresh токен',
                    invalidToken: true
                });
            }
            
            throw err;
        }
    } catch (error) {
        console.error('Ошибка обновления токенов:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка обновления токенов' 
        });
    }
});

// 🔐 Дебаг эндпоинт cookies
app.get('/api/debug/cookies', (req, res) => {
    console.log('DEBUG Cookies запроса:', req.cookies);
    
    res.json({
        success: true,
        cookies_present: {
            access_token: !!req.cookies.access_token,
            refresh_token: !!req.cookies.refresh_token,
            csrf_token: !!req.cookies.csrf_token,
            debug_cookie: 'set'
        },
        headers: req.headers
    });
});

// 🔐 Простой проверочный эндпоинт
app.get('/api/check-auth', (req, res) => {
    const token = req.cookies.access_token;
    
    if (!token) {
        return res.json({ 
            success: false, 
            message: 'No access token',
            has_cookie: !!token
        });
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        res.json({ 
            success: true, 
            email: decoded.email,
            has_cookie: true
        });
    } catch (err) {
        res.json({ 
            success: false, 
            message: err.message,
            has_cookie: true
        });
    }
});

// 🔐 Эндпоинт для проверки авторизации С CSRF
app.get('/api/check_auth', verifyTokenWithCsrf, (req, res) => {
    const user = users[req.user.email];
    
    res.json({ 
        success: true, 
        authenticated: true,
        email: req.user.email,
        isAdmin: user.isAdmin || false,
        tokenType: req.user.type,
        expiresIn: req.user.exp - Math.floor(Date.now() / 1000)
    });
});

// 🔐 Вспомогательная функция для генерации кода подтверждения
function generateVerificationCode() {
    return crypto.randomBytes(4).toString('hex').toUpperCase();
}

// 🔐 Функция очистки просроченных claims
async function cleanupExpiredClaims() {
    const now = Date.now();
    
    try {
        // Удаляем просроченные claims из БД
        await dbRun('DELETE FROM claims WHERE expires < ?', [now]);
        
        // Обновляем кэш в памяти
        const claimsRows = await dbAll('SELECT * FROM claims');
        claims = {};
        claimsRows.forEach(row => {
            claims[row.claim_code] = {
                claimCode: row.claim_code,
                encrypted: row.encrypted,
                encryptionMethod: row.encryption_method,
                method: row.method,
                sharedKey: row.shared_key,
                masterPassword: row.master_password,
                masterPasswordHash: row.master_password_hash,
                contacts: JSON.parse(row.contacts || '[]'),
                expires: row.expires,
                userEmail: row.user_email,
                createdAt: row.created_at,
                source: row.source,
                viewed: row.viewed === 1,
                viewedAt: row.viewed_at,
                ownerPremium: row.owner_premium === 1
            };
        });
        
        console.log(`Очищены просроченные claims из БД`);
    } catch (error) {
        console.error('Ошибка очистки claims:', error);
    }
}

// 🔐 Функция очистки просроченных временных регистраций
function cleanupPendingRegistrations() {
    const now = Date.now();
    let cleaned = 0;
    
    Object.keys(pendingRegistrations).forEach(email => {
        if (pendingRegistrations[email] && pendingRegistrations[email].expires < now) {
            delete pendingRegistrations[email];
            cleaned++;
        }
    });
    
    if (cleaned > 0) {
        console.log(`🗑️ Очищено ${cleaned} просроченных временных регистраций`);
    }
}

// 🔐 Функция очистки черного списка токенов
async function cleanupTokenBlacklist() {
    try {
        const now = Math.floor(Date.now() / 1000);
        await dbRun('DELETE FROM token_blacklist WHERE expires < ?', [now]);
        console.log('🗑️ Очищен черный список токенов');
    } catch (error) {
        console.error('Ошибка очистки черного списка:', error);
    }
}

// 🔐 Функция очистки старых claims (более 30 дней после просмотра)
async function cleanupOldClaims() {
    console.log('🔍 Очистка старых claims...');
    
    try {
        // Удаляем claims просмотренные более 30 дней назад
        await dbRun(`
            DELETE FROM claims 
            WHERE viewed = 1 AND datetime(viewed_at) < datetime('now', '-30 days')
        `);
        
        // Удаляем непросмотренные claims созданные более 60 дней назад
        await dbRun(`
            DELETE FROM claims 
            WHERE viewed = 0 AND datetime(created_at) < datetime('now', '-60 days')
        `);
        
        // Перезагружаем claims в память
        const claimsRows = await dbAll('SELECT * FROM claims');
        claims = {};
        claimsRows.forEach(row => {
            claims[row.claim_code] = {
                claimCode: row.claim_code,
                encrypted: row.encrypted,
                encryptionMethod: row.encryption_method,
                method: row.method,
                sharedKey: row.shared_key,
                masterPassword: row.master_password,
                masterPasswordHash: row.master_password_hash,
                contacts: JSON.parse(row.contacts || '[]'),
                expires: row.expires,
                userEmail: row.user_email,
                createdAt: row.created_at,
                source: row.source,
                viewed: row.viewed === 1,
                viewedAt: row.viewed_at,
                ownerPremium: row.owner_premium === 1
            };
        });
        
        console.log(`✅ Очищены старые claims из БД`);
    } catch (error) {
        console.error('Ошибка очистки старых claims:', error);
    }
}

// Запускаем очистку при старте
setTimeout(() => {
    cleanupExpiredClaims();
    cleanupPendingRegistrations();
    cleanupTokenBlacklist();
    cleanupOldClaims();
}, 5000);

// Запускаем очистку раз в день
setInterval(cleanupExpiredClaims, 24 * 60 * 60 * 1000);
setInterval(cleanupPendingRegistrations, 5 * 60 * 1000);
setInterval(cleanupTokenBlacklist, 24 * 60 * 60 * 1000);
setInterval(cleanupOldClaims, 24 * 60 * 60 * 1000);

// ========== ИСПРАВЛЕННЫЙ ПОИСК ПО EMAIL ==========
app.post('/api/search_user/email', (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ success: false, message: 'Email обязателен' });
    }

    const user = users[email];
    if (!user) {
      return res.status(404).json({ success: false, message: 'Пользователь не найден' });
    }

    const userSearchMethods = user.personalData?.searchMethods || ['email'];
    
    if (!userSearchMethods.includes('email')) {
      return res.status(403).json({ 
        success: false, 
        message: 'Этот пользователь настроил приватность только на поиск по личным данным' 
      });
    }

    if (user.deceased) {
      return res.status(400).json({ 
        success: false, 
        message: 'Этот пользователь уже отмечен как умерший',
        userDeceased: true 
      });
    }

    const userData = {
      email: email,
      fullName: user.personalData && user.personalData.lastName && user.personalData.firstName
        ? `${user.personalData.lastName} ${user.personalData.firstName} ${user.personalData.middleName || ''}`.trim()
        : null,
      birthDate: user.personalData ? user.personalData.birthDate : null
    };

    res.json({ success: true, user: userData });
  } catch (error) {
    console.error('Ошибка поиска пользователя:', error);
    res.status(500).json({ success: false, message: 'Ошибка поиска пользователя' });
  }
});

// ========== ИСПРАВЛЕННЫЙ ПОИСК ПО ЛИЧНЫМ ДАННЫМ ==========
app.post('/api/search_user/personal', (req, res) => {
  try {
    const { lastName, firstName, middleName, birthDate } = req.body;
    
    if (!lastName || !firstName || !birthDate) {
      return res.status(400).json({ success: false, message: 'Фамилия, имя и дата рождения обязательны' });
    }

    const normalizedLastName = lastName.trim().toLowerCase();
    const normalizedFirstName = firstName.trim().toLowerCase();
    const normalizedMiddleName = middleName ? middleName.trim().toLowerCase() : '';
    const normalizedBirthDate = birthDate.split('T')[0];

    console.log('Searching user with:', {
      lastName: normalizedLastName,
      firstName: normalizedFirstName, 
      middleName: normalizedMiddleName,
      birthDate: normalizedBirthDate
    });

    const foundUsers = [];
    
    for (const [email, user] of Object.entries(users)) {
      if (user.personalData && !user.personalData.isAnonymous) {
        
        if (!user.personalData.lastName || !user.personalData.firstName || !user.personalData.birthDate) {
          continue;
        }
        
        const userLastName = user.personalData.lastName.trim().toLowerCase();
        const userFirstName = user.personalData.firstName.trim().toLowerCase();
        const userMiddleName = user.personalData.middleName ? user.personalData.middleName.trim().toLowerCase() : '';
        const userBirthDate = user.personalData.birthDate.split('T')[0];
        
        const matchesLastName = userLastName === normalizedLastName;
        const matchesFirstName = userFirstName === normalizedFirstName;
        const matchesMiddleName = !normalizedMiddleName || userMiddleName === normalizedMiddleName;
        const matchesBirthDate = userBirthDate === normalizedBirthDate;
        
        if (matchesLastName && matchesFirstName && matchesMiddleName && matchesBirthDate) {
          
          if (user.deceased) {
            console.log(`User ${email} is deceased, skipping`);
            continue;
          }
          
          foundUsers.push({
            email: email,
            fullName: `${user.personalData.lastName} ${user.personalData.firstName} ${user.personalData.middleName || ''}`.trim(),
            birthDate: user.personalData.birthDate
          });
        }
      }
    }

    console.log('Found users:', foundUsers);

    if (foundUsers.length === 0) {
      return res.status(404).json({ success: false, message: 'Пользователь не найден' });
    }

    res.json({ success: true, users: foundUsers });
  } catch (error) {
    console.error('Ошибка поиска пользователей:', error);
    res.status(500).json({ success: false, message: 'Ошибка поиска пользователей' });
  }
});

// 🔐 СОХРАНЕНИЕ ЛИЧНЫХ ДАННЫХ С CSRF ЗАЩИТОЙ
app.post('/api/save_personal_data', verifyTokenWithCsrf, async (req, res) => {
  try {
    const { privacyMethod, personalData } = req.body;
    const userEmail = req.user.email;
    
    console.log('=== СОХРАНЕНИЕ ЛИЧНЫХ ДАННЫХ ===');
    console.log('Пользователь:', userEmail);
    console.log('Метод приватности:', privacyMethod);
    console.log('Личные данные:', personalData);
    
    if (!users[userEmail]) {
      return res.status(404).json({ success: false, message: 'Пользователь не найден' });
    }

    let personalDataJson;
    
    if (personalData && personalData.searchMethods) {
      personalDataJson = {
        searchMethods: personalData.searchMethods,
        isAnonymous: !personalData.searchMethods.includes('personal_data')
      };
      
      if (personalData.searchMethods.includes('personal_data')) {
        personalDataJson = {
          ...personalDataJson,
          lastName: personalData.lastName,
          firstName: personalData.firstName,
          middleName: personalData.middleName,
          birthDate: personalData.birthDate
        };
      }
      
      console.log('Сохранены данные:', personalDataJson);
    } else {
      if (privacyMethod === 'email_only') {
        personalDataJson = {
          isAnonymous: true,
          searchMethods: ['email']
        };
        console.log('Сохранены данные: только email (анонимно)');
      } else {
        personalDataJson = {
          isAnonymous: false,
          searchMethods: ['personal_data'],
          lastName: personalData.lastName,
          firstName: personalData.firstName,
          middleName: personalData.middleName,
          birthDate: personalData.birthDate
        };
        console.log('Сохранены полные данные:', personalDataJson);
      }
    }

    // Обновляем в БД
    await dbRun('UPDATE users SET personal_data = ? WHERE email = ?', 
        [JSON.stringify(personalDataJson), userEmail]);
    
    // Обновляем в памяти
    users[userEmail].personalData = personalDataJson;

    console.log('Личные данные успешно сохранены для:', userEmail);
    res.json({ success: true, message: 'Личные данные сохранены' });
  } catch (error) {
    console.error('Ошибка сохранения личных данных:', error);
    res.status(500).json({ success: false, message: 'Ошибка сохранения личных данных' });
  }
});

// Подача заявки на подтверждение смерти через доверенное лицо
app.post('/api/verify_death/trusted_person', async (req, res) => {
    try {
        const { deceasedEmail, accessCode } = req.body;
        
        if (!deceasedEmail || !accessCode) {
            return res.status(400).json({ success: false, message: 'Email и код доступа обязательны' });
        }

        const user = users[deceasedEmail];
        if (!user) {
            return res.status(404).json({ success: false, message: 'Пользователь не найден' });
        }

        if (user.deathVerificationCode !== accessCode) {
            return res.status(400).json({ success: false, message: 'Неверный код доступа' });
        }

        const verificationId = 'DV' + Date.now();
        const verificationDetails = {
            method: 'trusted_person',
            verifiedBy: 'code'
        };

        // Сохраняем в БД
        await dbRun(`
            INSERT INTO death_verifications 
            (id, user_email, verification_method, verification_details, status, submitted_at, reviewed_at, reviewed_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            verificationId, deceasedEmail, 'trusted_person', 
            JSON.stringify(verificationDetails), 'approved',
            new Date().toISOString(), new Date().toISOString(), 'auto_approved'
        ]);

        // Обновляем в памяти
        deathVerifications[verificationId] = {
            id: verificationId,
            userEmail: deceasedEmail,
            verificationMethod: 'trusted_person',
            verificationDetails: verificationDetails,
            status: 'approved',
            submittedAt: new Date().toISOString(),
            reviewedAt: new Date().toISOString(),
            reviewedBy: 'auto_approved'
        };

        await activateLegacy(deceasedEmail, verificationId);

        res.json({ 
            success: true, 
            message: 'Смерть подтверждена, завещание отправлено',
            verificationId
        });
    } catch (error) {
        console.error('Ошибка подтверждения смерти:', error);
        res.status(500).json({ success: false, message: 'Ошибка подтверждения смерти' });
    }
});

// 🔐 Подача заявки на подтверждение смерти через документы С CSRF ЗАЩИТОЙ
app.post('/api/verify_death/document', upload.single('document'), async (req, res) => {
  try {
    const { deceasedEmail, deceasedName, deathDate, additionalInfo } = req.body;
    
    console.log('=== ПОЛУЧЕНА ЗАЯВКА НА ПОДТВЕРЖДЕНИЕ СМЕРТИ ===');
    console.log('Email:', deceasedEmail);
    console.log('Имя:', deceasedName);
    console.log('Дата смерти:', deathDate);
    console.log('Файл:', req.file);
    
    if (!deceasedEmail || !deceasedName || !deathDate || !req.file) {
      return res.status(400).json({ 
        success: false, 
        message: 'Все поля обязательны: email, имя, дата смерти и документ' 
      });
    }

    const user = users[deceasedEmail];
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'Пользователь не найден' 
      });
    }

    // Проверяем, не умер ли уже пользователь
    if (user.deceased) {
      return res.status(400).json({ 
        success: false, 
        message: 'Этот пользователь уже отмечен как умерший',
        userDeceased: true 
      });
    }

    const verificationId = 'DV' + Date.now();
    const verificationDetails = {
        method: 'document',
        deceasedName: deceasedName,
        deathDate: deathDate,
        documentFile: req.file.filename,
        additionalInfo: additionalInfo || ''
    };

    // Сохраняем в БД
    await dbRun(`
        INSERT INTO death_verifications 
        (id, user_email, verification_method, verification_details, status, submitted_at)
        VALUES (?, ?, ?, ?, ?, ?)
    `, [
        verificationId, deceasedEmail, 'document', 
        JSON.stringify(verificationDetails), 'pending',
        new Date().toISOString()
    ]);

    // Обновляем в памяти
    deathVerifications[verificationId] = {
      id: verificationId,
      userEmail: deceasedEmail,
      verificationMethod: 'document',
      verificationDetails: verificationDetails,
      status: 'pending',
      submittedAt: new Date().toISOString(),
      reviewedAt: null,
      reviewedBy: null
    };

    console.log(`✅ Заявка ${verificationId} создана для ${deceasedEmail}`);
    
    res.json({ 
      success: true, 
      message: 'Заявка отправлена на модерацию',
      requestId: verificationId,
      requiresModeration: true
    });
  } catch (error) {
    console.error('❌ Полная ошибка подачи заявки:', error);
    console.error('Stack:', error.stack);
    res.status(500).json({ 
      success: false, 
      message: `Ошибка подачи заявки: ${error.message}` 
    });
  }
});

// Получение списка заявок для админа
app.get('/api/admin/death_verifications', verifyTokenWithCsrf, verifyAdmin, (req, res) => {
  try {
    const allVerifications = Object.values(deathVerifications)
      .filter(v => v.verificationMethod !== 'death_certificate' && v.verificationMethod !== 'notary_confirmation')
      .sort((a, b) => new Date(b.submittedAt) - new Date(a.submittedAt))
      .map(verification => {
        const user = users[verification.userEmail];
        const ownerPremium = user && user.subscription && (user.subscription.includes('premium') || user.subscription === 'lifetime');
        
        let claimViewed = false;
        let claimViewedAt = null;
        
        if (verification.claimCode && claims[verification.claimCode]) {
          const claim = claims[verification.claimCode];
          claimViewed = claim.viewed || false;
          claimViewedAt = claim.viewedAt || null;
        }
        
        return {
          ...verification,
          ownerPremium,
          claimViewed,
          claimViewedAt
        };
      });
    
    res.json({ success: true, verifications: allVerifications });
  } catch (error) {
    console.error('Ошибка загрузки заявки:', error);
    res.status(500).json({ success: false, message: 'Ошибка загрузки заявки' });
  }
});

// 🔐 ПОДТВЕРЖДЕНИЕ ЗАЯВКИ АДМИНОМ С CSRF ЗАЩИТОЙ
app.post('/api/admin/death_verifications/:id/verify', verifyTokenWithCsrf, verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const verification = deathVerifications[id];
    
    if (!verification) {
      return res.status(404).json({ success: false, message: 'Заявка не найдена' });
    }

    if (verification.status !== 'pending') {
      return res.status(400).json({ success: false, message: 'Заявка уже обработана' });
    }

    // Обновляем в БД
    await dbRun(`
        UPDATE death_verifications 
        SET status = ?, reviewed_at = ?, reviewed_by = ?
        WHERE id = ?
    `, ['approved', new Date().toISOString(), req.user.email, id]);

    // Обновляем в памяти
    verification.status = 'approved';
    verification.reviewedAt = new Date().toISOString();
    verification.reviewedBy = req.user.email;

    const activated = await activateLegacy(verification.userEmail, id);
    
    if (!activated) {
      return res.status(500).json({ success: false, message: 'Ошибка активации завещания' });
    }

    res.json({ success: true, message: 'Заявка подтверждена, завещание отправлено' });
  } catch (error) {
    console.error('Ошибка подтверждения заявка:', error);
    res.status(500).json({ success: false, message: 'Ошибка подтверждения заявка' });
  }
});

// 🔐 ОТКЛОНЕНИЕ ЗАЯВКИ АДМИНОМ С CSRF ЗАЩИТОЙ
app.post('/api/admin/death_verifications/:id/reject', verifyTokenWithCsrf, verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { reason } = req.body;
    const verification = deathVerifications[id];
    
    if (!verification) {
      return res.status(404).json({ success: false, message: 'Заявка не найден' });
    }

    if (verification.status !== 'pending') {
      return res.status(400).json({ success: false, message: 'Заявка уже обработана' });
    }

    // Обновляем в БД
    await dbRun(`
        UPDATE death_verifications 
        SET status = ?, reviewed_at = ?, reviewed_by = ?, rejection_reason = ?
        WHERE id = ?
    `, ['rejected', new Date().toISOString(), req.user.email, reason || 'Причина не указана', id]);

    // Обновляем в памяти
    verification.status = 'rejected';
    verification.reviewedAt = new Date().toISOString();
    verification.reviewedBy = req.user.email;
    verification.rejectionReason = reason || 'Причина не указана';

    res.json({ success: true, message: 'Заявка отклонена' });
  } catch (error) {
    console.error('Ошибка отклонения заявки:', error);
    res.status(500).json({ success: false, message: 'Ошибка отклонения заявки' });
  }
});

// ========== ИСПРАВЛЕННАЯ ЗАГРУЗКА МЕТОДОВ АКТИВАЦИИ ==========
app.get('/api/user_activation_methods/:email', (req, res) => {
  try {
    const { email } = req.params;
    const user = users[email];
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'Пользователь не найден' });
    }

    if (user.deceased) {
      return res.status(400).json({ 
        success: false, 
        message: 'Этот пользователь уже отмечен как умершим',
        userDeceased: true 
      });
    }

    res.json({ 
      success: true, 
      activationMethods: user.activationMethods || ['email_check'],
      deathVerificationCode: user.deathVerificationCode,
      trustedContacts: trustedContacts[email] || [],
      userDeceased: false
    });
  } catch (error) {
    console.error('Ошибка получения методов активации:', error);
    res.status(500).json({ success: false, message: 'Ошибка получения методов активации' });
  }
});

// Проверка разрешен ли метод для пользователя
app.post('/api/check_verification_method', (req, res) => {
  try {
    const { email, method } = req.body;
    const user = users[email];
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'Пользователь не найден' });
    }

    const isAllowed = user.activationMethods && user.activationMethods.includes(method);
    
    res.json({ 
      success: true, 
      allowed: isAllowed,
      message: isAllowed ? 'Метод разрешен' : 'Метод не разрешен для этого пользователя'
    });
  } catch (error) {
    console.error('Ошибка проверки метода:', error);
    res.status(500).json({ success: false, message: 'Ошибка проверки метода' });
  }
});

// ========== НОВЫЕ МАРШРУТЫ ДЛЯ ПРОВЕРКИ АКТИВНОСТИ ==========
// 🔐 ОТПРАВКА ПРОВЕРОЧНОГО ПИСЬМА С CSRF ЗАЩИТОЙ
app.post('/api/send_alive_check', verifyTokenWithCsrf, async (req, res) => {
  try {
    const userEmail = req.user.email;
    const user = users[userEmail];
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'Пользователь не найден' });
    }
    
    const emailCheckEnabled = user.activationMethods && user.activationMethods.includes('email_check');
    if (!emailCheckEnabled) {
      return res.status(400).json({ 
        success: false, 
        message: 'Проверка активности по почте не включена в настройках активации' 
      });
    }
    
    const intervalDays = parseInt(user.emailCheckSettings?.interval) || 30;
    const token = crypto.randomBytes(32).toString('hex');
    
    // Сохраняем токен в БД
    await dbRun(`
        INSERT OR REPLACE INTO alive_checks (email, token, last_check, next_check)
        VALUES (?, ?, ?, ?)
    `, [
        userEmail,
        token,
        new Date().toISOString(),
        new Date(Date.now() + intervalDays * 24 * 60 * 60 * 1000).toISOString()
    ]);
    
    // Сохраняем в памяти
    aliveCheckTokens[token] = {
      email: userEmail,
      token: token,
      created: new Date().toISOString(),
      expires: new Date(Date.now() + intervalDays * 24 * 60 * 60 * 1000).toISOString(),
      intervalDays: intervalDays
    };
    
    const emailSent = await sendAliveCheckEmail(userEmail, token, intervalDays);
    
    if (!emailSent) {
      return res.status(500).json({ 
        success: false, 
        message: 'Ошибка отправки письма проверки активности' 
      });
    }
    
    const lastAliveCheckSent = new Date().toISOString();
    const nextAliveCheckDate = new Date(Date.now() + intervalDays * 24 * 60 * 60 * 1000).toISOString();
    
    // Обновляем в БД
    await dbRun('UPDATE users SET last_alive_check_sent = ?, next_alive_check_date = ? WHERE email = ?',
        [lastAliveCheckSent, nextAliveCheckDate, userEmail]);
    
    // Обновляем в памяти
    user.lastAliveCheckSent = lastAliveCheckSent;
    user.nextAliveCheckDate = nextAliveCheckDate;
    
    res.json({ 
      success: true, 
      message: 'Письмо проверки активности отправлено',
      nextCheckDate: user.nextAliveCheckDate
    });
  } catch (error) {
    console.error('Ошибка отправки проверки активности:', error);
    res.status(500).json({ success: false, message: 'Ошибка отправки проверки активности' });
  }
});

// 🔐 БЕЗОПАСНОСТЬ: Подтверждение активности (публичный эндпоинт)
app.get('/api/confirm_alive/:token', async (req, res) => {
  try {
    let token = req.params.token;
    let tokenData = aliveCheckTokens[token];
    
    if (!tokenData) {
      // Пробуем найти токен в БД
      const row = await dbGet('SELECT * FROM alive_checks WHERE token = ?', [token]);
      if (!row) {
        return res.status(404).send(`
          <html>
            <head>
              <title>Токен не найден</title>
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
            </head>
            <body style="font-family: Arial; text-align: center; padding: 50px;">
              <h1 style="color: #f44336;">Ссылка недействительна</h1>
              <p>Возможно, ссылка устарела или уже была использована.</p>
              <a href="/" style="color: #4CAF50; text-decoration: none;">Вернуться на главную</a>
            </body>
          </html>
        `);
      }
      
      tokenData = {
        email: row.email,
        token: row.token,
        expires: new Date(row.next_check).getTime(),
        intervalDays: Math.round((new Date(row.next_check) - new Date(row.last_check)) / (24 * 60 * 60 * 1000))
      };
    }

    if (new Date(tokenData.expires) < new Date()) {
      delete aliveCheckTokens[token];
      await dbRun('DELETE FROM alive_checks WHERE token = ?', [token]);
      return res.status(400).send(`
        <html>
          <head>
            <title>Срок действия истек</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
          </head>
          <body style="font-family: Arial; text-align: center; padding: 50px;">
            <h1 style="color: #FF9800;">Срок действия ссылки истек</h1>
            <p>Пожалуйста, запросите новую проверку активности в вашем профиле.</p>
            <a href="/" style="color: #4CAF50; text-decoration: none;">Вернуться на главную</a>
          </body>
        </html>
      `);
    }

    const userEmail = tokenData.email;
    const user = users[userEmail];
    
    if (!user) {
      return res.status(404).send(`
        <html>
          <head>
            <title>Пользователь не найден</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
          </head>
          <body style="font-family: Arial; text-align: center; padding: 50px;">
            <h1 style="color: #f44336;">Пользователь не найден</h1>
            <a href="/" style="color: #4CAF50; text-decoration: none;">Вернуться на главную</a>
          </body>
        </html>
      `);
    }

    const lastAliveCheckConfirmed = new Date().toISOString();
    const lastActivity = new Date().toISOString();
    const nextAliveCheckDate = new Date(Date.now() + tokenData.intervalDays * 24 * 60 * 60 * 1000).toISOString();
    
    // Обновляем в БД
    await dbRun(`
        UPDATE users 
        SET last_alive_check_confirmed = ?, last_activity = ?, next_alive_check_date = ?
        WHERE email = ?
    `, [lastAliveCheckConfirmed, lastActivity, nextAliveCheckDate, userEmail]);
    
    // Удаляем токен из БД
    await dbRun('DELETE FROM alive_checks WHERE token = ?', [token]);
    
    // Обновляем в памяти
    user.lastAliveCheckConfirmed = lastAliveCheckConfirmed;
    user.lastActivity = lastActivity;
    user.nextAliveCheckDate = nextAliveCheckDate;
    
    delete aliveCheckTokens[token];

    res.send(`
      <html>
        <head>
          <title>Подтверждение успешно</title>
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <style>
            @import url('https://fonts.googleapis.com/css2?family=Montserrat:wght@400;500;600;700&family=Open+Sans&display=swap');
            body { 
              font-family: 'Open Sans', sans-serif; 
              text-align: center; 
              padding: 50px 20px;
              background: linear-gradient(135deg, #4CAF50 0%, #388E3C 100%);
              min-height: 100vh;
              display: flex;
              align-items: center;
              justify-content: center;
              margin: 0;
            }
            .container {
              background: white;
              border-radius: 20px;
              padding: 50px;
              max-width: 600px;
              box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            }
            h1 { 
              color: #4CAF50; 
              font-family: 'Montserrat', sans-serif;
              font-size: 2.5rem;
              margin-bottom: 20px;
            }
            .success-icon {
              font-size: 80px;
              color: #4CAF50;
              margin: 30px 0;
            }
            p { 
              font-size: 18px; 
              line-height: 1.6;
              color: #333;
              margin-bottom: 30px;
            }
            .button { 
              display: inline-block; 
              background: linear-gradient(45deg, #4CAF50, #388E3C);
              color: white; 
              padding: 18px 40px; 
              text-decoration: none; 
              border-radius: 50px; 
              font-size: 18px; 
              font-weight: bold;
              margin-top: 20px;
              border: none;
              cursor: pointer;
              transition: all 0.3s;
              box-shadow: 0 4px 15px rgba(76, 175, 80, 0.3);
            }
            .button:hover {
              transform: translateY(-3px);
              box-shadow: 0 6px 20px rgba(76, 175, 80, 0.4);
            }
            .user-email {
              background: #f8f9fa;
              padding: 15px;
              border-radius: 10px;
              margin: 20px 0;
              font-weight: bold;
              color: #4CAF50;
              border-left: 4px solid #4CAF50;
            }
            .info-box {
              background: #e8f5e9;
              border-radius: 10px;
              padding: 20px;
              margin: 30px 0;
              text-align: left;
            }
            .info-box h3 {
              color: #388E3C;
              margin-top: 0;
            }
            @media (max-width: 600px) {
              .container {
                padding: 30px 20px;
              }
              h1 {
                font-size: 2rem;
              }
            }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="success-icon">✅</div>
            <h1>Активность подтверждена!</h1>
            
            <div class="user-email">
              Аккаунт: ${userEmail}
            </div>
            
            <p>Вы успешно подтвердили свою активность в LegacyNet.</p>
            
            <div class="info-box">
              <h3>✅ Что это значит?</h3>
              <p>• Ваше завещание останется неактивным до следующей проверки</p>
              <p>• Следующая проверка будет через ${tokenData.intervalDays} дней</p>
              <p>• Вы можете отключить эту функцию в настройках активации</p>
            </div>
            
            <p>Спасибо, что пользуетесь нашим сервисом!</p>
            
            <a href="/" class="button">Вернуться на главную</a>
          </div>
        </body>
      </html>
    `);
  } catch (error) {
    console.error('Ошибка подтверждения активности:', error);
    res.status(500).send(`
      <html>
        <head>
          <title>Ошибка</title>
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="font-family: Arial; text-align: center; padding: 50px;">
          <h1 style="color: #f44336;">Произошла ошибка</h1>
          <p>Пожалуйста, попробуйте позже или обратитесь в поддержку.</p>
          <a href="/" style="color: #4CAF50; text-decoration: none;">Вернуться на главную</a>
        </body>
      </html>
    `);
  }
});

// Получение статуса проверки активности
app.get('/api/alive_check_status', verifyTokenWithCsrf, (req, res) => {
  try {
    const user = users[req.user.email];
    if (!user) {
      return res.status(404).json({ success: false, message: 'Пользователь не найден' });
    }
    
    const emailCheckEnabled = user.activationMethods && user.activationMethods.includes('email_check');
    
    let status = 'not_enabled';
    let daysUntilNextCheck = null;
    let isOverdue = false;
    
    if (emailCheckEnabled && user.nextAliveCheckDate) {
      const nextCheckDate = new Date(user.nextAliveCheckDate);
      const now = new Date();
      const diffTime = nextCheckDate - now;
      daysUntilNextCheck = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
      
      if (nextCheckDate < now) {
        status = 'overdue';
        isOverdue = true;
        daysUntilNextCheck = Math.abs(daysUntilNextCheck);
      } else {
        status = 'scheduled';
      }
    } else if (emailCheckEnabled) {
      status = 'never_sent';
    }
    
    res.json({
      success: true,
      emailCheckEnabled: emailCheckEnabled,
      emailCheckSettings: user.emailCheckSettings || { interval: '30', gracePeriod: '30' },
      lastAliveCheckSent: user.lastAliveCheckSent,
      lastAliveCheckConfirmed: user.lastAliveCheckConfirmed,
      nextAliveCheckDate: user.nextAliveCheckDate,
      daysUntilNextCheck: daysUntilNextCheck,
      isOverdue: isOverdue,
      intervalDays: user.emailCheckSettings?.interval || 30,
      gracePeriodDays: user.emailCheckSettings?.gracePeriod || 30
    });
  } catch (error) {
    console.error('Ошибка получения статуса проверки активности:', error);
    res.status(500).json({ success: false, message: 'Ошибка получения статуса' });
  }
});

// ========== ДОБАВЛЕННЫЕ ЭНДПОИНТЫ ДЛЯ НАСТРОЕК АКТИВАЦИИ ==========
// Получение настроек активации
app.get('/api/activation_settings', verifyTokenWithCsrf, (req, res) => {
  try {
    const user = users[req.user.email];
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'Пользователь не найден' });
    }
    
    const emailCheckEnabled = user.activationMethods && user.activationMethods.includes('email_check');
    
    res.json({
      success: true,
      settings: {
        activationMethods: user.activationMethods || ['email_check'],
        emailCheckSettings: user.emailCheckSettings || { interval: '30', gracePeriod: '30' },
        deathVerificationCode: user.deathVerificationCode || '',
        trustedContacts: user.trustedContacts || [],
        emailCheckEnabled: emailCheckEnabled,
        lastAliveCheckSent: user.lastAliveCheckSent,
        lastAliveCheckConfirmed: user.lastAliveCheckConfirmed,
        nextAliveCheckDate: user.nextAliveCheckDate
      }
    });
    
  } catch (error) {
    console.error('Ошибка загрузки настроек активации:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Ошибка загрузки настроек активации' 
    });
  }
});

// 🔐 СОХРАНЕНИЕ НАСТРОЕК АКТИВАЦИИ С CSRF ЗАЩИТОЙ
app.post('/api/activation_settings', verifyTokenWithCsrf, async (req, res) => {
  try {
    const userEmail = req.user.email;
    const user = users[userEmail];
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'Пользователь не найден' });
    }
    
    const { 
      activationMethods, 
      emailCheckSettings, 
      trustedContacts, 
      trustedContactCode 
    } = req.body;
    
    let updateFields = {};
    let updateValues = [];
    
    // Сохраняем методы активации
    if (activationMethods) {
      updateFields.activation_methods = JSON.stringify(activationMethods);
      user.activationMethods = activationMethods;
    }
    
    // Сохраняем настройки email-проверки
    if (emailCheckSettings) {
      updateFields.email_check_settings = JSON.stringify(emailCheckSettings);
      user.emailCheckSettings = emailCheckSettings;
    }
    
    // Сохраняем код для доверенного лица
    if (trustedContactCode) {
      updateFields.death_verification_code = trustedContactCode;
      user.deathVerificationCode = trustedContactCode;
    }
    
    // Сохраняем доверенные контакты
    if (trustedContacts) {
      updateFields.trusted_contacts = JSON.stringify(trustedContacts);
      user.trustedContacts = trustedContacts;
    }
    
    // Обновляем дату следующей проверки
    if (activationMethods && activationMethods.includes('email_check')) {
      const intervalDays = parseInt(emailCheckSettings?.interval || 30);
      const nextAliveCheckDate = new Date(Date.now() + intervalDays * 24 * 60 * 60 * 1000).toISOString();
      updateFields.next_alive_check_date = nextAliveCheckDate;
      user.nextAliveCheckDate = nextAliveCheckDate;
    }
    
    // Формируем SQL запрос
    if (Object.keys(updateFields).length > 0) {
      const setClause = Object.keys(updateFields).map(key => `${key} = ?`).join(', ');
      updateValues = [...Object.values(updateFields), userEmail];
      
      await dbRun(`UPDATE users SET ${setClause} WHERE email = ?`, updateValues);
    }
    
    res.json({ 
      success: true, 
      message: 'Настройки активации сохранены' 
    });
    
  } catch (error) {
    console.error('Ошибка сохранения настроек активации:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Ошибка сохранения настроек активации' 
    });
  }
});

// ========== ОСНОВНЫЕ ЭНДПОИНТЫ АУТЕНТИФИКАЦИИ ==========

const codes = {};

// 🔐 Регистрация - только временное сохранение данных
app.post('/api/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email и пароль обязательны' });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ success: false, message: 'Неверный формат email' });
    }

    const minLength = parseInt(process.env.PASSWORD_MIN_LENGTH) || 8;
    if (password.length < minLength) {
      return res.status(400).json({ 
        success: false, 
        message: `Пароль должен быть не менее ${minLength} символов` 
      });
    }

    // 🔐 Проверяем, не зарегистрирован ли уже email
    if (users[email]) {
      return res.status(400).json({ success: false, message: 'Email уже зарегистрирован' });
    }

    // 🔐 Проверяем, нет ли уже pending-регистрации для этого email
    if (pendingRegistrations[email]) {
      const pending = pendingRegistrations[email];
      if (pending.expires > Date.now()) {
        return res.status(400).json({ 
          success: false, 
          message: 'Регистрация для этого email уже начата. Проверьте почту или подождите 5 минут.' 
        });
      }
    }

    // 🔐 Хешируем пароль
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    
    // 🔐 Генерируем код подтверждения
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    
    // 🔐 Сохраняем во временные данные (не в основную базу!)
    pendingRegistrations[email] = {
      email: email,
      hashedPassword: hashedPassword,
      code: code,
      expires: Date.now() + 300000, // 5 минут
      attempts: 0
    };

    console.log(`✅ Временная регистрация для ${email}: ${code}`);

    // 🔐 Отправляем код на почту
    const emailSent = await sendEmailCode(email, code, 'register');
    
    if (!emailSent) {
      console.warn(`⚠️ Не удалось отправить email на ${email}, но регистрация продолжается`);
    }

    // 🔐 Создаем временный токен для подтверждения (15 минут)
    const tempToken = jwt.sign({ 
      email: email,
      type: 'registration_temp',
      iat: Math.floor(Date.now() / 1000)
    }, JWT_SECRET, { expiresIn: TEMP_TOKEN_EXPIRY });
    
    res.json({ 
      success: true, 
      temp_token: tempToken,
      message: emailSent ? 'Код подтверждения отправлен на вашу почту' : 'Код сгенерирован (проверьте консоль сервера)'
    });
  } catch (error) {
    console.error('❌ Ошибка регистрации:', error);
    res.status(500).json({ success: false, message: 'Внутренняя ошибка сервера' });
  }
});

// 🔐 Логин с защитой от брутфорса
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email и пароль обязательны' });
    }

    const user = users[email];
    
    if (user && user.loginAttempts >= (parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5)) {
      const lastFailed = user.lastFailedLogin ? new Date(user.lastFailedLogin) : null;
      const now = new Date();
      
      if (lastFailed && (now - lastFailed) < 15 * 60 * 1000) {
        return res.status(429).json({ 
          success: false, 
          message: 'Аккаунт временно заблокирован. Попробуйте через 15 минут.' 
        });
      } else {
        user.loginAttempts = 0;
      }
    }

    if (!user || !(await bcrypt.compare(password, user.password))) {
      if (user) {
        user.loginAttempts = (user.loginAttempts || 0) + 1;
        user.lastFailedLogin = new Date().toISOString();
        // Обновляем в БД
        await dbRun('UPDATE users SET login_attempts = ?, last_failed_login = ? WHERE email = ?',
            [user.loginAttempts, user.lastFailedLogin, email]);
      }
      
      return res.status(401).json({ 
        success: false, 
        message: 'Неверный email или пароль',
        attemptsLeft: user ? (parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5) - user.loginAttempts : 0
      });
    }

    user.loginAttempts = 0;
    user.lastFailedLogin = null;
    user.lastLogin = new Date().toISOString();
    user.lastActivity = new Date().toISOString();
    
    // Обновляем в БД
    await dbRun(`
        UPDATE users 
        SET login_attempts = ?, last_failed_login = ?, last_login = ?, last_activity = ?
        WHERE email = ?
    `, [0, null, user.lastLogin, user.lastActivity, email]);

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    codes[email] = { code, expires: Date.now() + 300000, type: 'login' };

    console.log(`Код входа для ${email}: ${code}`);

    const emailSent = await sendEmailCode(email, code, 'login');
    
    if (!emailSent) {
      console.warn(`Не удалось отправить email на ${email}, но вход продолжается`);
    }

    // 🔐 Временный токен для 2FA (15 минут)
    const tempToken = jwt.sign({ 
      email: email,
      type: 'login_temp'
    }, JWT_SECRET, { expiresIn: TEMP_TOKEN_EXPIRY });
    
    res.json({ 
      success: true, 
      temp_token: tempToken,
      message: emailSent ? 'Код отправлен на вашу почту' : 'Код сгенерирован (проверьте консоль сервера)'
    });
  } catch (error) {
    console.error('Ошибка входа:', error);
    res.status(500).json({ success: false, message: 'Внутренняя ошибка сервера' });
  }
});

// 🔐 Подтверждение 2FA и регистрации - ИСПРАВЛЕННЫЙ ВАРИАНТ С CSRF
app.post('/api/verify_2fa', async (req, res) => {
  try {
    const { temp_token, code } = req.body;
    
    if (!temp_token || !code) {
      return res.status(400).json({ success: false, message: 'Токен и код обязательны' });
    }

    const decoded = jwt.verify(temp_token, JWT_SECRET);
    
    // 🔐 Обработка регистрации
    if (decoded.type === 'registration_temp') {
      const pendingReg = pendingRegistrations[decoded.email];
      
      if (!pendingReg) {
        return res.status(400).json({ 
          success: false, 
          message: 'Регистрация не найдена или истекла. Начните заново.' 
        });
      }

      if (pendingReg.expires < Date.now()) {
        delete pendingRegistrations[decoded.email];
        return res.status(400).json({ 
          success: false, 
          message: 'Время подтверждения истекло. Начните регистрацию заново.' 
        });
      }

      if (pendingReg.code !== code) {
        pendingReg.attempts = (pendingReg.attempts || 0) + 1;
        
        if (pendingReg.attempts >= 5) {
          delete pendingRegistrations[decoded.email];
          return res.status(400).json({ 
            success: false, 
            message: 'Слишком много неверных попыток. Регистрация отменена.' 
          });
        }
        
        return res.status(401).json({ 
          success: false, 
          message: `Неверный код. Осталось попыток: ${5 - pendingReg.attempts}` 
        });
      }

      // 🔐 ВСЁ ПРОВЕРЕНО - СОЗДАЁМ АККАУНТ В БД
      const userSalt = crypto.randomBytes(16).toString('hex');
      const subscriptionExpiry = null;
      const tokenVersion = 0; // Начальная версия токенов
      const registrationDate = new Date().toISOString();
      const lastActivity = new Date().toISOString();
      
      // Вставляем пользователя в БД
      await dbRun(`
          INSERT INTO users (
              email, password, user_salt, token_version, registration_date, 
              last_activity, last_login, subscription, two_factor_enabled, 
              two_factor_secret, is_admin, personal_data, activation_methods, 
              email_check_settings, verified
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `, [
          decoded.email, pendingReg.hashedPassword, userSalt, tokenVersion,
          registrationDate, lastActivity, lastActivity, 'free', 1,
          null, 0,
          '{"isAnonymous":true,"searchMethods":["email"]}',
          '["email_check"]',
          '{"interval":"30","gracePeriod":"30"}',
          1
      ]);

      // Обновляем в памяти
      users[decoded.email] = { 
        password: pendingReg.hashedPassword, 
        encrypted: '', 
        contacts: [], 
        registrationDate: registrationDate, 
        lastLogin: lastActivity,
        lastActivity: lastActivity,
        subscription: 'free',
        subscriptionExpiry: subscriptionExpiry,
        twoFactorEnabled: true,
        twoFactorSecret: null,
        verificationCode: null,
        verificationCodeExpiry: null,
        verificationCodeAttempts: 0,
        aliveCheckToken: null,
        isAdmin: false,
        personalData: {
          isAnonymous: true,
          searchMethods: ['email']
        },
        activationMethods: ['email_check'],
        emailCheckSettings: { interval: '30', gracePeriod: '30' },
        masterPasswordHash: null,
        legacyEncrypted: null,
        encryptionMethod: 'no_encryption',
        legacyLastUpdated: null,
        userSalt: userSalt,
        tokenVersion: tokenVersion,
        lastAliveCheckSent: null,
        lastAliveCheckConfirmed: null,
        nextAliveCheckDate: null,
        loginAttempts: 0,
        lastFailedLogin: null,
        verified: true,
        banned: false,
        deceased: false,
        deathVerificationCode: null,
        trustedContacts: [],
        legacyKey: null,
        legacyMigrated: false
      };

      // 🔐 Очищаем временные данные
      delete pendingRegistrations[decoded.email];
      delete codes[decoded.email];

      console.log(`✅ Аккаунт создан в БД для ${decoded.email} после подтверждения email`);

      // 🔐 Генерируем access и refresh токены
      const accessToken = generateAccessToken(decoded.email, tokenVersion);
      const refreshToken = generateRefreshToken(decoded.email, tokenVersion);
      
      // 🔐 Генерируем и устанавливаем CSRF токен
      const csrfToken = crypto.randomBytes(32).toString('hex');
      const csrfExpiry = Date.now() + 4 * 60 * 60 * 1000;

      // Сохраняем в БД
      await dbRun(
          'INSERT INTO csrf_tokens (token, user_email, expires) VALUES (?, ?, ?)',
          [csrfToken, decoded.email, csrfExpiry]
      );

      // 🔐 УСТАНАВЛИВАЕМ HTTPONLY COOKIE
      res.cookie('csrf_token', csrfToken, {
          httpOnly: true, // НЕДОСТУПЕН для JS
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          path: '/',
          maxAge: 4 * 60 * 60 * 1000
      });
      
      // 🔐 Устанавливаем токены в cookies
      setAuthCookies(res, accessToken, refreshToken);
      
      res.json({ 
        success: true, 
        message: 'Аккаунт успешно создан и подтверждён!',
        email: decoded.email,
        csrfToken
      });
      
    } else if (decoded.type === 'login_temp') {
      // 🔐 Оригинальная логика для входа
      const storedCode = codes[decoded.email];
      
      if (!storedCode || storedCode.expires < Date.now() || storedCode.code !== code) {
        return res.status(401).json({ success: false, message: 'Неверный или истекший код' });
      }

      delete codes[decoded.email];

      const user = users[decoded.email];
      if (!user) {
        return res.status(404).json({ success: false, message: 'Пользователь не найден' });
      }

      // Получаем текущую версию токенов пользователя
      const tokenVersion = user.tokenVersion || 0;
      
      // Обновляем активность
      user.lastActivity = new Date().toISOString();
      user.lastLogin = new Date().toISOString();
      
      // Обновляем в БД
      await dbRun('UPDATE users SET last_activity = ?, last_login = ? WHERE email = ?',
          [user.lastActivity, user.lastLogin, decoded.email]);

      // 🔐 Генерируем access и refresh токены
      const newAccessToken = generateAccessToken(decoded.email, tokenVersion);
      const newRefreshToken = generateRefreshToken(decoded.email, tokenVersion);
      
      // 🔐 Генерируем и устанавливаем CSRF токен
      const csrfToken = crypto.randomBytes(32).toString('hex');
      const csrfExpiry = Date.now() + 4 * 60 * 60 * 1000;

      // Сохраняем в БД
      await dbRun(
          'INSERT INTO csrf_tokens (token, user_email, expires) VALUES (?, ?, ?)',
          [csrfToken, decoded.email, csrfExpiry]
      );

      // 🔐 УСТАНАВЛИВАЕМ HTTPONLY COOKIE
      res.cookie('csrf_token', csrfToken, {
          httpOnly: true, // НЕДОСТУПЕН для JS
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          path: '/',
          maxAge: 4 * 60 * 60 * 1000
      });
      
      // 🔐 Устанавливаем токены в cookies
      setAuthCookies(res, newAccessToken, newRefreshToken);
      
      res.json({ 
        success: true, 
        message: 'Успешный вход',
        email: decoded.email,
        csrfToken
      });
    } else {
      return res.status(400).json({ 
        success: false, 
        message: 'Неверный тип токена' 
      });
    }
  } catch (err) {
    console.error('❌ Ошибка верификации:', err);
    
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        success: false, 
        message: 'Время подтверждения истекло. Начните заново.' 
      });
    }
    
    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({ 
        success: false, 
        message: 'Неверный токен' 
      });
    }
    
    res.status(401).json({ success: false, message: 'Ошибка верификации' });
  }
});

// 🔐 Эндпоинт для выхода
app.post('/api/logout', verifyTokenWithCsrf, async (req, res) => {
  try {
    const refreshToken = req.cookies.refresh_token;
    
    // Добавляем refresh токен в черный список
    if (refreshToken) {
      await blacklistRefreshToken(refreshToken);
    }
    
    // Очищаем cookies
    clearAuthCookies(res);
    
    // Отзываем все CSRF токены пользователя
    const userEmail = req.user.email;
    const csrfKeys = csrfTokens.keys();
    csrfKeys.forEach(key => {
      if (key.startsWith(`${userEmail}:`)) {
        csrfTokens.del(key);
      }
    });
    
    res.json({ 
      success: true, 
      message: 'Выход выполнен' 
    });
  } catch (error) {
    console.error('Ошибка выхода:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Ошибка выхода' 
    });
  }
});

// 🔐 Эндпоинт для выхода со всех устройств
app.post('/api/logout_all_devices', verifyTokenWithCsrf, async (req, res) => {
  try {
    const userEmail = req.user.email;
    const user = users[userEmail];
    
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'Пользователь не найден' 
      });
    }
    
    // Увеличиваем версию токенов, что сделает все старые токены недействительными
    user.tokenVersion = (user.tokenVersion || 0) + 1;
    user.lastActivity = new Date().toISOString();
    
    // Обновляем в БД
    await dbRun('UPDATE users SET token_version = ?, last_activity = ? WHERE email = ?',
        [user.tokenVersion, user.lastActivity, userEmail]);
    
    // Отзываем все CSRF токены пользователя
    const csrfKeys = csrfTokens.keys();
    csrfKeys.forEach(key => {
      if (key.startsWith(`${userEmail}:`)) {
        csrfTokens.del(key);
      }
    });
    
    // Очищаем cookies
    clearAuthCookies(res);
    
    res.json({ 
      success: true, 
      message: 'Выполнен выход со всех устройств. Пожалуйста, войдите снова.',
      newTokenVersion: user.tokenVersion
    });
    
  } catch (error) {
    console.error('Ошибка выхода со всех устройств:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Ошибка выхода со всех устройств' 
    });
  }
});

// 🔐 Эндпоинт для отметки завещания как просмотренного
app.post('/api/mark_legacy_viewed', verifyTokenWithCsrf, async (req, res) => {
  try {
    const { claimCode } = req.body;
    
    if (!claimCode) {
      return res.status(400).json({ 
        success: false, 
        message: 'Код обязателен' 
      });
    }

    const claim = claims[claimCode];
    if (!claim) {
      return res.status(404).json({ 
        success: false, 
        message: 'Claim не найден' 
      });
    }

    // Отмечаем как просмотренное в БД
    const viewedAt = new Date().toISOString();
    await dbRun('UPDATE claims SET viewed = 1, viewed_at = ? WHERE claim_code = ?',
        [viewedAt, claimCode]);
    
    // Обновляем в памяти
    claim.viewed = true;
    claim.viewedAt = viewedAt;
    
    res.json({ 
      success: true, 
      message: 'Завещание отмечено как просмотренное' 
    });
  } catch (error) {
    console.error('Ошибка отметки завещания:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Ошибка отметки завещания' 
    });
  }
});

// 🔐 Получение профиля - ИСПРАВЛЕННЫЙ ВАРИАНТ
app.get('/api/profile', verifyTokenWithCsrf, async (req, res) => {
    try {
        const userEmail = req.user.email;
        const user = users[userEmail];
        
        if (!user) {
            console.error('Profile: пользователь не найден в базе:', userEmail);
            return res.status(404).json({ success: false, message: 'Пользователь не найден' });
        }
        
        // Проверяем подписку
        const subscriptionUpdated = checkAndUpdateSubscription(userEmail, user);
        if (subscriptionUpdated) {
            await dbRun('UPDATE users SET subscription = ?, subscription_expiry = ? WHERE email = ?',
                [user.subscription, user.subscriptionExpiry, userEmail]);
        }
        
        user.lastActivity = new Date().toISOString();
        await dbRun('UPDATE users SET last_activity = ? WHERE email = ?', 
            [user.lastActivity, userEmail]);
        
        let displaySubscriptionExpiry = null;
        if (user.subscriptionExpiry) {
            const expiryDate = new Date(user.subscriptionExpiry);
            displaySubscriptionExpiry = expiryDate.toLocaleDateString('ru-RU', {
                day: '2-digit',
                month: '2-digit', 
                year: 'numeric'
            });
        }
        
        // 🔐 ГЕНЕРИРУЕМ НОВЫЙ CSRF ТОКЕН ПРИ КАЖДОМ ЗАПРОСЕ ПРОФИЛЯ
        const newCsrfToken = crypto.randomBytes(32).toString('hex');
        const csrfExpiry = Date.now() + 4 * 60 * 60 * 1000;
        
        await dbRun(
            'INSERT INTO csrf_tokens (token, user_email, expires) VALUES (?, ?, ?)',
            [newCsrfToken, userEmail, csrfExpiry]
        );
        
        res.cookie('csrf_token', newCsrfToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            path: '/',
            maxAge: 4 * 60 * 60 * 1000
        });
        
        res.json({
            success: true,
            email: userEmail,
            masterPasswordSet: !!user.masterPasswordHash,
            encryptionMethod: user.encryptionMethod || 'no_encryption',
            legacyLastUpdated: user.legacyLastUpdated || null,
            legacyMigrated: user.legacyMigrated || false,
            subscription: user.subscription || 'free',
            subscriptionExpiry: user.subscriptionExpiry || null,
            subscriptionExpiryDisplay: displaySubscriptionExpiry,
            registrationDate: user.registrationDate,
            lastActivity: user.lastActivity || new Date().toISOString(),
            lastLogin: user.lastLogin,
            twoFactorEnabled: user.twoFactorEnabled !== undefined ? user.twoFactorEnabled : true,
            activationMethods: user.activationMethods || ['email_check'],
            deathVerificationCode: user.deathVerificationCode || '',
            deceased: user.deceased || false,
            personalData: user.personalData || { isAnonymous: true, searchMethods: ['email'] },
            lastAliveCheckSent: user.lastAliveCheckSent,
            lastAliveCheckConfirmed: user.lastAliveCheckConfirmed,
            nextAliveCheckDate: user.nextAliveCheckDate,
            emailCheckSettings: user.emailCheckSettings || { interval: '30', gracePeriod: '30' },
            tokenVersion: user.tokenVersion || 0,
            csrfToken: newCsrfToken // 🔥 ВОЗВРАЩАЕМ НОВЫЙ ТОКЕН
        });
    } catch (error) {
        console.error('Ошибка получения профиля:', error);
        res.status(500).json({ success: false, message: 'Ошибка загрузки профиля' });
    }
});

// 🔐 БЕЗОПАСНОСТЬ: Установка контактов с телефонами для Premium - ИСПРАВЛЕННЫЙ ВАРИАНТ
app.post('/api/set_contacts', verifyTokenWithCsrf, async (req, res) => {
    try {
        const { contacts } = req.body;
        
        // 🔥 ВАЖНО: Проверяем, что пользователь существует
        if (!users[req.user.email]) {
            console.error('Set contacts: пользователь не найден:', req.user.email);
            return res.status(404).json({ success: false, message: 'Пользователь не найден' });
        }
        
        const validContacts = [];
        
        // Проверяем каждый контакт
        for (const contact of contacts) {
            let email = null;
            let phone = null;
            
            // 🔥 ВАЖНО: Обрабатываем оба формата - строку и объект
            if (typeof contact === 'string') {
                email = contact.trim().toLowerCase();
            } else if (contact && typeof contact === 'object') {
                email = contact.email ? contact.email.trim().toLowerCase() : null;
                phone = contact.phone ? contact.phone.trim() : null;
            }
            
            if (!email) {
                console.log('Пропускаем контакт без email:', contact);
                continue;
            }
            
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                console.log('Некорректный email:', email);
                continue;
            }
            
            const contactData = { email: email };
            
            // Проверяем, есть ли телефон (только для Premium)
            const subscription = users[req.user.email].subscription || 'free';
            const isPremium = subscription.includes('premium') || subscription === 'lifetime';
            
            if (isPremium && phone) {
                const phoneDigits = phone.replace(/\D/g, '');
                if (phoneDigits.length >= 10) {
                    contactData.phone = phone;
                }
            }
            
            validContacts.push(contactData);
        }
        
        // Удаляем дубликаты по email
        const uniqueContacts = Array.from(new Map(validContacts.map(c => [c.email, c])).values());
        
        const subscription = users[req.user.email].subscription || 'free';
        const maxContacts = (subscription.includes('premium') || subscription === 'lifetime') ? 8 : 1;
        
        if (uniqueContacts.length > maxContacts) {
            return res.status(400).json({ 
                success: false, 
                message: `Превышен лимит контактов для вашего тарифа. Максимум: ${maxContacts}` 
            });
        }
        
        // Обновляем в БД
        await dbRun('UPDATE users SET contacts = ? WHERE email = ?',
            [JSON.stringify(uniqueContacts), req.user.email]);
        
        // Обновляем в памяти
        users[req.user.email].contacts = uniqueContacts;
        
        console.log('Контакты сохранены для', req.user.email, 'количество:', uniqueContacts.length);
        
        res.json({ 
            success: true, 
            message: `Контакты сохранены (${uniqueContacts.length} email)`,
            contacts: uniqueContacts 
        });
    } catch (error) {
        console.error('Ошибка сохранения контактов:', error);
        res.status(500).json({ success: false, message: 'Ошибка сохранения контактов' });
    }
});

// Получение контактов с телефонами
app.get('/api/get_contacts', verifyTokenWithCsrf, (req, res) => {
  try {
    const user = users[req.user.email];
    if (!user) {
      return res.status(404).json({ success: false, contacts: [] });
    }
    // Возвращаем контакты с телефонами, если они есть
    res.json({ success: true, contacts: user.contacts || [] });
  } catch (error) {
    console.error('Ошибка получения контактов:', error);
    res.status(500).json({ success: false, contacts: [] });
  }
});

// 🔐 Восстановление пароля - отправка кода
app.post('/api/forgot_password', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ success: false, message: 'Email обязателен' });
    }

    if (!users[email]) {
      // Все равно возвращаем успех для безопасности (security through obscurity)
      return res.json({ 
        success: true, 
        message: 'Если email зарегистрирован, код отправлен на почту' 
      });
    }

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    codes[email] = { code, expires: Date.now() + 300000, type: 'reset' };

    console.log(`Код восстановления для ${email}: ${code}`);

    const emailSent = await sendEmailCode(email, code, 'reset');
    
    if (!emailSent) {
      console.warn(`Не удалось отправить email на ${email}, но процесс восстановления продолжается`);
    }

    // 🔐 Временный токен для сброса пароля (15 минут)
    const tempToken = jwt.sign({ 
      email: email,
      type: 'reset_temp'
    }, JWT_SECRET, { expiresIn: TEMP_TOKEN_EXPIRY });
    
    res.json({ 
      success: true, 
      temp_token: tempToken,
      message: 'Если email зарегистрирован, код отправлен на почту'
    });
  } catch (error) {
    console.error('Ошибка восстановления пароля:', error);
    res.status(500).json({ success: false, message: 'Ошибка восстановления пароля' });
  }
});

// 🔐 Смена пароля
app.post('/api/reset_password', async (req, res) => {
  try {
    const { temp_token, code, newPassword } = req.body;
    
    if (!temp_token || !code || !newPassword) {
      return res.status(400).json({ success: false, message: 'Все поля обязательны' });
    }

    const decoded = jwt.verify(temp_token, JWT_SECRET);
    
    if (decoded.type !== 'reset_temp') {
      return res.status(400).json({ 
        success: false, 
        message: 'Неверный тип токена' 
      });
    }
    
    const storedCode = codes[decoded.email];
    
    if (!storedCode || storedCode.expires < Date.now() || storedCode.code !== code) {
      return res.status(401).json({ success: false, message: 'Неверный или истекший код' });
    }

    const minLength = parseInt(process.env.PASSWORD_MIN_LENGTH) || 8;
    if (newPassword.length < minLength) {
      return res.status(400).json({ 
        success: false, 
        message: `Пароль должен быть не менее ${minLength} символов` 
      });
    }

    const user = users[decoded.email];
    if (!user) {
      return res.status(404).json({ success: false, message: 'Пользователь не найден' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);
    const newTokenVersion = (user.tokenVersion || 0) + 1;
    
    // Обновляем в БД
    await dbRun(`
        UPDATE users 
        SET password = ?, login_attempts = 0, token_version = ?
        WHERE email = ?
    `, [hashedPassword, newTokenVersion, decoded.email]);
    
    // Обновляем в памяти
    user.password = hashedPassword;
    user.loginAttempts = 0;
    user.tokenVersion = newTokenVersion;
    
    delete codes[decoded.email];
    
    // 🔐 Генерируем новые токены
    const accessToken = generateAccessToken(decoded.email, newTokenVersion);
    const refreshToken = generateRefreshToken(decoded.email, newTokenVersion);
    
    // 🔐 Генерируем CSRF токен
    const csrfToken = crypto.randomBytes(32).toString('hex');
    const csrfExpiry = Date.now() + 4 * 60 * 60 * 1000;
    
    await dbRun(
        'INSERT INTO csrf_tokens (token, user_email, expires) VALUES (?, ?, ?)',
        [csrfToken, decoded.email, csrfExpiry]
    );
    
    // 🔐 Устанавливаем HTTPONLY COOKIE
    res.cookie('csrf_token', csrfToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        path: '/',
        maxAge: 4 * 60 * 60 * 1000
    });
    
    // 🔐 Устанавливаем токены в cookies
    setAuthCookies(res, accessToken, refreshToken);
    
    res.json({ 
      success: true, 
      message: 'Пароль успешно изменен',
      email: decoded.email,
      csrfToken
    });
  } catch (err) {
    console.error('Ошибка смены пароля:', err);
    
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        success: false, 
        message: 'Время сброса пароля истекло. Начните заново.' 
      });
    }
    
    res.status(401).json({ success: false, message: 'Ошибка смены пароля' });
  }
});

// 🔐 БЕЗОПАСНОСТЬ: Сохранение завещания с уникальными ключами
app.post('/api/save', verifyTokenWithCsrf, async (req, res) => {
  try {
    const { encrypted, encryptionMethod = 'no_encryption' } = req.body;
    const user = users[req.user.email];

    if (!user) {
      return res.status(404).json({ success: false, message: 'Пользователь не найден' });
    }

    console.log(`Сохранение завещания для ${req.user.email}, метод: ${encryptionMethod}`);
    
    let legacyEncrypted = encrypted;
    
    // Для метода без шифрования сохраняем как есть
    if (encryptionMethod !== 'no_encryption') {
      // 🔐 Генерируем/получаем уникальный ключ пользователя
      const userKey = getUserLegacyKey(req.user.email, user);
      
      // Шифруем данные уникальным ключом пользователя
      const encryptedData = CryptoJS.AES.encrypt(
        JSON.stringify(encrypted), 
        userKey
      ).toString();
      
      legacyEncrypted = encryptedData;
      
      // Помечаем как мигрированные
      await dbRun('UPDATE users SET legacy_migrated = 1 WHERE email = ?', [req.user.email]);
      user.legacyMigrated = true;
      
      console.log('Сохранено с уникальным ключом пользователя');
    }

    const legacyLastUpdated = new Date().toISOString();
    
    // Обновляем в БД
    await dbRun(`
        UPDATE users 
        SET legacy_encrypted = ?, encryption_method = ?, legacy_last_updated = ?
        WHERE email = ?
    `, [legacyEncrypted, encryptionMethod, legacyLastUpdated, req.user.email]);
    
    // Обновляем в памяти
    user.legacyEncrypted = legacyEncrypted;
    user.encryptionMethod = encryptionMethod;
    user.legacyLastUpdated = legacyLastUpdated;

    console.log(`Завещание сохранено для ${req.user.email}, метод: ${encryptionMethod}`);
    
    res.json({ success: true, message: 'Завещание сохранено' });
  } catch (error) {
    console.error('Ошибка сохранения завещания:', error);
    res.status(500).json({ success: false, message: 'Ошибка сохранения завещания' });
  }
});

// 🔐 БЕЗОПАСНОСТЬ: Загрузка завещания с уникальными ключами
app.post('/api/load', verifyTokenWithCsrf, async (req, res) => {
  try {
    const user = users[req.user.email];
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'Пользователь не найден' });
    }

    let decryptedData = null;
    
    if (user.legacyEncrypted) {
      if (user.encryptionMethod === 'no_encryption') {
        decryptedData = user.legacyEncrypted;
      } else {
        try {
          // 🔐 Автоматическая миграция при загрузке
          if (!user.legacyMigrated) {
            console.log(`Миграция данных при загрузке для ${req.user.email}`);
            await migrateLegacyDataToUserKey(req.user.email, user);
          }
          
          let decryptionKey;
          
          // Определяем ключ для дешифрования
          if (user.legacyKey && user.legacyMigrated) {
            decryptionKey = user.legacyKey;
            console.log(`Дешифровка с уникальным ключом для ${req.user.email}`);
          } else {
            // Резервный вариант для совместимости
            decryptionKey = 'legacy_net_default_key';
            console.log(`⚠️ Дешифровка со старым ключом для ${req.user.email} (требуется миграция)`);
          }
          
          const bytes = CryptoJS.AES.decrypt(user.legacyEncrypted, decryptionKey);
          const decryptedString = bytes.toString(CryptoJS.enc.Utf8);
          
          if (!decryptedString) {
            console.error('Не удалось расшифровать данные');
            throw new Error('Не удалось расшифровать завещание');
          }
          
          decryptedData = JSON.parse(decryptedString);
          console.log('Завещание успешно расшифровано');
        } catch (decryptError) {
          console.error('Ошибка дешифрования завещание:', decryptError);
          
          // 🔐 Пробуем альтернативные методы
          try {
            if (typeof user.legacyEncrypted === 'object') {
              decryptedData = user.legacyEncrypted;
            } else if (user.legacyEncrypted.trim().startsWith('{')) {
              decryptedData = JSON.parse(user.legacyEncrypted);
            } else {
              throw decryptError;
            }
          } catch (e) {
            return res.status(500).json({ 
              success: false, 
              message: 'Ошибка дешифрования завещание. Пожалуйста, пересохраните его.' 
            });
          }
        }
      }
    }

    res.json({
      success: true,
      encrypted: decryptedData,
      encryptionMethod: user.encryptionMethod || 'no_encryption',
      legacyLastUpdated: user.legacyLastUpdated || null,
      legacyMigrated: user.legacyMigrated || false
    });
  } catch (error) {
    console.error('Ошибка загрузки завещание:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Ошибка загрузки завещания' 
    });
  }
});

// 🔐 Отправка завещания с уникальными ключами С CSRF ЗАЩИТОЙ
app.post('/api/send_legacy', verifyTokenWithCsrf, async (req, res) => {
  try {
    const { encryptionMethod, masterPassword } = req.body;
    const user = users[req.user.email];
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'Пользователь не найден' });
    }

    if (!user.contacts || user.contacts.length === 0) {
      return res.status(400).json({ success: false, message: 'Добавьте контакты для отправки' });
    }

    if (!user.legacyEncrypted) {
      return res.status(400).json({ success: false, message: 'Сначала сохраните завещание' });
    }

    // Проверка метода шифрования
    if (encryptionMethod === 'master_password' && !masterPassword) {
      return res.status(400).json({ success: false, message: 'Мастер-пароль обязателен для выбранного метода' });
    }

    // 🔐 Проверяем, что метод шифрования соответствует сохраненному
    if (encryptionMethod !== user.encryptionMethod) {
      return res.status(400).json({ 
        success: false, 
        message: 'Метод шифрования не соответствует сохранному завещанию' 
      });
    }

    let emailsSent = 0;
    const userName = req.user.email.split('@')[0];
    
    // 🔐 Дешифруем завещание с помощью уникального ключа пользователя
    let decryptedLegacy;
    try {
      if (encryptionMethod === 'no_encryption') {
        decryptedLegacy = user.legacyEncrypted;
      } else {
        // Автоматическая миграция если нужно
        if (!user.legacyMigrated) {
          await migrateLegacyDataToUserKey(req.user.email, user);
        }
        
        let decryptionKey;
        if (user.legacyKey && user.legacyMigrated) {
          decryptionKey = user.legacyKey;
        } else {
          decryptionKey = 'legacy_net_default_key'; // Для совместимости
        }
        
        const bytes = CryptoJS.AES.decrypt(user.legacyEncrypted, decryptionKey);
        const decryptedString = bytes.toString(CryptoJS.enc.Utf8);
        
        if (!decryptedString) {
          throw new Error('Не удалось расшифровать');
        }
        
        decryptedLegacy = JSON.parse(decryptedString);
      }
    } catch (decryptError) {
      console.error('Ошибка дешифрования завещания:', decryptError);
      return res.status(500).json({ success: false, message: 'Ошибка обработки завещания' });
    }

    if (encryptionMethod === 'no_encryption') {
      // Для метода без шифрования - отправляем завещание прямо в письме
      try {
        const legacyData = decryptedLegacy;
        const legacyText = formatLegacyData(legacyData);
        
        // Отправляем каждому контакту
        for (const contact of user.contacts) {
          const contactEmail = typeof contact === 'string' ? contact : (contact.email || '');
          if (contactEmail) {
            const emailSent = await sendLegacyEmail(contactEmail, '', userName, 'no_encryption', legacyText);
            if (emailSent) {
              emailsSent++;
              console.log(`Завещание без шифрования отправлено на ${contactEmail}`);
            } else {
              console.error(`Не удалось отправить завещание на ${contactEmail}`);
            }
          }
        }
      } catch (error) {
        console.error('Ошибка обработки завещания:', error);
        return res.status(500).json({ success: false, message: 'Ошибка обработки завещания' });
      }
    } else {
      // Для методов с шифрованием - используем систему кодов
      const claimCode = crypto.randomBytes(12).toString('hex'); // ИЗМЕНЕНО: 12 байт вместо 8
      
      // 🔐 СОЗДАЕМ ВРЕМЕННЫЙ CLAIM В БД
      await dbRun(`
          INSERT INTO claims 
          (claim_code, encrypted, encryption_method, master_password, expires, user_email, source, owner_premium)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `, [
          claimCode, JSON.stringify(decryptedLegacy), encryptionMethod,
          encryptionMethod === 'master_password' ? masterPassword : null,
          Date.now() + 365 * 24 * 60 * 60 * 1000, // 1 год
          req.user.email, 'send_legacy_fixed_v2',
          user.subscription && (user.subscription.includes('premium') || user.subscription === 'lifetime') ? 1 : 0
      ]);

      // Обновляем в памяти
      claims[claimCode] = {
        claimCode,
        encrypted: JSON.stringify(decryptedLegacy),
        encryptionMethod: encryptionMethod,
        masterPassword: encryptionMethod === 'master_password' ? masterPassword : null,
        expires: Date.now() + 365 * 24 * 60 * 60 * 1000,
        userEmail: req.user.email,
        createdAt: new Date().toISOString(),
        source: 'send_legacy_fixed_v2',
        viewed: false,
        viewedAt: null,
        ownerPremium: user.subscription && (user.subscription.includes('premium') || user.subscription === 'lifetime')
      };

      console.log(`Claim сохранен в БД: ${claimCode}, тип данных: ${typeof decryptedLegacy}`);

      // Отправка email контактам
      for (const contact of user.contacts) {
        const contactEmail = typeof contact === 'string' ? contact : (contact.email || '');
        if (contactEmail) {
          const emailSent = await sendLegacyEmail(contactEmail, claimCode, userName, encryptionMethod);
          if (emailSent) {
            emailsSent++;
            console.log(`Завещание отправлено на ${contactEmail} (код претензии: ${claimCode})`);
          } else {
            console.error(`Не удалось отправить завещание на ${contactEmail}`);
          }
        }
      }
    }

    res.json({ 
      success: true, 
      message: `Завещание отправлено ${emailsSent} из ${user.contacts.length} контактам`,
      encryptionMethod: encryptionMethod
    });
  } catch (error) {
    console.error('Ошибка отправки завещание:', error);
    res.status(500).json({ success: false, message: 'Ошибка отправки завещание' });
  }
});

// 🔐 Претензия на завещание - БЕЗОПАСНАЯ ВЕРСИЯ С ПРОВЕРКОЙ МАСТЕР-ПАРОЛЯ
app.post('/api/claim_legacy', async (req, res) => {
  try {
    const { claimCode, masterPassword } = req.body;
    
    // 🔐 ВАЛИДАЦИЯ ВХОДНЫХ ДАННЫХ
    if (!claimCode || typeof claimCode !== 'string' || claimCode.length !== 24) {
        return res.status(400).json({ 
            success: false, 
            message: 'Неверный формат кода завещания',
            requiresMasterPassword: false 
        });
    }

    if (masterPassword && (typeof masterPassword !== 'string' || masterPassword.length < 8)) {
        return res.status(400).json({ 
            success: false, 
            message: 'Неверный формат мастер-пароля',
            requiresMasterPassword: true 
        });
    }
    
    console.log(`=== ЗАПРОС ЗАВЕЩАНИЯ ===`);
    console.log(`Код: ${claimCode}`);
    console.log(`Мастер-пароль предоставлен: ${!!masterPassword}`);
    
    const claim = claims[claimCode];
    
    if (!claim) {
      console.log(`Код не найден в базе данных`);
      return res.status(400).json({ 
        success: false, 
        message: 'Неверный код или срок действия истек',
        requiresMasterPassword: false 
      });
    }

    if (claim.expires < Date.now()) {
      console.log(`Код просрочен`);
      await dbRun('DELETE FROM claims WHERE claim_code = ?', [claimCode]);
      delete claims[claimCode];
      return res.status(400).json({ 
        success: false, 
        message: 'Срок действия кода истек',
        requiresMasterPassword: false 
      });
    }

    console.log(`Найден claim:`, {
      encryptionMethod: claim.encryptionMethod,
      source: claim.source || 'unknown',
      dataType: typeof claim.encrypted,
      isObject: typeof claim.encrypted === 'object',
      hasMasterPassword: !!claim.masterPassword
    });

    // Обновляем статус просмотра в БД
    if (!claim.viewed) {
      const viewedAt = new Date().toISOString();
      await dbRun('UPDATE claims SET viewed = 1, viewed_at = ? WHERE claim_code = ?',
          [viewedAt, claimCode]);
      
      claim.viewed = true;
      claim.viewedAt = viewedAt;
      console.log(`Завещание ${claimCode} отмечено как просмотренное`);
    }

    // 🔐 КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Если метод master_password
    if (claim.encryptionMethod === 'master_password') {
      console.log(`Метод шифрования: master_password`);
      
      if (!masterPassword) {
        console.log(`Мастер-пароль не предоставлен`);
        return res.status(400).json({ 
          success: false, 
          message: 'Для этого завещания требуется мастер-пароль',
          requiresMasterPassword: true,
          encryptionMethod: 'master_password'
        });
      }
      
      // 🔐 ПРОВЕРЯЕМ МАСТЕР-ПАРОЛЬ ЧЕРЕЗ BCrypt
      const userEmail = claim.userEmail;
      if (!userEmail) {
        console.log(`Нет email пользователя в claim`);
        return res.status(500).json({ 
          success: false, 
          message: 'Ошибка проверки пароля',
          requiresMasterPassword: true 
        });
      }
      
      const user = users[userEmail];
      if (!user) {
        console.log(`Пользователь не найден: ${userEmail}`);
        return res.status(400).json({ 
          success: false, 
          message: 'Ошибка проверки пароль',
          requiresMasterPassword: true 
        });
      }
      
      // 🔐 ПРОВЕРЯЕМ ХЕШ МАСТЕР-ПАРОЛЯ
      if (!user.masterPasswordHash) {
        console.log(`У пользователя нет хеша мастер-пароля`);
        return res.status(500).json({ 
          success: false, 
          message: 'Ошибка безопасности: мастер-пароль не установлен',
          requiresMasterPassword: true 
        });
      }
      
      const isPasswordValid = await bcrypt.compare(masterPassword, user.masterPasswordHash);
      if (!isPasswordValid) {
        console.log(`Неверный мастер-пароль`);
        return res.status(400).json({ 
          success: false, 
          message: 'Неверный мастер-пароль',
          requiresMasterPassword: true 
        });
      }
      
      console.log(`Мастер-пароль проверен успешно`);
    }

    // 🔐 Остальной код без изменений...
    let legacyData;
    
    if (typeof claim.encrypted === 'string') {
      console.log('Данные в виде строки, пытаемся расшифровать...');
      try {
        const FIXED_KEY = 'legacy_net_default_key';
        const bytes = CryptoJS.AES.decrypt(claim.encrypted, FIXED_KEY);
        const decryptedString = bytes.toString(CryptoJS.enc.Utf8);
        
        if (decryptedString) {
          legacyData = JSON.parse(decryptedString);
          console.log('Данные успешно расшифрованы из строки');
        } else {
          try {
            legacyData = JSON.parse(claim.encrypted);
            console.log('Данные парсились как JSON строка');
          } catch {
            throw new Error('Не удалось расшифровать данные');
          }
        }
      } catch (decryptError) {
        console.error('Ошибка расшифровки строки:', decryptError);
        return res.status(500).json({ 
          success: false, 
          message: 'Ошибка расшифровки завещания',
          requiresMasterPassword: false 
        });
      }
    } else if (typeof claim.encrypted === 'object') {
      console.log('Данные уже в виде объекта');
      legacyData = claim.encrypted;
    } else {
      console.error('Неизвестный формат данных:', typeof claim.encrypted);
      return res.status(500).json({ 
        success: false, 
        message: 'Некорректный формат завещания',
        requiresMasterPassword: false 
      });
    }

    // 🔐 САНИТИЗАЦИЯ ДАННЫХ ПЕРЕД ОТПРАВКОЙ КЛИЕНТУ
    legacyData = sanitizeLegacyData(legacyData);

    console.log('Данные для отправки:', {
      type: typeof legacyData,
      keys: legacyData ? Object.keys(legacyData) : 'null'
    });

    res.json({ 
      success: true, 
      encrypted: legacyData,
      encryptionMethod: claim.encryptionMethod
    });
    
    console.log('Завещание успешно отправлено клиенту');
    
  } catch (error) {
    console.error('Ошибка претензии на завещание:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Ошибка получения завещания',
      requiresMasterPassword: false 
    });
  }
});

// 🔐 ПОДПИСКА С CSRF ЗАЩИТОЙ
app.post('/api/subscribe', verifyTokenWithCsrf, async (req, res) => {
  try {
    const { plan } = req.body;
    
    if (!users[req.user.email]) {
      return res.status(404).json({ success: false, message: 'Пользователь не найден' });
    }
    
    let subscriptionExpiry = null;
    
    switch(plan) {
      case 'premium_monthly':
        subscriptionExpiry = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
        break;
      case 'premium_yearly':
        subscriptionExpiry = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();
        break;
      case 'lifetime':
        subscriptionExpiry = null;
        break;
      case 'free':
        subscriptionExpiry = null;
        break;
      default:
        subscriptionExpiry = null;
    }
    
    // Обновляем в БД
    await dbRun('UPDATE users SET subscription = ?, subscription_expiry = ?, last_activity = ? WHERE email = ?',
        [plan, subscriptionExpiry, new Date().toISOString(), req.user.email]);
    
    // Обновляем в памяти
    users[req.user.email].subscription = plan;
    users[req.user.email].subscriptionExpiry = subscriptionExpiry;
    users[req.user.email].lastActivity = new Date().toISOString();
    
    res.json({ 
      success: true, 
      message: 'Подписка активирована',
      subscriptionExpiry: subscriptionExpiry
    });
  } catch (error) {
    console.error('Ошибка подписки:', error);
    res.status(500).json({ success: false, message: 'Ошибка подписки' });
  }
});

// Проверка премиум-статуса пользователя
app.get('/api/check_premium_status', verifyTokenWithCsrf, (req, res) => {
    try {
        const user = users[req.user.email];
        if (!user) {
            return res.status(404).json({ success: false, message: 'Пользователь не найден' });
        }
        
        const isPremium = user.subscription && (user.subscription.includes('premium') || user.subscription === 'lifetime');
        
        res.json({ 
            success: true, 
            isPremium: isPremium,
            subscription: user.subscription || 'free'
        });
    } catch (error) {
        console.error('Ошибка проверки премиум-статуса:', error);
        res.status(500).json({ success: false, message: 'Ошибка проверки статуса' });
    }
});

// Получение статуса мастер-пароля
app.get('/api/master_password_status', verifyTokenWithCsrf, (req, res) => {
    try {
        const user = users[req.user.email];
        if (!user) {
            return res.status(404).json({ success: false, message: 'Пользователь не найден' });
        }
        
        res.json({ 
            success: true, 
            masterPasswordSet: !!user.masterPasswordHash 
        });
    } catch (error) {
        console.error('Ошибка получения статуса мастер  -пароля:', error);
        res.status(500).json({ success: false, message: 'Ошибка получения статуса' });
    }
});

// ==================== АДМИН-ПАНЕЛЬ ====================
// Middleware для проверки админских прав
function verifyAdmin(req, res, next) {
    const user = users[req.user.email];
    if (!user || !user.isAdmin) {
        return res.status(403).json({ success: false, message: 'Требуются права администратора' });
    }
    next();
}

// Получение списка пользователей (для админки)
app.get('/api/admin/users', verifyTokenWithCsrf, verifyAdmin, (req, res) => {
  try {
    const usersList = Object.keys(users).map(email => {
      const { password, encrypted, userSalt, ...userData } = users[email];
      return { email, ...userData };
    });
    res.json({ success: true, users: usersList });
  } catch (error) {
    console.error('Ошибка загрузки пользователей:', error);
    res.status(500).json({ success: false, message: 'Ошибка загрузки пользователей' });
  }
});

// 🔐 БАН/РАЗБАН ПОЛЬЗОВАТЕЛЯ С CSRF ЗАЩИТОЙ
app.post('/api/admin/users/:email/ban', verifyTokenWithCsrf, verifyAdmin, async (req, res) => {
  try {
    const { email } = req.params;
    if (!users[email]) {
      return res.status(404).json({ success: false, message: 'Пользователь не найден' });
    }
    
    await dbRun('UPDATE users SET banned = 1 WHERE email = ?', [email]);
    users[email].banned = true;
    
    res.json({ success: true, message: 'Пользователь забанен' });
  } catch (error) {
    console.error('Ошибка бана пользователя:', error);
    res.status(500).json({ success: false, message: 'Ошибка' });
  }
});

// 🔐 РАЗБАН ПОЛЬЗОВАТЕЛЯ С CSRF ЗАЩИТОЙ
app.post('/api/admin/users/:email/unban', verifyTokenWithCsrf, verifyAdmin, async (req, res) => {
  try {
    const { email } = req.params;
    if (!users[email]) {
      return res.status(404).json({ success: false, message: 'Пользователь не найден' });
    }
    
    await dbRun('UPDATE users SET banned = 0 WHERE email = ?', [email]);
    users[email].banned = false;
    
    res.json({ success: true, message: 'Пользователь разбанен' });
  } catch (error) {
    console.error('Ошибка разбана пользователя:', error);
    res.status(500).json({ success: false, message: 'Ошибка' });
  }
});

// 🔐 УДАЛЕНИЕ ПОЛЬЗОВАТЕЛЯ С CSRF ЗАЩИТОЙ
app.delete('/api/admin/users/:email', verifyTokenWithCsrf, verifyAdmin, async (req, res) => {
  try {
    const { email } = req.params;
    if (!users[email]) {
      return res.status(404).json({ success: false, message: 'Пользователь не найден' });
    }
    
    // Удаляем пользователя из всех таблиц
    await dbRun('DELETE FROM users WHERE email = ?', [email]);
    await dbRun('DELETE FROM trusted_contacts WHERE user_email = ?', [email]);
    await dbRun('DELETE FROM death_verifications WHERE user_email = ?', [email]);
    await dbRun('DELETE FROM support_requests WHERE user_email = ?', [email]);
    await dbRun('DELETE FROM claims WHERE user_email = ?', [email]);
    await dbRun('DELETE FROM alive_checks WHERE email = ?', [email]);
    
    // Удаляем из памяти
    delete users[email];
    delete trustedContacts[email];
    delete supportRequests[email];
    
    Object.keys(deathVerifications).forEach(key => {
      if (deathVerifications[key].userEmail === email) {
        delete deathVerifications[key];
      }
    });
    
    Object.keys(claims).forEach(key => {
      if (claims[key] && claims[key].userEmail === email) {
        delete claims[key];
      }
    });
    
    // Удаляем токены из aliveCheckTokens
    Object.keys(aliveCheckTokens).forEach(token => {
      if (aliveCheckTokens[token].email === email) {
        delete aliveCheckTokens[token];
      }
    });
    
    res.json({ success: true, message: 'Пользователь удален' });
  } catch (error) {
    console.error('Ошибка удаления пользователя:', error);
    res.status(500).json({ success: false, message: 'Ошибка удаления' });
  }
});

// 🔐 НАЗНАЧЕНИЕ АДМИНА С CSRF ЗАЩИТОЙ
app.post('/api/admin/users/:email/make-admin', verifyTokenWithCsrf, verifyAdmin, async (req, res) => {
  try {
    const { email } = req.params;
    if (!users[email]) {
      return res.status(404).json({ success: false, message: 'Пользователь не найден' });
    }
    
    await dbRun('UPDATE users SET is_admin = 1 WHERE email = ?', [email]);
    users[email].isAdmin = true;
    
    res.json({ success: true, message: 'Пользователь назначен администратором' });
  } catch (error) {
    console.error('Ошибка назначения админа:', error);
    res.status(500).json({ success: false, message: 'Ошибка' });
  }
});

// 🔐 СНЯТИЕ ПРАВ АДМИНА С CSRF ЗАЩИТОЙ
app.post('/api/admin/users/:email/remove-admin', verifyTokenWithCsrf, verifyAdmin, async (req, res) => {
  try {
    const { email } = req.params;
    if (!users[email]) {
      return res.status(404).json({ success: false, message: 'Пользователь не найден' });
    }
    
    await dbRun('UPDATE users SET is_admin = 0 WHERE email = ?', [email]);
    users[email].isAdmin = false;
    
    res.json({ success: true, message: 'Права администратора сняты' });
  } catch (error) {
    console.error('Ошибка снятия прав админа:', error);
    res.status(500).json({ success: false, message: 'Ошибка' });
  }
});

// Получение всех обращений в поддержку
app.get('/api/admin/support-requests', verifyTokenWithCsrf, verifyAdmin, (req, res) => {
  try {
    const allRequests = Object.values(supportRequests).flat();
    res.json({ success: true, requests: allRequests });
  } catch (error) {
    console.error('Ошибка загрузки обращений:', error);
    res.status(500).json({ success: false, message: 'Ошибка загрузки обращений' });
  }
});

// 🔐 ОТВЕТ НА ОБРАЩЕНИЕ В ПОДДЕРЖКУ С CSRF ЗАЩИТОЙ
app.post('/api/admin/support-requests/:requestId/reply', verifyTokenWithCsrf, verifyAdmin, async (req, res) => {
  try {
    const { requestId } = req.params;
    const { response } = req.body;
    
    const respondedAt = new Date().toISOString();
    
    // Обновляем в БД
    await dbRun(`
        UPDATE support_requests 
        SET response = ?, responded_at = ?, status = 'resolved', admin_email = ?
        WHERE id = ?
    `, [response, respondedAt, req.user.email, requestId]);
    
    // Обновляем в памяти
    let requestFound = false;
    for (const userEmail in supportRequests) {
      const userRequests = supportRequests[userEmail];
      const requestIndex = userRequests.findIndex(r => r.id === requestId);
      
      if (requestIndex !== -1) {
        userRequests[requestIndex].response = response;
        userRequests[requestIndex].respondedAt = respondedAt;
        userRequests[requestIndex].adminEmail = req.user.email;
        userRequests[requestIndex].status = 'resolved';
        requestFound = true;
        break;
      }
    }
    
    if (!requestFound) {
      return res.status(404).json({ success: false, message: 'Обращение не найдено' });
    }
    
    res.json({ success: true, message: 'Ответ отправлен' });
  } catch (error) {
    console.error('Ошибка отправки ответа:', error);
    res.status(500).json({ success: false, message: 'Ошибка отправки ответа' });
  }
});

// Статистика платформы
app.get('/api/admin/stats', verifyTokenWithCsrf, verifyAdmin, async (req, res) => {
  try {
    const totalUsers = Object.keys(users).length;
    const premiumUsers = Object.values(users).filter(u => u.subscription && u.subscription !== 'free').length;
    const weekAgo = new Date();
    weekAgo.setDate(weekAgo.getDate() - 7);
    const newUsers = Object.values(users).filter(u => new Date(u.registrationDate) > weekAgo).length;
    const bannedUsers = Object.values(users).filter(u => u.banned).length;
    
    const lifetimeUsers = Object.values(users).filter(u => u.subscription === 'lifetime').length;
    const yearlyUsers = Object.values(users).filter(u => u.subscription === 'premium_yearly').length;
    const monthlyUsers = Object.values(users).filter(u => u.subscription === 'premium_monthly').length;
    
    const sixMonthsAgo = new Date();
    sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);
    const inactiveUsers = Object.values(users).filter(u => 
      new Date(u.lastActivity) < sixMonthsAgo
    ).length;

    const pendingVerifications = Object.values(deathVerifications).filter(v => v.status === 'pending').length;
    const approvedVerifications = Object.values(deathVerifications).filter(v => v.status === 'approved').length;
    const rejectedVerifications = Object.values(deathVerifications).filter(v => v.status === 'rejected').length;
    
    const activeClaims = Object.keys(claims).length;
    const expiredClaims = Object.keys(claims).filter(key => claims[key] && claims[key].expires < Date.now()).length;
    
    res.json({
      success: true,
      stats: {
        totalUsers,
        premiumUsers,
        newUsers,
        bannedUsers,
        lifetimeUsers,
        yearlyUsers,
        monthlyUsers,
        inactiveUsers,
        pendingVerifications,
        approvedVerifications,
        rejectedVerifications,
        activeClaims,
        expiredClaims
      }
    });
  } catch (error) {
    console.error('Ошибка загрузки статистики:', error);
    res.status(500).json({ success: false, message: 'Ошибка загрузки статистики' });
  }
});

// 🔐 СОЗДАНИЕ ОБРАЩЕНИЯ В ПОДДЕРЖКУ С CSRF ЗАЩИТОЙ
app.post('/api/support-request', verifyTokenWithCsrf, async (req, res) => {
  try {
    const { subject, message } = req.body;
    const userEmail = req.user.email;
    
    if (!subject || !message || subject.trim().length < 3 || message.trim().length < 10) {
      return res.status(400).json({ 
        success: false, 
        message: 'Тема должна быть не менее 3 символов, сообщение - не менее 10 символов' 
      });
    }
    
    const newRequest = {
      id: 'SR' + Date.now(),
      userEmail,
      subject: subject.substring(0, 200),
      message: message.substring(0, 5000),
      date: new Date().toISOString(),
      status: 'open'
    };
    
    // Сохраняем в БД
    await dbRun(`
        INSERT INTO support_requests (id, user_email, subject, message, date, status)
        VALUES (?, ?, ?, ?, ?, ?)
    `, [newRequest.id, userEmail, newRequest.subject, newRequest.message, newRequest.date, 'open']);
    
    // Обновляем в памяти
    if (!supportRequests[userEmail]) {
      supportRequests[userEmail] = [];
    }
    
    supportRequests[userEmail].push(newRequest);
    
    res.json({ success: true, message: 'Обращение отправлено', requestId: newRequest.id });
  } catch (error) {
    console.error('Ошибка создания обращения:', error);
    res.status(500).json({ success: false, message: 'Ошибка отправки обращения' });
  }
});

// Получение обращений пользователя
app.get('/api/support-requests', verifyTokenWithCsrf, (req, res) => {
  try {
    const userEmail = req.user.email;
    const userRequests = supportRequests[userEmail] || [];
    res.json({ success: true, requests: userRequests });
  } catch (error) {
    console.error('Ошибка загрузки обращений:', error);
    res.status(500).json({ success: false, message: 'Ошибка загрузки обращений' });
  }
});

// 🔐 УСТАНОВКА МАСТЕР-ПАРОЛЯ С CSRF ЗАЩИТОЙ
app.post('/api/set_master_password', verifyTokenWithCsrf, async (req, res) => {
  try {
    const { newPassword, oldPassword } = req.body;
    
    const minLength = parseInt(process.env.PASSWORD_MIN_LENGTH) || 8;
    if (!newPassword || newPassword.length < minLength) {
      return res.json({ 
        success: false, 
        message: `Пароль должен быть минимум ${minLength} символов` 
      });
    }

    const user = users[req.user.email];

    if (user.masterPasswordHash) {
      if (!oldPassword) return res.json({ success: false, message: 'Введите старый пароль' });
      const match = await bcrypt.compare(oldPassword, user.masterPasswordHash);
      if (!match) return res.json({ success: false, message: 'Старый пароль неверный' });
    }

    const masterPasswordHash = await bcrypt.hash(newPassword, SALT_ROUNDS);
    
    if (!user.userSalt) {
      const userSalt = crypto.randomBytes(16).toString('hex');
      await dbRun('UPDATE users SET user_salt = ? WHERE email = ?', [userSalt, req.user.email]);
      user.userSalt = userSalt;
    }
    
    // Обновляем в БД
    await dbRun('UPDATE users SET master_password_hash = ? WHERE email = ?',
        [masterPasswordHash, req.user.email]);
    
    // Обновляем в памяти
    user.masterPasswordHash = masterPasswordHash;
    
    res.json({ success: true, message: 'Мастер-пароль сохранён' });
  } catch (error) {
    console.error('Ошибка установки мастер-пароля:', error);
    res.status(500).json({ success: false, message: 'Ошибка сохранения мастер-пароля' });
  }
});

// ========== ДОПОЛНИТЕЛЬНЫЕ ФУНКЦИИ ==========
// 🔐 Функция для проверки и обновления статуса подписки - ИСПРАВЛЕННЫЙ ВАРИАНТ
function checkAndUpdateSubscription(userEmail, user) {
    if (!userEmail || !user) {
        console.error('checkAndUpdateSubscription: не переданы email или user');
        return false;
    }
    
    console.log('Checking subscription for:', userEmail, 'Current:', user.subscription, 'Expiry:', user.subscriptionExpiry);
    
    if (user.subscriptionExpiry && new Date(user.subscriptionExpiry) < new Date()) {
        console.log('Subscription expired for:', userEmail);
        user.subscription = 'free';
        user.subscriptionExpiry = null;
        return true;
    }
    return false;
}

// 🔐 Nodemailer setup с правильными настройки для Gmail
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false,
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_PASSWORD
  },
  tls: {
    rejectUnauthorized: false
  },
  connectionTimeout: 10000,
  greetingTimeout: 10000,
  socketTimeout: 10000
});

// 🔐 Функция для форматирования данных завещания в читаемый текст
function formatLegacyData(legacyData) {
  let legacyText = "ЦИФРОВОЕ ЗАВЕЩАНИЕ\n\n";
  
  if (legacyData.social && Array.isArray(legacyData.social)) {
    legacyText += "СОЦИАЛЬНЫЕ СЕТИ:\n";
    legacyData.social.forEach(account => {
      legacyText += `- ${account.name || 'Без названия'}\n`;
      legacyText += `  Логин: ${account.login || 'Не указан'}\n`;
      legacyText += `  Пароль: ${account.password || 'Не указан'}\n`;
      if (account.instructions) legacyText += `  Инструкции: ${account.instructions}\n`;
      legacyText += '\n';
    });
  }
  
  if (legacyData.crypto && Array.isArray(legacyData.crypto)) {
    legacyText += "КРИПТОКОШЕЛЬКИ:\n";
    legacyData.crypto.forEach(wallet => {
      legacyText += `- ${wallet.name || 'Без названия'}\n`;
      legacyText += `  Адрес: ${wallet.address || 'Не указан'}\n`;
      if (wallet.seed) legacyText += `  Сид-фраза: ${wallet.seed}\n`;
      if (wallet.instructions) legacyText += `  Инструкции: ${wallet.instructions}\n`;
      legacyText += '\n';
    });
  }
  
  if (legacyData.credentials) {
    legacyText += "ПАРОЛИ И ЛОГИНЫ:\n";
    legacyText += legacyData.credentials + "\n\n";
  }
  
  if (legacyData.messages) {
    legacyText += "ЛИЧНЫЕ СООБЩЕНИЯ:\n";
    legacyText += legacyData.messages + "\n";
  }
  
  return legacyText;
}

// 🔐 Функция активации завещания - УЛУЧШЕННАЯ ВЕРСИЯ С УНИКАЛЬНЫМИ КЛЮЧЕЙ
async function activateLegacy(userEmail, verificationId) {
  try {
    console.log(`=== АКТИВАЦИЯ ЗАВЕЩАНИЯ ДЛЯ ${userEmail} ===`);
    
    const user = users[userEmail];
    if (!user || !user.legacyEncrypted) {
      console.log(`Пользователь ${userEmail} не найден или завещание отсутствует`);
      return false;
    }

    const deathVerifiedAt = new Date().toISOString();
    
    // Обновляем в БД
    await dbRun(`
        UPDATE users 
        SET deceased = 1, death_verified_at = ?, death_verification_id = ?
        WHERE email = ?
    `, [deathVerifiedAt, verificationId, userEmail]);
    
    // Обновляем в памяти
    user.deceased = true;
    user.deathVerifiedAt = deathVerifiedAt;
    user.deathVerificationId = verificationId;

    console.log(`Метод шифрования: ${user.encryptionMethod}`);

    // 🔐 Автоматическая миграция старых данных
    if (!user.legacyMigrated && user.encryptionMethod !== 'no_encryption') {
        console.log(`Выполняем миграцию данных для ${userEmail}...`);
        const migrated = await migrateLegacyDataToUserKey(userEmail, user);
        if (!migrated) {
            console.warn(`⚠️ Миграция не удалась, пробуем старый ключ`);
        }
    }

    let decryptedLegacy;
    
    if (user.encryptionMethod === 'no_encryption') {
      decryptedLegacy = user.legacyEncrypted;
      console.log('Способ: без шифрования');
    } else {
      try {
        let decryptionKey;
        
        // 🔐 Определяем ключ для дешифрования
        if (user.legacyKey && user.legacyMigrated) {
          // Используем уникальный ключ пользователя
          decryptionKey = user.legacyKey;
          console.log('Используется уникальный ключ пользователя');
        } else {
          // 🔴 РЕЗЕРВНЫЙ ВАРИАНТ: старый фиксированный ключ для совместимости
          decryptionKey = 'legacy_net_default_key';
          console.log('⚠️ ВНИМАНИЕ: используется фиксированный ключ (необходима миграция)');
        }
        
        const bytes = CryptoJS.AES.decrypt(user.legacyEncrypted, decryptionKey);
        const decryptedString = bytes.toString(CryptoJS.enc.Utf8);
        
        if (!decryptedString) {
          console.error('Не удалось расшифровать данные');
          return false;
        }
        
        decryptedLegacy = JSON.parse(decryptedString);
        console.log('Завещание успешно расшифровано');
      } catch (decryptError) {
        console.error('Ошибка дешифрования завещания:', decryptError);
        return false;
      }
    }

    const claimCode = crypto.randomBytes(12).toString('hex'); // ИЗМЕНЕНО: 12 байт вместо 8

    // Сохраняем claim в БД
    await dbRun(`
        INSERT INTO claims 
        (claim_code, encrypted, encryption_method, expires, user_email, source, owner_premium)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `, [
        claimCode, JSON.stringify(decryptedLegacy), user.encryptionMethod,
        Date.now() + 365 * 24 * 60 * 60 * 1000,
        userEmail, 'activateLegacy_fixed_v2',
        user.subscription && (user.subscription.includes('premium') || user.subscription === 'lifetime') ? 1 : 0
    ]);

    // Обновляем в памяти
    claims[claimCode] = {
      claimCode,
      encrypted: JSON.stringify(decryptedLegacy),
      encryptionMethod: user.encryptionMethod,
      expires: Date.now() + 365 * 24 * 60 * 60 * 1000,
      userEmail: userEmail,
      createdAt: new Date().toISOString(),
      source: 'activateLegacy_fixed_v2',
      viewed: false,
      viewedAt: null,
      ownerPremium: user.subscription && (user.subscription.includes('premium') || user.subscription === 'lifetime')
    };

    const userName = userEmail.split('@')[0];
    let emailsSent = 0;

    if (user.contacts && user.contacts.length > 0) {
      console.log(`Claim сохранен в БД при активации: ${claimCode}`);

      // 🔐 Получаем email из контактов (поддерживаем старый и новый формат)
      for (const contact of user.contacts) {
        const contactEmail = typeof contact === 'string' ? contact : (contact.email || '');
        if (contactEmail) {
          const emailSent = await sendLegacyEmail(contactEmail, claimCode, userName, user.encryptionMethod);
          if (emailSent) {
            emailsSent++;
            console.log(`Завещание отправлено на ${contactEmail} (код претензии: ${claimCode})`);
          }
        }
      }
    }

    // Сохраняем claimCode в deathVerifications
    if (deathVerifications[verificationId]) {
      // Обновляем в БД
      await dbRun('UPDATE death_verifications SET claim_code = ?, heirs_contacts = ? WHERE id = ?',
          [claimCode, JSON.stringify(user.contacts || []), verificationId]);
      
      // Обновляем в памяти
      deathVerifications[verificationId].claimCode = claimCode;
      deathVerifications[verificationId].heirsContacts = user.contacts || [];

    }

    console.log(`Завещание пользователя ${userEmail} активировано, отправлено ${emailsSent} писем`);
    return true;
  } catch (error) {
    console.error('Ошибка активации завещания:', error);
    return false;
  }
}

// 🔐 Функция для отправки email с кодом
async function sendEmailCode(email, code, type) {
  try {
    let subject, text;
    
    switch (type) {
      case 'register':
        subject = 'Код подтверждения регистрации LegacyNet';
        text = `Ваш код подтверждения для регистрации в LegacyNet: ${code}\nКод действителен в течение 5 минут.`;
        break;
      case 'login':
        subject = 'Код входа в LegacyNet';
        text = `Ваш код для входа в LegacyNet: ${code}\nКод действителен в течение 5 минут.`;
        break;
      case 'reset':
        subject = 'Код восстановления пароля LegacyNet';
        text = `Ваш код для восстановления пароля в LegacyNet: ${code}\nКод действителен в течение 5 минут.`;
        break;
      case 'death_verification':
        subject = 'Код подтверждения смерти - LegacyNet';
        text = `Ваш код для подтверждения смерти пользователя LegacyNet: ${code}\nКод действителен в течение 5 минут.`;
        break;
      default:
        subject = 'Код подтверждения LegacyNet';
        text = `Ваш код подтверждения: ${code}\nКод действителен в течение 5 минут.`;
    }

    const mailOptions = {
      from: 'LegacyNet <legacynetalert@gmail.com>',
      to: email,
      subject: subject,
      text: text,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #4CAF50;">LegacyNet</h2>
          <p>Ваш код подтверждения:</p>
          <div style="background-color: #f5f5f5; padding: 15px; border-radius: 5px; text-align: center; font-size: 24px; font-weight: bold; color: #333; margin: 20px 0;">
            ${code}
          </div>
          <p>Код действителен в течение 5 минут.</p>
          <p style="color: #666; font-size: 12px;">Если вы не запрашивали этот код, проигнорируйте это письмо.</p>
          <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
          <p style="color: #999; font-size: 11px;">Это автоматическое письмо, пожалуйста, не отвечайте на него.</p>
        </div>
      `
    };

    const result = await transporter.sendMail(mailOptions);
    console.log(`Email отправлен на ${email}:`, result.messageId);
    return true;
  } catch (error) {
    console.error('Ошибка отправки email:', error);
    return false;
  }
}

// 🔐 БЕЗОПАСНОСТЬ: Функция для отправки завещания на почту контактам
async function sendLegacyEmail(contactEmail, claimCode, userName, encryptionMethod, legacyData = null) {
  try {
    let subject, text, html;
    
    if (encryptionMethod === 'no_encryption' && legacyData) {
      subject = 'Цифровое завещание от ' + userName + ' (без шифрования)';
      
      let legacyText;
      if (typeof legacyData === 'object') {
        legacyText = formatLegacyData(legacyData);
      } else {
        legacyText = legacyData;
      }
      
      text = `Вы были указаны как контакт для получения цифрового завещания от ${userName}.\n\nЗАВЕЩАНИЕ:\n\n${legacyText}\n\nЭто завещание был отправлен без шифрования и доступно сразу.`;
      
      html = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #4CAF50;">LegacyNet - Цифровое завещание</h2>
          <p>Вы были указаны как контакт для получения цифрового завещания от <strong>${userName}</strong>.</p>
          <div style="background-color: #f9f9f9; padding: 20px; border-radius: 8px; margin: 20px 0; border: 2px solid #4CAF50;">
            <h3 style="color: #4CAF50; margin-top: 0;">Содержание завещания:</h3>
            <div style="white-space: pre-wrap; background: white; padding: 15px; border-radius: 5px; border: 1px solid #ddd;">
              ${legacyText}
            </div>
          </div>
          <p style="color: #666; font-size: 12px; background: #fff3cd; padding: 10px; border-radius: 5px;">
            <strong>Внимание:</strong> Это завещание был отправлен без шифрования и доступен для чтения сразу.
          </p>
          <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
          <p style="color: #999; font-size: 11px;">Это автоматическое письмо, пожалуйста, не отвечайте на него.</p>
        </div>
      `;
    } else {
      const claimLink = `https://legacynet.ru/claim?code=${claimCode}`;
      
      let methodInfo = '';
      if (encryptionMethod === 'master_password') {
        methodInfo = '<p style="color: #f44336; font-weight: bold;">⚠️ Для этого завещания требуется мастер-пароль!</p>';
      }
      
      subject = 'Цифровое завещание от ' + userName;
      text = `Вы были указаны как контакт для получения цифрового завещания.\n\nДля получения завещания перейдите по ссылке: ${claimLink}\n\nИспользуйте код: ${claimCode}`;
      
      html = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #4CAF50;">LegacyNet - Цифровое завещания</h2>
          <p>Вы были указаны как контакт для получения цифрового завещания от <strong>${userName}</strong>.</p>
          ${methodInfo}
          <div style="background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0;">
            <p style="margin: 0;"><strong>Код для получения завещания:</strong></p>
            <div style="text-align: center; font-size: 24px; font-weight: bold; color: #333; margin: 10px 0;">
              ${claimCode}
            </div>
            <p style="text-align: center; margin: 15px 0;">
              <a href="${claimLink}" style="background-color: #4CAF50; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">
                Получить завещание
              </a>
            </p>
          </div>
          <p>Или перейдите по ссылке: <a href="${claimLink}">${claimLink}</a></p>
          <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
          <p style="color: #999; font-size: 11px;">Это автоматическое письмо, пожалуйста, не отвечайте на него.</p>
        </div>
      `;
    }

    const mailOptions = {
      from: 'LegacyNet <legacynetalert@gmail.com>',
      to: contactEmail,
      subject: subject,
      text: text,
      html: html
    };

    const result = await transporter.sendMail(mailOptions);
    console.log(`Завещание отправлено на ${contactEmail}:`, result.messageId);
    
    return true;
  } catch (error) {
    console.error('Ошибка отправки завещания:', error);
    return false;
  }
}

// 🔐 БЕЗОПАСНОСТЬ: Функция для отправки письма проверки активности
async function sendAliveCheckEmail(email, token, intervalDays) {
  try {
    const confirmLink = `https://legacynet.ru/api/confirm_alive/${token}`;
    const mailOptions = {
      from: 'LegacyNet <legacynetalert@gmail.com>',
      to: email,
      subject: 'Проверка активности - LegacyNet',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: linear-gradient(135deg, #4CAF50 0%, #388E3C 100%); padding: 40px; border-radius: 15px; color: white;">
          <div style="text-align: center; margin-bottom: 30px;">
            <h1 style="color: white; margin: 0;">LegacyNet</h1>
            <p style="opacity: 0.9; margin: 5px 0;">Цифровое наследие</p>
          </div>
          
          <div style="background: white; border-radius: 10px; padding: 30px; color: #333;">
            <h2 style="color: #4CAF50; margin-top: 0; text-align: center;">✅ Проверка активности</h2>
            
            <p style="font-size: 16px; line-height: 1.6; color: #555;">
              Привет! Это автоматическая проверка активности вашего аккаунта в LegacyNet.
            </p>
            
            <p style="font-size: 16px; line-height: 1.6; color: #555;">
              Мы отправляем такие проверки раз в <strong>${intervalDays} дней</strong>, чтобы убедиться, что вы активны и ваше завещание актуально.
            </p>
            
            <div style="text-align: center; margin: 40px 0;">
              <a href="${confirmLink}" 
                 style="background: linear-gradient(45deg, #4CAF50, #388E3C); 
                        color: white; 
                        padding: 18px 40px; 
                        text-decoration: none; 
                        border-radius: 50px; 
                        font-size: 18px; 
                        font-weight: bold;
                        display: inline-block;
                        box-shadow: 0 4px 15px rgba(76, 175, 80, 0.3);
                        transition: all 0.3s;">
                ✅ Подтвердить активность
              </a>
            </div>
            
            <p style="font-size: 14px; color: #666; text-align: center; margin-top: 30px;">
              Просто нажмите на кнопку выше, чтобы подтвердить свою активность.<br>
              Ссылка действительна в течение 30 дней.
            </p>
            
            <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin-top: 25px; border-left: 4px solid #4CAF50;">
              <p style="margin: 0; font-size: 13px; color: #666;">
                <strong>ℹ️ Важно:</strong> Если мы не получим подтверждение в течение ${intervalDays} дней, 
                ваше завещание может быть активировано автоматически.
              </p>
            </div>
          </div>
          
          <div style="text-align: center; margin-top: 30px; color: rgba(255,255,255,0.8); font-size: 12px;">
            <p>Это автоматическое письмо, пожалуйста, не отвечайте на него.</p>
            <p>© 2025 LegacyNet. Все права защищены.</p>
          </div>
        </div>
      `
    };

    const result = await transporter.sendMail(mailOptions);
    console.log(`Письмо проверки активности отправлено на ${email}:`, result.messageId);
    return true;
  } catch (error) {
    console.error('Ошибка отправки письма проверки активности:', error);
    return false;
  }
}

// 🔐 ГЕНЕРАЦИЯ УНИКАЛЬНЫХ КЛЮЧЕЙ ДЛЯ ЗАВЕЩАНИЙ
function generateUserLegacyKey(userEmail, userSalt) {
    return crypto.createHmac('sha256', LEGACY_KEY_SECRET)
        .update(userEmail + userSalt)
        .digest('hex');
}

// 🔐 Функция получения ключа для пользователя (с миграцией)
function getUserLegacyKey(userEmail, user) {
    // Если у пользователя есть свой ключ - используем его
    if (user.legacyKey) {
        return user.legacyKey;
    }
    
    // Иначе генерируем новый на основе его данных
    if (!user.userSalt) {
        user.userSalt = crypto.randomBytes(16).toString('hex');
    }
    
    const newKey = generateUserLegacyKey(userEmail, user.userSalt);
    user.legacyKey = newKey;
    
    // Сохраняем пользователя с новым ключом в БД
    dbRun('UPDATE users SET legacy_key = ? WHERE email = ?', [newKey, userEmail]);
    
    return newKey;
}

// 🔐 Функция миграции старых данных на новые ключи
async function migrateLegacyDataToUserKey(userEmail, user) {
    if (!user.legacyEncrypted || user.legacyMigrated) {
        return true; // Нет данных или уже мигрировано
    }
    
    try {
        // 1. Дешифруем старым фиксированным ключом
        const bytes = CryptoJS.AES.decrypt(user.legacyEncrypted, 'legacy_net_default_key');
        const decryptedString = bytes.toString(CryptoJS.enc.Utf8);
        
        if (!decryptedString) {
            console.error(`Не удалось расшифровать старые данные для ${userEmail}`);
            return false;
        }
        
        const legacyData = JSON.parse(decryptedString);
        
        // 2. Получаем уникальный ключ пользователя
        const userKey = getUserLegacyKey(userEmail, user);
        
        // 3. Шифруем новым уникальным ключом
        const encryptedWithUserKey = CryptoJS.AES.encrypt(
            JSON.stringify(legacyData), 
            userKey
        ).toString();
        
        // 4. Сохраняем с новым ключом в БД
        await dbRun(`
            UPDATE users 
            SET legacy_encrypted = ?, legacy_migrated = 1, legacy_last_updated = ?
            WHERE email = ?
        `, [encryptedWithUserKey, new Date().toISOString(), userEmail]);
        
        // 5. Обновляем в памяти
        user.legacyEncrypted = encryptedWithUserKey;
        user.legacyMigrated = true;
        user.legacyLastUpdated = new Date().toISOString();
        
        console.log(`✅ Данные пользователя ${userEmail} мигрированы на уникальный ключ`);
        return true;
    } catch (error) {
        console.error(`Ошибка миграции данных для ${userEmail}:`, error);
        return false;
    }
}

// 🔐 Функция для проверки и отключения истекших подписок
async function checkSubscriptions() {
  console.log('🔍 Проверка истекших подписок...');
  const now = new Date();
  let expiredCount = 0;
  
  try {
    // Получаем пользователей с истекшими подписками
    const expiredRows = await dbAll(`
        SELECT email, subscription, subscription_expiry 
        FROM users 
        WHERE subscription_expiry IS NOT NULL 
        AND subscription_expiry < ?
    `, [now.toISOString()]);
    
    for (const row of expiredRows) {
      console.log(`❌ Подписка истекла для ${row.email} (${row.subscription})`);
      
      // Сбрасываем подписку в БД
      await dbRun('UPDATE users SET subscription = "free", subscription_expiry = NULL WHERE email = ?', 
          [row.email]);
      
      // Обновляем в памяти
      if (users[row.email]) {
        users[row.email].subscription = 'free';
        users[row.email].subscriptionExpiry = null;
      }
      
      expiredCount++;
      console.log(`ℹ️ Подписка пользователя ${row.email} была сброшена на free`);
    }
    
    if (expiredCount > 0) {
      console.log(`✅ Сброшено ${expiredCount} истекших подписок`);
    }
  } catch (error) {
    console.error('Ошибка проверки подписок:', error);
  }
}

// Старт сервера
const startServer = async () => {
  const port = process.env.PORT || 3000;
  
  // Создаем директорию для данных если не существует
  const dataDir = './data';
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
    fs.chmodSync(dataDir, 0o700);
  }
  
  // Инициализируем БД
  await initializeDatabase();
  
  // Загружаем данные из БД
  await loadAllData();
  
  // Запускаем проверки подписок и claims при старте сервера
  await checkSubscriptions();
  await cleanupOldClaims();
  
  // Запускаем ежедневную проверка подписок (раз в 24 часа)
  setInterval(async () => {
    await checkSubscriptions();
  }, 24 * 60 * 60 * 1000);
  console.log('🔄 Запущена ежедневная проверка подписок');
  
  // Запускаем ежедневную очистку старых claims
  setInterval(async () => {
    await cleanupOldClaims();
  }, 24 * 60 * 60 * 1000);
  console.log('🔄 Запущена ежедневная очистка старых claims');

  // 🔥 ИСПРАВЛЕННЫЙ ЗАПУСК СЕРВЕРА
  app.listen(port, '0.0.0.0', () => {
    console.log(`🚀 Сервер LegacyNet запущен на порту ${port}`);
    console.log(`🌐 Сайт доступен по адресу: https://legacynet.ru`);
    console.log(`🔌 API доступен по адресу: https://legacynet.ru/api`);
    console.log(`📄 Страница получения завещание: https://legacynet.ru/claim`);
    console.log(`⚰️ Страница подтверждения смерти: https://legacynet.ru/verification`);
    console.log(`🔐 Новая система токенов:`);
    console.log(`   • Access токен: ${ACCESS_TOKEN_EXPIRY}`);
    console.log(`   • Refresh токен: ${REFRESH_TOKEN_EXPIRY}`);
    console.log(`   • Временные токены: ${TEMP_TOKEN_EXPIRY}`);
    console.log(`🔐 УСИЛЕННАЯ CSRF ЗАЩИТА (Double Submit Cookie Pattern):`);
    console.log(`   • CSRF токены в HttpOnly cookies`);
    console.log(`   • Проверка совпадения токена из заголовка и cookie`);
    console.log(`   • Автоматическая генерация при аутентификации`);
    console.log(`   • Очистка старых токенов каждые 30 минут`);
    console.log(`🔒 База данных: SQLCipher (шифрованная SQLite)`);
    console.log(`🛡️ Claims сохранены в БД: ДА`);
    console.log(`🛡️ Черный список токенов в БД: АКТИВЕН`);
    console.log(`🛡️ Rate Limiting: АКТИВЕН`);
    console.log(`🛡️ Content Security Policy: АКТИВНА`);
    console.log(`🛡️ CORS: РАЗРЕШЕНЫ ТОЛЬКО https://legacynet.ru и https://www.legacynet.ru`);
    console.log(`🍪 Аутентификация через HTTP-only cookies: АКТИВНА`);
    console.log(`🔐 Усиленная безопасность claimCode: 24 символа вместо 16`);
    console.log(`🔐 Дешифровка только на сервере: АКТИВНА`);
    console.log(`🔐 DOMPurify санитизация: АКТИВНА`);
    console.log(`🔐 Добавлены недостающие поля в таблицы: ДА`);
    console.log(`🔐 Исправлен парсинг JSON в claims: ДА`);
    console.log(`🔐 Добавлена таблица alive_checks: ДА`);
    console.log(`🔐 Исправлена очистка старых claims (30/60 дней): ДА`);
    console.log(`🔐 ДОБАВЛЕНА таблица csrf_tokens в БД для персистентности`);
  });
};

startServer();

// 🔐 БЕЗОПАСНОСТЬ: Обработка необработанных исключений
process.on('uncaughtException', (err) => {
  console.error('Необработанное исключение:', err);
  setTimeout(() => {
    process.exit(1);
  }, 1000);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Необработанный промис:', reason);
});

// 🔐 Закрытие соединения с БД при завершении работы
process.on('exit', () => {
  db.close((err) => {
    if (err) {
      console.error('Ошибка закрытия БД:', err);
    } else {
      console.log('Соединение с БД закрыто');
    }
  });
});

process.on('SIGINT', () => {
  db.close((err) => {
    if (err) {
      console.error('Ошибка закрытия БД:', err);
    }
    process.exit();
  });
});


Вот мой Script.js:
console.log('LegacyNet Script v5 loaded - Security enhanced!');

// 🔐 БЕЗОПАСНОСТЬ: Автоматическое определение URL API с HTTPS в production
const API_URL = 'https://legacynet.ru/api';

console.log('API URL настроен на:', API_URL);

// 🔐 Проверка cookies при загрузке страницы (ДОБАВЛЕНО ПО ИНСТРУКЦИИ)
window.checkCookies = function() {
    console.log('=== ПРОВЕРКА COOKIES ===');
    console.log('document.cookie:', document.cookie);
    console.log('localStorage userEmail:', localStorage.getItem('userEmail'));
    
    fetch(`${API_URL}/debug/cookies`, {
        credentials: 'include'
    })
    .then(res => res.json())
    .then(data => {
        console.log('Debug cookies:', data);
    })
    .catch(err => {
        console.error('Debug cookies error:', err);
    });
};

// 🔐 Автоматически проверяем cookies на странице профиля
if (window.location.pathname === '/profile') {
    setTimeout(() => {
        window.checkCookies();
    }, 1000);
}

// 🔐 Проверка cookies при загрузке (ДОБАВЛЕНО ПО ИНСТРУКЦИИ)
document.addEventListener('DOMContentLoaded', function() {
    console.log('Cookies доступны:', {
        hasAccessToken: document.cookie.includes('access_token'),
        hasRefreshToken: document.cookie.includes('refresh_token'),
        allCookies: document.cookie
    });
});

// 🔐 Проверка является ли endpoint аутентификационным (ОБНОВЛЕНО ПО ИНСТРУКЦИИ)
function isAuthEndpoint(url) {
    const authPaths = [
        '/api/register',
        '/api/login',
        '/api/verify_2fa',
        '/api/forgot_password',
        '/api/reset_password',
        '/api/get-csrf'  // ❌ НЕ включаем /api/check_auth - он требует CSRF!
    ];
    return authPaths.some(path => url.includes(path));
}

// 🔐 Функция обновления токенов (ОБНОВЛЕНО ПО ИНСТРУКЦИИ)
async function refreshTokens() {
    try {
        console.log('refreshTokens: попытка обновления...');
        
        // 🔥 ИСПОЛЬЗУЕМ secureFetch с CSRF токеном
        const data = await secureFetch(`${API_URL}/refresh_token`, {
            method: 'POST',
            credentials: 'include'
        });
        
        console.log('refreshTokens ответ:', data);
        
        if (data.success) {
            console.log('✅ Токены успешно обновлены');
            
            // Сохраняем новый CSRF токен
            if (data.csrfToken) {
                localStorage.setItem('csrf_token', data.csrfToken);
                console.log('Новый CSRF токен сохранен');
            }
            
            return true;
        } else {
            console.log('❌ Не удалось обновить токены:', data.message);
            
            // Если CSRF токен невалиден, очищаем его
            if (data.invalidCSRF || data.requiresCSRF) {
                localStorage.removeItem('csrf_token');
            }
            
            return false;
        }
    } catch (error) {
        console.error('refreshTokens ошибка:', error);
        
        // Если ошибка CSRF, очищаем токен
        if (error.responseData && 
            (error.responseData.invalidCSRF || error.responseData.requiresCSRF)) {
            localStorage.removeItem('csrf_token');
        }
        
        return false;
    }
}

// 🔐 Безопасный fetch с CSRF защитой (ОБНОВЛЕННАЯ ВЕРСИЯ ПО ИНСТРУКЦИИ)
async function secureFetch(url, options = {}, retryCount = 0) {
    const isAuth = isAuthEndpoint(url);
    let csrfToken = localStorage.getItem('csrf_token');
    
    console.log('🔐 secureFetch:', {
        url,
        isAuth,
        hasCsrfToken: !!csrfToken,
        method: options.method || 'GET'
    });
    
    const headers = {
        'Content-Type': 'application/json',
        ...options.headers
    };
    
    // 🔥 ВАЖНОЕ ИСПРАВЛЕНИЕ: Для ВСЕХ не-аутентификационных запросов добавляем CSRF
    if (!isAuth && csrfToken) {
        headers['X-CSRF-Token'] = csrfToken;
        console.log('✅ Добавлен CSRF токен в заголовок');
    }
    
    try {
        const response = await fetch(url, {
            ...options,
            headers,
            credentials: 'include'
        });
        
        console.log('📊 Ответ secureFetch:', {
            url,
            status: response.status,
            hasCSRF: !!headers['X-CSRF-Token']
        });
        
        // 🔐 ОБРАБОТКА refresh_token ОШИБОК
        const isRefreshRequest = url.includes('/refresh_token');
        if (isRefreshRequest) {
            if (response.status === 403) {
                const errorText = await response.text();
                if (errorText.includes('CSRF') || errorText.includes('csrf')) {
                    console.log('refresh_token: CSRF ошибка');
                    
                    // Очищаем CSRF токен и перебрасываем на логин
                    localStorage.removeItem('csrf_token');
                    localStorage.removeItem('userEmail');
                    
                    throw new Error('CSRF токен недействителен. Пожалуйста, войдите снова.');
                }
            }
        }
        
        // 🔥 ОБРАБОТКА CSRF ОШИБОК
        if (response.status === 403 && !isAuth && retryCount < 1) {
            const errorText = await response.text();
            if (errorText.includes('CSRF') || errorText.includes('csrf')) {
                console.log('🔄 CSRF ошибка, пытаемся получить новый токен...');
                
                // Получаем новый CSRF токен
                const csrfResponse = await fetch(`${API_URL}/get-csrf`, {
                    method: 'GET',
                    credentials: 'include'
                });
                
                if (csrfResponse.ok) {
                    const csrfData = await csrfResponse.json();
                    if (csrfData.success && csrfData.csrfToken) {
                        localStorage.setItem('csrf_token', csrfData.csrfToken);
                        console.log('✅ Получен новый CSRF токен, повторяем запрос');
                        return secureFetch(url, options, retryCount + 1);
                    }
                }
            }
        }
        
        // 🔐 Обработка ошибки 401 (токен истек)
        if (response.status === 401 && !isAuth && retryCount < 1) {
            console.log('401 detected, trying to refresh tokens...');
            
            // 🔥 ИСПОЛЬЗУЕМ secureFetch для refresh_token
            const refreshSuccess = await refreshTokens();
            
            if (refreshSuccess) {
                console.log('Tokens refreshed, retrying original request...');
                return secureFetch(url, options, retryCount + 1);
            }
            
            // Если не удалось обновить, очищаем данные
            localStorage.removeItem('userEmail');
            localStorage.removeItem('csrf_token');
            window.location.href = '/';
            throw new Error('Сессия истекла');
        }
        
        let data;
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            data = await response.json();
        } else {
            data = { success: false, message: await response.text() || 'Non-JSON response' };
        }
        
        if (!response.ok || (data && data.success === false)) {
            const error = new Error(data.message || `HTTP error! status: ${response.status}`);
            error.responseData = data;
            error.status = response.status;
            throw error;
        }
        
        return data;
    } catch (error) {
        console.error('🔴 secureFetch ошибка:', error);
        
        if (error.responseData) {
            throw error;
        }
        
        const networkError = new Error('Ошибка сети. Проверьте соединение и попробуйте снова.');
        networkError.isNetworkError = true;
        throw networkError;
    }
}

// 🔐 ФУНКЦИЯ ДЛЯ ПОЛУЧЕНИЯ CSRF ТОКЕНА (ОБНОВЛЕНА ПО ИНСТРУКЦИИ)
async function getCsrfToken() {
    try {
        console.log('🔄 Получение CSRF токена...');
        const response = await fetch(`${API_URL}/get-csrf`, {
            method: 'GET',
            credentials: 'include'
        });
        
        if (!response.ok) {
            console.error('❌ Не удалось получить CSRF токен, статус:', response.status);
            return null;
        }
        
        const data = await response.json();
        
        if (data.success && data.csrfToken) {
            localStorage.setItem('csrf_token', data.csrfToken);
            console.log('✅ CSRF токен получен и сохранен');
            return data.csrfToken;
        }
        
        return null;
    } catch (error) {
        console.error('❌ Ошибка получения CSRF токена:', error);
        return null;
    }
}

// 🔐 Санитизация ввода с использованием DOMPurify (ИЗМЕНЕНО ПО ИНСТРУКЦИИ)
function sanitizeInput(input) {
    if (typeof input !== 'string') return input;
    
    // Используем DOMPurify для очистки от всех HTML-тегов и скриптов
    if (typeof DOMPurify !== 'undefined') {
        return DOMPurify.sanitize(input, {
            ALLOWED_TAGS: [], // Не разрешаем никакие теги
            ALLOWED_ATTR: [], // Не разрешаем никакие атрибуты
            KEEP_CONTENT: true // Сохраняем текстовое содержимое
        });
    }
    
    // Fallback если DOMPurify не загружен
    return input
        .replace(/[<>]/g, '') // Удаляем HTML теги
        .replace(/javascript:/gi, '') // Удаляем javascript:
        .replace(/script/gi, ''); // Удаляем script
}

// 🔐 Валидация email (добавлено по инструкции)
function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

// 🔐 Валидация пароля (добавлено по инструкции)
function validatePassword(password) {
    return password.length >= 8;
}

// 🔐 Безопасное хранение данных (добавлено по инструкции)
function secureStorage(key, value) {
    try {
        if (value === null || value === undefined) {
            localStorage.removeItem(key);
        } else {
            const stringValue = typeof value === 'string' ? value : JSON.stringify(value);
            localStorage.setItem(key, stringValue);
        }
    } catch (error) {
        console.error('Ошибка localStorage:', error);
    }
}

// 🔐 Безопасное получение данных (добавлено по инструкции)
function secureRetrieve(key) {
    try {
        const value = localStorage.getItem(key);
        if (!value) return null;
        
        try {
            return JSON.parse(value);
        } catch {
            return value;
        }
    } catch (error) {
        console.error('Ошибка получения из localStorage:', error);
        return null;
    }
}

// Обновляем дату последнего визита при каждом заходе на сайт
if (localStorage.getItem('userEmail')) {
    const now = new Date();
    localStorage.setItem('lastVisit', now.toISOString());
}

const translations = {
    ru: {
        logo: 'LegacyNet',
        registration: 'Регистрация',
        login: 'Вход',
        hero_title: 'Защитите своё цифровое наследие с LegacyNet',
        hero_description: 'В эпоху цифровизации ваши аккаунты, фото, крипта и сообщения — это часть вас. LegacyNet помогает создать "цифровое завещание": инструкции, пароли и сообщения для близких. Безопасно, просто, с шифрованием и удобностью.',
        start_free: 'Начать бесплатно',
        why_legacy_net: 'Почему LegacyNet?',
        secure_encryption: 'Максимальная безопасность',
        secure_encryption_desc: 'Ваши данные шифруются на устройстве с помощью AES-256 — стандарта, который используют банки. Никто, даже мы, не увидит содержимое без вашего ключа. Защита от хакеров на уровне: CSRF, rate-limiting и HTTPS-only.',
        ai_generation: 'Автоматическая отправка',
        ai_generation_desc: 'Завещание уйдёт наследникам автоматически после подтверждения (через "проверку жизни" или модерацию). Нет бюрократии — всё онлайн.',
        sharing_with_family: 'Легкий доступ для наследников',
        sharing_with_family_desc: 'Наследники получат ссылку с инструкциями. Если наследник не сможет получить завещание.',
        export_backup: 'Гибкое шифрование',
        export_backup_desc: 'Выберите уровень: без пароля (быстро), с кодом (shared key) или мастер-паролем (самый безопасный, с bcrypt-хэшем). Для премиум — экспорт в файл.',
        personal_profile: 'Личный профиль',
        information_security: 'Информация и безопасность',
        email: 'Email',
        email_loading: 'Email: Загрузка...',
        legacy_status: 'Статус завещания',
        statistics: 'Статистика',
        accounts_protected: 'Защищено аккаунтов',
        wallets_specified: 'Указано кошельков',
        registration_date: 'Дата регистрации',
        last_login: 'Последний визит',
        current_plan: 'Текущий тарифный план:',
        two_factor_auth: 'Двухфакторная авторизация',
        create_master_password: 'Создать мастер-пароль',
        change_master_password: 'Сменить мастер-пароль',
        legacy_management: 'Управление завещание',
        last_updated: 'Последнее обновление',
        history_no_records: 'История действий: Нет записей.',
        registration_date_loading: 'Дата регистрации: Загрузка...',
        last_login_loading: 'Последний визит: Загрузка...',
        settings: 'Настройки',
        legacy: 'Завещание',
        go_to_legacy: 'Перейти к завещание',
        load_legacy: 'Загрузить завещание',
        logout: 'Выход',
        support: 'Поддержка',
        theme: 'Тема',
        language: 'Язык',
        notifications: 'Уведомления',
        receive_email_notifications: 'Получать уведомления на email',
        save: 'Сохранить',
        back: 'Назад',
        compose_legacy: 'Составьте завещание',
        social_networks: 'Соцсети',
        crypto: 'Крипто',
        passwords: 'Пароли',
        messages: 'Сообщения',
        add_account: 'Добавить аккаунт',
        add_wallet: 'Добавить кошелёк',
        passwords_logins: 'Пароли и логины',
        credentials_placeholder: 'Пароли, логины, инструкции...',
        messages_for_family: 'Сообщения для близких',
        messages_placeholder: 'Сообщения...',
        master_password: 'Мастер-пароль:',
        send_to_contacts: 'Отправить контактам',
        download: 'Скачать',
        back_to_profile: 'Назад в профиль',
        copyright: '© 2025 LegacyNet. Все права защищены.',
        privacy_policy: 'Политика конфиденциальности',
        terms_of_use: 'Условия использования',
        auth_title: 'Регистрация / Вход',
        password: 'Пароль',
        confirm_password: 'Подтвердите пароль',
        confirm: 'Подтвердить',
        profile: 'Профиль',
        fill_fields: 'Заполните поля!',
        passwords_mismatch: 'Пароли не совпадают!',
        password_short: 'Пароль слишком короткий! Минимум 8 символов.',
        error: 'Ошибка!',
        master_password_required: 'Мастер-пароль обязателен!',
        master_password_prompt: 'Мастер-пароль:',
        loaded: 'Загружено.',
        add_contacts: 'Добавьте контакты!',
        theme_dark: 'Тёмная',
        theme_light: 'Светлая',
        lang_ru: 'Русский',
        lang_en: 'English',
        history_sample: 'История действий: Зарегистрирован 26.08.2025, завещание сохранено 1 раз.',
        registration_date_sample: 'Дата регистрации: 26.08.2025',
        last_login_sample: 'Последний визит: 27.08.2025 15:30',
        menu: 'Меню',
        delete: 'Удалить',
        enter_code: 'Введите 6-значный код',
        code_sent: 'Код отправлен на вашу почту.',
        forgot_password: 'Забыли пароль?',
        reset_password: 'Восстановление пароля',
        send_code: 'Отправить код',
        new_password: 'Новый пароль',
        confirm_new_password: 'Подтвердите новый пароль',
        reset: 'Сменить пароль',
        contacts: 'Контакты',
        add_contact: 'Добавить',
        remove: 'Удалить',
        code: 'Код',
        claim_legacy: 'Претензия на завещание',
        claim_code: 'Код претензии',
        get: 'Получить',
        warning: 'Предупреждение: Поделитесь мастер-паролем с контактами оффлайн (например, в завещании или у нотариуса). Не отправляйте его по email!',
        premium: 'Премиум',
        premium_title: 'Подписка Premium LegacyNet',
        premium_description: 'Получите расширенные возможности для вашего цифрового наследия. Выберите план, подходящий вам.',
        free_plan: 'Free',
        premium_monthly: 'Ежемесячно',
        premium_yearly: 'Ежегодно',
        subscribe: 'Подписаться',
        subscription_loading: 'Подпика: Загрузка...',
        current_password: 'Текущий пароль',
        change_password_button: 'Сменить пароль',
        password_changed_success: 'Пароль успешно изменен!',
        password_change_error: 'Ошибка при смене пароля',
        passwords_do_not_match: 'Пароли не совпадают',
        legacy_active: 'Активно и сохранено',
        legacy_not_created: 'Не создано',
        status_error: 'Ошибка проверки статуса',
        no_data: 'Нет данных',
        encryption_method: 'Метод шифрования',
        claim_title: 'Получение цифрового завещания',
        claim_description: 'Enter details to receive digital legacy',
        enter_claim_details: 'Enter sender email and legacy code',
        legacy_content: 'Содержание завещания',
        social_accounts: 'Социальные сети',
        crypto_wallets: 'Криптокошельки',
        passwords_and_logins: 'Пароли и логины',
        personal_messages: 'Личные сообщения',
        instructions: 'Инструкции',
        wallet_address: 'Адрес кошелька',
        seed_phrase: 'Сид-фраза',
        required_master_password: 'Требуется мастер-пароль',
        account_name: 'Название аккаунта',
        login: 'Логин',
        wallet_type: 'Тип кошелька',
        verification: 'Подтвердить смерть',
        death_verification: 'Подтвердить смерть',
        verification_title: 'Подтверждение смерти пользователя',
        verification_description: 'Сообщите о смерти пользователя для активации цифрового завещания',
        choose_method: 'Выберите метод подтверждения',
        trusted_person: 'Доверенное лицо',
        verification_steps: 'Шаги подтверждения',
        step_1: 'Шаг 1: Поиск пользователя',
        step_1_desc: 'Выберите способ поиска',
        step_2: 'Шаг 2: Ввод данных',
        step_2_desc: 'Введите информацию',
        step_3: 'Шаг 3: Метод подтверждения',
        step_3_desc: 'Выберите способ',
        step_4: 'Шаг 4: Завершение',
        step_4_desc: 'Получите результат',
        find_user: 'Найти пользователя',
        choose_search_method: 'Выберите способ поиска пользователя для подтверждения смерти',
        search_by_email: 'Поиск по Email',
        search_by_email_desc: 'Найти пользователя по email-адресу',
        search_by_personal: 'Поиск по личным данным',
        search_by_personal_desc: 'Найти по ФИО и дате рождения',
        search_user: 'Поиск пользователя',
        deceased_email: 'Email пользователя',
        available_methods: 'Доступные методы подтверждения:',
        trusted_person_selected: 'Вы выбрали подтверждение через доверенное лицо',
        trusted_person_hint: 'Введите код доступа, который был предоставлен вам пользователем при жизни',
        trusted_person_desc: 'Используйте код доступа, предоставленный пользователем',
        fast: 'Быстро',
        verification_info: 'Информация для подтверждения',
        access_code: 'Код доступа',
        deceased_name: 'Полное имя умершего',
        death_date: 'Дата смерти',
        submit_verification: 'Отправить на проверку',
        legacy_activated: 'Завещание активировано!',
        legacy_sent: 'Цифровое завещание было успешно отправлено всем указанным контактами.',
        moderation_sent: 'Заявка отправлена на модeration',
        moderation_pending: 'Ваша заявка будет проверена в течение 1-3 рабочих дней.',
        request_status: 'Статус заявки',
        request_submitted: 'Заявка подана',
        request_sent: 'Ваша заявка успешно отправлена на проверку',
        moderator_review: 'Проверка модератором',
        documents_check: 'Документы проверяются на подлинность',
        verification_complete: 'Завершение проверки',
        get_notification: 'Вы получите уведомление о результате',
        request_id: 'ID заявки',
        status: 'Статус',
        status_pending: 'Ожидает проверки',
        pending: 'Ожидает',
        return_home: 'Вернуться на главную',
        select_method: 'Выберите способ подтверждения смерти',
        enter_info: 'Заполните необходимые данные',
        get_result: 'Получите результат проверки',
        instant_activation: 'Мгновенная активация после ввода кода',
        moderator_check: 'Требуется проверка модератора (1-3 дня',
        next: 'Далее',
        back_to_method: 'Назад к выбору метода',
        user_info: 'Информация о пользователя',
        privacy_settings: 'Настройки приватности',
        privacy_method: 'Метод приватности',
        email_only: 'Только email (анонимно)',
        personal_data: 'Личные данные',
        personal_info: 'Личная информация',
        last_name: 'Фамилия',
        first_name: 'Имя',
        middle_name: 'Отчество',
        birth_date: 'Дата рождения',
        save_personal_data: 'Сохранить личные данные',
        personal_data_saved: 'Личные данные сохранены',
        fill_required_fields: 'Заполните все обязательные поля',
        phone: 'Телефон',
        phone_placeholder: '+7 (999) 123-45-67',
        secure_phone_storage: 'Номера телефонов хранятся в зашифрованном виде',
        premium_phone_feature: 'Укажите телефоны наследников. При активации завещания мы позвоним им.'
    },
    en: {
        logo: 'LegacyNet',
        registration: 'Registration',
        login: 'Login',
        hero_title: 'Protect Your Digital Heritage with LegacyNet',
        hero_description: 'In the era of digitalization, your accounts, photos, crypto, and messages are part of you. LegacyNet helps create a "digital will": instructions, passwords, and messages for loved ones. Secure, simple, with encryption and convenience.',
        start_free: 'Start for Free',
        why_legacy_net: 'Why LegacyNet?',
        secure_encryption: 'Secure Encryption',
        secure_encryption_desc: 'All data is end-to-end encrypted, like in banking systems. Master password only with you.',
        ai_generation: 'Automatic Backup',
        ai_generation_desc: 'Your data is securely stored with automatic backup.',
        sharing_with_family: 'Sharing with Family',
        sharing_with_family_desc: 'Assign contacts for automatic sending of your digital heritage.',
        export_backup: 'Export and Backup',
        export_backup_desc: 'Download the will as a file or export to PDF for a notary.',
        personal_profile: 'Personal Profile',
        information_security: 'Information and Security',
        email: 'Email',
        email_loading: 'Email: Loading...',
        legacy_status: 'Will Status',
        statistics: 'Statistics',
        accounts_protected: 'Accounts protected',
        wallets_specified: 'Wallets specified',
        registration_date: 'Registration Date',
        last_login: 'Last Visit',
        current_plan: 'Current Plan:',
        two_factor_auth: 'Two-factor authentication',
        create_master_password: 'Create master password',
        change_master_password: 'Change master password',
        legacy_management: 'Will Management',
        last_updated: 'Last updated',
        history_no_records: 'Activity History: No records.',
        registration_date_loading: 'Registration Date: Loading...',
        last_login_loading: 'Last Visit: Loading...',
        settings: 'Settings',
        legacy: 'Will',
        go_to_legacy: 'Go to Will',
        load_legacy: 'Load Will',
        logout: 'Logout',
        support: 'Support',
        theme: 'Theme',
        language: 'Language',
        notifications: 'Notifications',
        receive_email_notifications: 'Receive notifications via email',
        save: 'Save',
        back: 'Back',
        compose_legacy: 'Compose Will',
        social_networks: 'Social Networks',
        crypto: 'Crypto',
        passwords: 'Passwords',
        messages: 'Messages',
        add_account: 'Add Account',
        add_wallet: 'Add Wallet',
        passwords_logins: 'Passwords and Logins',
        credentials_placeholder: 'Passwords, logins, instructions...',
        messages_for_family: 'Messages for Loved Ones',
        messages_placeholder: 'Messages...',
        master_password: 'Master Password:',
        send_to_contacts: 'Send to Contacts',
        download: 'Download',
        back_to_profile: 'Back to Profile',
        copyright: '© 2025 LegacyNet. All rights reserved.',
        privacy_policy: 'Privacy Policy',
        terms_of_use: 'Terms of Use',
        auth_title: 'Registration / Login',
        password: 'Password',
        confirm_password: 'Confirm Password',
        confirm: 'Confirm',
        profile: 'Profile',
        fill_fields: 'Fill in the fields!',
        passwords_mismatch: 'Passwords do not match!',
        password_short: 'Password is too short! Minimum 8 characters.',
        error: 'Error!',
        master_password_required: 'Master password is required!',
        master_password_prompt: 'Master Password:',
        loaded: 'Loaded.',
        add_contacts: 'Add contacts!',
        theme_dark: 'Dark',
        theme_light: 'Light',
        lang_ru: 'Russian',
        lang_en: 'English',
        history_sample: 'Activity History: Registered 08/26/2025, will saved 1 time.',
        registration_date_sample: 'Registration Date: 08/26/2025',
        last_login_sample: 'Last Visit: 08/27/2025 15:30',
        menu: 'Menu',
        delete: 'Delete',
        enter_code: 'Enter 6-digit code',
        code_sent: 'Code sent to your email.',
        forgot_password: 'Forgot password?',
        reset_password: 'Password Recovery',
        send_code: 'Send Code',
        new_password: 'New Password',
        confirm_new_password: 'Confirm New Password',
        reset: 'Reset Password',
        contacts: 'Contacts',
        add_contact: 'Add',
        remove: 'Remove',
        code: 'Code',
        claim_legacy: 'Claim Legacy',
        claim_code: 'Claim Code',
        get: 'Get',
        warning: 'Warning: Share the master password with contacts offline (e.g., in a will or with a notary). Do not send it via email!',
        premium: 'Premium',
        premium_title: 'LegacyNet Premium Subscription',
        premium_description: 'Get advanced features for your digital heritage. Choose the plan that suits you.',
        free_plan: 'Free',
        premium_monthly: 'Monthly',
        premium_yearly: 'Yearly',
        subscribe: 'Subscribe',
        subscription_loading: 'Subscription: Loading...',
        current_password: 'Current password',
        change_password_button: 'Change password',
        password_changed_success: 'Password changed successfully!',
        password_change_error: 'Error changing password',
        passwords_do_not_match: 'Passwords do not match',
        legacy_active: 'Active and saved',
        legacy_not_created: 'Not created',
        status_error: 'Status check error',
        no_data: 'No data',
        encryption_method: 'Encryption Method',
        claim_title: 'Digital Legacy Claim',
        claim_description: 'Enter details to receive digital legacy',
        enter_claim_details: 'Enter sender email and legacy code',
        legacy_content: 'Legacy Content',
        social_accounts: 'Social Networks',
        crypto_wallets: 'Crypto Wallets',
        passwords_and_logins: 'Passwords and Logins',
        personal_messages: 'Personal Messages',
        instructions: 'Instructions',
        wallet_address: 'Wallet Address',
        seed_phrase: 'Seed Phrase',
        required_master_password: 'Master password required',
        account_name: 'Account Name',
        login: 'Login',
        wallet_type: 'Wallet Type',
        verification: 'Death Verification',
        death_verification: 'Death Verification',
        verification_title: 'User Death Verification',
        verification_description: 'Report user death to activate digital will',
        choose_method: 'Choose verification method',
        trusted_person: 'Trusted Person',
        verification_steps: 'Verification Steps',
        step_1: 'Step 1: User Search',
        step_1_desc: 'Choose search method',
        step_2: 'Step 2: Data Input',
        step_2_desc: 'Enter information',
        step_3: 'Step 3: Verification Method',
        step_3_desc: 'Choose method',
        step_4: 'Step 4: Completion',
        step_4_desc: 'Get result',
        find_user: 'Find User',
        choose_search_method: 'Choose a method to search for a user to confirm death',
        search_by_email: 'Search by Email',
        search_by_email_desc: 'Find user by email address',
        search_by_personal: 'Search by Personal Data',
        search_by_personal_desc: 'Find by full name and date of birth',
        search_user: 'Search User',
        deceased_email: 'User email',
        available_methods: 'Available confirmation methods:',
        trusted_person_selected: 'You have selected confirmation through a trusted person',
        trusted_person_hint: 'Enter the access code that was provided to you by the user during their lifetime',
        trusted_person_desc: 'Use access code provided by the user',
        fast: 'Fast',
        verification_info: 'Verification information',
        access_code: 'Access code',
        deceased_name: 'Full name of deceased',
        death_date: 'Date of death',
        submit_verification: 'Submit for verification',
        legacy_activated: 'Will activated!',
        legacy_sent: 'Digital will successfully sent to all specified contacts.',
        moderation_sent: 'Request sent for moderation',
        moderation_pending: 'Your request will be verified within 1-3 business days.',
        request_status: 'Request status',
        request_submitted: 'Request submitted',
        request_sent: 'Your request successfully sent for verification',
        moderator_review: 'Moderator review',
        documents_check: 'Documents checked for authenticity',
        verification_complete: 'Verification completion',
        get_notification: 'You will receive notification about result',
        request_id: 'Request ID',
        status: 'Status',
        status_pending: 'Pending verification',
        pending: 'Pending',
        return_home: 'Return to home',
        select_method: 'Select death confirmation method',
        enter_info: 'Fill in required data',
        get_result: 'Get verification result',
        instant_activation: 'Instant activation after code entry',
        moderator_check: 'Requires moderator verification (1-3 days)',
        next: 'Next',
        back_to_method: 'Back to method selection',
        user_info: 'User Information',
        privacy_settings: 'Privacy Settings',
        privacy_method: 'Privacy Method',
        email_only: 'Email only (anonymous)',
        personal_data: 'Personal data',
        personal_info: 'Personal Information',
        last_name: 'Last Name',
        first_name: 'First Name',
        middle_name: 'Middle Name',
        birth_date: 'Birth Date',
        save_personal_data: 'Save Personal Data',
        personal_data_saved: 'Personal data saved',
        fill_required_fields: 'Fill all required fields',
        phone: 'Phone',
        phone_placeholder: '+1 (555) 123-4567',
        secure_phone_storage: 'Phone numbers are stored encrypted',
        premium_phone_feature: 'Specify heir phone numbers. We will call them when will is activated.'
    }
};

let currentClaimData = null;
let isButtonDisabled = false;
let tempToken = '';
let selectedEncryptionMethod = localStorage.getItem('selectedEncryptionMethod') || 'no_encryption';
let masterPasswordCreated = localStorage.getItem('masterPasswordCreated') === 'true';
let authType = '';
let notificationCounter = 0;
const MAX_NOTIFICATIONS = 3;
let activeNotifications = 0;

// ========== ИСПРАВЛЕННАЯ ФУНКЦИЯ УВЕДОМЛЕНИЙ ==========
let lastNotificationMessage = '';
let lastNotificationTime = 0;

function showNotification(message, isError = false) {
    console.log('Creating notification:', message);
    
    // 🔐 Защита от XSS: санитизация ввода (добавлено по инструкции)
    const safeMessage = sanitizeInput(message);
    
    // 🔐 Защита от дублирования: если такое же сообщение было показано менее 1 секунды назад - игнорируем
    const now = Date.now();
    if (safeMessage === lastNotificationMessage && (now - lastNotificationTime) < 1000) {
        console.log('Duplicate notification prevented:', safeMessage);
        return;
    }
    
    lastNotificationMessage = safeMessage;
    lastNotificationTime = now;
    
    const existingNotifications = document.querySelectorAll('.notification');
    
    // 🔐 Удаляем старые уведомления если их больше максимума
    if (existingNotifications.length >= MAX_NOTIFICATIONS) {
        const oldestNotification = existingNotifications[existingNotifications.length - 1];
        if (oldestNotification.parentNode) {
            oldestNotification.parentNode.removeChild(oldestNotification);
        }
    }
    
    notificationCounter++;
    const notificationId = 'notification-' + Date.now() + '-' + notificationCounter;
    
    const notification = document.createElement('div');
    notification.id = notificationId;
    notification.className = 'notification';
    if (isError) {
        notification.style.borderLeftColor = '#f44336';
    }
    notification.innerHTML = `<span>${safeMessage}</span>`;
    
    let notificationContainer = document.getElementById('notification-container');
    if (!notificationContainer) {
        notificationContainer = document.createElement('div');
        notificationContainer.id = 'notification-container';
        notificationContainer.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 10000;
            max-width: 400px;
        `;
        document.body.appendChild(notificationContainer);
    }
    
    notificationContainer.appendChild(notification);
    
    updateNotificationPositions();
    
    const closeNotification = () => {
        if (!notification.parentNode) return;
        
        // 🔐 Очищаем таймаут для этого уведомления
        if (notification.timeoutId) {
            clearTimeout(notification.timeoutId);
        }
        
        notification.style.opacity = '0';
        notification.style.transform = 'translateX(100%) scale(0.8)';
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
                updateNotificationPositions();
            }
        }, 300);
    };
    
    notification.addEventListener('click', closeNotification);
    
    setTimeout(() => {
        notification.style.opacity = '1';
        notification.style.transform = 'translateX(0) scale(1)';
    }, 10);
    
    // 🔐 Автоматическое закрытие через 3 секунды
    notification.timeoutId = setTimeout(closeNotification, 3000);
}

function updateNotificationPositions() {
    const notificationContainer = document.getElementById('notification-container');
    if (!notificationContainer) return;
    
    const notifications = notificationContainer.querySelectorAll('.notification');
    notifications.forEach((notification, index) => {
        const offset = index * 80;
        notification.style.top = (20 + offset) + 'px';
    });
}

// ========== AUTH FUNCTIONS ==========
function openModal(type) {
    authType = type;
    const lang = secureRetrieve('language') || 'ru';
    const modal = document.getElementById('auth-modal');
    const title = document.getElementById('modal-title');
    const button = document.getElementById('modal-button');
    const message = document.getElementById('modal-message');
    const confirmPasswordGroup = document.getElementById('confirm-password-group');
    const forgotLink = document.getElementById('forgot-password-link');
    
    if (message) message.textContent = '';
    
    const emailInput = document.getElementById('modal-email');
    const passwordInput = document.getElementById('modal-password');
    if (emailInput) emailInput.value = '';
    if (passwordInput) passwordInput.value = '';
    
    if (type === 'register') {
        if (title) title.textContent = translations[lang].registration;
        if (button) button.textContent = translations[lang].registration;
        if (confirmPasswordGroup) confirmPasswordGroup.style.display = 'block';
        const confirmInput = document.getElementById('modal-confirm-password');
        if (confirmInput) confirmInput.value = '';
        if (forgotLink) forgotLink.style.display = 'none';
    } else {
        if (title) title.textContent = translations[lang].login;
        if (button) button.textContent = translations[lang].login;
        if (confirmPasswordGroup) confirmPasswordGroup.style.display = 'none';
        if (forgotLink) forgotLink.style.display = 'block';
    }
    
    if (modal) modal.style.display = 'flex';
}

// 🔐 ОБНОВЛЕННАЯ ФУНКЦИЯ handleAuth с корректной обработкой ошибок
async function handleAuth() {
    if (isButtonDisabled) return;
    
    const lang = secureRetrieve('language') || 'ru';
    const email = sanitizeInput(document.getElementById('modal-email').value);
    const password = document.getElementById('modal-password').value;
    const confirmPassword = document.getElementById('modal-confirm-password').value;
    const authButton = document.getElementById('modal-button');

    if (!disableButton(authButton, 5000)) return;

    // 🔐 Валидация email (по инструкции)
    if (!validateEmail(email)) {
        const message = document.getElementById('modal-message');
        if (message) message.textContent = 'Введите корректный email адрес';
        isButtonDisabled = false;
        authButton.disabled = false;
        authButton.textContent = authType === 'register' ? translations[lang].registration : translations[lang].login;
        return;
    }

    if (!validatePassword(password)) {
        const message = document.getElementById('modal-message');
        if (message) message.textContent = 'Пароль должен быть не менее 8 символов';
        isButtonDisabled = false;
        authButton.disabled = false;
        authButton.textContent = authType === 'register' ? translations[lang].registration : translations[lang].login;
        return;
    }

    if (authType === 'register') {
        if (password !== confirmPassword) {
            const message = document.getElementById('modal-message');
            if (message) message.textContent = translations[lang].passwords_mismatch;
            isButtonDisabled = false;
            authButton.disabled = false;
            authButton.textContent = authType === 'register' ? translations[lang].registration : translations[lang].login;
            return;
        }
    }

    const endpoint = authType === 'register' ? '/register' : '/login';
    
    try {
        // 🔐 Используем secureFetch (теперь он понимает, что это auth запрос)
        const data = await secureFetch(`${API_URL}${endpoint}`, {
            method: 'POST',
            body: JSON.stringify({ email, password })
        });
        
        if (data.temp_token) {
            tempToken = data.temp_token;
            closeModal('auth-modal');
            const codeInput = document.getElementById('2fa-code');
            if (codeInput) codeInput.value = '';
            const modal2fa = document.getElementById('2fa-modal');
            if (modal2fa) modal2fa.style.display = 'flex';
        } else {
            const message = document.getElementById('modal-message');
            if (message) message.textContent = data.message || translations[lang].error;
        }
    } catch (error) {
        console.error('Auth error:', error);
        const message = document.getElementById('modal-message');
        
        let errorMessage = 'Ошибка сети. Проверьте соединение и попробуйте снова.';
        
        if (error.responseData && error.responseData.message) {
            // 🔐 Отображаем сообщение от сервера
            errorMessage = error.responseData.message;
        } else if (error.message.includes('Сессия истекла')) {
            errorMessage = 'Сессия истекла. Пожалуйста, войдите снова.';
        } else if (error.isNetworkError) {
            errorMessage = 'Ошибка сети. Проверьте соединение и попробуйте снова.';
        }
        
        if (message) message.textContent = errorMessage;
    } finally {
        isButtonDisabled = false;
        authButton.disabled = false;
        authButton.textContent = authType === 'register' ? translations[lang].registration : translations[lang].login;
    }
}

// ========== 🔥 ИСПРАВЛЕННАЯ ФУНКЦИЯ verify2FA (ПО ИНСТРУКЦИИ) ==========
async function verify2FA() {
    const code = document.getElementById('2fa-code').value.trim();
    
    if (!code) {
        showNotification('Введите код подтверждения');
        return;
    }
    
    const verifyButton = document.getElementById('2fa-button');
    if (!disableButton(verifyButton, 3000)) return;

    try {
        console.log('Отправка verify_2fa запроса...');
        
        const response = await fetch(`${API_URL}/verify_2fa`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'include',
            body: JSON.stringify({ 
                temp_token: tempToken, 
                code: code 
            })
        });
        
        const data = await response.json();
        console.log('Ответ сервера:', data);
        
        if (data.success) {
            // 🔥 СОХРАНЯЕМ CSRF ТОКЕН ИЗ ОТВЕТА
            if (data.csrfToken) {
                localStorage.setItem('csrf_token', data.csrfToken);
                console.log('✅ CSRF токен сохранен после входа');
            }
            
            if (data.email) {
                secureStorage('userEmail', data.email);
            }
            
            showNotification('✅ Успешный вход!');
            closeModal('2fa-modal');
            
            // 🔥 ПЕРЕЗАГРУЖАЕМ СТРАНИЦУ ЧЕРЕЗ 500ms
            setTimeout(() => {
                window.location.href = '/profile';
            }, 500);
            
        } else {
            showNotification(data.message || 'Неверный код');
            isButtonDisabled = false;
            verifyButton.disabled = false;
            verifyButton.textContent = 'Подтвердить';
        }
    } catch (err) {
        console.error('❌ Ошибка верификации:', err);
        showNotification('Ошибка сети. Проверьте соединение.');
        isButtonDisabled = false;
        verifyButton.disabled = false;
        verifyButton.textContent = 'Подтвердить';
    }
}

function openForgotPasswordModal() {
    closeModal('auth-modal');
    const modal = document.getElementById('reset-modal');
    if (modal) modal.style.display = 'flex';
}

function sendResetCode() {
    const email = document.getElementById('reset-email').value.trim();
    
    if (!email) {
        showNotification('Введите email');
        return;
    }
    
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        showNotification('Введите корректный email адрес');
        return;
    }
    
    secureFetch(`${API_URL}/forgot_password`, {
        method: 'POST',
        body: JSON.stringify({ email })
    })
    .then(data => {
        if (data.temp_token) {
            tempToken = data.temp_token;
            const codeGroup = document.getElementById('reset-code-group');
            if (codeGroup) codeGroup.style.display = 'block';
            showNotification(data.message || 'Код отправлен');
        } else {
            showNotification(data.message || 'Ошибка отправки кода');
        }
    })
    .catch(err => {
        console.error('Reset password error:', err);
        
        let errorMessage = 'Ошибка отправки кода';
        if (err.responseData && err.responseData.message) {
            errorMessage = err.responseData.message;
        }
        
        showNotification(errorMessage);
    });
}

function resetPassword() {
    const code = document.getElementById('reset-code').value.trim();
    const newPassword = document.getElementById('new-password').value;
    const confirmPassword = document.getElementById('confirm-new-password').value;
    const lang = secureRetrieve('language') || 'ru';
    
    if (!code) {
        showNotification('Введите код подтверждения');
        return;
    }
    
    if (newPassword !== confirmPassword) {
        showNotification(translations[lang].passwords_mismatch);
        return;
    }
    
    if (newPassword.length < 8) {
        showNotification('Пароль должен быть не менее 8 символов');
        return;
    }
    
    secureFetch(`${API_URL}/reset_password`, {
        method: 'POST',
        body: JSON.stringify({ temp_token: tempToken, code, newPassword })
    })
    .then(data => {
        showNotification(data.message || 'Пароль изменен');
        if (data.success) {
            closeModal('reset-modal');
        }
    })
    .catch(err => {
        console.error('Reset password error:', err);
        
        let errorMessage = 'Ошибка смены пароля';
        if (err.responseData && err.responseData.message) {
            errorMessage = err.responseData.message;
        }
        
        showNotification(errorMessage);
    });
}

function setupAuthHandlers() {
    const registerButton = document.getElementById('register-button');
    const loginButton = document.getElementById('login-button');
    const startFreeButton = document.getElementById('start-free-button');
    const modalButton = document.getElementById('modal-button');
    const forgotLink = document.getElementById('forgot-password-link');
    const sendResetButton = document.getElementById('send-reset-code-button');
    const resetPasswordButton = document.getElementById('reset-password-button');
    const twoFaButton = document.getElementById('2fa-button');

    if (registerButton) registerButton.addEventListener('click', () => openModal('register'));
    if (loginButton) loginButton.addEventListener('click', () => openModal('login'));
    if (startFreeButton) startFreeButton.addEventListener('click', () => openModal('register'));
    if (modalButton) modalButton.addEventListener('click', handleAuth);
    if (forgotLink) forgotLink.addEventListener('click', openForgotPasswordModal);
    if (sendResetButton) sendResetButton.addEventListener('click', sendResetCode);
    if (resetPasswordButton) resetPasswordButton.addEventListener('click', resetPassword);
    if (twoFaButton) twoFaButton.addEventListener('click', verify2FA);

    const modalPassword = document.getElementById('modal-password');
    const twoFaCode = document.getElementById('2fa-code');
    const confirmNewPassword = document.getElementById('confirm-new-password');

    if (modalPassword) {
        modalPassword.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') handleAuth();
        });
    }

    if (twoFaCode) {
        twoFaCode.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') verify2FA();
        });
    }

    if (confirmNewPassword) {
        confirmNewPassword.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') resetPassword();
        });
    }
}

// ========== BASIC FUNCTIONS ==========
function setLanguage(lang) {
    document.querySelectorAll('[data-lang]').forEach(el => {
        el.textContent = translations[lang][el.dataset.lang];
    });
    document.querySelectorAll('[data-placeholder]').forEach(el => {
        el.placeholder = translations[lang][el.dataset.placeholder];
    });
    
    const themeSelect = document.getElementById('theme-select');
    if (themeSelect) {
        themeSelect.options[0].text = translations[lang].theme_dark;
        themeSelect.options[1].text = translations[lang].theme_light;
    }
    
    const languageSelect = document.getElementById('language-select');
    if (languageSelect) {
        languageSelect.options[0].text = translations[lang].lang_ru;
        languageSelect.options[1].text = translations[lang].lang_en;
    }
    
    document.documentElement.lang = lang;
}

function applyTheme(theme) {
    document.body.classList.remove('light', 'dark');
    document.body.classList.add(theme);
}

function disableButton(button, duration = 3000) {
    if (isButtonDisabled) return false;
    
    isButtonDisabled = true;
    button.disabled = true;
    const originalText = button.textContent;
    button.textContent = 'Загрузка...';
    
    setTimeout(() => {
        isButtonDisabled = false;
        button.disabled = false;
        button.textContent = originalText;
    }, duration);
    
    return true;
}

// 🔴 ИСПРАВЛЕННАЯ ФУНКЦИЯ updateNavAfterLogin (по инструкции)
async function updateNavAfterLogin() {
    const registerButton = document.getElementById('register-button');
    const loginButton = document.getElementById('login-button');
    const userMenuButton = document.getElementById('user-menu-button');
    
    if (registerButton) registerButton.style.display = 'none';
    if (loginButton) loginButton.style.display = 'none';
    if (userMenuButton) userMenuButton.style.display = 'inline-block';
    
    // Проверяем авторизацию через secureFetch
    try {
        const data = await secureFetch(`${API_URL}/profile`);
        if (data.success) {
            checkAdminStatus();
        }
    } catch (error) {
        console.log('Ошибка проверки авторизации:', error);
    }
}

async function checkAdminStatus() {
    try {
        const response = await secureFetch(`${API_URL}/admin/users`);
        
        if (response.ok) {
            addAdminLinkToMenu();
        }
    } catch (error) {
        console.log('Пользователь не является администратором');
    }
}

function addAdminLinkToMenu() {
    const userSubmenu = document.getElementById('user-submenu');
    if (userSubmenu && !document.querySelector('#admin-link')) {
        const adminLink = document.createElement('a');
        adminLink.href = '/admin';
        adminLink.id = 'admin-link';
        adminLink.innerHTML = '<i class="fas fa-cog"></i> Админ-панель';
        
        const logoutLink = userSubmenu.querySelector('a[onclick*="logout"]');
        if (logoutLink) {
            userSubmenu.insertBefore(adminLink, logoutLink);
        } else {
            userSubmenu.appendChild(adminLink);
        }
    }
}

// 🔴 ИСПРАВЛЕННАЯ ФУНКЦИЯ logout (по инструкции)
function logout() {
    // Сначала отправляем запрос на сервер для очистки куки
    fetch(`${API_URL}/logout`, {
        method: 'POST',
        credentials: 'include'
    })
    .then(() => {
        // Потом очищаем localStorage на клиенте
        localStorage.removeItem('userEmail');
        localStorage.removeItem('csrf_token'); // 🔴 ОЧИЩАЕМ CSRF ТОКЕН
        localStorage.removeItem('subscription');
        localStorage.removeItem('currentSection');
        localStorage.removeItem('masterPasswordCreated');
        localStorage.removeItem('selectedEncryptionMethod');
        localStorage.removeItem('lastVisit');
        
        // Обновляем навигацию
        const registerButton = document.getElementById('register-button');
        const loginButton = document.getElementById('login-button');
        const userMenuButton = document.getElementById('user-menu-button');
        
        if (registerButton) registerButton.style.display = 'inline-block';
        if (loginButton) loginButton.style.display = 'inline-block';
        if (userMenuButton) userMenuButton.style.display = 'none';
        
        // Перенаправляем на главную
        window.location.href = '/';
    })
    .catch(err => {
        console.error('Ошибка выхода:', err);
        // Все равно очищаем и редиректим
        localStorage.clear();
        window.location.href = '/';
    });
}

function toggleUserSubmenu() {
    const submenu = document.getElementById('user-submenu');
    if (submenu) {
        submenu.style.display = submenu.style.display === 'block' ? 'none' : 'block';
    }
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'none';
    }
}

// ========== MODAL HANDLERS ==========
function setupModalHandlers() {
    window.addEventListener('click', function(event) {
        const modals = document.querySelectorAll('.modal');
        modals.forEach(modal => {
            if (event.target === modal) {
                modal.style.display = 'none';
            }
        });
    });

    const closeButtons = document.querySelectorAll('.close');
    closeButtons.forEach(button => {
        button.addEventListener('click', function() {
            const modal = this.closest('.modal');
            if (modal) {
                modal.style.display = 'none';
            }
        });
    });
}

// ========== NAVIGATION HANDLERS ==========
function setupNavigationHandlers() {
    const userMenuButton = document.getElementById('user-menu-button');
    if (userMenuButton) {
        userMenuButton.addEventListener('click', toggleUserSubmenu);
    }

    document.addEventListener('click', function(e) {
        const userMenuButton = document.getElementById('user-menu-button');
        const userSubmenu = document.getElementById('user-submenu');
        
        if (userSubmenu && userSubmenu.style.display === 'block') {
            if (!userMenuButton.contains(e.target) && !userSubmenu.contains(e.target)) {
                userSubmenu.style.display = 'none';
            }
        }
    });
}

// ========== PROFILE FUNCTIONS ==========
function updateSubscriptionDisplay(subscription, subscriptionExpiry, subscriptionExpiryDisplay) {
    const subscriptionLink = document.getElementById('subscription-plan');
    const subscriptionExpiryElement = document.getElementById('subscription-expiry');
    
    console.log('Subscription data:', { subscription, subscriptionExpiry, subscriptionExpiryDisplay });
    
    if (subscriptionLink) {
        let displayText = 'Free';
        let displayClass = 'free';
        
        if (subscription === 'premium_monthly') {
            displayText = 'Premium (Месячная)';
            displayClass = 'premium';
        } else if (subscription === 'premium_yearly') {
            displayText = 'Premium (Годовая)';
            displayClass = 'premium';
        } else if (subscription === 'lifetime') {
            displayText = 'Premium Навсегда';
            displayClass = 'premium';
        }
        
        subscriptionLink.textContent = displayText;
        subscriptionLink.className = 'plan-link ' + displayClass;
        
        subscriptionLink.style.cursor = 'pointer';
        subscriptionLink.onclick = function() {
            window.location.href = '/premium';
        };
    }
    
    if (subscriptionExpiryElement) {
        console.log('Setting expiry display for:', subscription, subscriptionExpiryDisplay);
        
        if (subscriptionExpiry && (subscription === 'premium_monthly' || subscription === 'premium_yearly')) {
            subscriptionExpiryElement.innerHTML = `<strong>Действует до:</strong> ${subscriptionExpiryDisplay}`;
            subscriptionExpiryElement.style.display = 'block';
            subscriptionExpiryElement.style.marginTop = '5px';
            subscriptionExpiryElement.style.fontSize = '0.9em';
            subscriptionExpiryElement.style.color = '#4CAF50';
        } else {
            subscriptionExpiryElement.style.display = 'none';
        }
    }
}

// 🔴 ИСПРАВЛЕННАЯ ФУНКЦИЯ updateMasterPasswordButton (по инструкции Шаг 4)
function updateMasterPasswordButton() {
    const masterPasswordButton = document.getElementById('master-password-button');
    const lang = secureRetrieve('language') || 'ru';
    
    if (masterPasswordButton) {
        // 🔴 ИСПРАВИТЬ проверку:
        const masterPasswordCreated = localStorage.getItem('masterPasswordCreated') === 'true';
        
        if (masterPasswordCreated) {
            masterPasswordButton.textContent = translations[lang].change_master_password;
        } else {
            masterPasswordButton.textContent = translations[lang].create_master_password;
        }
    }
}

// 🔴 ИСПРАВЛЕННАЯ ФУНКЦИЯ openMasterPasswordModal (по инструкции Шаг 5)
function openMasterPasswordModal() {
    const modal = document.getElementById('changePasswordModal');
    const title = document.getElementById('master-password-title');
    const warning = document.getElementById('master-password-warning');
    const oldPasswordGroup = document.getElementById('old-password-group');
    const submitButton = document.getElementById('master-password-submit');
    
    // 🔴 ДОБАВИТЬ проверку авторизации:
    const userEmail = localStorage.getItem('userEmail');
    if (!userEmail) {
        showNotification('Сначала авторизуйтесь');
        return;
    }
    
    // 🔴 ВАЖНО: Проверяем, что все элементы существуют
    if (!modal) {
        console.error('Модальное окно changePasswordModal не найдено');
        showNotification('Ошибка загрузки формы');
        return;
    }
    
    if (!title) {
        console.error('Элемент master-password-title не найден');
        // Можно продолжить, это не критично
    }
    
    if (!warning) {
        console.error('Элемент master-password-warning не найден');
        // Можно продолжить, это не критично
    }
    
    if (!oldPasswordGroup) {
        console.error('Элемент old-password-group не найден');
        showNotification('Ошибка загрузки формы');
        return;
    }
    
    if (!submitButton) {
        console.error('Элемент master-password-submit не найден');
        showNotification('Ошибка загрузки формы');
        return;
    }
    
    // 🔴 ПРОВЕРЯЕМ статус мастер-пароля из localStorage
    const masterPasswordCreated = localStorage.getItem('masterPasswordCreated') === 'true';
    
    if (masterPasswordCreated) {
        title.textContent = 'Сменить мастер-пароль';
        submitButton.textContent = 'Сменить мастер-пароль';
        oldPasswordGroup.style.display = 'block';
        if (warning) warning.style.display = 'block';
    } else {
        title.textContent = 'Создать мастер-пароль';
        submitButton.textContent = 'Создать мастер-пароль';
        oldPasswordGroup.style.display = 'none';
        if (warning) warning.style.display = 'block';
    }
    
    // 🔴 СБРАСЫВАЕМ форму
    const form = document.getElementById('changePasswordForm');
    if (form) {
        form.reset();
    }
    
    modal.style.display = 'flex';
}

// 🔴 ИСПРАВЛЕННАЯ ФУНКЦИЯ handleMasterPasswordSubmit (по инструкции Шаг 6)
function handleMasterPasswordSubmit(e) {
    e.preventDefault();
    
    const oldMasterPassword = document.getElementById('old-master-password').value;
    const newMasterPassword = document.getElementById('new-master-password').value;
    const confirmNewMasterPassword = document.getElementById('confirm-new-master-password').value;
    const lang = secureRetrieve('language') || 'ru';

    if (!newMasterPassword || !confirmNewMasterPassword) {
        showNotification('Все поля обязательны для заполнения');
        return;
    }

    if (newMasterPassword.length < 8) {
        showNotification('Пароль должен быть не менее 8 символов');
        return;
    }

    if (newMasterPassword !== confirmNewMasterPassword) {
        showNotification(translations[lang].passwords_do_not_match);
        return;
    }

    // 🔴 ПРОВЕРЯЕМ авторизацию
    const userEmail = localStorage.getItem('userEmail');
    if (!userEmail) {
        showNotification('Ошибка авторизации');
        return;
    }

    const submitButton = document.getElementById('master-password-submit');
    
    if (!disableButton(submitButton, 3000)) return;

    // 🔴 ИСПОЛЬЗУЕМ secureFetch (правильный способ)
    secureFetch(`${API_URL}/set_master_password`, {
        method: 'POST',
        body: JSON.stringify({
            oldPassword: oldMasterPassword,
            newPassword: newMasterPassword
        })
    })
    .then(data => {
        if (data.success) {
            // 🔴 ОБНОВЛЯЕМ статус
            secureStorage('masterPasswordCreated', 'true');
            masterPasswordCreated = true;
            
            showNotification(masterPasswordCreated ? 'Мастер-пароль успешно создан!' : 'Мастер-пароль успешно изменен!');
            closeModal('changePasswordModal');
            
            // 🔴 ОБНОВЛЯЕМ кнопку
            updateMasterPasswordButton();
            
            // 🔴 ОБНОВЛЯЕМ профиль
            if (typeof loadProfile === 'function') {
                loadProfile();
            }
        } else {
            showNotification(data.message || 'Ошибка сохранения мастер-пароля');
        }
    })
    .catch(err => {
        console.error('Ошибка сохранения мастер-пароля:', err);
        showNotification('Ошибка сохранения мастер-пароля');
    })
    .finally(() => {
        isButtonDisabled = false;
        submitButton.disabled = false;
        submitButton.textContent = masterPasswordCreated ? 'Сменить мастер-пароль' : 'Создать мастер-пароль';
    });
}

// ========== КОНТАКТЫ - БЕЗОПАСНАЯ ВЕРСИЯ С ТЕЛЕФОНАМИ ДЛЯ PREMIUM ==========
let contactsModalInitialized = false;
let contactsHandlersInitialized = false;

// 🔴 ИСПРАВЛЕННАЯ ФУНКЦИЯ openContactsModal (по инструкции)
function openContactsModal() {
    console.log('Opening contacts modal - SECURE VERSION WITH PHONES');
    
    // 🔴 ДОБАВИТЬ: проверку авторизации
    const userEmail = localStorage.getItem('userEmail');
    if (!userEmail) {
        showNotification('Сначала авторизуйтесь');
        return;
    }
    
    const modal = document.getElementById('contacts-modal');
    const list = document.getElementById('contacts-list');
    
    if (modal && list) {
        list.innerHTML = '';
        
        const lang = secureRetrieve('language') || 'ru';
        const subscription = secureRetrieve('subscription') || 'free';
        const isPremium = subscription.includes('premium') || subscription === 'lifetime';
        
        // 🔐 Добавляем уведомление о безопасности для премиум  пользователей
        const securityNotice = document.getElementById('phone-security-notice');
        const premiumNotice = document.getElementById('contacts-premium-notice');
        
        if (securityNotice) {
            securityNotice.style.display = isPremium ? 'flex' : 'none';
        }
        
        if (premiumNotice) {
            premiumNotice.style.display = isPremium ? 'flex' : 'none';
        }
        
        secureFetch(`${API_URL}/get_contacts`)
        .then(data => {
            console.log('Contacts data from server:', data);
            
            if (data.success && data.contacts && data.contacts.length > 0) {
                // 🔐 Проверяем формат данных (старый: массив email, новый: массив объектов)
                const isNewFormat = data.contacts.length > 0 && typeof data.contacts[0] === 'object';
                
                if (isNewFormat && isPremium) {
                    // 🔐 Новый формат для премиум: [{email, phone}]
                    const validContacts = data.contacts.filter(contact => 
                        contact && contact.email && contact.email.trim() !== '' && 
                        /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contact.email.trim())
                    );
                    
                    console.log('Premium contacts with phones:', validContacts);
                    
                    validContacts.forEach(contact => {
                        addContactField(contact.email, contact.phone || '', true);
                    });
                } else {
                    // 🔐 Старый формат для бесплатных или legacy данных
                    const validContacts = data.contacts.filter(contact => {
                        if (typeof contact === 'string') {
                            return contact && contact.trim() !== '' && 
                                   /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contact.trim());
                        } else if (contact && contact.email) {
                            return contact.email.trim() !== '' && 
                                   /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contact.email.trim());
                        }
                        return false;
                    });
                    
                    validContacts.forEach(contact => {
                        const email = typeof contact === 'string' ? contact : contact.email;
                        addContactField(email, '', true);
                    });
                }
                
                console.log('Added contacts from server');
            } else {
                addContactField('', '');
                console.log('No contacts on server, added one empty field');
            }
            
            modal.style.display = 'flex';
            
            if (!contactsHandlersInitialized) {
                setupContactsHandlers();
                contactsHandlersInitialized = true;
            }
        })
        .catch(err => {
            console.error('Ошибка загрузки контактов:', err);
            addContactField('', '');
            modal.style.display = 'flex';
            
            if (!contactsHandlersInitialized) {
                setupContactsHandlers();
                contactsHandlersInitialized = true;
            }
        });
    }
}

// 🔐 ОБНОВЛЕННАЯ ФУНКЦИЯ: добавление полей контакта с телефоном для премиум
function addContactField(email = '', phone = '', isFromServer = false) {
    const list = document.getElementById('contacts-list');
    if (list) {
        const currentCount = list.querySelectorAll('.contact-item').length;
        
        const subscription = secureRetrieve('subscription') || 'free';
        const isPremium = subscription.includes('premium') || subscription === 'lifetime';
        const maxContacts = isPremium ? 8 : 1;
        
        // 🔐 Проверяем лимит только если контакт добавляется не с сервера
        if (!isFromServer && currentCount >= maxContacts) {
            showNotification(`Лимит контактов: ${maxContacts} для вашего тарифа. Для увеличения лимита приобретите премиум.`);
            return;
        }
        
        const existingInputs = list.querySelectorAll('.contact-email');
        const duplicate = Array.from(existingInputs).some(input => input.value === email && email !== '');
        
        if (duplicate) {
            console.log('Duplicate contact found, skipping:', email);
            return;
        }
        
        const lang = secureRetrieve('language') || 'ru';
        const div = document.createElement('div');
        div.className = 'contact-item';
        
        if (isPremium) {
            // 🔐 Премиум-версия с полем для телефона
            div.innerHTML = `
                <div class="contact-field">
                    <i class="fas fa-envelope"></i>
                    <input type="email" class="contact-email" placeholder="${translations[lang].email}" value="${email}">
                </div>
                <div class="contact-field">
                    <i class="fas fa-phone"></i>
                    <input type="tel" class="contact-phone" placeholder="${translations[lang].phone_placeholder}" value="${phone}">
                </div>
                <button type="button" class="delete-button" onclick="removeContactField(this)">
                    <i class="fas fa-times"></i>
                </button>
            `;
        } else {
            // 🔐 Бесплатная версия - только email
            div.innerHTML = `
                <input type="email" class="contact-email" placeholder="${translations[lang].email}" value="${email}">
                <button type="button" class="delete-button" onclick="removeContactField(this)">
                    <i class="fas fa-times"></i>
                </button>
            `;
        }
        
        list.appendChild(div);
        
        console.log('Added contact field with email:', email || 'empty', 'phone:', phone || 'empty');
        
        updateContactsLimitDisplay(currentCount + 1, maxContacts);
    }
}

function removeContactField(button) {
    const contactItem = button.parentNode;
    const contactList = contactItem.parentNode;
    
    if (contactList.children.length > 1) {
        contactItem.remove();
        
        const currentCount = contactList.querySelectorAll('.contact-item').length;
        const subscription = secureRetrieve('subscription') || 'free';
        const isPremium = subscription.includes('premium') || subscription === 'lifetime';
        const maxContacts = isPremium ? 8 : 1;
        updateContactsLimitDisplay(currentCount, maxContacts);
    } else {
        // 🔐 Очищаем все поля в последнем контакте
        const emailInput = contactItem.querySelector('.contact-email');
        if (emailInput) emailInput.value = '';
        
        const phoneInput = contactItem.querySelector('.contact-phone');
        if (phoneInput) phoneInput.value = '';
        
        const currentCount = 1;
        const subscription = secureRetrieve('subscription') || 'free';
        const isPremium = subscription.includes('premium') || subscription === 'lifetime';
        const maxContacts = isPremium ? 8 : 1;
        updateContactsLimitDisplay(currentCount, maxContacts);
    }
}

function updateContactsLimitDisplay(currentCount, maxContacts) {
    const limitDisplay = document.getElementById('contacts-limit-display');
    if (limitDisplay) {
        limitDisplay.textContent = `${currentCount}/${maxContacts} контактов`;
        
        if (currentCount >= maxContacts) {
            limitDisplay.className = 'contacts-limit limit-reached';
        } else if (currentCount >= maxContacts * 0.8) {
            limitDisplay.className = 'contacts-limit limit-warning';
        } else {
            limitDisplay.className = 'contacts-limit';
        }
    }
}

// 🔥 ИСПРАВЛЕННАЯ ФУНКЦИЯ saveContacts (по инструкции)
function saveContacts() {
    const contactItems = document.querySelectorAll('.contact-item');
    const subscription = secureRetrieve('subscription') || 'free';
    const isPremium = subscription.includes('premium') || subscription === 'lifetime';
    const lang = secureRetrieve('language') || 'ru';
    
    let contacts = [];
    let hasValidEmail = false;
    
    if (isPremium) {
        contactItems.forEach(item => {
            const emailInput = item.querySelector('.contact-email');
            
            if (emailInput && emailInput.value.trim()) {
                const email = emailInput.value.trim();
                const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                
                if (!emailRegex.test(email)) {
                    showNotification(`Некорректный email: ${email}`);
                    return;
                }
                
                const phoneInput = item.querySelector('.contact-phone');
                const phone = phoneInput ? phoneInput.value.trim() : '';
                
                contacts.push({ email, phone });
                hasValidEmail = true;
            }
        });
    } else {
        contactItems.forEach(item => {
            const emailInput = item.querySelector('.contact-email');
            
            if (emailInput && emailInput.value.trim()) {
                const email = emailInput.value.trim();
                const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                
                if (!emailRegex.test(email)) {
                    showNotification(`Некорректный email: ${email}`);
                    return;
                }
                
                contacts.push(email);
                hasValidEmail = true;
            }
        });
    }
    
    // 🔥 ВАЖНО: Исправляем проверку
    if (contacts.length === 0 || !hasValidEmail) {
        showNotification('Добавьте хотя бы один валидный email');
        return;
    }
    
    const maxContacts = isPremium ? 8 : 1;
    
    if (contacts.length > maxContacts) {
        showNotification(`Превышен лимит контактов для вашего тарифа. Максимум: ${maxContacts}`);
        return;
    }
    
    console.log('Saving contacts to server:', contacts);
    
    secureFetch(`${API_URL}/set_contacts`, {
        method: 'POST',
        body: JSON.stringify({ contacts: contacts })
    })
    .then(data => {
        console.log('Server response:', data);
        // 🔥 ИСПРАВЛЯЕМ текст уведомления
        showNotification(data.message || `Контакты сохранены (${contacts.length} email)`);
        if (data.success) {
            closeModal('contacts-modal');
        }
    })
    .catch(err => {
        console.error('Ошибка сохранения контактов:', err);
        showNotification('Ошибка сохранения контактов');
    });
}

function setupContactsHandlers() {
    console.log('Setting up contacts handlers - SECURE VERSION');
    
    document.addEventListener('keypress', function(e) {
        if (e.target.matches('.contact-email') && e.key === 'Enter') {
            e.preventDefault();
            saveContacts();
        }
    });
    
    const addContactButton = document.getElementById('add-contact-button');
    if (addContactButton) {
        const newAddButton = addContactButton.cloneNode(true);
        addContactButton.parentNode.replaceChild(newAddButton, addContactButton);
        
        newAddButton.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            console.log('Add contact button clicked - SECURE ADDITION');
            addContactField('', '');
        }, { once: false });
    }
    
    const saveContactsButton = document.getElementById('save-contacts-button');
    if (saveContactsButton) {
        const newSaveButton = saveContactsButton.cloneNode(true);
        saveContactsButton.parentNode.replaceChild(newSaveButton, saveContactsButton);
        
        newSaveButton.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            console.log('Save contacts button clicked - SECURE SAVE');
            saveContacts();
        }, { once: false });
    }
}

// ========== LEGACY FUNCTIONS ==========
function setupEncryptionMethods() {
    const encryptionCards = document.querySelectorAll('.encryption-card');
    
    if (encryptionCards.length === 0) return;
    
    const savedMethod = secureRetrieve('selectedEncryptionMethod');
    if (savedMethod) {
        selectedEncryptionMethod = savedMethod;
    }
    
    updateEncryptionCards();
    
    encryptionCards.forEach(card => {
        card.removeEventListener('click', handleEncryptionCardClick);
        card.addEventListener('click', handleEncryptionCardClick);
    });
}

function handleEncryptionCardClick() {
    const method = this.getAttribute('data-method');
    const subscription = secureRetrieve('subscription') || 'free';
    const isPremium = subscription.includes('premium') || subscription === 'lifetime';
    
    // 🔐 Проверяем премиум доступ
    if ((method === 'shared_key' || method === 'master_password') && !isPremium) {
        showNotification('Этот метод доступен только для премиум пользователей');
        return;
    }
    
    // 🔐 Проверяем мастер-пароль для метода с мастер-паролем
    if (method === 'master_password') {
        if (!window.masterPasswordCreated) {
            showNotification('Сначала создайте мастер-пароль в профиле!');
            return;
        }
    }
    
    // Сохраняем выбранный метод
    window.selectedEncryptionMethod = method;
    secureStorage('selectedEncryptionMethod', method);
    
    updateEncryptionCards();
}

function updateEncryptionCards() {
    const encryptionCards = document.querySelectorAll('.encryption-card');
    encryptionCards.forEach(card => {
        card.classList.remove('selected');
        if (card.getAttribute('data-method') === selectedEncryptionMethod) {
            card.classList.add('selected');
        }
    });
}

function openMasterPasswordForSendModal() {
    const modal = document.getElementById('master-password-send-modal');
    if (modal) {
        modal.style.display = 'flex';
        const input = document.getElementById('master-password-for-send');
        if (input) input.value = '';
    }
}

// 🔴 ИСПРАВЛЕННАЯ ФУНКЦИЯ sendLegacy (по инструкции)
async function sendLegacy() {
    const lang = secureRetrieve('language') || 'ru';
    
    // 🔴 ДОБАВИТЬ проверку авторизации
    const userEmail = localStorage.getItem('userEmail');
    if (!userEmail) {
        showNotification('Сначала авторизуйтесь');
        return;
    }
    
    if (selectedEncryptionMethod === 'master_password' && !masterPasswordCreated) {
        showNotification('Сначала создайте мастер-пароль в профиле!');
        return;
    }

    if (selectedEncryptionMethod === 'master_password') {
        openMasterPasswordForSendModal();
        return;
    }

    const sendButton = document.getElementById('send-legacy-button');
    if (!disableButton(sendButton, 5000)) return;

    try {
        const data = await secureFetch(`${API_URL}/send_legacy`, {
            method: 'POST',
            body: JSON.stringify({ 
                encryptionMethod: selectedEncryptionMethod
            })
        });
        
        if (data.success) {
            showNotification(`✅ Завещание отправлено контактам (метод: ${getEncryptionMethodName(data.encryptionMethod)})`);
        } else {
            showNotification(data.message || translations[lang].error, true);
        }
    } catch (error) {
        console.error('Send legacy error:', error);
        showNotification('❌ Ошибка отправки завещания', true);
    } finally {
        isButtonDisabled = false;
        sendButton.disabled = false;
        sendButton.textContent = translations[lang].send_to_contacts;
    }
}

function getEncryptionMethodName(method) {
    switch(method) {
        case 'no_encryption': return 'без шифрования';
        case 'shared_key': return 'код доступа';
        case 'master_password': return 'мастер-пароль';
        default: return method;
    }
}

// 🔐 ОБНОВЛЕННАЯ ФУНКЦИЯ sendLegacyWithMasterPassword с secureFetch
async function sendLegacyWithMasterPassword(masterPassword) {
    const lang = secureRetrieve('language') || 'ru';
    const sendButton = document.getElementById('send-legacy-button');
    
    if (!disableButton(sendButton, 5000)) return;

    try {
        const data = await secureFetch(`${API_URL}/send_legacy`, {
            method: 'POST',
            body: JSON.stringify({ 
                encryptionMethod: selectedEncryptionMethod,
                masterPassword: masterPassword
            })
        });
        
        if (data.success) {
            showNotification(`✅ Завещание отправлено контактам (метод: ${getEncryptionMethodName(data.encryptionMethod)})`);
        } else {
            showNotification(data.message || translations[lang].error, true);
        }
    } catch (error) {
        console.error('Send legacy error:', error);
        showNotification('❌ Ошибка отправки завещания', true);
    } finally {
        isButtonDisabled = false;
        sendButton.disabled = false;
        sendButton.textContent = translations[lang].send_to_contacts;
    }
}

function addSocialAccount(name = '', login = '', password = '', instructions = '') {
    const lang = secureRetrieve('language') || 'ru';
    const container = document.getElementById('social-accounts');
    if (container) {
        const div = document.createElement('div');
        div.className = 'dynamic-field';
        div.innerHTML = `
            <input type="text" placeholder="${translations[lang].account_name} (VK, Instagram)" value="${sanitizeInput(name)}">
            <input type="text" placeholder="${translations[lang].login}" value="${sanitizeInput(login)}">
            <input type="password" placeholder="${translations[lang].password}" value="${password}">
            <textarea placeholder="${translations[lang].instructions}">${sanitizeInput(instructions)}</textarea>
            <button class="delete-button" onclick="this.parentNode.remove()"><i class="fas fa-times"></i></button>
        `;
        container.appendChild(div);
    }
}

function addCryptoWallet(name = '', address = '', seed = '', instructions = '') {
    const lang = secureRetrieve('language') || 'ru';
    const container = document.getElementById('crypto-wallets');
    if (container) {
        const div = document.createElement('div');
        div.className = 'dynamic-field';
        div.innerHTML = `
            <input type="text" placeholder="${translations[lang].wallet_type} (Bitcoin, Ethereum)" value="${sanitizeInput(name)}">
            <input type="text" placeholder="${translations[lang].wallet_address}" value="${sanitizeInput(address)}">
            <textarea placeholder="${translations[lang].seed_phrase}">${seed}</textarea>
            <textarea placeholder="${translations[lang].instructions}">${sanitizeInput(instructions)}</textarea>
            <button class="delete-button" onclick="this.parentNode.remove()"><i class="fas fa-times"></i></button>
        `;
        container.appendChild(div);
    }
}

function openTab(tabName) {
    console.log('Opening tab from script.js:', tabName);
    const tabs = document.getElementsByClassName('tab-content');
    for (let tab of tabs) {
        tab.style.display = 'none';
    }
    const targetTab = document.getElementById(`${tabName}-tab`);
    if (targetTab) {
        targetTab.style.display = 'block';
        console.log('Tab displayed successfully:', tabName);
    }
}

// 🔴 ИСПРАВЛЕННАЯ ФУНКЦИЯ saveLegacy (по инструкции)
async function saveLegacy() {
    const lang = secureRetrieve('language') || 'ru';
    
    // 🔴 ДОБАВИТЬ проверку авторизации
    const userEmail = localStorage.getItem('userEmail');
    if (!userEmail) {
        showNotification('Сначала авторизуйтесь');
        return;
    }
    
    if (selectedEncryptionMethod === 'master_password' && !masterPasswordCreated) {
        showNotification('Сначала создайте мастер-пароль в профиле!');
        return;
    }

    const data = {
        social: Array.from(document.querySelectorAll('#social-accounts .dynamic-field')).map(field => ({
            name: sanitizeInput(field.querySelectorAll('input')[0].value),
            login: sanitizeInput(field.querySelectorAll('input')[1].value),
            password: field.querySelectorAll('input')[2].value, // Пароль не санитизируем
            instructions: sanitizeInput(field.querySelector('textarea').value)
        })),
        crypto: Array.from(document.querySelectorAll('#crypto-wallets .dynamic-field')).map(field => ({
            name: sanitizeInput(field.querySelectorAll('input')[0].value),
            address: sanitizeInput(field.querySelectorAll('input')[1].value),
            seed: field.querySelectorAll('textarea')[0].value, // Сид-фразу не санитизируем
            instructions: sanitizeInput(field.querySelectorAll('textarea')[1].value)
        })),
        credentials: document.getElementById('credentials').value,
        messages: sanitizeInput(document.getElementById('messages').value)
    };

    try {
        const response = await secureFetch(`${API_URL}/save`, {
            method: 'POST',
            body: JSON.stringify({ 
                encrypted: data,
                encryptionMethod: selectedEncryptionMethod 
            })
        });
        
        if (response.success) {
            showNotification('✅ Завещание сохранено с шифрованием');
        } else {
            showNotification('❌ ' + (response.message || 'Ошибка сохранения'), true);
        }
    } catch (error) {
        showNotification('❌ Ошибка сети при сохранении', true);
    }
}

function downloadLegacy() {
    console.log('Download legacy function called');
    
    const subscription = secureRetrieve('subscription') || 'free';
    if (subscription === 'free') {
        showNotification('Экспорт доступен только в премиум версии!');
        return;
    }

    const userEmail = secureRetrieve('userEmail');
    if (!userEmail) {
        showNotification('Необходимо авторизоваться');
        return;
    }

    // 🔐 БЛОКИРУЕМ кнопку чтобы предотвратить повторные нажатия
    const downloadButton = document.getElementById('download-legacy-button-2');
    if (downloadButton) {
        downloadButton.disabled = true;
        downloadButton.textContent = 'Загрузка...';
        
        // 🔐 Разблокируем через 3 секунды
        setTimeout(() => {
            downloadButton.disabled = false;
            downloadButton.textContent = 'Скачать';
        }, 3000);
    }

    secureFetch(`${API_URL}/load`, {
        method: 'POST'
    })
    .then(data => {
        console.log('Download response:', data);
        if (data.encrypted) {
            try {
                const blob = new Blob([JSON.stringify(data.encrypted, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'legacy.json';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                // 🔐 ОДНО уведомление при успехе
                showNotification('Завещание скачано!');
            } catch (err) {
                console.error('Download error:', err);
                showNotification('Ошибка при загрузке завещания', true);
            }
        } else {
            // 🔐 ОДНО уведомление если нет завещания
            showNotification('Нет сохраненного завещания');
        }
    })
    .catch(err => {
        console.error('Download fetch error:', err);
        showNotification('Ошибка сети: ' + err.message, true);
    })
    .finally(() => {
        // 🔐 Всегда разблокируем кнопку
        if (downloadButton) {
            downloadButton.disabled = false;
            downloadButton.textContent = 'Скачать';
        }
    });
}

// ========== ФУНКЦИИ ДЛЯ РАБОТЫ С ДАННЫМИ ЗАВЕЩАНИЯ ==========
function loadLegacyData() {
    const userEmail = secureRetrieve('userEmail');
    if (!userEmail) return;

    // 🔐 ДОБАВИТЬ: проверка чтобы избежать двойной загрузки
    if (window.legacyDataLoaded) {
        console.log('Legacy data already loaded, skipping...');
        return;
    }
    window.legacyDataLoaded = true;

    secureFetch(`${API_URL}/load`, {
        method: 'POST'
    })
    .then(data => {
        console.log('Load response:', data);
        if (!data.encrypted) return;

        let decrypted = data.encrypted;

        if (decrypted) {
            console.log('Decrypted data:', decrypted);
            if (decrypted.social && decrypted.social.length > 0) {
                decrypted.social.forEach(account => {
                    addSocialAccount(account.name, account.login, account.password, account.instructions);
                });
            }
            if (decrypted.crypto && decrypted.crypto.length > 0) {
                decrypted.crypto.forEach(wallet => {
                    addCryptoWallet(wallet.name, wallet.address, wallet.seed, wallet.instructions);
                });
            }
            if (document.getElementById('credentials')) {
                document.getElementById('credentials').value = decrypted.credentials || '';
            }
            if (document.getElementById('messages')) {
                document.getElementById('messages').value = decrypted.messages || '';
            }
        }
    })
    .catch(err => {
        console.error('Load error:', err);
    });
}

// ========== CLAIM FUNCTIONS ==========
// 🔴 ИСПРАВЛЕННАЯ ФУНКЦИЯ claimLegacyFromPage
function claimLegacyFromPage() {
    const claimCode = document.getElementById('claim-code').value.trim();
    
    if (!claimCode) {
        showNotification('Введите код завещания');
        return;
    }
    
    // 🔐 ПРОВЕРКА ДЛИНЫ КОДА (24 СИМВОЛА ДЛЯ HEX)
    if (claimCode.length !== 24) {
        showNotification('Неверный формат кода завещания. Код должен содержать 24 символа.');
        return;
    }
    
    const claimButton = document.getElementById('claim-legacy-button');
    if (!disableButton(claimButton, 3000)) return;
    
    secureFetch(`${API_URL}/claim_legacy`, {
        method: 'POST',
        body: JSON.stringify({ claimCode })
    })
    .then(data => {
        if (data.success) {
            // 🔐 ИСПРАВЛЕНО: сервер теперь присылает уже расшифрованные данные
            displayLegacyContent(data.decrypted, data.encryptionMethod, claimCode);
        } else if (data.requiresMasterPassword) {
            // 🔴 ПОКАЗЫВАЕМ ПОЛЕ ДЛЯ МАСТЕР-ПАРОЛЯ
            document.getElementById('master-password-section').style.display = 'block';
            showNotification('Для этого завещания требуется мастер-пароль');
        } else {
            showNotification(data.message || 'Ошибка получения завещания');
        }
        isButtonDisabled = false;
        claimButton.disabled = false;
        claimButton.textContent = 'Получить завещание';
    })
    .catch(err => {
        console.error('Ошибка получения завещания:', err);
        
        // 🔴 ОБРАБАТЫВАЕМ ОШИБКУ С ФЛАГОМ requiresMasterPassword
        if (err.responseData && err.responseData.requiresMasterPassword) {
            document.getElementById('master-password-section').style.display = 'block';
            showNotification('Для этого завещания требуется мастер-пароль');
        } else {
            showNotification(err.message || 'Ошибка получения завещания');
        }
        
        isButtonDisabled = false;
        claimButton.disabled = false;
        claimButton.textContent = 'Получить завещание';
    });
}

// 🔐 ИСПРАВЛЕННАЯ ФУНКЦИЯ decryptLegacy с безопасной проверкой
function decryptLegacy() {
    const masterPassword = document.getElementById('claim-master-password').value;
    
    if (!masterPassword) {
        showNotification('Введите мастер-пароль');
        return;
    }
    
    if (masterPassword.length < 8) {
        showNotification('Мастер-пароль должен быть не менее 8 символов');
        return;
    }
    
    const claimCode = document.getElementById('claim-code').value.trim();
    if (!claimCode) {
        showNotification('Код завещания не введен');
        return;
    }
    
    // 🔐 ПРОВЕРКА ДЛИНЫ КОДА (24 СИМВОЛА ДЛЯ HEX)
    if (claimCode.length !== 24) {
        showNotification('Неверный формат кода завещания. Код должен содержать 24 символа.');
        return;
    }
    
    const decryptButton = document.getElementById('decrypt-legacy-button');
    if (!disableButton(decryptButton, 3000)) return;
    
    // 🔐 Показываем индикатор загрузки
    decryptButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Проверка пароля...';
    
    secureFetch(`${API_URL}/claim_legacy`, {
        method: 'POST',
        body: JSON.stringify({ 
            claimCode: claimCode,
            masterPassword: masterPassword
        })
    })
    .then(data => {
        if (data.success) {
            // 🔐 ИСПРАВЛЕНО: сервер теперь присылает уже расшифрованные данные
            displayLegacyContent(data.decrypted, data.encryptionMethod, claimCode);
            document.getElementById('master-password-section').style.display = 'none';
            showNotification('✅ Завещание успешно расшифровано');
        } else {
            showNotification(`❌ ${data.message || 'Неверный мастер-пароль'}`);
            // 🔐 Очищаем поле пароля при ошибке
            document.getElementById('claim-master-password').value = '';
        }
        isButtonDisabled = false;
        decryptButton.disabled = false;
        decryptButton.innerHTML = '<i class="fas fa-lock"></i> Расшифровать завещание';
    })
    .catch(err => {
        console.error('Ошибка расшифровки:', err);
        if (err.responseData && err.responseData.requiresMasterPassword) {
            showNotification('❌ Неверный мастер-пароль. Попробуйте снова.');
            document.getElementById('claim-master-password').value = '';
            document.getElementById('claim-master-password').focus();
        } else {
            showNotification('❌ Ошибка расшифровки: ' + (err.message || 'Неизвестная ошибка'));
        }
        isButtonDisabled = false;
        decryptButton.disabled = false;
        decryptButton.innerHTML = '<i class="fas fa-lock"></i> Расшифровать завещание';
    });
}

// 🔐 БЕЗОПАСНАЯ ФУНКЦИЯ ОТОБРАЖЕНИЯ ЗАВЕЩАНИЯ (дешифровка на сервере) - ПОЛНОСТЬЮ ПЕРЕПИСАНА ПО ИНСТРУКЦИИ
function displayLegacyContent(decryptedData, encryptionMethod, claimCode) {
    console.log('displayLegacyContent called (SECURE VERSION):', { 
        decryptedData, 
        encryptionMethod,
        type: typeof decryptedData,
        isObject: typeof decryptedData === 'object'
    });
    
    try {
        // 🔐 ПРОВЕРЯЕМ, ЧТО ДАННЫЕ УЖЕ РАСШИФРОВАНЫ СЕРВЕРОМ
        if (typeof decryptedData !== 'object' || decryptedData === null) {
            throw new Error('Сервер вернул некорректные данные. Пожалуйста, обратитесь к администратору.');
        }
        
        const resultContainer = document.getElementById('legacy-content');
        if (!resultContainer) {
            console.error('Result container not found');
            showNotification('Ошибка отображения завещания');
            return;
        }
        
        // 🔐 ПОКАЗЫВАЕМ ПРЕДУПРЕЖДЕНИЕ О СРОКЕ ДЕЙСТВИЯ
        const warningElement = document.getElementById('time-limit-warning');
        if (warningElement) {
            warningElement.style.display = 'block';
        }
        
        // Формируем HTML с информацией о сроке действия
        let html = `
            <div class="legacy-content">
                <h3>Содержание завещания</h3>
                <div class="legacy-expiry-info">
                    <i class="fas fa-info-circle"></i>
                    <strong>Информация о сроке действия:</strong> Это завещание будет доступно в течение 
                    <strong>30 дней</strong> с момента первого просмотра. После истечения этого срока 
                    оно будет автоматически удалено из системы.
                </div>
        `;
        
        // 🔐 ПРОВЕРЯЕМ И ОТОБРАЖАЕМ ДАННЫЕ С САНИТИЗАЦИЕЙ
        if (decryptedData.social && Array.isArray(decryptedData.social) && decryptedData.social.length > 0) {
            html += `<div class="legacy-section"><h4><i class="fas fa-share-alt"></i> Социальные сети</h4>`;
            decryptedData.social.forEach(account => {
                html += `<div class="legacy-item">
                    <h5>${sanitizeInput(account.name || 'Без названия')}</h5>
                    <p><strong>Логин:</strong> <span class="long-text">${sanitizeInput(account.login || 'Не указан')}</span></p>
                    <p><strong>Пароль:</strong> <span class="long-text">${sanitizeInput(account.password || 'Не указан')}</span></p>
                    ${account.instructions ? `<p><strong>Инструкции:</strong> <span class="long-text">${sanitizeInput(account.instructions)}</span></p>` : ''}
                </div>`;
            });
            html += `</div>`;
        }
        
        if (decryptedData.crypto && Array.isArray(decryptedData.crypto) && decryptedData.crypto.length > 0) {
            html += `<div class="legacy-section"><h4><i class="fas fa-coins"></i> Криптокошельки</h4>`;
            decryptedData.crypto.forEach(wallet => {
                html += `<div class="legacy-item">
                    <h5>${sanitizeInput(wallet.name || 'Без названия')}</h5>
                    <p><strong>Адрес кошелька:</strong> <span class="long-text">${sanitizeInput(wallet.address || 'Не указан')}</span></p>
                    ${wallet.seed ? `<p><strong>Сид-фраза:</strong> <span class="long-text" style="word-break: break-all;">${wallet.seed}</span></p>` : ''}
                    ${wallet.instructions ? `<p><strong>Инструкции:</strong> <span class="long-text">${sanitizeInput(wallet.instructions)}</span></p>` : ''}
                </div>`;
            });
            html += `</div>`;
        }
        
        if (decryptedData.credentials) {
            html += `<div class="legacy-section">
                <h4><i class="fas fa-key"></i> Пароли и логины</h4>
                <div class="legacy-item"><pre style="white-space: pre-wrap; word-break: break-word;">${sanitizeInput(decryptedData.credentials)}</pre></div>
            </div>`;
        }
        
        if (decryptedData.messages) {
            html += `<div class="legacy-section">
                <h4><i class="fas fa-envelope"></i> Личные сообщения</h4>
                <div class="legacy-item"><p style="white-space: pre-wrap; word-break: break-word;">${sanitizeInput(decryptedData.messages)}</p></div>
            </div>`;
        }
        
        // Если ничего нет
        if (!decryptedData.social?.length && !decryptedData.crypto?.length && !decryptedData.credentials && !decryptedData.messages) {
            html += `<div class="legacy-section">
                <div class="legacy-item">
                    <p><strong>Завещание не содержит данных или данные недоступны</strong></p>
                    <p>Метод шифрования: ${encryptionMethod || 'не указан'}</p>
                </div>
            </div>`;
        }
        
        html += `</div>`;
        
        // Показываем результат
        resultContainer.innerHTML = html;
        resultContainer.style.display = 'block';
        
        // Скрываем форму
        const claimForm = document.querySelector('.claim-form');
        if (claimForm) {
            claimForm.style.display = 'none';
        }
        
        // Скрываем секцию мастер-пароля, если она была показана
        const masterPasswordSection = document.getElementById('master-password-section');
        if (masterPasswordSection) {
            masterPasswordSection.style.display = 'none';
        }
        
        resultContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
        
        console.log('Legacy content displayed successfully (secure version)');
        showNotification('Завещание успешно загружено');
        
        // 🔐 ОТМЕЧАЕМ ЗАВЕЩАНИЕ КАК ПРОСМОТРЕННОЕ
        markLegacyAsViewed(claimCode);
        
    } catch (err) {
        console.error('Ошибка обработки завещания:', err);
        showNotification('Ошибка: ' + err.message);
        
        const resultContainer = document.getElementById('legacy-content');
        if (resultContainer) {
            resultContainer.style.display = 'block';
            resultContainer.innerHTML = `
                <div class="legacy-content">
                    <h3>Ошибка при загрузке завещания</h3>
                    <div class="legacy-item error">
                        <p><strong>${err.message}</strong></p>
                        <p>Пожалуйста, обратитесь в поддержку или проверьте правильность введенных данных.</p>
                    </div>
                </div>
            `;
        }
    }
}

// 🔴 НОВАЯ ФУНКЦИЯ: Отметка завещания как просмотренного
function markLegacyAsViewed(claimCode) {
    if (!claimCode) return;
    
    console.log('Marking legacy as viewed:', claimCode);
    
    // Отправляем запрос на сервер, чтобы отметить завещание как просмотренное
    secureFetch(`${API_URL}/mark_legacy_viewed`, {
        method: 'POST',
        body: JSON.stringify({ claimCode })
    })
    .then(data => {
        if (data.success) {
            console.log('Завещание отмечено как просмотренное');
        }
    })
    .catch(err => {
        console.error('Ошибка при отметке завещания как просмотренного:', err);
    });
}

// ========== PREMIUM FUNCTIONS ==========
function subscribe(plan) {
    secureFetch(`${API_URL}/subscribe`, {
        method: 'POST',
        body: JSON.stringify({ plan })
    })
    .then(data => {
        if (data.success) {
            showNotification('Подписка активирована! (Симуляция)');
            secureStorage('subscription', plan);
            loadProfile();
        } else {
            showNotification('Ошибка подписки');
        }
    })
    .catch(err => {
        console.error('Ошибка подписки:', err);
        showNotification('Ошибка подписки');
    });
}

function subscribeMonthlyOrYearly() {
    const isYearly = document.getElementById('yearly-switch')?.classList.contains('active');
    const plan = isYearly ? 'premium_yearly' : 'premium_monthly';
    subscribe(plan);
}

function resetPriceToMonthly() {
    const monthlySwitch = document.getElementById('monthly-switch');
    const yearlySwitch = document.getElementById('yearly-switch');
    const slider = document.querySelector('.switcher-slider');
    
    if (monthlySwitch && yearlySwitch && slider) {
        monthlySwitch.classList.add('active');
        yearlySwitch.classList.remove('active');
        slider.style.width = `${monthlySwitch.offsetWidth}px`;
        slider.style.left = `0px`;
        updatePriceDisplay(119, '/мес');
    }
}

function initSwitcher() {
    const monthlySwitch = document.getElementById('monthly-switch');
    const yearlySwitch = document.getElementById('yearly-switch');
    const slider = document.querySelector('.switcher-slider');

    if (monthlySwitch && yearlySwitch && slider) {
        monthlySwitch.classList.add('active');
        yearlySwitch.classList.remove('active');
        slider.style.width = `${monthlySwitch.offsetWidth}px`;
        slider.style.left = `0px`;

        monthlySwitch.addEventListener('click', () => {
            if (!monthlySwitch.classList.contains('active')) {
                monthlySwitch.classList.add('active');
                yearlySwitch.classList.remove('active');
                slider.style.width = `${monthlySwitch.offsetWidth}px`;
                slider.style.left = `0px`;
                animatePriceChange(119, '/мес');
            }
        });

        yearlySwitch.addEventListener('click', () => {
            if (!yearlySwitch.classList.contains('active')) {
                yearlySwitch.classList.add('active');
                monthlySwitch.classList.remove('active');
                slider.style.width = `${yearlySwitch.offsetWidth}px`;
                slider.style.left = `${monthlySwitch.offsetWidth}px`;
                animatePriceChange(679, '/год');
            }
        });
    }
}

function animatePriceChange(targetAmount, period) {
    const priceAmount = document.getElementById('price-amount');
    const pricePeriod = document.getElementById('price-period');
    
    if (priceAmount && pricePeriod) {
        priceAmount.style.opacity = '0';
        setTimeout(() => {
            priceAmount.textContent = targetAmount;
            pricePeriod.textContent = period;
            priceAmount.style.opacity = '1';
        }, 300);
    }
}

function updatePriceDisplay(amount, period) {
    const priceAmount = document.getElementById('price-amount');
    const pricePeriod = document.getElementById('price-period');
    
    if (priceAmount && pricePeriod) {
        priceAmount.textContent = amount;
        pricePeriod.textContent = period;
    }
}

// ========== VERIFICATION PAGE FUNCTIONALITY ==========
const verification = {
    currentStep: 1,
    selectedSearchMethod: '',
    selectedVerificationMethod: '',
    foundUser: null,

    // 🔐 ИСПРАВЛЕННАЯ ФУНКЦИЯ init
    init: function() {
        // 🔐 Проверяем, что мы на странице verification
        const verificationPage = document.querySelector('.verification-page');
        if (!verificationPage) {
            console.log('Не на странице verification, пропускаем инициализацию');
            return;
        }
        
        this.showStep(1);
    },

    goToStep: function(step) {
        if (step < 1 || step > 5) return;
        
        if (step === 2 && !this.selectedSearchMethod) {
            showNotification('Выберите метод поиска');
            return;
        }
        
        if (step === 3 && !this.foundUser) {
            showNotification('Сначала найдите пользователя');
            return;
        }
        
        if (step === 4 && !this.selectedVerificationMethod) {
            showNotification('Выберите метод подтверждения');
            return;
        }
        
        this.showStep(step);
    },

    // 🔐 ИСПРАВЛЕННАЯ ФУНКЦИЯ showStep
    showStep: function(step) {
        this.currentStep = step;
        
        // 🔐 Проверяем, что элемент существует
        const panel = document.getElementById(`step${step}-panel`);
        if (!panel) {
            console.log(`Панель шага ${step} не найдена, возможно не на странице verification`);
            return; // Просто выходим если нет элемента
        }
        
        document.querySelectorAll('.step-panel').forEach(panel => {
            panel.classList.remove('active');
        });
        
        panel.classList.add('active');
        
        this.updateProgressSteps();
        this.setupStepDisplay(step);
    },

    updateProgressSteps: function() {
        const steps = document.querySelectorAll('.step');
        steps.forEach((step, index) => {
            step.classList.remove('active', 'completed');
            if (index + 1 < this.currentStep) {
                step.classList.add('completed');
            } else if (index + 1 === this.currentStep) {
                step.classList.add('active');
            }
        });
    },

    setupStepDisplay: function(step) {
        console.log('Setup step display:', step, 'Method:', this.selectedVerificationMethod);
        
        switch(step) {
            case 2:
                document.getElementById('email-search-fields').style.display = 
                    this.selectedSearchMethod === 'email' ? 'block' : 'none';
                document.getElementById('personal-search-fields').style.display = 
                    this.selectedSearchMethod === 'personal' ? 'block' : 'none';
                
                document.getElementById('search-section-title').textContent = 
                    this.selectedSearchMethod === 'email' ? 'Поиск по Email' : 'Поиск по личным данным';
                break;
                
            case 4:
                if (this.selectedVerificationMethod === 'trusted_contact_code') {
                    document.getElementById('trusted-person-fields').style.display = 'block';
                    console.log('Showing trusted person fields');
                } else {
                    document.getElementById('trusted-person-fields').style.display = 'none';
                    console.log('Hiding trusted person fields');
                }
                break;
        }
    },

    selectSearchMethod: function(method) {
        this.selectedSearchMethod = method;
        
        document.querySelectorAll('.search-method-card').forEach(card => {
            card.classList.remove('selected');
        });
        
        event.currentTarget.classList.add('selected');
        
        this.goToStep(2);
    },

    loadActivationMethods: function(userEmail) {
        showNotification('Загрузка доступных методов подтверждения...');
        
        fetch(`${API_URL}/user_activation_methods/${userEmail}`)
            .then(res => {
                if (!res.ok) {
                    throw new Error(`HTTP error! status: ${res.status}`);
                }
                return res.json();
            })
            .then(data => {
                if (data.success) {
                    if (data.userDeceased) {
                        this.renderNoMethods('Этот пользователь уже отмечен как умерший');
                        return;
                    }
                    
                    const filteredMethods = data.activationMethods.filter(method => 
                        method !== 'trusted_contact_email' && method !== 'email_check' &&
                        method !== 'death_certificate' && method !== 'notary_confirmation'
                    );
                    
                    if (filteredMethods.length === 0) {
                        this.renderNoMethods('Нет доступных методов подтверждения');
                        return;
                    }
                    
                    this.renderAvailableMethods(filteredMethods, data.trustedContacts);
                    document.getElementById('available-methods-text').textContent = 
                        `Доступные методы подтверждения для пользователя:`;
                } else {
                    showNotification(data.message || 'Ошибка загрузки методов');
                    this.renderNoMethods('Ошибка загрузки методов');
                }
            })
            .catch(err => {
                console.error('Ошибка загрузки методов:', err);
                showNotification('Ошибка загрузки методов подтверждения');
                this.renderNoMethods('Ошибка загрузки методов');
            });
    },

    renderNoMethods: function(message) {
        const container = document.getElementById('available-methods');
        if (!container) return;

        container.innerHTML = `
            <div class="no-methods">
                <i class="fas fa-exclamation-triangle"></i>
                <p>${message}</p>
            </div>
        `;
        
        document.getElementById('next-to-info').style.display = 'none';
    },

    renderAvailableMethods: function(methods, trustedContacts) {
        const container = document.getElementById('available-methods');
        if (!container) return;

        container.innerHTML = '';

        const methodConfig = {
            'trusted_contact_code': {
                title: 'Доверенное лицо',
                icon: 'fas fa-user-check',
                description: 'Используйте код доступа, предоставленный пользователем',
                badge: 'Быстро'
            },
            'trusted_contact_email': {
                title: 'Доверенные контакты',
                icon: 'fas fa-users',
                description: 'Подтверждение через доверенные контакты пользователя',
                badge: 'Надежно'
            },
            'email_check': {
                title: 'Проверка по почте',
                icon: 'fas fa-envelope',
                description: 'Система проверит активность по электронной почте',
                badge: 'Автоматически'
            }
        };

        methods.forEach(method => {
            const config = methodConfig[method];
            if (!config) return;

            const methodCard = document.createElement('div');
            methodCard.className = 'method-card';
            methodCard.setAttribute('data-method', method);
            methodCard.innerHTML = `
                <div class="method-icon">
                    <i class="${config.icon}"></i>
                </div>
                <h4>${config.title}</h4>
                <p>${config.description}</p>
                <div class="method-badge">${config.badge}</div>
            `;
            
            methodCard.addEventListener('click', () => {
                this.selectVerificationMethod(method);
            });
            
            container.appendChild(methodCard);
        });

        if (methods.length === 0) {
            container.innerHTML = `
                <div class="no-methods">
                    <i class="fas fa-exclamation-triangle"></i>
                    <p>Пользователь не настроил методы подтверждения смерти</p>
                </div>
            `;
        }
    },

    selectVerificationMethod: function(method) {
        this.selectedVerificationMethod = method;
        
        document.querySelectorAll('.method-card').forEach(card => {
            card.classList.remove('selected');
        });
        
        const selectedCard = document.querySelector(`[data-method="${method}"]`);
        if (selectedCard) {
            selectedCard.classList.add('selected');
        }
        
        this.setupStepDisplay(4);
        
        document.getElementById('next-to-info').style.display = 'inline-block';
        
        showNotification(`Выбран метод: ${this.getMethodDisplayName(method)}`);
    },

    getMethodDisplayName: function(method) {
        const names = {
            'trusted_contact_code': 'Доверенное лицо',
            'trusted_contact_email': 'Доверенные контакты', 
            'email_check': 'Проверка по почте'
        };
        return names[method] || method;
    },

    searchUserByEmail: function(email) {
        showNotification('Поиск пользователя...');
        
        fetch(`${API_URL}/search_user/email`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: email })
        })
        .then(res => {
            if (!res.ok) {
                throw new Error(`HTTP error! status: ${res.status}`);
            }
            return res.json();
        })
        .then(data => {
            if (data.success) {
                this.foundUser = data.user;
                this.loadActivationMethods(email);
                showNotification('Пользователь найден');
                this.goToStep(3);
            } else {
                showNotification(data.message || 'Пользователь не найден');
            }
        })
        .catch(err => {
            console.error('Ошибка поиска:', err);
            showNotification('Ошибка поиска пользователя');
        });
    },

    searchUserByPersonalData: function(lastName, firstName, birthDate) {
        showNotification('Поиск пользователя...');
        
        const middleName = document.getElementById('search-middle-name').value;
        
        fetch(`${API_URL}/search_user/personal`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                lastName, 
                firstName, 
                middleName, 
                birthDate 
            })
        })
        .then(res => {
            if (!res.ok) {
                throw new Error(`HTTP error! status: ${res.status}`);
            }
            return res.json();
        })
        .then(data => {
            console.log('Search response:', data);
            if (data.success) {
                if (data.users && data.users.length > 0) {
                    this.foundUser = data.users[0];
                    this.loadActivationMethods(this.foundUser.email);
                    showNotification('Пользователь найден');
                    this.goToStep(3);
                } else {
                    showNotification('Пользователь не найден');
                }
            } else {
                showNotification(data.message || 'Пользователь не найден');
            }
        })
        .catch(err => {
            console.error('Ошибка поиска:', err);
            showNotification('Ошибка поиска пользователя');
        });
    },

    searchUser: function() {
        if (!this.selectedSearchMethod) {
            showNotification('Выберите метод поиска');
            return;
        }

        if (this.selectedSearchMethod === 'email') {
            const email = document.getElementById('search-email').value.trim();
            if (!email) {
                showNotification('Введите email для поиска');
                return;
            }
            this.searchUserByEmail(email);
        } else {
            const lastName = document.getElementById('search-last-name').value.trim();
            const firstName = document.getElementById('search-first-name').value.trim();
            const birthDate = document.getElementById('search-birth-date').value;
            
            if (!lastName || !firstName || !birthDate) {
                showNotification('Заполните обязательные поля: Фамилия, Имя и Дата рождения');
                return;
            }
            this.searchUserByPersonalData(lastName, firstName, birthDate);
        }
    },

    submitVerification: function() {
        if (!this.foundUser) {
            showNotification('Пользователь не найден');
            return;
        }

        if (!this.selectedVerificationMethod) {
            showNotification('Выберите метод подтверждения');
            return;
        }

        fetch(`${API_URL}/check_verification_method`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                email: this.foundUser.email,
                method: this.selectedVerificationMethod
            })
        })
        .then(res => {
            if (!res.ok) {
                throw new Error(`HTTP error! status: ${res.status}`);
            }
            return res.json();
        })
        .then(data => {
            if (!data.allowed) {
                showNotification('Этот метод подтверждения не разрешен для данного пользователя');
                return;
            }

            if (this.selectedVerificationMethod === 'trusted_contact_code') {
                this.submitTrustedPersonVerification();
            } else {
                showNotification('Этот метод подтверждения еще не реализован');
            }
        })
        .catch(err => {
            console.error('Ошибка проверки метода:', err);
            showNotification('Ошибка проверки метода подтверждения');
        });
    },

    submitTrustedPersonVerification: function() {
        const accessCode = document.getElementById('access-code').value.trim();
        
        if (!accessCode) {
            showNotification('Введите код доступа');
            return;
        }

        if (!this.foundUser) {
            showNotification('Пользователь не найден');
            return;
        }

        showNotification('Проверка кода...');
        
        fetch(`${API_URL}/verify_death/trusted_person`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                deceasedEmail: this.foundUser.email,
                accessCode: accessCode
            })
        })
        .then(res => {
            if (!res.ok) {
                throw new Error(`HTTP error! status: ${res.status}`);
            }
            return res.json();
        })
        .then(data => {
            if (data.success) {
                document.getElementById('instant-success').style.display = 'block';
                document.getElementById('moderation-pending').style.display = 'none';
                this.goToStep(5);
                showNotification('Смерть подтверждена! Завещание отправлено контактам.');
            } else {
                showNotification(data.message || 'Неверный код доступа');
            }
        })
        .catch(err => {
            console.error('Ошибка подтверждения:', err);
            showNotification('Ошибка подтверждения смерти');
        });
    }
};

// ========== ФУНКЦИИ ДЛЯ ЛИЧНЫХ ДАННЫХ ==========
// 🔴 ИСПРАВЛЕННАЯ ФУНКЦИЯ loadPersonalData (по инструкции)
function loadPersonalData() {
    // 🔴 ДОБАВИТЬ проверку авторизации
    const userEmail = localStorage.getItem('userEmail');
    if (!userEmail) {
        showNotification('Сначала авторизуйтесь');
        return;
    }
    
    secureFetch(`${API_URL}/profile`)
    .then(data => {
        if (data.success && data.personalData) {
            const personalData = data.personalData;
            updatePersonalDataUI(personalData);
        }
    })
    .catch(err => {
        console.error('Ошибка загрузки личных данных:', err);
    });
}

function updatePersonalDataUI(personalData) {
    const privacyEmailRadio = document.getElementById('privacy-email');
    const privacyPersonalRadio = document.getElementById('privacy-personal');
    const personalDataFields = document.getElementById('personal-data-fields');
    
    if (!privacyEmailRadio || !privacyPersonalRadio) return;
    
    if (personalData.isAnonymous) {
        privacyEmailRadio.checked = true;
        if (personalDataFields) personalDataFields.style.display = 'none';
    } else {
        privacyPersonalRadio.checked = true;
        if (personalDataFields) personalDataFields.style.display = 'block';
        
        if (personalData.lastName) {
            const lastNameField = document.getElementById('last-name');
            if (lastNameField) lastNameField.value = personalData.lastName;
        }
        if (personalData.firstName) {
            const firstNameField = document.getElementById('first-name');
            if (firstNameField) firstNameField.value = personalData.firstName;
        }
        if (personalData.middleName) {
            const middleNameField = document.getElementById('middle-name');
            if (middleNameField) middleNameField.value = personalData.middleName;
        }
        if (personalData.birthDate) {
            const birthDateField = document.getElementById('birth-date');
            if (birthDateField) {
                birthDateField.value = personalData.birthDate;
            }
        }
    }
}

// 🔴 ИСПРАВЛЕННАЯ ФУНКЦИЯ savePersonalData (по инструкции)
function savePersonalData() {
    // 🔴 ДОБАВИТЬ проверку авторизации
    const userEmail = localStorage.getItem('userEmail');
    if (!userEmail) {
        showNotification('Сначала авторизуйтесь');
        return;
    }
    
    const privacyMethod = document.querySelector('input[name="privacyMethod"]:checked').value;
    let personalData = {};

    if (privacyMethod === 'personal_data') {
        const lastName = document.getElementById('last-name').value.trim();
        const firstName = document.getElementById('first-name').value.trim();
        const birthDate = document.getElementById('birth-date').value;

        if (!lastName || !firstName || !birthDate) {
            showNotification('Заполните все обязательные поля для личных данных');
            return;
        }

        personalData = {
            lastName: lastName,
            firstName: firstName,
            middleName: document.getElementById('middle-name').value.trim(),
            birthDate: birthDate
        };
    }

    secureFetch(`${API_URL}/save_personal_data`, {
        method: 'POST',
        body: JSON.stringify({
            privacyMethod: privacyMethod,
            personalData: personalData
        })
    })
    .then(data => {
        if (data.success) {
            showNotification('Личные данные сохранены');
            closeModal('personal-data-modal');
        } else {
            showNotification(data.message || 'Ошибка сохранения данных');
        }
    })
    .catch(err => {
        console.error('Ошибка сохранения личных данных:', err);
        showNotification('Ошибка сохранения личных данных');
    });
}

function initializePersonalDataSection() {
    const privacyRadios = document.querySelectorAll('input[name="privacyMethod"]');
    const savePersonalDataButton = document.getElementById('save-personal-data');
    
    if (privacyRadios.length > 0) {
        privacyRadios.forEach(radio => {
            radio.addEventListener('change', function() {
                const personalDataFields = document.getElementById('personal-data-fields');
                if (this.value === 'personal_data') {
                    personalDataFields.style.display = 'block';
                } else {
                    personalDataFields.style.display = 'none';
                }
            });
        });
        
        loadPersonalData();
    }
    
    if (savePersonalDataButton) {
        savePersonalDataButton.addEventListener('click', savePersonalData);
    }
}

// ========== ОБРАБОТЧИКИ ДЛЯ МОДАЛЬНЫХ ОКОН ==========
function initializeProfileModals() {
    const closeActivationModal = document.getElementById('close-activation-modal');
    const closePersonalDataModal = document.getElementById('close-personal-data-modal');
    
    if (closeActivationModal) {
        closeActivationModal.addEventListener('click', () => closeModal('activation-settings-modal'));
    }
    
    if (closePersonalDataModal) {
        closePersonalDataModal.addEventListener('click', () => closeModal('personal-data-modal'));
    }
    
    const personalDataButton = document.getElementById('personal-data-button');
    if (personalDataButton) {
        personalDataButton.addEventListener('click', function() {
            const modal = document.getElementById('personal-data-modal');
            if (modal) {
                modal.style.display = 'flex';
                loadPersonalData();
                
                const privacyRadios = document.querySelectorAll('input[name="privacyMethod"]');
                privacyRadios.forEach(radio => {
                    radio.addEventListener('change', function() {
                        const personalDataFields = document.getElementById('personal-data-fields');
                        if (this.value === 'personal_data') {
                            personalDataFields.style.display = 'block';
                        } else {
                            personalDataFields.style.display = 'none';
                        }
                    });
                });
            }
        });
    }

    initializeProfileButtons();
}

function initializeProfileButtons() {
    console.log('Initializing profile buttons...');
    
    const contactsButton = document.getElementById('contacts-button');
    if (contactsButton) {
        console.log('Found contacts button, adding event listener');
        contactsButton.addEventListener('click', openContactsModal);
    } else {
        console.log('Contacts button not found');
    }
    
    const masterPasswordButton = document.getElementById('master-password-button');
    if (masterPasswordButton) {
        console.log('Found master password button, adding event listener');
        masterPasswordButton.addEventListener('click', openMasterPasswordModal);
    } else {
        console.log('Master password button not found');
    }
    
    const activationSettingsButton = document.getElementById('activation-settings-button');
    if (activationSettingsButton) {
        console.log('Found activation settings button, adding event listener');
        activationSettingsButton.addEventListener('click', function() {
            const modal = document.getElementById('activation-settings-modal');
            if (modal) modal.style.display = 'flex';
        });
    }
    
    const supportButton = document.getElementById('support-button');
    if (supportButton) {
        console.log('Found support button, adding event listener');
        supportButton.addEventListener('click', function() {
            const modal = document.getElementById('support-modal');
            if (modal) modal.style.display = 'flex';
        });
    }
    
    const submitSupportButton = document.getElementById('submit-support-button');
    if (submitSupportButton) {
        console.log('Found submit support button, adding event listener');
        submitSupportButton.addEventListener('click', submitSupportRequest);
    }
    
    const sendWithPasswordButton = document.getElementById('send-with-password-button');
    if (sendWithPasswordButton) {
        console.log('Found send with password button, adding event listener');
        sendWithPasswordButton.addEventListener('click', function() {
            const masterPassword = document.getElementById('master-password-for-send').value;
            if (!masterPassword) {
                showNotification('Введите мастер-пароль');
                return;
            }
            sendLegacyWithMasterPassword(masterPassword);
            closeModal('master-password-send-modal');
        });
    }

    updateMasterPasswordButton();
}

// ========== SUPPORT FUNCTIONS ==========
function submitSupportRequest() {
    const subject = document.getElementById('support-subject').value.trim();
    const message = document.getElementById('support-message').value.trim();
    
    if (!subject || !message) {
        showNotification('Заполните все поля');
        return;
    }
    
    if (subject.length < 3) {
        showNotification('Тема должна быть не менее 3 символов');
        return;
    }
    
    if (message.length < 10) {
        showNotification('Сообщение должно быть не менее 10 символов');
        return;
    }
    
    secureFetch(`${API_URL}/support-request`, {
        method: 'POST',
        body: JSON.stringify({ subject, message })
    })
    .then(data => {
        if (data.success) {
            showNotification('Обращение отправлено');
            document.getElementById('support-subject').value = '';
            document.getElementById('support-message').value = '';
            closeModal('support-modal');
        } else {
            showNotification(data.message || 'Ошибка отправки');
        }
    })
    .catch(err => {
        console.error('Ошибка отправки обращения:', err);
        showNotification('Ошибка отправки');
    });
}

// ========== ФУНКЦИИ ДЛЯ РАБОТЫ С НАСТРОЙКАМИ АКТИВАЦИИ ==========
function initializeActivationCheckboxes() {
    const checkboxes = document.querySelectorAll('input[name="activationMethods"]');
    
    checkboxes.forEach(checkbox => {
        checkbox.removeEventListener('change', handleActivationCheckboxChange);
        checkbox.addEventListener('change', handleActivationCheckboxChange);
        
        toggleMethodSettings(checkbox.value, checkbox.checked);
    });
}

function handleActivationCheckboxChange() {
    toggleMethodSettings(this.value, this.checked);
}

function initializeActivationSettings() {
    initializeActivationCheckboxes();
}

function loadActivationSettings() {
    secureFetch(`${API_URL}/activation_settings`)
    .then(data => {
        if (data.success) {
            updateActivationSettingsUI(data.settings);
            initializeActivationCheckboxes();
        } else {
            updateActivationSettingsUI({
                activationMethods: ['email_check'],
                emailCheckSettings: { interval: '30', gracePeriod: '30' }
            });
        }
    })
    .catch(err => {
        console.error('Ошибка загрузки настроек активации:', err);
        updateActivationSettingsUI({
                activationMethods: ['email_check'],
                emailCheckSettings: { interval: '30', gracePeriod: '30' }
            });
    });
}

function updateActivationSettingsUI(settings) {
    const methodCheckboxes = document.querySelectorAll('input[name="activationMethods"]');
    methodCheckboxes.forEach(checkbox => {
        checkbox.checked = settings.activationMethods && settings.activationMethods.includes(checkbox.value);
        toggleMethodSettings(checkbox.value, checkbox.checked);
    });

    if (settings.emailCheckSettings) {
        const intervalInput = document.getElementById('email-check-interval');
        const graceInput = document.getElementById('email-check-grace');
        if (intervalInput) intervalInput.value = settings.emailCheckSettings.interval || '30';
        if (graceInput) graceInput.value = settings.emailCheckSettings.gracePeriod || '30';
    }

    // 🔴 ИСПРАВЛЕНО: Проверяем существование элемента
    const codeInput = document.getElementById('death-verification-code-input');
    if (codeInput) {
        if (settings.deathVerificationCode) {
            codeInput.value = settings.deathVerificationCode;
        } else {
            codeInput.value = '';
        }
    }
}

function toggleMethodSettings(method, isChecked) {
    console.log('Toggle method:', method, 'checked:', isChecked);
    
    if (method === 'trusted_contact_code') {
        const display = document.getElementById('trusted-code-display');
        if (display) {  // 🟢 Добавить проверку
            display.style.display = isChecked ? 'block' : 'none';
        }
    } else if (method === 'email_check') {
        const settings = document.getElementById('email-check-settings');
        if (settings) {  // 🟢 Добавить проверку
            settings.style.display = isChecked ? 'block' : 'none';
        }
    }
}

function generateAndDisplayVerificationCode() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let code = '';
    for (let i = 0; i < 8; i++) {
        code += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    
    const codeInput = document.getElementById('death-verification-code-input');
    if (codeInput) {
        codeInput.value = code;
    }
    
    return code;
}

function saveActivationSettings() {
  const selectedMethods = [];
  const methodCheckboxes = document.querySelectorAll('input[name="activationMethods"]:checked');
  methodCheckboxes.forEach(checkbox => {
    selectedMethods.push(checkbox.value);
  });

  if (selectedMethods.length === 0) {
    showNotification('Выберите хотя бы один метод активации');
    return;
  }
  
  const emailCheckSettings = {
    interval: document.getElementById('email-check-interval').value,
    gracePeriod: document.getElementById('email-check-grace').value
  };
  
  let trustedContactCode = null;
  if (selectedMethods.includes('trusted_contact_code')) {
    trustedContactCode = document.getElementById('death-verification-code-input').value;
    if (!trustedContactCode) {
      showNotification('Введите код для доверенного лица');
      return;
    }
  }

  const saveButton = document.getElementById('save-activation-settings');
  if (!disableButton(saveButton, 3000)) return;

  secureFetch(`${API_URL}/activation_settings`, {
    method: 'POST',
    body: JSON.stringify({
      activationMethods: selectedMethods,
      emailCheckSettings: emailCheckSettings,
      trustedContacts: [],
      trustedContactCode: trustedContactCode
    })
  })
  .then(data => {
    if (data.success) {
      showNotification('Настройки активации сохранены');
      closeModal('activation-settings-modal');
      
      if (selectedMethods.includes('email_check')) {
        setTimeout(() => {
          sendAliveCheck();
          showNotification('Первая проверка активности отправлена на вашу почту');
        }, 1000);
      }
      
      setTimeout(() => {
        if (typeof loadAliveCheckStatus === 'function') {
          loadAliveCheckStatus();
        }
      }, 1500);
    } else {
      showNotification(data.message || 'Ошибка сохранения настроек');
    }
    isButtonDisabled = false;
    saveButton.disabled = false;
    saveButton.textContent = 'Сохранить настройки';
  })
  .catch(err => {
    console.error('Ошибка сохранения настроек:', err);
    showNotification('Ошибка сохранения настроек');
    isButtonDisabled = false;
    saveButton.disabled = false;
    saveButton.textContent = 'Сохранить настройки';
  });
}

// ========== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ==========
function updateSecurityStatus(twoFactorEnabled, masterPasswordCreated) {
    const securityStatus = document.getElementById('security-status');
    if (securityStatus) {
        let statusText = '';
        if (twoFactorEnabled && masterPasswordCreated) {
            statusText = 'Высокий уровень безопасности';
        } else if (twoFactorEnabled || masterPasswordCreated) {
            statusText = 'Средний уровень безопасности';
        } else {
            statusText = 'Низкий уровень безопасности';
        }
        securityStatus.textContent = statusText;
    }
}

function updateLegacyStatus(legacyData, lang) {
    const legacyStatus = document.getElementById('legacy-status');
    if (legacyStatus) {
        if (legacyData.encrypted) {
            legacyStatus.textContent = translations[lang].legacy_active;
            legacyStatus.className = 'status-active';
        } else {
            legacyStatus.textContent = translations[lang].legacy_not_created;
            legacyStatus.className = 'status-inactive';
        }
    }
}

function setErrorStatus(lang) {
    const legacyStatus = document.getElementById('legacy-status');
    if (legacyStatus) {
        legacyStatus.textContent = translations[lang].status_error;
        legacyStatus.className = 'status-error';
    }
}

function initVerificationPage() {
    if (typeof verification !== 'undefined') {
        verification.init();
    }
}

function updateLegacyInfo(legacyData) {
    const lastUpdated = document.getElementById('last-updated');
    const contactsCount = document.getElementById('contacts-count');
    const encryptionMethod = document.getElementById('encryption-method');
    const statusText = document.getElementById('status-text');
    const lang = secureRetrieve('language') || 'ru';
    
    // Проверка на существование элементов перед использованием
    if (!statusText) return;
    
    if (legacyData.encrypted) {
        statusText.textContent = translations[lang].legacy_active;
        statusText.className = 'status-text active';
    } else {
        statusText.textContent = translations[lang].legacy_not_created;
        statusText.className = 'status-text inactive';
    }
    
    if (lastUpdated) {
        lastUpdated.textContent = legacyData.legacyLastUpdated ? 
            new Date(legacyData.legacyLastUpdated).toLocaleDateString('ru-RU') : '—';
    }
    
    if (encryptionMethod) {
        const methodMap = {
            'no_encryption': 'Без шифрования',
            'shared_key': 'Код доступа', 
            'master_password': 'Мастер-пароль'
        };
        encryptionMethod.textContent = methodMap[legacyData.encryptionMethod] || 'Неизвестно';
    }
    
    secureFetch(`${API_URL}/get_contacts`)
    .then(data => {
        if (data.success && contactsCount) {
            contactsCount.textContent = data.contacts ? data.contacts.length : 0;
        }
    })
    .catch(err => {
        console.error('Ошибка загрузки контактов:', err);
        if (contactsCount) {
            contactsCount.textContent = '0';
        }
    });
}

// ========== PROFILE LOADING ==========
// 🔥 ИСПРАВЛЕННАЯ ФУНКЦИЯ loadProfile (ПО ИНСТРУКЦИИ ШАГ 2) - ОБНОВЛЕННАЯ ВЕРСИЯ
async function loadProfile() {
    console.log('loadProfile: начало загрузки профиля');
    
    const userEmail = localStorage.getItem('userEmail');
    if (!userEmail) {
        console.log('loadProfile: Нет userEmail в localStorage');
        showNotification('Сначала авторизуйтесь');
        setTimeout(() => window.location.href = '/', 1000);
        return;
    }
    
    // 🔥 ПРОВЕРЯЕМ CSRF ТОКЕН ПЕРЕД ЗАПРОСОМ (добавлено по инструкции)
    let csrfToken = localStorage.getItem('csrf_token');
    if (!csrfToken) {
        console.log('CSRF токен отсутствует, пытаемся получить...');
        try {
            csrfToken = await getCsrfToken();
            if (!csrfToken) {
                console.log('Не удалось получить CSRF токен');
            }
        } catch (error) {
            console.error('Не удалось получить CSRF токен:', error);
        }
    }
    
    try {
        console.log('loadProfile: Запрашиваем профиль через secureFetch...');
        
        // 🔥 ИСПОЛЬЗУЕМ secureFetch
        const data = await secureFetch(`${API_URL}/profile`);
        
        console.log('loadProfile: Ответ сервера:', data);
        
        if (!data.success) {
            console.log('loadProfile: Ошибка в данных:', data.message);
            
            // Если токен истек, пробуем обновить
            if (data.message && (data.message.includes('истек') || data.accessTokenExpired)) {
                console.log('loadProfile: Токен истек, пробуем обновить...');
                const refreshSuccess = await refreshTokens();
                
                if (refreshSuccess) {
                    console.log('loadProfile: Токены обновлены, повторяем запрос...');
                    return loadProfile(); // Рекурсивно вызываем снова
                } else {
                    throw new Error('Не удалось обновить токен');
                }
            }
            
            throw new Error(data.message || 'Ошибка загрузки профиля');
        }

        console.log('loadProfile: ✅ Профиль загружен успешно');
        
        // Сохраняем данные
        if (data.email) {
            secureStorage('userEmail', data.email);
        }
        
        masterPasswordCreated = data.masterPasswordSet;
        secureStorage('masterPasswordCreated', data.masterPasswordSet ? 'true' : 'false');
        
        // Обновляем отображение
        updateProfileDisplay(data);
        
        // Загружаем дополнительные данные
        await loadAdditionalProfileData();
        
    } catch (error) {
        console.error('loadProfile: ❌ Ошибка загрузки:', error);
        
        // Обработка ошибок авторизации
        if (error.status === 401 || error.message.includes('Сессия истекла') || 
            error.message.includes('истек') || error.accessTokenExpired) {
            
            console.log('loadProfile: Сессия истекла, пробуем обновить токены...');
            const refreshSuccess = await refreshTokens();
            
            if (refreshSuccess) {
                console.log('loadProfile: Токены обновлены, перезагружаем страницу...');
                setTimeout(() => window.location.reload(), 500);
                return;
            }
            
            // Если не удалось обновить - выходим
            localStorage.removeItem('userEmail');
            localStorage.removeItem('csrf_token');
            showNotification('Сессия истекла. Войдите заново.', true);
            setTimeout(() => window.location.href = '/', 1000);
            
        } else {
            showNotification('Ошибка загрузки профиля', true);
        }
    }
}

// 🔐 Обновление отображения профиля
function updateProfileDisplay(data) {
    // Email
    const profileEmail = document.getElementById('profile-email');
    if (profileEmail && data.email) {
        profileEmail.innerHTML = `<strong>Email:</strong> ${data.email}`;
    }
    
    // Дата регистрации
    const registrationDate = document.getElementById('registration-date');
    if (registrationDate && data.registrationDate) {
        try {
            const regDate = new Date(data.registrationDate);
            registrationDate.textContent = regDate.toLocaleDateString('ru-RU');
        } catch (e) {
            registrationDate.textContent = data.registrationDate;
        }
    }
    
    // Последний вход
    const lastLoginElement = document.getElementById('last-login');
    if (lastLoginElement && data.lastLogin) {
        try {
            const lastLogin = new Date(data.lastLogin);
            lastLoginElement.textContent = lastLogin.toLocaleDateString('ru-RU', {
                day: '2-digit',
                month: '2-digit',
                year: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            });
        } catch (e) {
            lastLoginElement.textContent = data.lastLogin;
        }
    }
    
    // Подписка
    if (typeof updateSubscriptionDisplay === 'function') {
        updateSubscriptionDisplay(
            data.subscription || 'free',
            data.subscriptionExpiry,
            data.subscriptionExpiryDisplay
        );
    }
    
    // Мастер-пароль
    if (typeof updateMasterPasswordButton === 'function') {
        updateMasterPasswordButton();
    }
}

// 🔐 Загрузка дополнительных данных профиля
async function loadAdditionalProfileData() {
    try {
        // Контакты
        const contactsData = await secureFetch(`${API_URL}/get_contacts`);
        console.log('Контакты загружены:', contactsData.success);
        
        // Завещание
        const legacyData = await secureFetch(`${API_URL}/load`, {
            method: 'POST'
        });
        console.log('Завещание загружено:', legacyData.success);
        
        // Настройки активации
        if (typeof loadActivationSettings === 'function') {
            loadActivationSettings();
        }
        
        // Статус проверки активности
        if (typeof loadAliveCheckStatus === 'function') {
            loadAliveCheckStatus();
        }
        
    } catch (error) {
        console.log('Дополнительные данные не загружены:', error.message);
    }
}

// ========== ИНИЦИАЛИЗАЦИЯ ГЛОБАЛЬНЫХ КНОПОК ==========
function initializeGlobalButtons() {
    console.log('Initializing global buttons...');
    
    const sendLegacyButton = document.getElementById('send-legacy-button');
    if (sendLegacyButton) {
        console.log('Found send legacy button, adding event listener');
        sendLegacyButton.addEventListener('click', sendLegacy);
    }
    
    const downloadLegacyButton = document.getElementById('download-legacy-button');
    if (downloadLegacyButton) {
        console.log('Found download legacy button, adding event listener');
        downloadLegacyButton.addEventListener('click', downloadLegacy);
    }
    
    const saveLegacyButton = document.getElementById('save-legacy-button');
    if (saveLegacyButton) {
        console.log('Found save legacy button, adding event listener');
        saveLegacyButton.addEventListener('click', saveLegacy);
    }
    
    const addAccountButton = document.getElementById('add-account-button');
    if (addAccountButton) {
        console.log('Found add account button, adding event listener');
        addAccountButton.addEventListener('click', function() {
            addSocialAccount();
        });
    }
    
    const addWalletButton = document.getElementById('add-wallet-button');
    if (addWalletButton) {
        console.log('Found add wallet button, adding event listener');
        addWalletButton.addEventListener('click', function() {
            addCryptoWallet();
        });
    }
    
    const changePasswordForm = document.getElementById('changePasswordForm');
    if (changePasswordForm) {
        console.log('Found master password form, adding event listener');
        changePasswordForm.addEventListener('submit', handleMasterPasswordSubmit);
    }
    
    setupEncryptionMethods();
}

// ========== ФУНКЦИИ ПРОВЕРКИ АКТИВНОСТИ ==========

function loadAliveCheckStatus() {
  const statusContainer = document.getElementById('alive-check-status');
  if (!statusContainer) return;

  secureFetch(`${API_URL}/alive_check_status`)
  .then(data => {
    console.log('Alive check status response:', data);
    if (data.success) {
      renderAliveCheckStatus(data);
    } else {
      showNotification('Ошибка загрузки статуса проверки');
      renderAliveCheckStatus({ emailCheckEnabled: false });
    }
  })
  .catch(err => {
    console.error('Ошибка загрузки статуса проверки:', err);
    showNotification('Ошибка загрузки статуса проверки');
    renderAliveCheckStatus({ emailCheckEnabled: false });
  });
}

function renderAliveCheckStatus(data) {
  const statusContainer = document.getElementById('alive-check-status');
  const sendButton = document.getElementById('send-alive-check-button');
  const hint = document.getElementById('alive-check-hint');
  
  if (!statusContainer) return;

  console.log('Render alive check status with data:', data);
  
  if (!data || data.emailCheckEnabled === false) {
    statusContainer.innerHTML = `
      <div class="alive-check-disabled">
        <i class="fas fa-bell-slash"></i>
        <p><strong>Проверка по почте отключена</strong></p>
        <p>Для включения перейдите в <a href="#" onclick="openActivationSettings()">настройки активации</a></p>
      </div>
    `;
    if (sendButton) sendButton.style.display = 'none';
    if (hint) {
      hint.textContent = 'Проверка по почте отключена в настройках активации';
    }
    return;
  }

  const now = new Date();
  const lastSent = data.lastAliveCheckSent ? new Date(data.lastAliveCheckSent) : null;
  const lastConfirmed = data.lastAliveCheckConfirmed ? new Date(data.lastAliveCheckConfirmed) : null;
  const nextCheck = data.nextAliveCheckDate ? new Date(data.nextAliveCheckDate) : null;
  
  const intervalDays = parseInt(data.intervalDays || data.emailCheckSettings?.interval || '30');
  const graceDays = parseInt(data.gracePeriodDays || data.emailCheckSettings?.gracePeriod || '30');
  
  let statusText = 'active';
  let statusIcon = '✅';
  let statusColor = 'confirmed';
  
  if (!lastConfirmed) {
    if (lastSent) {
      const daysSinceLastSent = Math.floor((now - lastSent) / (1000 * 60 * 60 * 24));
      if (daysSinceLastSent > graceDays) {
        statusText = 'expired';
        statusIcon = '⚠️';
        statusColor = 'expired';
      } else {
        statusText = 'pending';
        statusIcon = '⏳';
        statusColor = 'pending';
      }
    } else {
      statusText = 'never_sent';
      statusIcon = '⏳';
      statusColor = 'pending';
    }
  } else {
    const daysSinceLastConfirm = Math.floor((now - lastConfirmed) / (1000 * 60 * 60 * 24));
    
    if (daysSinceLastConfirm > graceDays) {
      statusText = 'expired';
      statusIcon = '⚠️';
      statusColor = 'expired';
    } else if (daysSinceLastConfirm > intervalDays) {
      statusText = 'pending';
      statusIcon = '⏳';
      statusColor = 'pending';
    }
  }
  
  let nextCheckHtml = '';
  if (nextCheck) {
    const timeDiff = nextCheck - now;
    if (timeDiff > 0) {
      const daysLeft = Math.floor(timeDiff / (1000 * 60 * 60 * 24));
      const hoursLeft = Math.floor((timeDiff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
      nextCheckHtml = `
        <div class="status-item">
          <div class="status-label">Следующая проверка через:</div>
          <div class="status-value neutral countdown">${daysLeft}д ${hoursLeft}ч</div>
        </div>
      `;
    } else {
      nextCheckHtml = `
        <div class="status-item">
          <div class="status-label">Следующая проверка:</div>
          <div class="status-value expired">Пора отправить</div>
        </div>
      `;
    }
  } else {
    nextCheckHtml = `
      <div class="status-item">
        <div class="status-label">Следующая отправка:</div>
        <div class="status-value neutral">Отправьте первую проверку</div>
      </div>
    `;
  }
  
  statusContainer.innerHTML = `
    <div class="alive-check-details">
      <div class="status-item">
        <div class="status-label">Статус:</div>
        <div class="status-value ${statusColor}">
          <span class="status-icon ${statusColor}">${statusIcon}</span>
          ${getStatusText(statusText)}
        </div>
      </div>
      
      ${lastSent ? `
      <div class="status-item">
        <div class="status-label">Последняя отправка:</div>
        <div class="status-value neutral">${formatDate(lastSent)}</div>
      </div>
      ` : ''}
      
      ${lastConfirmed ? `
      <div class="status-item">
        <div class="status-label">Последнее подтверждение:</div>
        <div class="status-value confirmed">${formatDate(lastConfirmed)}</div>
      </div>
      ` : ''}
      
      ${nextCheckHtml}
      
      <div class="status-item">
        <div class="status-label">Интервал проверки:</div>
        <div class="status-value neutral">${intervalDays} дней</div>
      </div>
      
      <div class="status-item">
        <div class="status-label">Период ожидания:</div>
        <div class="status-value neutral">${graceDays} дней</div>
      </div>
    </div>
    
    ${statusText === 'expired' ? `
    <div class="status-note">
      <p><i class="fas fa-exclamation-triangle"></i> <strong>Требуется подтверждение!</strong></p>
      <p>Период ожидания истек. Отправьте проверочное письмо для подтверждения активности.</p>
    </div>
    ` : ''}
    
    ${statusText === 'pending' ? `
    <div class="status-note">
      <p><i class="fas fa-clock"></i> <strong>Ожидает подтверждения</strong></p>
      <p>Отправьте проверочное письмо, если не получали его или письмо потерялось.</p>
    </div>
    ` : ''}
    
    ${statusText === 'never_sent' ? `
    <div class="status-note">
      <p><i class="fas fa-info-circle"></i> <strong>Первая проверка</strong></p>
      <p>Отправьте первое проверочное письмо для активации системы проверки активности.</p>
    </div>
    ` : ''}
  `;
  
  if (sendButton) {
    sendButton.style.display = 'inline-block';
    sendButton.onclick = sendAliveCheck;
    if (statusText === 'never_sent') {
      sendButton.innerHTML = '<i class="fas fa-paper-plane"></i> Отправить первую проверку';
    } else {
      sendButton.innerHTML = '<i class="fas fa-paper-plane"></i> Отправить проверку сейчас';
    }
  }
  
  if (hint) {
    hint.textContent = `Проверочные письма отправляются автоматически раз в ${intervalDays} дней`;
  }
}

function getStatusText(status) {
  switch(status) {
    case 'active': return 'Активен';
    case 'pending': return 'Ожидает подтверждения';
    case 'expired': return 'Требует внимания';
    default: return 'Неизвестно';
  }
}

function formatDate(date) {
  return date.toLocaleDateString('ru-RU', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
}

function sendAliveCheck() {
  const sendButton = document.getElementById('send-alive-check-button');
  if (!disableButton(sendButton, 5000)) return;

  secureFetch(`${API_URL}/send_alive_check`, {
    method: 'POST'
  })
  .then(data => {
    if (data.success) {
      showNotification('✅ Письмо с проверкой активности отправлено на вашу почту');
      loadAliveCheckStatus();
    } else {
      showNotification(data.message || 'Ошибка отправки проверки');
    }
    isButtonDisabled = false;
    if (sendButton) {
      sendButton.disabled = false;
      sendButton.textContent = 'Отправить проверку сейчас';
    }
  })
  .catch(err => {
    console.error('Ошибка отправки проверки:', err);
    showNotification('Ошибка отправки проверки');
    isButtonDisabled = false;
    if (sendButton) {
      sendButton.disabled = false;
      sendButton.textContent = 'Отправить проверку сейчас';
    }
  });
}

function openActivationSettings() {
  const modal = document.getElementById('activation-settings-modal');
  if (modal) {
    modal.style.display = 'flex';
    if (typeof loadActivationSettings === 'function') {
      loadActivationSettings();
    }
  }
}

// ========== ОСНОВНАЯ ИНИЦИАЛИЗАЦИЯ ==========
// 🔐 ОСНОВНАЯ ИНИЦИАЛИЗАЦИЯ
document.addEventListener('DOMContentLoaded', async function() {
    console.log('DOMContentLoaded: начало', window.location.pathname);
    
    const savedTheme = secureRetrieve('theme') || 'dark';
    const savedLanguage = secureRetrieve('language') || 'ru';
    
    applyTheme(savedTheme);
    setLanguage(savedLanguage);
    
    setupAuthHandlers();
    setupModalHandlers();
    setupNavigationHandlers();
    
    // 🔥 ОСОБАЯ ЛОГИКА ДЛЯ СТРАНИЦЫ ПРОФИЛЯ
    if (window.location.pathname === '/profile') {
        console.log('=== СТРАНИЦА ПРОФИЛЯ ===');
        
        const userEmail = localStorage.getItem('userEmail');
        if (!userEmail) {
            console.log('Нет userEmail, редирект на главную');
            setTimeout(() => window.location.href = '/', 500);
            return;
        }
        
        console.log('userEmail найден:', userEmail);
        
        // Ждем 300мс чтобы cookies точно установились
        await new Promise(resolve => setTimeout(resolve, 300));
        
        // Проверяем авторизацию через secureFetch
        try {
            console.log('Проверка авторизации через secureFetch...');
            const authData = await secureFetch(`${API_URL}/check_auth`);
            
            console.log('Результат проверки авторизации:', authData);
            
            if (!authData.authenticated) {
                console.log('Не авторизован, пробуем обновить токены...');
                const refreshSuccess = await refreshTokens();
                
                if (!refreshSuccess) {
                    console.log('Не удалось обновить, выход');
                    localStorage.removeItem('userEmail');
                    localStorage.removeItem('csrf_token');
                    setTimeout(() => window.location.href = '/', 1000);
                    return;
                }
                
                // После обновления проверяем снова
                const newAuthData = await secureFetch(`${API_URL}/check_auth`);
                if (!newAuthData.authenticated) {
                    console.log('Все равно не авторизован, выход');
                    localStorage.clear();
                    setTimeout(() => window.location.href = '/', 1000);
                    return;
                }
            }
            
            console.log('✅ Авторизация подтверждена, загружаем профиль');
            
            // Инициализируем модалки профиля
            if (typeof initializeProfileModals === 'function') {
                initializeProfileModals();
            }
            
            // Загружаем профиль через 100мс
            setTimeout(() => {
                if (typeof loadProfile === 'function') {
                    loadProfile();
                }
            }, 100);
            
        } catch (error) {
            console.error('Ошибка проверки авторизации:', error);
            
            // Пробуем обновить токены при ошибке
            const refreshSuccess = await refreshTokens();
            if (refreshSuccess) {
                console.log('Токены обновлены, перезагружаем страницу...');
                setTimeout(() => window.location.reload(), 500);
            } else {
                setTimeout(() => window.location.href = '/', 1000);
            }
        }
        
        return;
    }
    
    // 🔐 ДЛЯ ВСЕХ СТРАНИЦ: проверяем авторизацию
    const userEmail = localStorage.getItem('userEmail');
    if (userEmail) {
        try {
            // 🔐 Пробуем получить CSRF токен если его нет
            if (!localStorage.getItem('csrf_token') && 
                (window.location.pathname === '/profile' || 
                 window.location.pathname === '/legacy' ||
                 window.location.pathname === '/premium')) {
                await getCsrfToken();
            }
            
            // 🔐 Проверяем авторизацию через secureFetch (с CSRF)
            const authData = await secureFetch(`${API_URL}/check_auth`);
            
            if (!authData.authenticated) {
                console.log('Не авторизован, пробуем обновить токены...');
                const refreshSuccess = await refreshTokens();
                
                if (!refreshSuccess) {
                    console.log('Не удалось обновить, выход');
                    localStorage.removeItem('userEmail');
                    localStorage.removeItem('csrf_token');
                    setTimeout(() => window.location.href = '/', 1000);
                    return;
                }
            }
            
            console.log('✅ Авторизация подтверждена');
            
            // 🔐 Загружаем профиль если на странице профиля
            if (window.location.pathname === '/profile') {
                if (typeof initializeProfileModals === 'function') {
                    initializeProfileModals();
                }
                
                setTimeout(() => {
                    if (typeof loadProfile === 'function') {
                        loadProfile();
                    }
                }, 100);
            }
            
        } catch (error) {
            console.error('Ошибка проверки авторизации:', error);
            
            // Пробуем обновить токены при ошибке
            const refreshSuccess = await refreshTokens();
            if (refreshSuccess) {
                console.log('Токены обновлены, перезагружаем страницу...');
                setTimeout(() => window.location.reload(), 500);
            } else {
                setTimeout(() => window.location.href = '/', 1000);
            }
        }
    }
    
    // 🔐 ИНИЦИАЛИЗАЦИЯ ДЛЯ КОНКРЕТНЫХ СТРАНИЦ
    if (window.location.pathname === '/verification') {
        initVerificationPage();
    }
    
    if (window.location.pathname === '/premium') {
        if (typeof initSwitcher === 'function') {
            initSwitcher();
        }
    }
    
    if (document.getElementById('activation-settings-modal')) {
        initializeActivationSettings();
    }

    initializeGlobalButtons();
    
    console.log('✅ Инициализация завершена');
});

// ========== ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ И ФУНКЦИИ ==========
window.API_URL = API_URL;
window.isButtonDisabled = isButtonDisabled;
window.selectedEncryptionMethod = selectedEncryptionMethod;
window.masterPasswordCreated = masterPasswordCreated;

window.disableButton = disableButton;
window.closeModal = closeModal;
window.showNotification = showNotification;
window.openTab = openTab;
window.addSocialAccount = addSocialAccount;
window.addCryptoWallet = addCryptoWallet;
window.saveLegacy = saveLegacy;
window.sendLegacy = sendLegacy;
window.sendLegacyWithMasterPassword = sendLegacyWithMasterPassword;
window.downloadLegacy = downloadLegacy;
window.loadLegacyData = loadLegacyData;
window.saveActivationSettings = saveActivationSettings;
window.generateAndDisplayVerificationCode = generateAndDisplayVerificationCode;
window.loadAliveCheckStatus = loadAliveCheckStatus;
window.sendAliveCheck = sendAliveCheck;
window.openActivationSettings = openActivationSettings;
window.markLegacyAsViewed = markLegacyAsViewed;
window.openContactsModal = openContactsModal;
window.removeContactField = removeContactField;
window.verification = verification;
window.getCsrfToken = getCsrfToken;

вот мой profile.html:
<!DOCTYPE html>
<html lang="ru">
<head>
    <link rel="icon" href="/favicon.svg" type="image/svg+xml">
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <!-- ДОБАВЛЕН МЕТА-ТЕГ CSRF -->
    <meta name="csrf-token" content="" id="csrf-token-meta">
    <title>Профиль - LegacyNet</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@700&family=Open+Sans&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/style.css">
    <style>
        /* Стили для проверки активности */
        .alive-check-section {
            margin: 20px 0;
            padding: 20px;
            background: rgba(76, 175, 80, 0.1);
            border-radius: 10px;
            border-left: 4px solid #4CAF50;
        }

        .alive-check-section h4 {
            color: #4CAF50;
            margin-top: 0;
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 16px;
        }

        .alive-check-section h4 i {
            color: #4CAF50;
        }

        .status-loading {
            text-align: center;
            padding: 20px;
            color: #666;
        }

        .alive-check-details {
            margin: 15px 0;
        }

        .status-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
            padding: 10px;
            background: rgba(76, 175, 80, 0.08);
            border-radius: 6px;
            border: 1px solid rgba(76, 175, 80, 0.1);
        }

        .status-label {
            font-weight: 500;
            color: #ccc;
            font-size: 14px;
        }

        .status-value {
            font-weight: bold;
            color: #fff;
            font-size: 14px;
        }

        .status-value.confirmed {
            color: #4CAF50;
        }

        .status-value.pending {
            color: #FF9800;
        }

        .status-value.expired {
            color: #f44336;
        }

        .status-value.neutral {
            color: #4CAF50;
        }

        .status-icon {
            width: 20px;
            height: 20px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-right: 10px;
            color: white;
            font-size: 10px;
        }

        .status-icon.confirmed {
            background: #4CAF50;
        }

        .status-icon.pending {
            background: #FF9800;
        }

        .status-icon.expired {
            background: #f44336;
        }

        .countdown {
            font-family: 'Courier New', monospace;
            font-size: 14px;
            color: #4CAF50;
        }

        .alive-check-actions {
            display: flex;
            gap: 10px;
            margin-top: 15px;
            flex-wrap: wrap;
        }

        .alive-check-actions .green-button {
            flex: 1;
            min-width: 150px;
            font-size: 14px;
        }

        .alive-check-actions .green-button i {
            margin-right: 8px;
        }

        .status-note {
            margin-top: 10px;
            padding: 10px;
            background: rgba(255, 152, 0, 0.1);
            border-radius: 6px;
            border-left: 3px solid #FF9800;
            font-size: 12px;
        }

        .status-note p {
            margin: 5px 0;
            color: #FF9800;
        }

        .status-note i {
            color: #FF9800;
            margin-right: 8px;
        }

        .alive-check-disabled {
            text-align: center;
            padding: 20px;
            color: #666;
        }

        .alive-check-disabled i {
            font-size: 24px;
            margin-bottom: 10px;
            color: #ccc;
        }

        .alive-check-disabled a {
            color: #4CAF50;
            text-decoration: none;
        }

        .alive-check-disabled a:hover {
            text-decoration: underline;
        }

        /* Стили для модальных окон */
        .activation-methods {
            margin: 20px 0;
        }

        .method-option {
            margin-bottom: 15px;
            padding: 15px;
            border: 2px solid #444;
            border-radius: 8px;
            transition: all 0.3s ease;
        }

        .method-option:hover {
            border-color: #4CAF50;
            background: rgba(76, 175, 80, 0.05);
        }

        .method-option input[type="checkbox"],
        .method-option input[type="radio"] {
            margin-right: 10px;
        }

        .method-option label {
            cursor: pointer;
            display: block;
        }

        .method-option strong {
            color: #4CAF50;
            font-size: 16px;
        }

        .method-option p {
            margin: 5px 0 0 0;
            color: #aaa;
            font-size: 14px;
        }

        .method-note {
            font-style: italic;
            color: #FF9800 !important;
            font-size: 13px;
        }

        .trusted-code-display {
            margin-top: 10px;
            padding: 10px;
            background: rgba(76, 175, 80, 0.1);
            border-radius: 5px;
            border-left: 3px solid #4CAF50;
        }

        .code-input-group {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .code-input-group label {
            font-weight: bold;
            color: #4CAF50;
            font-size: 14px;
        }

        .code-input-field {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .code-input-field input {
            flex: 1;
            background: rgba(255, 255, 255, 0.1);
            border: 1px solid #4CAF50;
            border-radius: 5px;
            padding: 8px 12px;
            color: white;
            font-size: 14px;
        }

        .code-hint {
            font-size: 12px;
            color: #888;
            margin-top: 5px;
        }

        .settings-description {
            color: #aaa;
            margin-bottom: 20px;
            font-size: 14px;
        }

        .settings-note {
            margin-top: 15px;
            font-size: 13px;
            color: #888;
            text-align: center;
        }

        .info-section {
            margin: 20px 0;
        }

        .info-card {
            display: flex;
            align-items: flex-start;
            gap: 15px;
            padding: 15px;
            background: rgba(76, 175, 80, 0.1);
            border-radius: 8px;
            margin-bottom: 15px;
            border-left: 4px solid #4CAF50;
        }

        .info-card i {
            color: #4CAF50;
            font-size: 20px;
            margin-top: 5px;
        }

        .info-card h4 {
            margin: 0 0 5px 0;
            color: #4CAF50;
            font-size: 16px;
        }

        .info-card p {
            margin: 0;
            font-size: 14px;
        }

        .method-settings {
            margin-top: 10px;
            padding: 15px;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 5px;
            border-left: 3px solid #4CAF50;
        }

        .green-button.small {
            padding: 8px 16px;
            font-size: 14px;
        }

        /* Стили для личных данных */
        .privacy-options {
            margin: 20px 0;
        }

        .privacy-option {
            margin-bottom: 15px;
            padding: 15px;
            border: 2px solid #444;
            border-radius: 8px;
            transition: all 0.3s ease;
        }

        .privacy-option:hover {
            border-color: #4CAF50;
            background: rgba(76, 175, 80, 0.05);
        }

        .privacy-option input[type="checkbox"] {
            margin-right: 10px;
        }

        .privacy-option label {
            cursor: pointer;
            display: block;
        }

        .privacy-option strong {
            color: #4CAF50;
            font-size: 16px;
        }

        .privacy-option p {
            margin: 5px 0 0 0;
            color: #aaa;
            font-size: 14px;
        }

        .personal-data-fields {
            margin-top: 15px;
            padding: 15px;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 5px;
            border-left: 3px solid #4CAF50;
        }

        .personal-data-fields .form-group {
            margin-bottom: 15px;
        }

        .personal-data-fields label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
            color: #ccc;
            font-size: 14px;
        }

        .personal-data-fields input {
            background: rgba(255, 255, 255, 0.1);
            border: 1px solid #444;
            border-radius: 5px;
            padding: 10px;
            width: 100%;
            color: white;
            box-sizing: border-box;
            font-size: 14px;
        }

        /* Упрощенное поле даты */
        .date-input {
            background: rgba(255, 255, 255, 0.1);
            border: 1px solid #444;
            border-radius: 5px;
            padding: 10px;
            width: 100%;
            color: white;
            box-sizing: border-box;
            font-size: 14px;
        }

        /* Стили для статистики профиля */
        .profile-stats {
            margin: 20px 0;
            padding: 15px;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 8px;
            border-left: 4px solid #4CAF50;
        }

        .profile-stats h4 {
            color: #4CAF50;
            margin-bottom: 15px;
            font-size: 16px;
        }

        .stat-item {
            display: flex;
            align-items: center;
            margin-bottom: 12px;
            padding: 8px 0;
        }

        .stat-item i {
            width: 20px;
            color: #4CAF50;
            margin-right: 10px;
            font-size: 16px;
        }

        .stat-label {
            flex: 1;
            font-weight: 500;
            color: #ccc;
            font-size: 14px;
        }

        .stat-value {
            font-weight: bold;
            color: #fff;
            font-size: 14px;
        }

        /* Стили для информации о завещании */
        .legacy-info {
            margin-top: 20px;
            padding: 15px;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 8px;
            border-left: 4px solid #2196F3;
        }

        .legacy-info h4 {
            color: #2196F3;
            margin-bottom: 15px;
            font-size: 16px;
        }

        .info-item {
            display: flex;
            align-items: center;
            margin-bottom: 12px;
            padding: 8px 0;
        }

        .info-item i {
            width: 20px;
            color: #2196F3;
            margin-right: 10px;
            font-size: 16px;
        }

        .info-item span:first-of-type {
            flex: 1;
            font-weight: 500;
            color: #ccc;
            font-size: 14px;
        }

        .info-item span:last-of-type {
            font-weight: bold;
            color: #fff;
            font-size: 14px;
        }

        /* === НОВЫЕ СТИЛИ ДЛЯ КОНТАКТОВ С ТЕЛЕФОНАМИ === */
        .contact-item {
            display: block;
            margin-bottom: 20px;
            padding: 15px;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 8px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            position: relative;
        }

        .contact-fields {
            display: flex;
            flex-direction: column;
            gap: 10px;
        }

        .contact-email {
            width: 100%;
            padding: 10px 12px;
            border: 1px solid #444;
            border-radius: 6px;
            background: rgba(255, 255, 255, 0.1);
            color: white;
            font-size: 14px;
            box-sizing: border-box;
        }

        .contact-phone-group {
            display: flex;
            flex-direction: column;
            gap: 5px;
        }

        .contact-phone-input {
            width: 100%;
            padding: 10px 12px;
            border: 1px solid #444;
            border-radius: 6px;
            background: rgba(255, 255, 255, 0.1);
            color: white;
            font-size: 14px;
            box-sizing: border-box;
        }

        .contact-phone-input:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }

        .phone-hint {
            font-size: 12px;
            color: #888;
            display: flex;
            align-items: center;
            gap: 5px;
        }

        .premium-badge-contact {
            background: linear-gradient(45deg, #FFD700, #FFA500);
            color: #000;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 0.7rem;
            font-weight: bold;
            vertical-align: middle;
        }

        .delete-button {
            position: absolute;
            top: 10px;
            right: 10px;
            background: #f44336;
            color: white;
            border: none;
            border-radius: 50%;
            width: 30px;
            height: 30px;
            cursor: pointer;
            font-size: 18px;
            line-height: 30px;
            text-align: center;
            transition: background 0.3s;
        }

        .delete-button:hover {
            background: #d32f2f;
        }

        /* Стиль для связи почты и телефона */
        .contact-pair {
            position: relative;
        }

        .contact-pair:after {
            content: "";
            position: absolute;
            left: 15px;
            top: 40px;
            bottom: 10px;
            width: 2px;
            background: rgba(76, 175, 80, 0.3);
            border-radius: 1px;
        }

        /* === МОБИЛЬНЫЕ СТИЛИ (добавлены из мобильной версии) === */
        @media (max-width: 768px) {
            /* Базовые мобильные стили */
            body {
                overflow-x: hidden;
                max-width: 100%;
                font-size: 14px;
            }
            
            .container {
                max-width: 100%;
                padding-left: 10px;
                padding-right: 10px;
            }
            
            /* Адаптивность для проверки активности */
            .alive-check-actions {
                flex-direction: column;
            }
            
            .alive-check-actions .green-button {
                width: 100%;
            }
            
            .status-item {
                flex-direction: column;
                align-items: flex-start;
                gap: 5px;
            }
            
            /* Мобильная адаптация профиля */
            .profile .container {
                padding: 8px;
            }
            
            .profile-grid {
                display: flex;
                flex-direction: column;
                gap: 12px;
                width: 100%;
            }
            
            .profile-card {
                width: 100%;
                padding: 12px;
                margin-bottom: 0;
                box-sizing: border-box;
            }
            
            h2 {
                font-size: 1.4rem;
                text-align: center;
                margin-bottom: 12px;
            }
            
            h3 {
                font-size: 1.1rem;
                margin-bottom: 10px;
            }
            
            .status-block {
                font-size: 12px;
                margin: 8px 0;
                display: flex;
                justify-content: space-between;
            }
            
            .master-password-section h4 {
                font-size: 13px;
                margin-bottom: 8px;
            }
            
            .master-password-section .green-button {
                width: 100%;
                padding: 10px;
                font-size: 13px;
                margin-bottom: 8px;
            }
            
            .password-hint {
                font-size: 11px;
                margin-top: 6px;
            }
            
            .profile-card .green-button {
                width: 100%;
                margin-bottom: 8px;
                padding: 10px;
                font-size: 13px;
                display: block;
            }
            
            #profile-email {
                font-size: 12px;
                word-break: break-all;
            }
            
            .status-label, .status-value {
                width: 100%;
                text-align: left;
                font-size: 12px;
            }
            
            /* Мобильные версии компонентов */
            .alive-check-section {
                margin: 15px 0;
                padding: 12px;
                border-radius: 8px;
            }

            .alive-check-section h4 {
                gap: 8px;
                font-size: 15px;
            }

            .status-loading {
                padding: 12px;
                font-size: 13px;
            }

            .alive-check-details {
                margin: 10px 0;
            }

            .status-item {
                margin-bottom: 8px;
                padding: 8px;
            }

            .status-label {
                font-size: 13px;
            }

            .status-value {
                font-size: 13px;
            }

            .status-icon {
                width: 18px;
                height: 18px;
                margin-right: 8px;
                font-size: 9px;
            }

            .countdown {
                font-size: 13px;
            }

            .alive-check-actions .green-button {
                font-size: 13px;
                padding: 10px;
            }

            .alive-check-actions .green-button i {
                margin-right: 6px;
            }

            .status-note {
                margin-top: 8px;
                padding: 8px;
                font-size: 11px;
            }

            .status-note p {
                margin: 4px 0;
            }

            .status-note i {
                margin-right: 6px;
            }

            .alive-check-disabled {
                padding: 12px;
                font-size: 13px;
            }

            .alive-check-disabled i {
                font-size: 18px;
                margin-bottom: 6px;
            }

            /* Стили для модальных окон на мобильных */
            .modal-content {
                width: 95%;
                max-height: 90vh;
                overflow-y: auto;
                padding: 12px;
                margin: 10px auto;
                box-sizing: border-box;
            }
            
            #activation-settings-modal .modal-content,
            #personal-data-modal .modal-content {
                width: 95%;
                max-width: 95%;
            }
            
            .form-group {
                margin-bottom: 10px;
            }
            
            .form-group input, .form-group select {
                padding: 8px;
                font-size: 13px;
                width: 100%;
                box-sizing: border-box;
            }
            
            .modal-content .green-button {
                width: 100%;
                margin-bottom: 8px;
                padding: 10px;
                font-size: 13px;
            }
            
            /* Убираем горизонтальный скролл */
            html, body {
                overflow-x: hidden;
                position: relative;
            }
            
            .header .container {
                padding: 0 10px;
            }
            
            .nav {
                display: flex;
                gap: 8px;
            }
            
            /* Мобильные стили для компонентов */
            .activation-methods {
                margin: 15px 0;
            }

            .method-option {
                margin-bottom: 10px;
                padding: 10px;
                border-radius: 6px;
            }

            .method-option label {
                font-size: 13px;
            }

            .method-option strong {
                font-size: 14px;
            }

            .method-option p {
                margin: 4px 0 0 0;
                font-size: 12px;
            }

            .method-note {
                font-size: 11px;
            }

            .trusted-code-display {
                margin-top: 8px;
                padding: 8px;
                border-radius: 4px;
            }

            .code-input-group label {
                font-size: 12px;
            }

            .code-input-field input {
                padding: 6px 10px;
                font-size: 12px;
            }

            .code-hint {
                font-size: 10px;
                margin-top: 4px;
            }

            .settings-description {
                margin-bottom: 12px;
                font-size: 12px;
            }

            .settings-note {
                margin-top: 12px;
                font-size: 11px;
            }

            .info-section {
                margin: 12px 0;
            }

            .info-card {
                gap: 10px;
                padding: 10px;
                border-radius: 6px;
                margin-bottom: 10px;
            }

            .info-card i {
                font-size: 16px;
                margin-top: 2px;
            }

            .info-card h4 {
                margin: 0 0 4px 0;
                font-size: 14px;
            }

            .info-card p {
                font-size: 12px;
            }

            .method-settings {
                margin-top: 8px;
                padding: 10px;
                border-radius: 4px;
            }

            .green-button.small {
                padding: 6px 12px;
                font-size: 12px;
            }

            .privacy-options {
                margin: 12px 0;
            }

            .privacy-option {
                margin-bottom: 10px;
                padding: 10px;
                border-radius: 6px;
            }

            .privacy-option label {
                font-size: 13px;
            }

            .privacy-option strong {
                font-size: 14px;
            }

            .privacy-option p {
                margin: 4px 0 0 0;
                font-size: 12px;
            }

            .personal-data-fields {
                margin-top: 10px;
                padding: 10px;
                border-radius: 4px;
            }

            .personal-data-fields .form-group {
                margin-bottom: 10px;
            }

            .personal-data-fields label {
                margin-bottom: 4px;
                font-size: 12px;
            }

            .personal-data-fields input {
                padding: 8px;
                font-size: 13px;
            }

            .date-input {
                padding: 8px;
                font-size: 13px;
            }

            .profile-stats {
                margin: 12px 0;
                padding: 10px;
                border-radius: 6px;
            }

            .profile-stats h4 {
                margin-bottom: 10px;
                font-size: 14px;
            }

            .stat-item {
                flex-direction: column;
                align-items: flex-start;
                margin-bottom: 8px;
                padding: 6px 0;
            }

            .stat-item i {
                width: 20px;
                margin-right: 8px;
                font-size: 14px;
                margin-bottom: 4px;
            }

            .stat-label {
                font-size: 12px;
                margin-bottom: 2px;
            }

            .stat-value {
                font-size: 12px;
                width: 100%;
            }

            .legacy-info {
                margin-top: 12px;
                padding: 10px;
                border-radius: 6px;
            }

            .legacy-info h4 {
                margin-bottom: 10px;
                font-size: 14px;
            }

            .info-item {
                flex-direction: column;
                align-items: flex-start;
                margin-bottom: 8px;
                padding: 6px 0;
            }

            .info-item i {
                width: 20px;
                margin-right: 8px;
                font-size: 14px;
                margin-bottom: 4px;
            }

            .info-item span:first-of-type {
                font-size: 12px;
                margin-bottom: 2px;
            }

            .info-item span:last-of-type {
                font-size: 12px;
                width: 100%;
            }
            
            .profile-grid {
                grid-template-columns: 1fr;
            }
            
            /* Мобильные стили для контактов */
            .contact-item {
                padding: 12px;
                margin-bottom: 15px;
            }
            
            .contact-email, .contact-phone-input {
                font-size: 16px; /* Убирает зум на iOS */
                padding: 12px;
            }
            
            .delete-button {
                width: 28px;
                height: 28px;
                font-size: 16px;
                line-height: 28px;
                top: 8px;
                right: 8px;
            }
            
            .phone-hint {
                font-size: 11px;
            }
            
            .contact-pair:after {
                left: 12px;
                top: 44px;
            }
        }
        
        /* Планшет */
        @media (min-width: 769px) and (max-width: 1024px) {
            .profile-grid {
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 15px;
            }
            
            .profile-card {
                padding: 15px;
            }
            
            .container {
                max-width: 95%;
            }
        }
        
        /* Десктоп */
        @media (min-width: 1025px) {
            .container {
                max-width: 1200px;
                margin: 0 auto;
            }
            
            .contact-item {
                padding: 15px;
            }
            
            .contact-email, .contact-phone-input {
                padding: 12px;
            }
        }
    </style>
</head>
<body class="dark">

    <header class="header">
        <div class="container">
            <div class="logo" onclick="window.location.href='/'">
                <span data-lang="logo">LegacyNet</span>
                <i class="fas fa-shield-alt logo-shield"></i>
            </div>
            <nav class="nav">
                <button class="green-button" id="register-button" data-lang="registration">Регистрация</button>
                <button class="green-button" id="login-button" data-lang="login">Вход</button>
                <button class="green-button" id="user-menu-button" style="display: none;" data-lang="menu">Меню</button>
                <div id="user-submenu" class="submenu">
                    <a href="/profile" data-lang="profile">Профиль</a>
                    <a href="/settings" data-lang="settings">Настройки</a>
                    <a href="/legacy" data-lang="legacy">Завещание</a>
                    <a href="/premium" data-lang="premium">Премиум</a>
                    <a href="/verification" data-lang="death_verification">Подтверждение</a>
                    <a href="/support" data-lang="support">Поддержка</a>
                    <a href="#" onclick="logout()" data-lang="logout">Выход</a>
                </div>
            </nav>
        </div>
    </header>

    <section class="profile">
        <div class="container">
            <h2 data-lang="personal_profile">Личный профиль</h2>
            <div class="profile-grid">
                <div class="profile-card">
                    <h3 data-lang="information_security">Информация и безопасность</h3>
                    <p id="profile-email" data-lang="email_loading">Email: Загрузка...</p>
                    
                    <div class="status-block">
                        <span data-lang="legacy_status">Статус завещания:</span>
                        <span id="status-text" class="status-text">Не создано</span>
                    </div>
                    
                    <!-- ИСПРАВЛЕННАЯ СТАТИСТИКА -->
                    <div class="profile-stats">
                        <h4>Статистика аккаунта</h4>
                        <div class="stat-item">
                            <i class="fas fa-calendar-plus"></i>
                            <span class="stat-label">Дата регистрации:</span>
                            <span id="registration-date" class="stat-value">Загрузка...</span>
                        </div>
                        <div class="stat-item">
                            <i class="fas fa-sign-in-alt"></i>
                            <span class="stat-label">Последний вход:</span>
                            <span id="last-login" class="stat-value">Загрузка...</span>
                        </div>
                        <div class="stat-item">
                            <i class="fas fa-shield-alt"></i>
                            <span class="stat-label">Уровень безопасности:</span>
                            <span id="security-level" class="stat-value">Высокий</span>
                        </div>
                    </div>
                    
                    <p id="current-plan">
                        <span data-lang="current_plan">Текущий тарифный план:</span> 
                        <span id="subscription-plan" class="plan-link">Загрузка...</span>
                    </p>
                    <!-- ЭТОТ ЭЛЕМЕНТ ДОЛЖЕН БЫТЬ - проверь что он есть -->
                    <p id="subscription-expiry" style="display: none;"></p>
                    
                    <!-- УБРАНА СТРОКА ПРО ДВУХФАКТОРНУЮ АУТЕНТИФКАЦИЮ -->
                    
                    <div class="master-password-section">
                        <h4>Управление мастер-паролем</h4>
                        <button class="green-button" id="master-password-button">Создать мастер-пароль</button>
                        <p class="password-hint">Пароль используется для шифрования ваших данных. Убедитесь, что он надежный.</p>
                    </div>
                    
                    <!-- Блок проверки активности -->
                    <div class="alive-check-section">
                      <h4><i class="fas fa-heartbeat"></i> Проверка активности</h4>
                      
                      <div class="alive-check-status" id="alive-check-status">
                        <div class="status-loading">
                          <i class="fas fa-spinner fa-spin"></i> Загрузка статуса...
                        </div>
                      </div>
                      
                      <button class="green-button" id="send-alive-check-button" style="display: none;">
                        <i class="fas fa-paper-plane"></i> Отправить проверку сейчас
                      </button>
                      
                      <p class="password-hint" id="alive-check-hint">
                        Система будет автоматически отправлять проверочные письма для подтверждения вашей активности
                      </p>
                    </div>
                    
                    <!-- УДАЛЕНА КНОПКА КОНТАКТОВ ОТСЮДА -->
                </div>
                
                <div class="profile-card profile-legacy">
                    <h3 data-lang="legacy_management">Управление завещания</h3>
                    <!-- УДАЛЕНЫ КНОПКИ "Перейти к завещанию" и "Скачать копию" -->
                    
                    <!-- НОВЫЕ КНОПКИ ДЛЯ ВСПЛЫВАЮЩИХ ОКОН -->
                    <button class="green-button" id="activation-settings-button">Активация завещания</button>
                    <button class="green-button" id="personal-data-button">Личные данные</button>
                    
                    <!-- ПЕРЕНЕСЕНА КНОПКА КОНТАКТОВ СЮДА -->
                    <button class="green-button" id="contacts-button" data-lang="contacts">Контакты</button>
                    
                    <!-- ЗАМЕНЕННЫЙ БЛОК legacy-info -->
                    <div class="legacy-info" style="border-left-color: #4CAF50;">
                        <h4 style="color: #4CAF50;">Информация о завещании</h4>
                        <div class="info-item">
                            <i class="fas fa-edit" style="color: #4CAF50;"></i>
                            <span>Последнее обновление:</span>
                            <span id="last-updated">—</span>
                        </div>
                        <div class="info-item">
                            <i class="fas fa-users" style="color: #4CAF50;"></i>
                            <span>Назначенные контакты:</span>
                            <span id="contacts-count">0</span>
                        </div>
                        <div class="info-item">
                            <i class="fas fa-shield-alt" style="color: #4CAF50;"></i>
                            <span>Метод шифрования:</span>
                            <span id="encryption-method">—</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <footer class="footer">
        <div class="container">
            <p data-lang="copyright">© 2025 LegacyNet. Все права защищены.</p>
            <div class="footer-links">
                <a href="#" data-lang="privacy_policy">Политика конфиденциальности</a>
                <a href="#" data-lang="terms_of_use">Условия использования</a>
                <a href="/claim" data-lang="claim_legacy">Получить завещание</a>
            </div>
        </div>
    </footer>

    <!-- Модал авторизации -->
    <div id="auth-modal" class="modal">
        <div class="modal-content">
            <span class="close" id="close-auth-modal">&times;</span>
            <h2 id="modal-title" data-lang="auth_title">Регистрация / Вход</h2>
            <p id="modal-message"></p>
            <div class="form-group">
                <label for="modal-email" data-lang="email">Email:</label>
                <input type="email" id="modal-email">
            </div>
            <div class="form-group">
                <label for="modal-password" data-lang="password">Пароль:</label>
                <input type="password" id="modal-password">
            </div>
            <div class="form-group" id="confirm-password-group">
                <label for="modal-confirm-password" data-lang="confirm_password">Подтвердите пароль:</label>
                <input type="password" id="modal-confirm-password">
            </div>
            <button class="green-button" id="modal-button" data-lang="confirm">Подтвердить</button>
            <p id="forgot-password-link" data-lang="forgot_password">Забыли пароль?</p>
        </div>
    </div>

    <!-- Модал 2FA -->
    <div id="2fa-modal" class="modal">
        <div class="modal-content">
            <span class="close" id="close-2fa-modal">&times;</span>
            <h2 data-lang="enter_code">Введите 6-значный код</h2>
            <p data-lang="code_sent">Код отправлен на вашу почту.</p>
            <div class="form-group">
                <input type="text" id="2fa-code" maxlength="6" placeholder="000000">
            </div>
            <button id="2fa-button" class="green-button" data-lang="confirm">Подтвердить</button>
        </div>
    </div>

    <!-- Модал восстановления пароля -->
    <div id="reset-modal" class="modal">
        <div class="modal-content">
            <span class="close" id="close-reset-modal">&times;</span>
            <h2 data-lang="reset_password">Восстановление пароля</h2>
            <div class="form-group">
                <label for="reset-email" data-lang="email">Email:</label>
                <input type="email" id="reset-email">
                <button class="green-button" id="send-reset-code-button" data-lang="send_code">Отправить код</button>
            </div>
            <div id="reset-code-group" style="display: none;">
                <div class="form-group">
                    <label for="reset-code" data-lang="code">Код:</label>
                    <input type="text" id="reset-code" maxlength="6">
                </div>
                <div class="form-group">
                    <label for="new-password" data-lang="new_password">Новый пароль:</label>
                    <input type="password" id="new-password">
                </div>
                <div class="form-group">
                    <label for="confirm-new-password" data-lang="confirm_new_password">Подтвердите новый пароль:</label>
                    <input type="password" id="confirm-new-password">
                </div>
                <button class="green-button" id="reset-password-button" data-lang="reset">Сменить пароль</button>
            </div>
        </div>
    </div>

    <!-- ОБНОВЛЕННЫЙ МОДАЛ КОНТАКТОВ -->
    <div id="contacts-modal" class="modal">
        <div class="modal-content">
            <span class="close" id="close-contacts-modal">&times;</span>
            <h2 data-lang="contacts">Контакты</h2>
            <div id="contacts-list"></div>
            <button class="green-button" id="add-contact-button" data-lang="add_contact">Добавить</button>
            <button class="green-button" id="save-contacts-button" data-lang="save">Сохранить</button>
        </div>
    </div>

    <!-- НОВОЕ МОДАЛЬНОЕ ОКНО ДЛЯ МАСТЕР-ПАРОЛЯ (как в script.js) -->
    <div id="changePasswordModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal('changePasswordModal')">&times;</span>
            <h2 id="master-password-title">Создание мастер-пароля</h2>
            
            <p id="master-password-warning" style="color: #FF9800; display: block;">
                Внимание: мастер-пароль нельзя восстановить. Убедитесь, что вы его запомнили.
            </p>
            
            <form id="changePasswordForm">
                <div class="form-group" id="old-password-group" style="display:none;">
                    <label for="old-master-password">Текущий мастер-пароль:</label>
                    <input type="password" id="old-master-password">
                </div>
                <div class="form-group">
                    <label for="new-master-password">Новый мастер-пароль:</label>
                    <input type="password" id="new-master-password">
                </div>
                <div class="form-group">
                    <label for="confirm-new-master-password">Подтвердите новый пароль:</label>
                    <input type="password" id="confirm-new-master-password">
                </div>
                <button type="submit" class="green-button" id="master-password-submit">Сохранить</button>
            </form>
        </div>
    </div>

    <!-- НОВОЕ МОДАЛЬНОЕ ОКНО ДЛЯ АКТИВАЦИИ ЗАВЕЩАНИЯ -->
    <div id="activation-settings-modal" class="modal">
        <div class="modal-content" style="max-width: 800px; max-height: 90vh; overflow-y: auto;">
            <span class="close" id="close-activation-modal">&times;</span>
            <h2><i class="fas fa-user-shield"></i> Настройки активации завещания</h2>
            
            <!-- ИНФОРМАЦИОННЫЕ БЛОКИ ПЕРЕНЕСЕНЫ СЮДА -->
            <div class="info-section">
                <div class="info-card">
                    <i class="fas fa-info-circle"></i>
                    <div>
                        <h4>Как это работает?</h4>
                        <p>При подтверждении смерти ваше завещание автоматически отправляется всем указанным контактам.</p>
                    </div>
                </div>
                
                <div class="info-card">
                    <i class="fas fa-users"></i>
                    <div>
                        <h4>Доверенные лица</h4>
                        <p>Добавьте людей, которым вы доверяете подтвердить вашу смерть. Они получат специальные инструкции.</p>
                    </div>
                </div>
                
                <div class="info-card">
                    <i class="fas fa-layer-group"></i>
                    <div>
                        <h4>Резервные методы</h4>
                        <p>Рекомендуем настроить несколько методов активации для надежности.</p>
                    </div>
                </div>
            </div>

            <div class="activation-methods">
                <h3>Выберите методы активации</h3>
                <p class="settings-description">Отметьте методы, которые могут быть использованы для активации вашего завещания. Можно выбрать несколько.</p>
                
                <div class="method-option checkbox-option">
                    <input type="checkbox" id="method-trusted-code" name="activationMethods" value="trusted_contact_code">
                    <label for="method-trusted-code">
                        <strong>Код доверенного лица</strong>
                        <p>Доверенное лицо вводит специальный код для мгновенной активации</p>
                        <div id="trusted-code-display" class="trusted-code-display" style="display: none;">
                            <div class="code-input-group">
                                <label for="death-verification-code-input">Ваш код подтверждения:</label>
                                <div class="code-input-field">
                                    <input type="text" id="death-verification-code-input" placeholder="Придумайте и введите код">
                                </div>
                                <p class="code-hint">Сообщите этот код доверенному лицу оффлайн.</p>
                            </div>
                        </div>
                    </label>
                </div>
                
                <div class="method-option checkbox-option">
                    <input type="checkbox" id="method-email-check" name="activationMethods" value="email_check">
                    <label for="method-email-check">
                        <strong>Проверка по почте</strong>
                        <p>Регулярная отправка проверочных писем с требованием ответа</p>
                        <div id="email-check-settings" class="method-settings" style="display: none;">
                            <div class="form-group">
                                <label for="email-check-interval">Интервал проверки:</label>
                                <select id="email-check-interval" class="styled-select">
                                    <option value="30">Раз в месяц</option>
                                    <option value="90">Раз в 3 месяца</option>
                                    <option value="180">Раз в 6 месяцев</option>
                                    <option value="365">Раз в год</option>
                                </select>
                                <p class="field-hint">Система будет отправлять проверочные письма с выбранным интервалом</p>
                            </div>
                            <div class="form-group">
                                <label for="email-check-grace">Период ожидания ответа:</label>
                                <select id="email-check-grace" class="styled-select">
                                    <option value="7">7 дней</option>
                                    <option value="14">14 дней</option>
                                    <option value="30">30 дней</option>
                                </select>
                                <p class="field-hint">Если в течение этого периода не будет ответа, завещание будет активировано</p>
                            </div>
                        </div>
                    </label>
                </div>
            </div>
            
            <button class="green-button" id="save-activation-settings" onclick="saveActivationSettingsAndRefresh()">Сохранить настройки</button>
            <p class="settings-note">Любой из выбранных методов может быть использован для активации вашего завещание. Рекомендуется выбрать несколько методов для надежности.</p>
        </div>
    </div>

    <!-- НОВОЕ МОДАЛЬНОЕ ОКНО ДЛЯ ЛИЧНЫХ ДАННЫХ -->
    <div id="personal-data-modal" class="modal">
        <div class="modal-content" style="max-width: 600px;">
            <span class="close" id="close-personal-data-modal">&times;</span>
            <h2><i class="fas fa-user-circle"></i> Личные данные</h2>
            <p class="settings-description">Настройте, как другие пользователи смогут найти вас для подтверждения смерти</p>
            
            <div class="privacy-options">
                <div class="privacy-option checkbox-option">
                    <input type="checkbox" id="privacy-email" name="privacyMethod" value="email" checked>
                    <label for="privacy-email">
                        <strong>Поиск по Email</strong>
                        <p>Другие пользователи смогут найти меня по email-адресу</p>
                        <p class="method-note">Рекомендуется для максимальной анонимности</p>
                    </label>
                </div>
                
                <div class="privacy-option checkbox-option">
                    <input type="checkbox" id="privacy-personal" name="privacyMethod" value="personal_data">
                    <label for="privacy-personal">
                        <strong>Поиск по личным данным</strong>
                        <p>Разрешить поиск по ФИО и дате рождения</p>
                        <div id="personal-data-fields" class="personal-data-fields" style="display: none;">
                            <div class="form-group">
                                <label for="last-name">Фамилия:</label>
                                <input type="text" id="last-name" placeholder="Иванов">
                            </div>
                            <div class="form-group">
                                <label for="first-name">Имя:</label>
                                <input type="text" id="first-name" placeholder="Иван">
                            </div>
                            <div class="form-group">
                                <label for="middle-name">Отчество (если есть):</label>
                                <input type="text" id="middle-name" placeholder="Иванович">
                            </div>
                            <div class="form-group">
                                <label for="birth-date">Дата рождения:</label>
                                <input type="date" id="birth-date" class="date-input">
                            </div>
                        </div>
                    </label>
                </div>
            </div>
            
            <button class="green-button" id="save-personal-data">Сохранить настройки</button>
            <p class="settings-note">Эти настройки влияют только на возможность поиска вас для подтверждения смерти</p>
        </div>
    </div>

    <!-- МОДАЛ С ИНФОРМАЦИЕЙ О ПРЕМИУМ-ФУНКЦИИ ТЕЛЕФОНОВ -->
    <div id="premium-phone-modal" class="modal">
        <div class="modal-content" style="max-width: 500px;">
            <span class="close" onclick="closeModal('premium-phone-modal')">&times;</span>
            <h2><i class="fas fa-crown" style="color: #FFD700;"></i> Premium-функция</h2>
            <div style="text-align: center; margin: 20px 0;">
                <i class="fas fa-phone-alt" style="font-size: 60px; color: #4CAF50; margin-bottom: 20px;"></i>
                <h3>Добавление номеров телефона</h3>
                <p>С Premium-подпиской вы можете указать номера телефонов наследников. Мы позвоним им, чтобы убедиться, что завещание получено, даже если оно попадет в спам.</p>
                
                <div style="background: rgba(76, 175, 80, 0.1); padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 3px solid #4CAF50;">
                    <h4>Как это работает:</h4>
                    <ul style="text-align: left; padding-left: 20px;">
                        <li>Добавьте номер телефона к каждому email</li>
                        <li>При активации завещания мы отправим SMS и позвоним</li>
                        <li>Уведомим о получении завещания</li>
                        <li>Повысим вероятность получения информации</li>
                    </ul>
                </div>
                
                <button class="green-button" onclick="closeModal('premium-phone-modal'); window.location.href='/premium'">
                    <i class="fas fa-crown"></i> Перейти к Premium
                </button>
                <button class="green-button" style="background: #757575; margin-top: 10px;" onclick="closeModal('premium-phone-modal')">
                    Понятно
                </button>
            </div>
        </div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js"></script>
    <script src="/script.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', async function() {
            console.log('🔄 Загрузка профиля...');
            
            // 1. Проверяем наличие CSRF токена
            let csrfToken = localStorage.getItem('csrf_token');
            
            // 2. Если нет - пытаемся получить
            if (!csrfToken) {
                console.log('❌ CSRF токен отсутствует, запрашиваем...');
                csrfToken = await getCsrfToken(); // Используем функцию из script.js
                
                if (!csrfToken) {
                    console.log('❌ Не удалось получить CSRF токен, требуется вход');
                    showNotification('Требуется повторный вход');
                    setTimeout(() => window.location.href = '/', 2000);
                    return;
                }
            }
            
            // 3. Проверяем авторизацию ЧЕРЕЗ secureFetch (с CSRF)
            try {
                const response = await secureFetch(`${window.API_URL || '/api'}/check_auth`, {
                    method: 'GET',
                    credentials: 'include'
                });
                
                if (!response.ok) {
                    console.log('❌ Ошибка авторизации, статус:', response.status);
                    window.location.href = '/';
                    return;
                }
                
                const data = await response.json();
                console.log('check_auth ответ:', data);
                
                if (!data.success || !data.authenticated) {
                    console.log('❌ Пользователь не авторизован');
                    window.location.href = '/';
                    return;
                }
                
                console.log('✅ Пользователь авторизован:', data.email);
                
                // 4. Загружаем профиль
                if (typeof loadProfile === 'function') {
                    await loadProfile();
                }
                
            } catch (error) {
                console.error('❌ Ошибка проверки авторизации:', error);
                window.location.href = '/';
            }

            // 🔴 ИСПРАВЛЕНО: Только проверка статуса кнопки мастер-пароля
            const masterPasswordButton = document.getElementById('master-password-button');
            if (masterPasswordButton && localStorage.getItem('masterPasswordCreated') === 'true') {
                masterPasswordButton.textContent = 'Сменить мастер-пароль';
            }

            // Обработчики для кнопок профиля
            const contactsButton = document.getElementById('contacts-button');
            const activationSettingsButton = document.getElementById('activation-settings-button');
            const personalDataButton = document.getElementById('personal-data-button');

            if (contactsButton) {
                contactsButton.addEventListener('click', () => {
                    if (typeof openContactsModal === 'function') {
                        openContactsModal();
                    }
                });
            }

            // Обработчики для новых модальных окон
            if (activationSettingsButton) {
                activationSettingsButton.addEventListener('click', function() {
                    const modal = document.getElementById('activation-settings-modal');
                    if (modal) {
                        modal.style.display = 'flex';
                        if (typeof loadActivationSettings === 'function') {
                            loadActivationSettings();
                        }
                    }
                });
            }

            if (personalDataButton) {
                personalDataButton.addEventListener('click', function() {
                    console.log('Personal data button clicked');
                    const modal = document.getElementById('personal-data-modal');
                    if (modal) {
                        modal.style.display = 'flex';
                        if (typeof loadPersonalData === 'function') {
                            loadPersonalData();
                        }
                        
                        // Инициализация обработчиков для чекбоксов
                        const emailCheckbox = document.getElementById('privacy-email');
                        const personalCheckbox = document.getElementById('privacy-personal');
                        const personalDataFields = document.getElementById('personal-data-fields');
                        
                        function togglePersonalDataFields() {
                            if (personalCheckbox && personalCheckbox.checked && personalDataFields) {
                                personalDataFields.style.display = 'block';
                            } else if (personalDataFields) {
                                personalDataFields.style.display = 'none';
                            }
                        }
                        
                        if (emailCheckbox && personalCheckbox) {
                            emailCheckbox.addEventListener('change', togglePersonalDataFields);
                            personalCheckbox.addEventListener('change', togglePersonalDataFields);
                            // Вызываем сразу, чтобы установить правильное состояние
                            togglePersonalDataFields();
                        }
                        
                        // Назначаем обработчик для кнопки сохранения
                        const saveButton = document.getElementById('save-personal-data');
                        if (saveButton) {
                            saveButton.onclick = function() {
                                console.log('Save personal data button clicked');
                                if (typeof savePersonalData === 'function') {
                                    savePersonalData();
                                } else {
                                    console.error('savePersonalData function not found');
                                    showNotification('Ошибка: функция сохранения не найдена');
                                }
                            };
                        }
                    }
                });
            }

            const closeActivationModal = document.getElementById('close-activation-modal');
            const closePersonalDataModal = document.getElementById('close-personal-data-modal');
            
            if (closeActivationModal) closeActivationModal.addEventListener('click', () => closeModal('activation-settings-modal'));
            if (closePersonalDataModal) closePersonalDataModal.addEventListener('click', () => closeModal('personal-data-modal'));

            console.log('Profile page initialization completed');
        });

        // Правильная валидация поля даты рождения в профиле
        document.addEventListener('DOMContentLoaded', function() {
            const birthDateInput = document.getElementById('birth-date');
            if (birthDateInput) {
                birthDateInput.addEventListener('input', function(e) {
                    let value = e.target.value;
                    if (value.length > 10) {
                        e.target.value = value.slice(0, 10);
                    }
                });
                
                const today = new Date().toISOString().split('T')[0];
                birthDateInput.max = today;
                birthDateInput.min = '1900-01-01';
            }
        });

        function savePersonalData() {
            const selectedMethods = [];
            const emailCheckbox = document.getElementById('privacy-email');
            const personalCheckbox = document.getElementById('privacy-personal');
            
            if (emailCheckbox && emailCheckbox.checked) {
                selectedMethods.push('email');
            }
            if (personalCheckbox && personalCheckbox.checked) {
                selectedMethods.push('personal_data');
            }
            
            if (selectedMethods.length === 0) {
                selectedMethods.push('email');
                if (emailCheckbox) emailCheckbox.checked = true;
            }

            let personalData = {};
            
            if (selectedMethods.includes('personal_data')) {
                const lastName = document.getElementById('last-name') ? document.getElementById('last-name').value.trim() : '';
                const firstName = document.getElementById('first-name') ? document.getElementById('first-name').value.trim() : '';
                const birthDate = document.getElementById('birth-date') ? document.getElementById('birth-date').value : '';

                if (!lastName || !firstName || !birthDate) {
                    showNotification('Заполните все обязательные поля для личных данных: Фамилия, Имя и Дата рождения');
                    return;
                }

                personalData = {
                    lastName: lastName,
                    firstName: firstName,
                    middleName: document.getElementById('middle-name') ? document.getElementById('middle-name').value.trim() : '',
                    birthDate: birthDate,
                    searchMethods: selectedMethods
                };
            } else {
                personalData = {
                    searchMethods: selectedMethods
                };
            }

            secureFetch(`${API_URL}/save_personal_data`, {
                method: 'POST',
                body: JSON.stringify({
                    privacyMethod: 'custom',
                    personalData: personalData
                })
            })
            .then(data => {
                if (data.success) {
                    showNotification('Настройки приватности сохранены');
                    closeModal('personal-data-modal');
                } else {
                    showNotification(data.message || 'Ошибка сохранения данных');
                }
            })
            .catch(err => {
                console.error('Ошибка сохранения личных данных:', err);
                showNotification('Ошибка сохранения личных данных');
            });
        }

        function saveActivationSettingsAndRefresh() {
            if (typeof saveActivationSettings === 'function') {
                saveActivationSettings();
                
                // Ждем сохранения настроек, затем обновляем статус проверки активности
                setTimeout(function() {
                    if (typeof loadAliveCheckStatus === 'function') {
                        loadAliveCheckStatus();
                    }
                }, 1000);
            }
        }
    </script>
</body>
</html>
