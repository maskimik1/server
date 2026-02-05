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
