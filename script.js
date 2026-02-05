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
