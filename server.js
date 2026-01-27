const express = require('express');
const cookieSession = require('cookie-session');
const axios = require('axios');
const bodyParser = require('body-parser');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// CORS 設定 - 允許指定的前端域名跨域請求
// 設定環境變數 ALLOWED_ORIGINS 來指定允許的來源 (逗號分隔)
// 例如: ALLOWED_ORIGINS=https://example.com,https://app.example.com
// 預設允許 localhost 和 127.0.0.1
const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || [
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    'http://localhost:5500',  // VS Code Live Server
    'http://127.0.0.1:5500'
];

app.use(cors({
    origin: function (origin, callback) {
        // 允許無 origin 的請求 (如 curl、Postman 或同源請求)
        if (!origin) return callback(null, true);

        // 如果設定了 '*'，允許所有來源 (開發用，不建議正式環境使用)
        if (allowedOrigins.includes('*')) {
            return callback(null, true);
        }

        if (allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            console.warn(`CORS: Blocked request from origin: ${origin}`);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true // 允許攜帶 cookie (必須，因為我們使用 session)
}));

// Middleware
app.use(bodyParser.json());
app.use(cookieSession({
    name: 'session',
    keys: process.env.SESSION_KEYS?.split(',') || ['key1', 'key2'], // In production, use real secret keys via env var
    // Cookie Options
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    httpOnly: true, // Secure: Client JS cannot access
    secure: process.env.NODE_ENV === 'production', // Auto-enable secure in production
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax' // 'none' required for cross-site cookies
}));

// Serve static files from current directory
app.use(express.static(path.join(__dirname, '.')));

// --- API Endpoints ---

// 1. Auth Endpoint: Save keys to encrypted session
app.post('/api/auth/login', (req, res) => {
    const { host, apiKey, geminiApiKey, firebaseConfig, corsProxy } = req.body;

    if (!host || !apiKey) {
        return res.status(400).json({ error: 'Redmine Host and API Key are required' });
    }

    req.session.redmineHost = host.replace(/\/$/, '');
    req.session.redmineApiKey = apiKey;
    req.session.geminiApiKey = geminiApiKey;
    req.session.firebaseConfig = firebaseConfig;
    req.session.corsProxy = corsProxy; // Optional, might be deprecated if backend handles everything

    res.json({ success: true, message: 'Settings saved to secure session' });
});

// 2. Auth Status: Check if logged in
app.get('/api/auth/status', (req, res) => {
    if (req.session.redmineHost && req.session.redmineApiKey) {
        // Return config that is safe for frontend (e.g., Firebase config might be needed)
        // BUT Redmine API Key and Gemini Key stay in backend
        res.json({
            loggedIn: true,
            host: req.session.redmineHost,
            firebaseConfig: req.session.firebaseConfig || null
        });
    } else {
        res.json({ loggedIn: false });
    }
});

// 3. Logout
app.post('/api/auth/logout', (req, res) => {
    req.session = null;
    res.json({ success: true });
});

// 4. Redmine Proxy
app.all('/api/proxy', async (req, res) => {
    if (!req.session.redmineHost || !req.session.redmineApiKey) {
        return res.status(401).json({ error: 'Unauthorized. Please configure settings first.' });
    }

    const targetPath = req.query.path || '';
    if (!targetPath) {
        return res.status(400).json({ error: 'Missing path query parameter' });
    }

    // Construct URL
    const baseUrl = req.session.redmineHost;
    // Ensure path starts with / if not present
    const cleanPath = targetPath.startsWith('/') ? targetPath : `/${targetPath}`;

    // Merge query params from the client request (excluding 'path')
    const queryParams = new URLSearchParams(req.query);
    queryParams.delete('path');

    const url = `${baseUrl}${cleanPath}${cleanPath.includes('?') ? '&' : '?'}${queryParams.toString()}`;

    try {
        const response = await axios({
            method: req.method,
            url: url,
            headers: {
                'X-Redmine-API-Key': req.session.redmineApiKey,
                'Content-Type': 'application/json'
            },
            data: req.method !== 'GET' ? req.body : undefined
        });
        res.json(response.data);
    } catch (error) {
        console.error('Proxy Error:', error.message);
        if (error.response) {
            res.status(error.response.status).json({ error: error.response.data || 'Proxy Error' });
        } else {
            res.status(500).json({ error: 'Internal Server Error' });
        }
    }
});

// 5. Gemini AI Proxy
app.post('/api/ai/generate', async (req, res) => {
    if (!req.session.geminiApiKey) {
        return res.status(401).json({ error: 'Gemini API Key not configured' });
    }

    const model = req.body.model || 'gemini-1.5-flash';
    const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${req.session.geminiApiKey}`;

    try {
        const response = await axios.post(apiUrl, req.body, {
            headers: { 'Content-Type': 'application/json' }
        });
        res.json(response.data);
    } catch (error) {
        console.error('Gemini API Error:', error.message);
        if (error.response) {
            res.status(error.response.status).json(error.response.data);
        } else {
            res.status(500).json({ error: 'AI Service Error' });
        }
    }
});

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
    console.log(`Please access http://localhost:${PORT}/redmine_diary_report.html`);
});
