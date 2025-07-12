require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const app = express();

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'cokgizlisisifre';

// --- Middleware ---
app.use(cors());
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(morgan('combined'));

// Rate limiting: API'ye kötü amaçlı istekleri sınırlamak için
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 dakika
  max: 100, // 15 dakikada max 100 istek
  message: { error: 'Çok fazla istek yaptınız, lütfen biraz bekleyin.' }
});

app.use('/api/', apiLimiter);

// --- Kullanıcı veritabanı (memory) ---
// Gelişmiş projelerde gerçek DB bağlanacak
const users = new Map(); // key: email, value: { passwordHash, keys: [] }

// --- Yardımcı Fonksiyonlar ---

async function hashPassword(password) {
  const saltRounds = 12;
  return await bcrypt.hash(password, saltRounds);
}

async function comparePassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

function generateJWT(email) {
  return jwt.sign({ email }, JWT_SECRET, { expiresIn: '8h' });
}

function verifyJWT(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

function generateApiKey() {
  return uuidv4().replace(/-/g, '') + uuidv4().replace(/-/g, '');
}

// --- Routes ---

// Yeni kullanıcı kayıt & login (şifreli)
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email ve şifre gerekli.' });

  const user = users.get(email);
  if (!user) {
    // Yeni kullanıcı oluştur
    const passwordHash = await hashPassword(password);
    users.set(email, { passwordHash, keys: [] });
    const token = generateJWT(email);
    return res.json({ message: 'Hesap oluşturuldu.', token });
  }

  // Var olan kullanıcı giriş
  const match = await comparePassword(password, user.passwordHash);
  if (!match) return res.status(401).json({ error: 'Şifre yanlış.' });

  const token = generateJWT(email);
  res.json({ message: 'Giriş başarılı.', token });
});

// Middleware: JWT doğrulama
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Yetkisiz, token gerekli.' });
  const token = authHeader.split(' ')[1] || authHeader;
  const decoded = verifyJWT(token);
  if (!decoded) return res.status(401).json({ error: 'Geçersiz token.' });
  req.user = decoded;
  next();
}

// API Key oluşturma
app.post('/api/create-key', authMiddleware, (req, res) => {
  const email = req.user.email;
  const user = users.get(email);
  if (!user) return res.status(401).json({ error: 'Kullanıcı bulunamadı.' });

  const newKey = generateApiKey();
  user.keys.push(newKey);
  res.json({ key: newKey });
});

// Kullanıcının API key listesini döner
app.get('/api/mykeys', authMiddleware, (req, res) => {
  const email = req.user.email;
  const user = users.get(email);
  if (!user) return res.status(401).json({ error: 'Kullanıcı bulunamadı.' });

  res.json({ keys: user.keys });
});

// API dosya listesi
app.get('/api/list', (req, res) => {
  const apiDir = path.join(__dirname, 'api');
  fs.readdir(apiDir, (err, files) => {
    if (err) return res.status(500).json({ error: 'API dizini okunamadı.' });
    const apis = files.filter(f => f.endsWith('.js')).map(f => ({ name: f, url: `/api/${f}` }));
    res.json({ apis });
  });
});

// Statik dosyalar
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api', express.static(path.join(__dirname, 'api')));

app.listen(PORT, () => {
  console.log(`Sunucu port ${PORT} üzerinde çalışıyor...`);
});
