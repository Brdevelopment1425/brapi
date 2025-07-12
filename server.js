require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const morgan = require('morgan');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretjwtkey';
const JWT_EXPIRES = '8h';

// Middleware
app.use(cors());
app.use(helmet());
app.use(morgan('combined'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Rate limiter
const limiter = rateLimit({
  windowMs: 15*60*1000,
  max: 100,
  message: { error: 'Çok fazla istek yaptınız, lütfen bekleyin.' }
});
app.use('/api/', limiter);

// Memory kullanıcı DB
const users = new Map(); // email => { passwordHash, keys: [] }

// Helper
function generateToken(email) {
  return jwt.sign({ email }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
}
function verifyToken(token) {
  try { return jwt.verify(token, JWT_SECRET); }
  catch { return null; }
}
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;
  if (!token) return res.status(401).json({ error: 'Token gerekli.' });
  const payload = verifyToken(token);
  if (!payload) return res.status(401).json({ error: 'Geçersiz token.' });
  req.user = payload;
  next();
}

// API login/register
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email ve şifre gerekli' });
  
  const user = users.get(email);
  if (!user) {
    const hash = await bcrypt.hash(password, 12);
    users.set(email, { passwordHash: hash, keys: [] });
    const token = generateToken(email);
    return res.json({ message: 'Hesap oluşturuldu', token });
  }
  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.status(401).json({ error: 'Şifre yanlış' });
  const token = generateToken(email);
  res.json({ message: 'Giriş başarılı', token });
});

// API key oluşturma
app.post('/api/create-key', authMiddleware, (req, res) => {
  const email = req.user.email;
  const user = users.get(email);
  if (!user) return res.status(401).json({ error: 'Kullanıcı yok' });

  const newKey = uuidv4().replace(/-/g, '') + uuidv4().replace(/-/g, '');
  user.keys.push(newKey);
  res.json({ key: newKey });
});

// API key listeleme
app.get('/api/mykeys', authMiddleware, (req, res) => {
  const email = req.user.email;
  const user = users.get(email);
  if (!user) return res.status(401).json({ error: 'Kullanıcı yok' });
  res.json({ keys: user.keys });
});

// API listesi
app.get('/api/list', (req, res) => {
  const apiDir = path.join(__dirname, 'api');
  fs.readdir(apiDir, (err, files) => {
    if (err) return res.status(500).json({ error: 'API okunamadı' });
    const apis = files.filter(f => f.endsWith('.js')).map(f => ({ name: f, url: `/api/${f}` }));
    res.json({ apis });
  });
});

// API dosyaları statik (./api klasörü)
app.use('/api', express.static(path.join(__dirname, 'api')));

// Statik dosyalar (kökte css, js, resimler vs)
app.use(express.static(path.join(__dirname)));

// HTML sayfa yönlendirmeleri
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/apikeys', (req, res) => res.sendFile(path.join(__dirname, 'apikeys.html')));
app.get('/mykeys', (req, res) => res.sendFile(path.join(__dirname, 'mykeys.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));

// 404 handler
app.use((req, res) => res.status(404).send('Sayfa bulunamadı'));

// Hata middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: 'Sunucu hatası' });
});

app.listen(PORT, () => {
  console.log(`Sunucu ${PORT} portunda çalışıyor`);
});
