// server.js
const express = require('express');
const app = express();
const path = require('path');
const crypto = require('crypto');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Basit kullanıcı verisi (demo amaçlı)
const users = {
  'demo@gmail.com': { password: 'demo123', keys: [] }
};

// Basit oturum yönetimi için cookie parser (isteğe bağlı)
const cookieParser = require('cookie-parser');
app.use(cookieParser());

// Oturum kontrolü (basit, cookie tabanlı)
const sessions = {};

function createSession(email) {
  const token = crypto.randomBytes(24).toString('hex');
  sessions[token] = email;
  return token;
}

function getUserBySession(token) {
  return sessions[token] ? sessions[token] : null;
}

// Giriş API (şifre kontrolü, kod doğrulama basitleştirilmiş)
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email ve şifre gerekli.' });
  if (!users[email]) {
    // Yeni kullanıcı oluştur
    users[email] = { password, keys: [] };
    const token = createSession(email);
    return res.json({ message: 'Hesap oluşturuldu.', token });
  }
  // Var olan kullanıcı kontrolü
  if (users[email].password === password) {
    const token = createSession(email);
    return res.json({ message: 'Giriş başarılı.', token });
  }
  res.status(401).json({ error: 'Şifre yanlış.' });
});

// API key oluşturma
app.post('/api/create-key', (req, res) => {
  const token = req.headers.authorization;
  const email = getUserBySession(token);
  if (!email) return res.status(401).json({ error: 'Yetkisiz' });
  const key = crypto.randomBytes(20).toString('hex');
  users[email].keys.push(key);
  res.json({ key });
});

// Key listesini getir
app.get('/api/mykeys', (req, res) => {
  const token = req.headers.authorization;
  const email = getUserBySession(token);
  if (!email) return res.status(401).json({ error: 'Yetkisiz' });
  res.json({ keys: users[email].keys });
});

// API listesi (örnek olarak /api dizinindeki JS dosyalarını okuma, burayı statik yapıyoruz)
const fs = require('fs');
app.get('/api/list', (req, res) => {
  const apiDir = path.join(__dirname, 'api');
  fs.readdir(apiDir, (err, files) => {
    if (err) return res.status(500).json({ error: 'API dizini okunamadı.' });
    // Sadece .js dosyaları
    const apis = files.filter(f => f.endsWith('.js')).map(f => ({ name: f, url: `/api/${f}` }));
    res.json({ apis });
  });
});

// API dosyalarını public/api olarak sun
app.use('/api', express.static(path.join(__dirname, 'api')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Sunucu ${PORT} portunda çalışıyor.`));
```
