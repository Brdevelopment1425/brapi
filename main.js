// main.js

const API_BASE = '/api';
const token = localStorage.getItem('token') || null;

// Container’ı oluşturup sayfaya ekler
function createApiContainer(apiName) {
  const container = document.createElement('div');
  container.classList.add('api-container');
  container.style = 'border:1px solid #ccc; padding:12px; margin:12px 0; border-radius:6px;';

  const title = document.createElement('h3');
  title.textContent = apiName;
  container.appendChild(title);

  // Buton
  const btn = document.createElement('button');
  btn.textContent = 'API\'yi Çağır';
  btn.style = 'padding:6px 12px; cursor:pointer; margin-bottom:8px;';
  container.appendChild(btn);

  // Sonuç alanı
  const result = document.createElement('pre');
  result.style = 'background:#f4f4f4; padding:8px; border-radius:4px; max-height:200px; overflow:auto;';
  container.appendChild(result);

  btn.addEventListener('click', async () => {
    result.textContent = 'Yükleniyor...';
    try {
      // Burada apiName tam dosya adı, örn: weather.js, biz onu /api/weather.js yapacağız
      const url = `${API_BASE}/${apiName}`;

      // Basit GET isteği (parametre yok, keysiz demo)
      const headers = {};
      if (token) headers['Authorization'] = token;

      const res = await fetch(url, { headers });
      if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);

      // JSON mı kontrol et
      const contentType = res.headers.get('content-type') || '';
      let data;
      if (contentType.includes('application/json')) data = await res.json();
      else data = await res.text();

      // Sonucu göster
      result.textContent = JSON.stringify(data, null, 2);
    } catch (e) {
      result.textContent = 'Hata: ' + e.message;
    }
  });

  document.getElementById('apisContainer').appendChild(container);
}

// API listesini çek ve container oluştur
async function loadApis() {
  try {
    const res = await fetch(`${API_BASE}/list`);
    if (!res.ok) throw new Error('API listesi alınamadı');
    const data = await res.json();
    if (!data.apis || !Array.isArray(data.apis)) throw new Error('Geçersiz API listesi');

    data.apis.forEach(api => {
      createApiContainer(api.name);
    });
  } catch (e) {
    document.getElementById('apisContainer').textContent = 'API yüklenirken hata: ' + e.message;
  }
}

window.addEventListener('DOMContentLoaded', loadApis);
