// api/math.js
const express = require('express');
const router = express.Router();

router.get('/math', (req, res) => {
  const a = Number(req.query.a);
  const b = Number(req.query.b);
  if (isNaN(a) || isNaN(b)) return res.status(400).json({ error: 'a ve b sayısal olmalı' });

  res.json({
    a, b,
    toplam: a + b,
    fark: a - b,
    carpim: a * b,
    bolum: b !== 0 ? a / b : 'Tanımsız (b=0)'
  });
});

module.exports = router;
