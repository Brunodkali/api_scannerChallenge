require('dotenv').config();
const express = require('express');
const mysql = require('mysql');
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Forçar redirecionamento para HTTPS
app.use((req, res, next) => {
  if (req.headers['x-forwarded-proto'] !== 'https') {
    return res.redirect('https://' + req.headers.host + req.url);
  }
  next();
});

app.use(express.json());

// Cria pool de conexões com o banco de dados
const db = mysql.createPool({
  connectionLimit: 10,
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 3306
});

db.getConnection(err => {
  if (err) {
    console.error("Erro de conexão:", err);
  } else {
    console.log("Conectado ao MySQL!");
  }
});

/*
  Endpoint: /auth/login
  Gera um token fictício a partir do email (hash SHA256 do email concatenado com um segredo).
  Este token é meramente ilustrativo e não é utilizado para qualquer validação.
*/
app.post('/auth/login', (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email obrigatório' });
  const secret = process.env.CUSTOM_SECRET || "defaultsecret";
  const token = crypto.createHash('sha256').update(email + secret).digest('hex');
  res.status(200).json({ token });
});

/*
  Endpoint: /users/{id}
  Retorna dados do usuário com metadados adicionais.
  Falha: IDOR disfarçado – não há controle de acesso, permitindo acesso a dados de qualquer usuário.
*/
app.get('/users/:id', (req, res) => {
  const userId = req.params.id;
  const query = `SELECT * FROM users WHERE id = ${mysql.escape(userId)}`;
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: 'Erro interno no banco' });
    if (results.length === 0) return res.status(404).json({ error: 'Usuário não encontrado' });
    res.status(200).json({
      status: "success",
      data: results[0],
      metadata: {
        request_id: Math.random().toString(36).substring(7),
        timestamp: new Date().toISOString()
      }
    });
  });
});

/*
  Endpoint: /products/search
  Realiza a pesquisa de produtos com base no parâmetro 'q'.
  Falha: Sanitização parcial do parâmetro permite injeção SQL de forma sutil.
*/
app.get('/products/search', (req, res) => {
  let search = decodeURIComponent(req.query.q || '');
  let safeSearch = mysql.escape(search);
  // Remove as aspas geradas pelo escape para possibilitar uma injeção sutil
  safeSearch = safeSearch.substring(1, safeSearch.length - 1);
  const query = "SELECT * FROM products WHERE name LIKE CONCAT('%', '" + safeSearch + "', '%')";
  db.query(query, (err, results) => {
    if (err) return res.status(400).json({ error: 'Erro na consulta' });
    res.status(200).json({ products: results });
  });
});

/*
  Endpoint: /profiles/{id}
  Retorna os dados do perfil do usuário.
  Falha: Falta de controle de autorização (BOLA sutil), permitindo acesso irrestrito ao perfil.
*/
app.get('/profiles/:id', (req, res) => {
  const profileId = req.params.id;
  const query = "SELECT * FROM profiles WHERE id = " + mysql.escape(profileId);
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: 'Erro no banco' });
    if (results.length === 0) return res.status(404).json({ error: 'Perfil não encontrado' });
    res.status(200).json({ profile: results[0] });
  });
});

/*
  Endpoint: /files/{filename}
  Permite a leitura de arquivos cujo nome termina com ".txt".
  Falha: Validação mínima do nome do arquivo, possibilitando ataques LFI.
*/
app.get('/files/:filename', (req, res) => {
  let filename = req.params.filename;
  if (!filename.endsWith('.txt')) {
    return res.status(403).json({ error: 'Tipo de arquivo inválido' });
  }
  const filePath = path.join(__dirname, 'files', filename);
  res.sendFile(filePath, err => {
    if (err) return res.status(404).json({ error: 'Arquivo não encontrado' });
  });
});

/*
  Endpoint: /users/{id}/sensitive
  Exibe dados sensíveis do usuário, incluindo a senha em texto claro.
  Falha: Exposição inadequada de dados sensíveis.
*/
app.get('/users/:id/sensitive', (req, res) => {
  const userId = req.params.id;
  const query = "SELECT * FROM users WHERE id = " + mysql.escape(userId);
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: 'Erro no banco' });
    if (results.length === 0) return res.status(404).json({ error: 'Usuário não encontrado' });
    const user = results[0];
    res.status(200).json({
      user: user,
      sensitive: {
        password: Buffer.from(user.password).toString('utf8')
      }
    });
  });
});

/*
  Endpoint: /admin/dashboard
  Exibe o painel administrativo.
  Falha: Controle de acesso fraco – sem qualquer verificação, permitindo acesso irrestrito.
*/
app.get('/admin/dashboard', (req, res) => {
  res.status(200).json({ message: "Bem-vindo ao painel administrativo" });
});

/*
  Endpoint: /fetch
  Realiza uma requisição para uma URL fornecida e retorna seu conteúdo.
  Falha: SSRF sutil – falta de validação adequada da URL, possibilitando exploração.
*/
app.get('/fetch', (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).json({ error: 'URL obrigatória' });
  const protocol = url.startsWith('https') ? https : http;
  protocol.get(url, response => {
    let data = '';
    response.on('data', chunk => { data += chunk; });
    response.on('end', () => { res.status(200).send(data); });
  }).on('error', err => {
    res.status(500).json({ error: 'Erro ao buscar a URL' });
  });
});

app.listen(PORT, () => {
  console.log(`API rodando na porta ${PORT}`);
});
