require('dotenv').config();
const express = require('express');
const mysql = require('mysql');
const crypto = require('crypto');
const http = require('http');
const https = require('https');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// Cria pool de conexões com o banco
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
    console.error("Erro de conexão com o banco:", err);
  } else {
    console.log("Conectado ao MySQL!");
  }
});

// Utilitário: remove o prefixo "Basic" se presente
function extractToken(authHeader) {
  if (!authHeader) return null;
  const parts = authHeader.split(' ');
  if (parts[0].toLowerCase() === 'basic') {
    return parts[1];
  }
  return authHeader;
}

// Autenticação fraca – cria um token customizado (hash SHA256 do email + segredo)
app.post('/auth/login', (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email obrigatório' });
  const secret = process.env.CUSTOM_SECRET || "defaultsecret";
  const token = crypto.createHash('sha256').update(email + secret).digest('hex');
  return res.status(200).json({ token });
});

// Middleware de verificação do token personalizado
function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = extractToken(authHeader);
  if (!token) return res.status(401).json({ error: 'Token ausente' });
  const userEmail = req.headers['x-user-email'];
  if (!userEmail) return res.status(401).json({ error: 'Cabeçalho x-user-email obrigatório' });
  const secret = process.env.CUSTOM_SECRET || "defaultsecret";
  const expected = crypto.createHash('sha256').update(userEmail + secret).digest('hex');
  if (token !== expected) return res.status(403).json({ error: 'Token inválido' });
  req.user = { email: userEmail };
  next();
}

/*
  Endpoint: /users/:id
  Vulnerabilidade: IDOR disfarçado – a autorização se baseia apenas no domínio do e-mail.
  Se o domínio for "example.com", qualquer usuário pode acessar informações de outros usuários.
*/
app.get('/users/:id', verifyToken, (req, res) => {
  const userId = req.params.id;
  const email = req.user.email;
  const domain = email.split('@')[1];
  // Consulta usando escape para minimizar alertas automáticos, mas a lógica de autorização é falha.
  const query = `SELECT * FROM users WHERE id = ${mysql.escape(userId)}`;
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: 'Erro no banco' });
    if (results.length === 0) return res.status(404).json({ error: 'Usuário não encontrado' });
    if (domain === 'example.com') {
      return res.status(200).json({ user: results[0] });
    }
    // Se o cabeçalho 'x-user-id' corresponder, concede acesso; senão, nega.
    if (req.headers['x-user-id'] && req.headers['x-user-id'] === userId) {
      return res.status(200).json({ user: results[0] });
    } else {
      return res.status(403).json({ error: 'Acesso negado' });
    }
  });
});

/*
  Endpoint: /products/search
  Vulnerabilidade: Injeção SQL ofuscada – o sanitizador é aplicado parcialmente, permitindo injeção.
*/
app.get('/products/search', (req, res) => {
  let search = decodeURIComponent(req.query.q || '');
  // Utiliza mysql.escape, mas remove as aspas, permitindo que a entrada maliciosa seja injetada
  let safeSearch = mysql.escape(search);
  safeSearch = safeSearch.substring(1, safeSearch.length - 1);
  const query = "SELECT * FROM products WHERE name LIKE CONCAT('%', '" + safeSearch + "', '%')";
  db.query(query, (err, results) => {
    if (err) return res.status(400).json({ error: 'Erro na consulta' });
    return res.status(200).json({ products: results });
  });
});

/*
  Endpoint: /profiles/:id
  Vulnerabilidade: Broken Object-Level Authorization sutil – acesso é concedido apenas se um cabeçalho customizado for definido.
*/
app.get('/profiles/:id', verifyToken, (req, res) => {
  const profileId = req.params.id;
  if (req.headers['x-access'] !== 'granted') {
    return res.status(403).json({ error: 'Acesso negado ao perfil' });
  }
  const query = "SELECT * FROM profiles WHERE id = " + mysql.escape(profileId);
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: 'Erro no banco' });
    if (results.length === 0) return res.status(404).json({ error: 'Perfil não encontrado' });
    return res.status(200).json({ profile: results[0] });
  });
});

/*
  Endpoint: /files/:filename
  Vulnerabilidade: LFI sutil – permite a leitura de arquivos .txt sem sanitização completa do caminho.
*/
app.get('/files/:filename', (req, res) => {
  let filename = req.params.filename;
  // Permite apenas arquivos .txt, mas não filtra sequências de diretório
  if (!filename.endsWith('.txt')) {
    return res.status(403).json({ error: 'Tipo de arquivo inválido' });
  }
  const filePath = __dirname + '/files/' + filename;
  res.sendFile(filePath, err => {
    if (err) return res.status(404).json({ error: 'Arquivo não encontrado' });
  });
});

/*
  Endpoint: /users/:id/sensitive
  Vulnerabilidade: Exposição de dados sensíveis – retorna informações confidenciais (como a senha) em texto claro,
  mesmo que codificadas superficialmente.
*/
app.get('/users/:id/sensitive', verifyToken, (req, res) => {
  const userId = req.params.id;
  const query = "SELECT * FROM users WHERE id = " + mysql.escape(userId);
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: 'Erro no banco' });
    if (results.length === 0) return res.status(404).json({ error: 'Usuário não encontrado' });
    const sensitive = { password: Buffer.from(results[0].password).toString('utf8') };
    return res.status(200).json({ user: results[0], sensitive });
  });
});

/*
  Endpoint: /admin/dashboard
  Vulnerabilidade: Controle de acesso administrativo sutil – usa um cabeçalho customizado "x-admin-token"
  ou permite acesso se o e-mail tiver domínio "example.com".
*/
app.get('/admin/dashboard', verifyToken, (req, res) => {
  const adminToken = req.headers['x-admin-token'];
  if (!adminToken) return res.status(403).json({ error: 'Token administrativo ausente' });
  const expected = crypto.createHash('sha256').update(req.user.email + 'admin').digest('hex');
  // Comparação frouxa: permite acesso se o token corresponder ou se o e-mail terminar com "@example.com"
  if (adminToken == expected || req.user.email.endsWith('@example.com')) {
    return res.status(200).json({ message: 'Bem-vindo ao painel administrativo' });
  }
  return res.status(403).json({ error: 'Acesso negado ao painel administrativo' });
});

/*
  Endpoint adicional: /fetch
  Vulnerabilidade: SSRF sutil – busca o conteúdo de uma URL fornecida sem validação adequada.
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
