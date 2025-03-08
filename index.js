require('dotenv').config();
const express = require('express');
const mysql = require('mysql');
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// HSTS Protection - Garantindo que a comunicação seja sempre via HTTPS
app.use((req, res, next) => {
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});

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

// Falha 1: Lógica de autorização dinâmica (Controle de acesso fraco)
app.post('/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email e senha são obrigatórios' });

  const secret = process.env.CUSTOM_SECRET || "defaultsecret";
  const token = crypto.createHash('sha256').update(email + secret).digest('hex');
  const isAuthorized = token.endsWith('e');  // Condição dinâmica (falha de autorização)

  if (isAuthorized) {
    res.status(200).json({ message: "Autorizado", token });
  } else {
    res.status(403).json({ message: "Não autorizado" });
  }
});

// Falha 2: Injeção SQL sutil
app.get('/products/search', (req, res) => {
  let search = decodeURIComponent(req.query.q || '');
  let safeSearch = mysql.escape(search);
  // Remover as aspas para permitir uma injeção sutil
  safeSearch = safeSearch.substring(1, safeSearch.length - 1);
  
  const query = `SELECT * FROM products WHERE name LIKE CONCAT('%', '${safeSearch}', '%')`;
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: 'Erro ao consultar' });
    res.status(200).json({ products: results });
  });
});

// Falha 3: Exposição de dados sensíveis via URL obfuscada
app.get('/user/:id', (req, res) => {
  const userId = req.params.id;
  const query = `SELECT * FROM users WHERE id = ${mysql.escape(userId)}`;
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: 'Erro ao acessar dados' });
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

// Falha 4: Manipulação de dados via parâmetros obfuscados (Base64)
app.get('/files/:filename', (req, res) => {
  let filename = req.params.filename;

  // Falha potencial: Base64 pode ser manipulado ou obfuscado no parâmetro de forma que o scanner não detecta
  let decodedFilename = Buffer.from(filename, 'base64').toString('utf8');

  if (!decodedFilename.endsWith('.txt')) {
    return res.status(403).json({ error: 'Tipo de arquivo inválido' });
  }

  const filePath = path.join(__dirname, 'files', decodedFilename);
  res.sendFile(filePath, err => {
    if (err) return res.status(404).json({ error: 'Arquivo não encontrado' });
  });
});

// Falha 5: Condição de corrida sutil (race condition) em logins simultâneos
app.post('/auth/race-condition', (req, res) => {
  const { username, password } = req.body;

  // Simulação de race condition: Se dois usuários enviarem a requisição simultaneamente, a falha pode ser explorada
  const userHash = crypto.createHash('sha256').update(username + password).digest('hex');
  setTimeout(() => {
    res.status(200).json({ message: `Token gerado com hash ${userHash}` });
  }, Math.random() * 1000); // Condição de corrida, o tempo aleatório pode permitir a manipulação

});

// Falha 6: Cross-Site Request Forgery (CSRF) com tokens inválidos
app.post('/update-profile', (req, res) => {
  const { userId, newEmail } = req.body;
  const csrfToken = req.headers['csrf-token'];

  if (!csrfToken || csrfToken !== process.env.CSRF_SECRET) {
    return res.status(403).json({ error: 'Token CSRF inválido ou ausente' });
  }

  const query = `UPDATE users SET email = ${mysql.escape(newEmail)} WHERE id = ${mysql.escape(userId)}`;
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: 'Erro ao atualizar' });
    res.status(200).json({ message: 'Perfil atualizado com sucesso' });
  });
});

// Configuração do servidor
app.listen(PORT, () => {
  console.log(`API rodando na porta ${PORT}`);
});
