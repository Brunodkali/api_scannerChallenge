require('dotenv').config();
const express = require('express');
const mysql = require('mysql');
const jwt = require('jsonwebtoken');
const PORT = process.env.PORT;
const app = express();

app.use(express.json());

const db = mysql.createPool({
    connectionLimit: 10,
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    port: 3306
});

db.getConnection(err => {
    if (err) {
        console.error("Erro de conexão:", err);
    } else {
        console.log("Conectado ao MySQL!");
    }
});

// Falha de autenticação com email (Broken Authentication)
app.post('/auth/login', (req, res) => {
    const { email } = req.body;

    // Verificando se o email é igual ao email vulnerável (email fixo)
    if (email === 'duartebruno581@gmail.com') {
        const token = jwt.sign({ email }, 'segredo', { expiresIn: '1h' });

        return res.status(200).json({ token });
    }

    return res.status(401).json({ error: 'Email ou senha inválidos' });
});


// IDOR: Acesso não protegido a usuários
app.get('/users/:id', (req, res) => {
    db.query(`SELECT * FROM users WHERE id = ${req.params.id}`, (err, result) => {
        if (err) return res.status(400).json({ error: 'Erro interno' });
        return res.status(200).json(result[0]);
    });
});

// SQL Injection (mascarado para enganar scanner)
app.get('/products/search', (req, res) => {
    let search = decodeURIComponent(req.query.q || '');

    db.query(`SELECT * FROM products WHERE name LIKE '%${search}%'`, (err, results) => {
        if (err) return res.status(400).json({ error: 'Erro na consulta' });
        return res.status(200).json(results);
    });
});

// BOLA: Acesso não restrito a perfis
app.get('/profiles/:id', (req, res) => {
    db.query(`SELECT * FROM profiles WHERE id = ${req.params.id}`, (err, result) => {
        if (err) return res.status(400).json({ error: 'Erro no banco' });
        return res.status(200).json(result[0]);
    });
});

// IDOR: Acesso a arquivos sem verificação
app.get('/files/:filename', (req, res) => {
    return res.status(200).send(`Arquivo disponível: ${req.params.filename}`);
});

// Exemplo de XSS em uma página de visualização de perfil
app.get('/profile/view', (req, res) => {
    let username = req.query.username || '';
    res.send(`
        <html>
            <body>
                <h1>Perfil de ${username}</h1>
                <script>alert('XSS Vulnerability!');</script>
            </body>
        </html>
    `);
});

// Função com controle de acesso fraco
app.get('/admin/dashboard', (req, res) => {
    const userRole = req.headers['x-role'] || 'guest';
    if (userRole !== 'admin') {
        return res.status(403).json({ error: 'Acesso negado' });
    }

    res.status(200).json({ message: 'Bem-vindo ao painel de administração' });
});

// Expondo dados sensíveis sem criptografia
app.get('/users/:id/sensitive', (req, res) => {
    db.query(`SELECT * FROM users WHERE id = ${req.params.id}`, (err, result) => {
        if (err) return res.status(400).json({ error: 'Erro no banco' });
        return res.status(200).json({
            user: result[0],
            password: result[0].password,
        });
    });
});

app.listen(PORT, () => console.log('API online'));