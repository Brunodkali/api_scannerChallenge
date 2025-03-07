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

// Login (Autenticação Fraca)
app.post('/auth/login', (req, res) => {
    const { email } = req.body;
    const token = Buffer.from(email).toString('base64'); // Token falso
    
    return res.status(200).json({ token });
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

app.listen(PORT, () => console.log('API online'));