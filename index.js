const express = require('express');
const mysql = require('mysql');
const app = express();
const port = 3000;
const fs = require('fs');

app.use(express.json());

// Conexão com banco MySQL (simulação)
const db = mysql.createConnection({
    host: '193.203.175.157',
    user: 'u522975890_teste',
    password: '*8gjl4DK',
    database: 'u522975890_teste'
});

db.connect(err => {
    if (err) throw err;
    console.log('Conectado ao MySQL');
});

// 1. Autenticação Fraca - Apenas ID como "autenticação" com um token fake
app.post('/login', (req, res) => {
    const userId = req.body.userId;
    const token = Buffer.from(userId + ':fakeToken').toString('base64');
    res.json({ message: 'Autenticado com sucesso', token });
});

// 2. Exposição Excessiva de Dados - Disfarçada com nome de campo genérico
app.get('/users/:id', (req, res) => {
    const userId = req.params.id;
    db.query(`SELECT id, name, email, secret_data AS info FROM users WHERE id = ${userId}`, (err, result) => {
        if (err) throw err;
        res.json(result);
    });
});

// 3. BOLA - Ocultando a real vulnerabilidade através de uma verificação superficial
app.get('/profile/:id', (req, res) => {
    const userId = req.params.id;
    if (!isNaN(userId)) { // Verificação inútil apenas para enganar scanners básicos
        db.query(`SELECT id, username, private_notes FROM profiles WHERE id = ${userId}`, (err, result) => {
            if (err) throw err;
            res.json(result);
        });
    } else {
        res.status(400).json({ error: 'Invalid request' });
    }
});

// 4. SQL Injection - Disfarçada com encode e tentativa de validação fraca
app.get('/search', (req, res) => {
    let query = req.query.q;
    if (query.includes("--") || query.includes("'")) { // Tentativa superficial de validação
        return res.status(400).json({ error: "Invalid search query" });
    }
    query = decodeURIComponent(query); // Mas ainda vulnerável
    db.query(`SELECT * FROM products WHERE name LIKE '%${query}%'`, (err, result) => {
        if (err) throw err;
        res.json(result);
    });
});

// 5. IDOR - Ocultado com verificação falsa de tipo de arquivo
app.get('/files/:filename', (req, res) => {
    const filename = req.params.filename;
    if (!filename.endsWith('.pdf') && !filename.endsWith('.txt')) { // Verificação inútil
        return res.status(403).json({ error: 'Access denied' });
    }
    res.sendFile(__dirname + '/uploads/' + filename);
});

app.listen(port, () => {
    console.log(`API online`);
});