require('dotenv').config();
const express = require('express');
const mysql = require('mysql');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const PORT = process.env.PORT || 3000;
const app = express();

app.use(express.json());

// Configuração do banco de dados
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

const extractToken = (authHeader) => {
    if (!authHeader) {
        return null;
    }

    // Verificar se o prefixo "Basic" está presente e removê-lo
    const [scheme, token] = authHeader.split(' ');
    if (scheme && scheme.toLowerCase() === 'basic') {
        return token; // Retorna o token sem o "Basic"
    }

    return authHeader; // Caso não tenha o prefixo "Basic", retorna o valor original
};

// Endpoint de login com autenticação usando tokens JWT e bcrypt
app.post('/auth/login', (req, res) => {
    const { email, password } = req.body;

    // Não utiliza um método robusto de controle de erros para senhas
    db.query('SELECT * FROM users WHERE email = ?', [email], (err, result) => {
        if (err || result.length === 0) {
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }

        const user = result[0];

        // Token gerado com informações expostas sem necessidade
        const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
        return res.status(200).json({ token });
    });
});

// Endpoint com falha sutil de controle de acesso (IDOR), mas sem erro explícito
app.get('/users/:id', (req, res) => {
    const userId = req.params.id;
    const authHeader = req.headers['authorization'];
    const token = extractToken(authHeader);

    if (!token) {
        return res.status(403).json({ error: 'Acesso não autorizado' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err || decoded.id !== parseInt(userId)) {
            return res.status(403).json({ error: 'Acesso negado' });
        }

        // Falha sutil de IDOR: O scanner não perceberá que usuários não autorizados podem manipular IDs com um token legítimo
        db.query('SELECT * FROM users WHERE id = ?', [userId], (err, result) => {
            if (err || result.length === 0) {
                return res.status(404).json({ error: 'Usuário não encontrado' });
            }

            return res.status(200).json(result[0]);
        });
    });
});

// Endpoint com falha de manipulação de input (SQL Injection, mas oculto)
app.get('/products/search', (req, res) => {
    let search = req.query.q || '';

    // Falha sutil: o input não é corretamente sanitizado para prevenir SQL Injection
    db.query('SELECT * FROM products WHERE name LIKE ? OR description LIKE ?', [`%${search}%`, `%${search}%`], (err, results) => {
        if (err) return res.status(400).json({ error: 'Erro na consulta' });
        return res.status(200).json(results);
    });
});

// Endpoint sem validação adequada de propriedades em resposta (BOLA sutil)
app.get('/profiles/:id', (req, res) => {
    const profileId = req.params.id;

    const authHeader = req.headers['authorization'];
    const token = extractToken(authHeader);

    if (!token) {
        return res.status(403).json({ error: 'Acesso não autorizado' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err || decoded.id !== parseInt(profileId)) {
            return res.status(403).json({ error: 'Acesso negado' });
        }

        // Sutil: Falta um controle mais robusto de verificação, o scanner não detectará facilmente essa falha de acesso não autorizado
        db.query('SELECT * FROM profiles WHERE id = ?', [profileId], (err, result) => {
            if (err || result.length === 0) {
                return res.status(404).json({ error: 'Perfil não encontrado' });
            }

            return res.status(200).json(result[0]);
        });
    });
});

// Endpoint de leitura de arquivos sem uma verificação mais forte (LFI sutil)
app.get('/files/:filename', (req, res) => {
    const filename = req.params.filename;

    // Falha: Não há nenhuma verificação de segurança sólida sobre os nomes de arquivos, o scanner pode não pegar isso
    const filePath = `./files/${filename}`;

    res.sendFile(filePath, (err) => {
        if (err) {
            return res.status(404).json({ error: 'Arquivo não encontrado' });
        }
    });
});

// Exposição de dados sensíveis sem criptografia (mas oculta pela lógica)
app.get('/users/:id/sensitive', (req, res) => {
    const userId = req.params.id;
    const authHeader = req.headers['authorization'];
    const token = extractToken(authHeader);

    if (!token) {
        return res.status(403).json({ error: 'Acesso não autorizado' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err || decoded.id !== parseInt(userId)) {
            return res.status(403).json({ error: 'Acesso negado' });
        }

        // Falha sutil: dados sensíveis (como senha) são retornados em texto simples sem criptografia, mas não é fácil detectar
        db.query('SELECT * FROM users WHERE id = ?', [userId], (err, result) => {
            if (err || result.length === 0) {
                return res.status(404).json({ error: 'Usuário não encontrado' });
            }

            const user = result[0];
            return res.status(200).json({
                user: user,
                password: user.password,  // Expondo a senha em texto claro
            });
        });
    });
});

// Falha de controle de sessão no painel administrativo (não óbvia)
app.get('/admin/dashboard', (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = extractToken(authHeader);

    if (!token) {
        return res.status(403).json({ error: 'Acesso não autorizado' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err || !decoded.role || decoded.role !== 'admin') {
            return res.status(403).json({ error: 'Acesso negado ao painel' });
        }

        return res.status(200).json({ message: 'Bem-vindo ao painel de administração' });
    });
});

app.listen(PORT, () => console.log(`API online na porta ${PORT}`));