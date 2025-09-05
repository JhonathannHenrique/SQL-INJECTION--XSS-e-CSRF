const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const app = express();
const port = 3000;

// Configuração do EJS
app.set('view engine', 'ejs');
app.set('views', './views');

// Middleware para servir arquivos estáticos
app.use(express.static('public'));

// Middleware para parsear o corpo das requisições
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Configuração da sessão para simular usuário logado
app.use(session({
    secret: 'supersegredo', // Em produção, use uma string aleatória forte
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Para PoC local, secure: false. Em produção, use true com HTTPS
}));

// --- SIMULAÇÃO DE BANCO DE DADOS EM MEMÓRIA ---
// Usuários para autenticação (vulnerável a SQLi)
const users = [
    { username: 'admin', password: '123' },
    { username: 'user', password: 'userpass' }
];

// Posts para demonstração de XSS
let posts = [
    { id: 1, author: 'Alice', content: 'Olá a todos! Bem-vindos à PoC.' },
    { id: 2, author: 'Bob', content: 'Que dia lindo!' }
];
let nextPostId = 3;

// --- ROTAS ---

// Rota de Login (Vulnerável a SQL Injection)
app.get('/', (req, res) => {
    res.redirect('/login');
});

app.get('/login', (req, res) => {
    res.render('login', { message: req.query.message });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // --- VULNERABILIDADE: SQL INJECTION SIMULADA ---
    // Em uma aplicação real, aqui estaria uma consulta SQL como:
    // `SELECT * FROM users WHERE username='${username}' AND password='${password}'`
    // Sem sanitização, um payload como ' OR '1'='1 -- pode bypassar.

    const userFound = users.find(user => 
        user.username === username && user.password === password
    );

    // Para simular a SQL Injection de bypass sem um DB real,
    // vamos adicionar uma lógica para o payload comum.
    if (!userFound) {
        // Payload comum para bypass de autenticação: ' OR '1'='1
        // Se o username for o payload, consideramos autenticado para a PoC
        if (username === "' OR '1'='1--" || username === "' OR 1=1 --") {
            req.session.isAuthenticated = true;
            req.session.username = 'admin'; // Simula login como admin
            console.log("SQL Injection successful! Logged in as admin.");
            return res.redirect('/dashboard?message=SQL_Injection_Successful!');
        }
    }

    if (userFound) {
        req.session.isAuthenticated = true;
        req.session.username = userFound.username;
        return res.redirect('/dashboard');
    } else {
        res.render('login', { message: 'Usuário ou senha inválidos.' });
    }
});

// Middleware para checar autenticação
function requireAuth(req, res, next) {
    if (req.session.isAuthenticated) {
        next();
    } else {
        res.redirect('/login?message=Por_favor_faça_login.');
    }
}

// Rota Dashboard
app.get('/dashboard', requireAuth, (req, res) => {
    res.render('dashboard', { username: req.session.username, message: req.query.message });
});

// --- Rotas de Posts (Vulnerável a XSS) ---
app.get('/posts', requireAuth, (req, res) => {
    res.render('posts', { posts: posts });
});

app.get('/add-post', requireAuth, (req, res) => {
    res.render('add-post'); 
});

app.post('/add-post', requireAuth, (req, res) => {
    const { content } = req.body;
    const author = req.session.username || 'Anônimo';

    // --- VULNERABILIDADE: XSS ---
    // O conteúdo é armazenado e exibido diretamente sem sanitização.
    // Qualquer script injetado aqui será executado no navegador de outros usuários.
    posts.push({ id: nextPostId++, author: author, content: content });
    res.redirect('/posts');
});

// --- Rotas de Excluir Conta (Vulnerável a CSRF) ---
app.get('/delete-account', requireAuth, (req, res) => {
    res.render('delete-account', { username: req.session.username, message: req.query.message });
});

// Rota POST para exclusão de conta (Vulnerável a CSRF)
app.post('/delete-account-action', requireAuth, (req, res) => {
    // Em uma aplicação real, aqui haveria a lógica de exclusão no banco de dados.
    // Para esta PoC, simplesmente deslogamos o usuário e removemos a sessão.
    const userToDelete = req.session.username;
    console.log(`Simulando exclusão da conta de: ${userToDelete}`);
    req.session.destroy(err => {
        if (err) {
            console.error('Erro ao destruir sessão:', err);
            return res.status(500).send('Erro interno do servidor.');
        }
        res.redirect('/login?message=Sua_conta_foi_simuladamente_excluída.');
    });
});


// Rota de Logout
app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Erro ao destruir sessão:', err);
            return res.status(500).send('Erro interno do servidor.');
        }
        res.redirect('/login?message=Você_foi_desconectado.');
    });
});


// Iniciar o servidor
app.listen(port, () => {
    console.log(`PoC de Segurança rodando em http://localhost:${port}`);
    console.log('----------------------------------------------------');
    console.log('Vulnerabilidades para testar:');
    console.log('  - SQL Injection: Tente fazer login com o payload abaixo.');
    console.log('  - XSS: Publique um comentário com um script HTML/JS.');
    console.log('  - CSRF: Tente a demonstração de exclusão de conta.');
    console.log('----------------------------------------------------');
});