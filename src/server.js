require('dotenv').config();
const express = require('express');
const path = require('path');
const { expressjwt: jwt } = require('express-jwt');
const jwksRsa = require('jwks-rsa');
const apiRoutes = require('./routes/api');
const cors = require('cors');
const bodyParser = require('body-parser');
const http = require('http');
const { Server } = require('socket.io');


const app = express();
const PORT = process.env.PORT || 3000;

const distPath = path.join(__dirname, '../public/dist');
app.use(express.static(distPath));

// Для SPA: всегда возвращаем index.html на все остальные маршруты
app.get('*', (req, res) => {
  res.sendFile(path.join(distPath, 'index.html'));
});

const server = http.createServer(app); // создаём HTTP-сервер на базе Express
const io = new Server(server, {
    cors: {
        origin: 'https://contractors-0q4c.onrender.com',
        methods: ['GET', 'POST', 'DELETE', 'PATCH', 'PUT', 'OPTIONS'],
        allowedHeaders: ['Content-Type','Authorization'],
    }
});

app.set('io', io); // добавляем io в app для доступа в роутерах

// Обработка подключений
io.on('connection', (socket) => {
    console.log('A user connected:', socket.id);

    socket.on('joinChat', (chatId) => {
        socket.join(chatId);
        console.log(`Socket ${socket.id} joined chat ${chatId}`);
    });

    socket.on('disconnect', () => {
        console.log('A user disconnected:', socket.id);
    });
});

// Настройка Auth0
const authConfig = {
    domain: process.env.AUTH0_DOMAIN,
    audience: process.env.AUTH0_AUDIENCE,
};

// Middleware для проверки JWT
const checkJwt = jwt({
    secret: jwksRsa.expressJwtSecret({
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 5,
        jwksUri: `https://${authConfig.domain}/.well-known/jwks.json`,
    }),
    audience: authConfig.audience,
    issuer: `https://${authConfig.domain}/`,
    algorithms: ['RS256'],
});

server.listen(PORT, () => {
    console.log(`✅ Server is running on port ${PORT}`);
});

// Настройка CORS
app.use(cors({
    origin: 'https://contractors-0q4c.onrender.com', // Укажите адрес вашего фронтенда
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Authorization', 'Content-Type'], // Разрешаем заголовок Authorization
    credentials: false, // Не используем куки
}));
app.use(bodyParser.json()); // Для обработки JSON-запросов

// Middleware для логирования запросов
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
    next(); // Передаем управление следующему middleware или маршруту
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/index.html'));
});

// Подключение маршрутов API
app.use('/api', apiRoutes);

// Обработка необработанных исключений и отклонений
process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});
