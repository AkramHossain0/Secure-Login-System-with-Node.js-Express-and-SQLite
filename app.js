import express from 'express';
import cookieParser from 'cookie-parser';
import router from './api/auth.js';
import dotenv from 'dotenv';

dotenv.config();

const app = express();

const PORT = process.env.PORT || 5000;
app.use(express.json());
app.use(cookieParser(process.env.COOKIE_SECRET)); 
app.use('/api', router);

app.get('/', (req, res) => {
    res.json({ message: 'hello world' });
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});