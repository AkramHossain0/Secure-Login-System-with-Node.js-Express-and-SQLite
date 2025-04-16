import express from 'express';
import { register, verify, login, forget, reset, update ,decryptToken} from '../controllers/auth.js';

const router = express.Router();

router.post('/register', register);
router.post('/verify', verify);
router.post('/login', login);
router.post('/forget', forget);
router.post('/reset', reset);
router.post('/update', update);
router.post('/decrypt', (req, res, next) => {
    console.log('Decrypt Token API hit');
    next();
}, decryptToken);
export default router;