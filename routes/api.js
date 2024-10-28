const express = require('express');
const User = require('../models/User');
const Book = require('../models/Book');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const axios = require('axios');
const auth = require('../middleware/auth');
const router = express.Router();
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');

// Registro de usuario
router.post('/register', async (req, res) => {
    const { name, email, password, preferredGenres } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Generate TOTP secret during registration
    const secret = speakeasy.generateSecret({ length: 20 });
    
    const user = new User({
        name,
        email,
        password: hashedPassword,
        preferredGenres,
        totpSecret: secret.base32 // Store the secret in the user model
    });
    
    await user.save();
    res.status(201).send('User registered successfully.');
});

// Primera fase del login - verificación de credenciales
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Buscar usuario
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).send('Email or password is incorrect.');
        }

        // Verificar contraseña
        const validPass = await bcrypt.compare(password, user.password);
        if (!validPass) {
            return res.status(400).send('Email or password is incorrect.');
        }

        // Generate QR code for first-time setup
        const otpauthUrl = speakeasy.otpauthURL({
            secret: user.totpSecret,
            label: `app:${user.email}`,
            issuer: 'empresa',
            encoding: 'base32'
        });

        // Generate QR code as data URL
        const qrCodeUrl = await qrcode.toDataURL(otpauthUrl);

        // Create a temporary token for the 2FA step
        const tempToken = jwt.sign(
            { _id: user._id, temp: true },
            process.env.JWT_SECRET,
            { expiresIn: '5m' } // Short expiration for security
        );

        res.json({
            message: 'First step successful. Please provide TOTP.',
            tempToken,
            qrCode: qrCodeUrl // Only sent on first login or if user needs to re-setup 2FA
        });

    } catch (error) {
        res.status(500).send('Error in login process');
    }
});

// Segunda fase del login - verificación TOTP
router.post('/verify-login', async (req, res) => {
    try {
        const { tempToken, totpToken } = req.body;

        // Verify temp token
        const decoded = jwt.verify(tempToken, process.env.JWT_SECRET);
        if (!decoded._id || !decoded.temp) {
            return res.status(401).send('Invalid temporary token');
        }

        // Get user
        const user = await User.findById(decoded._id);
        if (!user) {
            return res.status(404).send('User not found');
        }

        // Verify TOTP
        const verified = speakeasy.totp.verify({
            secret: user.totpSecret,
            encoding: 'base32',
            token: totpToken
        });

        if (!verified) {
            return res.status(401).send('Invalid TOTP token');
        }

        // Create final access token
        const accessToken = jwt.sign(
            { _id: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            message: 'Login successful',
            token: accessToken
        });

    } catch (error) {
        res.status(500).send('Error in verification process');
    }
});

// Middleware mejorado para verificar TOTP
const verifyTOTP = async (req, res, next) => {
    try {
        console.log('Headers recibidos:', req.headers); // Debug headers
        const totpToken = req.header('x-totp-token'); // Nota: los headers llegan en minúsculas
        console.log('TOTP Token recibido:', totpToken);

        if (!totpToken) {
            return res.status(401).json({
                error: 'TOTP token required',
                receivedHeaders: req.headers // Debug info
            });
        }

        if (!req.user || !req.user._id) {
            return res.status(401).json({
                error: 'User not authenticated properly',
                user: req.user // Debug info
            });
        }

        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({
                error: 'User not found',
                userId: req.user._id // Debug info
            });
        }

        console.log('Verificando TOTP con:', {
            secret: user.totpSecret,
            token: totpToken
        });

        const verified = speakeasy.totp.verify({
            secret: user.totpSecret,
            encoding: 'base32',
            token: totpToken,
            window: 1 // Permite una ventana de 30 segundos antes/después
        });

        console.log('Resultado verificación:', verified);

        if (!verified) {
            return res.status(401).json({
                error: 'Invalid TOTP token',
                provided: totpToken,
                // No incluir el secret por seguridad
                timestamp: new Date().toISOString()
            });
        }

        next();
    } catch (error) {
        console.error('Error en verifyTOTP:', error);
        res.status(500).json({
            error: 'Error verifying TOTP',
            details: error.message
        });
    }
};

// Endpoint de prueba para generar un nuevo token TOTP
router.get('/generate-current-totp', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        if (!user || !user.totpSecret) {
            return res.status(404).send('User or TOTP secret not found');
        }

        const token = speakeasy.totp({
            secret: user.totpSecret,
            encoding: 'base32'
        });

        res.json({
            currentToken: token,
            validUntil: new Date(Math.floor(Date.now() / 30000 + 1) * 30000)
        });
    } catch (error) {
        res.status(500).json({
            error: 'Error generating TOTP',
            details: error.message
        });
    }
});
// Obtener recomendaciones con verificación TOTP
router.get('/recommendations', auth, verifyTOTP, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).send('User not found.');
        }

        const genres = user.preferredGenres.join(', ');

        const response = await axios.post('https://api.openai.com/v1/chat/completions', {
            model: "gpt-3.5-turbo",
            messages: [{ role: "user", content: `Recomiéndame libros de los siguientes géneros: ${genres}` }]
        }, {
            headers: {
                'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`,
                'Content-Type': 'application/json'
            }
        });

        const recommendations = response.data.choices[0].message.content;
        res.json({ recommendations });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).send('Error al obtener recomendaciones: ' + error.message);
    }
});

module.exports = router;
