const express = require('express');
const User = require('../models/User');
const Book = require('../models/Book');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const axios = require('axios');
const auth = require('../middleware/auth'); // Añade esta línea
const router = express.Router();
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');



// Registro de usuario
router.post('/register', async (req, res) => {
    const { name, email, password, preferredGenres } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword, preferredGenres });
    await user.save();
    res.status(201).send('User  registered successfully.');
});

// Inicio de sesión
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

        // Crear token con el ID del usuario
        const token = jwt.sign(
            { _id: user._id }, // Asegúrate de incluir el _id aquí
            process.env.JWT_SECRET,
            { expiresIn: '24h' } // Opcional: añadir tiempo de expiración
        );

        // Enviar token
        res.header('Authorization', `Bearer ${token}`).json({ token: token });
    } catch (error) {
        res.status(500).send('Error in login process');
    }
});

// Obtener recomendaciones
router.get('/recommendations', auth, async (req, res) => {
    try {
        // Verificar si req.user existe
        if (!req.user || !req.user._id) {
            return res.status(401).send('User not authenticated properly.');
        }

        // Buscar usuario
        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).send('User not found.');
        }

        const genres = user.preferredGenres.join(', ');

        // Hacer la petición a OpenAI
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