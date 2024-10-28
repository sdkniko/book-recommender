const jwt = require('jsonwebtoken');

const auth = (req, res, next) => {
    try {
        // Obtener el token del header
        const authHeader = req.header('Authorization');
        if (!authHeader) {
            return res.status(401).send('Access denied. No token provided.');
        }

        // Verificar si el token comienza con 'Bearer '
        if (!authHeader.startsWith('Bearer ')) {
            return res.status(401).send('Invalid token format.');
        }

        // Extraer el token
        const token = authHeader.substring(7); // Removes 'Bearer '

        // Verificar el token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Asignar el usuario decodificado a req.user
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).send('Invalid token.');
    }
};

module.exports = auth;