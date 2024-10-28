const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const app = express();

dotenv.config();

mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('Conexión exitosa a MongoDB'))
    .catch(err => console.error('Error al conectar a MongoDB:', err));

app.use(express.json());
app.use('/api', require('./routes/api'));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Servidor ejecutándose en el puerto ${port}`));