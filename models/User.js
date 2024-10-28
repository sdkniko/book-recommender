const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  preferredGenres: [String],
  totpSecret: String // Agrega este campo
});

module.exports = mongoose.model('User', userSchema);
