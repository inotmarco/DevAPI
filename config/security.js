require('dotenv').config();
const crypto = require('crypto');

let secret = process.env.JWT_SECRET;

if (!secret) {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('JWT_SECRET não definido. Configure a variável de ambiente (veja .env.example).');
  }
  // Apenas desenvolvimento: segredo efêmero (tokens deixam de valer ao reiniciar).
  secret = crypto.randomBytes(48).toString('hex');
  console.warn('[AVISO] JWT_SECRET ausente: usando segredo temporário. Crie um .env a partir do .env.example.');
}

module.exports = {
  JWT_SECRET: secret,
  JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || '1h',
  BCRYPT_ROUNDS: Number(process.env.BCRYPT_ROUNDS) || 10
};
