const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require('../config/security');

function autenticarToken(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const [esquema, token] = authHeader.split(' ');

  if (!token || !/^Bearer$/i.test(esquema)) {
    return res.status(401).json({ erro: "Token de autenticação não fornecido." });
  }

  try {
    // Fixar o algoritmo impede ataques de troca de algoritmo (ex.: alg "none").
    const payload = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    req.usuario = { id: Number(payload.sub), nome: payload.nome, role: payload.role };
    next();
  } catch (err) {
    const mensagem = err.name === 'TokenExpiredError' ? "Token expirado." : "Token inválido.";
    return res.status(401).json({ erro: mensagem });
  }
}

function exigirRole(roleEsperada) {
  return (req, res, next) => {
    if (!req.usuario || req.usuario.role !== roleEsperada) {
      return res.status(403).json({ erro: `Acesso proibido: privilégio de ${roleEsperada} exigido.` });
    }
    next();
  };
}

module.exports = { autenticarToken, exigirRole };
