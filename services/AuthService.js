const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const repository = require('../repositories/LivrariaRepository');
const { JWT_SECRET, JWT_EXPIRES_IN, BCRYPT_ROUNDS } = require('../config/security');

// Hash descartável usado para igualar o tempo de resposta quando o e-mail não existe
// (evita enumeração de usuários por timing attack).
const HASH_FALSO = bcrypt.hashSync('senha-falsa-para-timing', BCRYPT_ROUNDS);

class AuthService {
  async registrar({ nome, email, senha }) {
    if (!nome || !email || !senha) {
      throw { status: 400, message: "Campos obrigatórios ausentes: nome, email ou senha." };
    }
    if (typeof senha !== 'string' || senha.length < 6) {
      throw { status: 400, message: "A senha deve ter no mínimo 6 caracteres." };
    }

    const emailNormalizado = String(email).trim().toLowerCase();

    if (repository.buscarUsuarioPorEmail(emailNormalizado)) {
      throw { status: 409, message: "E-mail já cadastrado no sistema." };
    }

    // BCrypt: o salt aleatório é gerado e embutido no hash; o work factor vem de BCRYPT_ROUNDS.
    const senha_hash = await bcrypt.hash(senha, BCRYPT_ROUNDS);

    // SEGURANÇA: o cadastro público SEMPRE cria perfil USER.
    // Aceitar "role" vindo do body permitiria escalonamento de privilégio (qualquer um viraria ADMIN).
    const novoUsuario = repository.salvarUsuario({
      nome: String(nome).trim(),
      email: emailNormalizado,
      senha_hash,
      role: "USER"
    });

    const { senha_hash: _, ...usuarioRetorno } = novoUsuario;
    return usuarioRetorno;
  }

  async login({ email, senha }) {
    if (!email || !senha || typeof senha !== 'string') {
      throw { status: 400, message: "E-mail e senha são obrigatórios." };
    }

    const usuario = repository.buscarUsuarioPorEmail(String(email).trim().toLowerCase());

    // Sempre executa o compare, exista o usuário ou não; mensagem genérica nos dois casos.
    const senhaConfere = await bcrypt.compare(senha, usuario ? usuario.senha_hash : HASH_FALSO);
    if (!usuario || !senhaConfere) {
      throw { status: 401, message: "Credenciais inválidas." };
    }

    const token = jwt.sign(
      { nome: usuario.nome, role: usuario.role },
      JWT_SECRET,
      { subject: String(usuario.id), expiresIn: JWT_EXPIRES_IN, algorithm: 'HS256' }
    );

    return {
      usuario: { id: usuario.id, nome: usuario.nome, role: usuario.role },
      token
    };
  }
}

module.exports = new AuthService();
