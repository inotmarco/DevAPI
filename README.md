# Livraria API (Node + Express) — Camada de Segurança

API de Livros e Autores com **BCrypt**, **JWT stateless** e **RBAC**.

## Como rodar
```bash
npm install
cp .env.example .env      # defina JWT_SECRET
npm start                 # http://localhost:3000
```
> Se existir um `database.txt` antigo (com hashes falsos), apague-o: ele é recriado com hashes BCrypt reais.
> O front de teste é o `index.html` (abra no navegador com a API rodando).

## Credenciais
| Perfil | E-mail | Senha |
|---|---|---|
| ADMIN | admin@livraria.com | admin123 |
| USER | leitor@gmail.com | leitor123 |

## O que foi implementado
- **BCrypt** (`bcryptjs`): hash com salt aleatório e work factor 10 (configurável) no cadastro e no seed; senhas nunca são retornadas.
- **JWT** (`jsonwebtoken`): emitido no login (HS256, `sub`, `nome`, `role`, expira em 1h); validado no middleware com algoritmo fixado (bloqueia `alg: none`). Segredo em `.env`.
- **RBAC**: `autenticarToken` (401) + `exigirRole('ADMIN')` (403).
- **Decisões de segurança**
  - `/auth/register` ignora `role` do body e sempre cria `USER` (evita auto-promoção a ADMIN).
  - Login devolve a mesma mensagem para e-mail inexistente e senha errada, e executa `bcrypt.compare` nos dois casos (evita enumeração por timing).
  - E-mails normalizados para minúsculas; senha mínima de 6 caracteres.
  - `index.html`: escape de HTML nos dados renderizados (XSS) e correção do campo `autor_nome` dos comentários.

## Matriz de permissões
| Método | Rota | Acesso | Sucesso | Falha |
|---|---|---|---|---|
| GET | /api/v1/livros | Público | 200 | — |
| GET | /api/v1/livros/:id | Público | 200 | — |
| POST | /api/v1/auth/register | Público | 201 | — |
| POST | /api/v1/auth/login | Público | 200 | 401 |
| POST | /api/v1/livros/:id/comentarios | USER ou ADMIN | 201 | 401 |
| POST | /api/v1/autores | ADMIN | 201 | 401 / 403 |
| POST | /api/v1/livros | ADMIN | 201 | 401 / 403 |

## Teste rápido (curl)
```bash
TOKEN=$(curl -s -X POST localhost:3000/api/v1/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"admin@livraria.com","senha":"admin123"}' | jq -r .token)
curl -X POST localhost:3000/api/v1/autores -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"nome":"Clarice Lispector","nacionalidade":"Brasileira"}'
```
