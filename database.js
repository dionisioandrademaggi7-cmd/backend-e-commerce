const Database = require('better-sqlite3');
const path     = require('path');

const db = new Database(path.join(__dirname, 'data', 'vendas.db'));

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    nome         TEXT    NOT NULL,
    email        TEXT    UNIQUE NOT NULL,
    senha_hash   TEXT    NOT NULL,
    verificado   INTEGER DEFAULT 0,
    pagou        INTEGER DEFAULT 0,
    stripe_id    TEXT,
    criado_em    TEXT    DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS codigos (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    email      TEXT    NOT NULL,
    codigo     TEXT    NOT NULL,
    tipo       TEXT    NOT NULL,
    expira_em  TEXT    NOT NULL,
    usado      INTEGER DEFAULT 0,
    criado_em  TEXT    DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS sessoes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    token      TEXT    UNIQUE NOT NULL,
    expira_em  TEXT    NOT NULL,
    criado_em  TEXT    DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS logs (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    evento    TEXT NOT NULL,
    detalhe   TEXT,
    criado_em TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS tentativas (
    chave         TEXT NOT NULL,
    tipo          TEXT NOT NULL,
    contador      INTEGER DEFAULT 1,
    bloqueado_ate TEXT,
    atualizado_em TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (chave, tipo)
  );

  CREATE TABLE IF NOT EXISTS products (
                                          id              INTEGER PRIMARY KEY AUTOINCREMENT,
                                          slug            TEXT    UNIQUE NOT NULL,
                                          nome            TEXT    NOT NULL,
                                          descricao       TEXT,
                                          stripe_price_id TEXT,
                                          ativo           INTEGER DEFAULT 1,
                                          criado_em       TEXT    DEFAULT (datetime('now'))
      );

  CREATE TABLE IF NOT EXISTS purchases (
                                           id              INTEGER PRIMARY KEY AUTOINCREMENT,
                                           user_id         INTEGER NOT NULL,
                                           product_id      INTEGER NOT NULL,
                                           stripe_id       TEXT,
                                           criado_em       TEXT    DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (product_id) REFERENCES products(id),
      UNIQUE (user_id, product_id)
      );
`);

const stmts = {

    // ── Users ──────────────────────────────────────────────────
    criarUser: db.prepare(`
        INSERT INTO users (nome, email, senha_hash)
        VALUES (@nome, @email, @senha_hash)
    `),

    buscarUserPorEmail: db.prepare(`
        SELECT * FROM users WHERE email = ?
    `),

    buscarUserPorId: db.prepare(`
        SELECT * FROM users WHERE id = ?
    `),

    verificarUser: db.prepare(`
        UPDATE users SET verificado = 1 WHERE email = ?
    `),

    ativarAcesso: db.prepare(`
        UPDATE users SET pagou = 1, stripe_id = @stripe_id WHERE email = @email
    `),

    revogarAcesso: db.prepare(`
        UPDATE users SET pagou = 0 WHERE email = @email
    `),

    atualizarSenha: db.prepare(`
        UPDATE users SET senha_hash = @senha_hash WHERE email = @email
    `),

    // ── Códigos ────────────────────────────────────────────────
    inserirCodigo: db.prepare(`
        INSERT INTO codigos (email, codigo, tipo, expira_em)
        VALUES (@email, @codigo, @tipo, @expira_em)
    `),

    buscarCodigo: db.prepare(`
        SELECT * FROM codigos
        WHERE email = ? AND tipo = ? AND usado = 0
        ORDER BY criado_em DESC LIMIT 1
    `),

    marcarCodigoUsado: db.prepare(`
        UPDATE codigos SET usado = 1 WHERE id = ?
    `),

    // ── Sessões ────────────────────────────────────────────────
    criarSessao: db.prepare(`
        INSERT INTO sessoes (user_id, token, expira_em)
        VALUES (@user_id, @token, @expira_em)
    `),

    buscarSessao: db.prepare(`
        SELECT s.*, u.id as uid, u.nome, u.email, u.pagou, u.verificado
        FROM sessoes s
        JOIN users u ON u.id = s.user_id
        WHERE s.token = ?
    `),

    eliminarSessao: db.prepare(`
        DELETE FROM sessoes WHERE token = ?
    `),

    // ── Logs ───────────────────────────────────────────────────
    log: db.prepare(`
        INSERT INTO logs (evento, detalhe) VALUES (?, ?)
    `),

// ── Tentativas (brute force) ───────────────────────────────
    buscarTentativa: db.prepare(`
        SELECT * FROM tentativas WHERE chave = ? AND tipo = ?
    `),

    upsertTentativa: db.prepare(`
        INSERT INTO tentativas (chave, tipo, contador, bloqueado_ate, atualizado_em)
        VALUES (@chave, @tipo, 1, NULL, datetime('now'))
        ON CONFLICT(chave, tipo) DO UPDATE SET
            contador      = contador + 1,
            bloqueado_ate = @bloqueado_ate,
            atualizado_em = datetime('now')
    `),

    limparTentativa: db.prepare(`
        DELETE FROM tentativas WHERE chave = ? AND tipo = ?
    `),

    // ── Limpeza de sessões ─────────────────────────────────────
    limparSessoesExpiradas: db.prepare(`
        DELETE FROM sessoes WHERE expira_em < datetime('now')
    `),

    // ── Limpeza de sessões do utilizador ──────────────────────
    eliminarSessoesDoUser: db.prepare(`
        DELETE FROM sessoes WHERE user_id = ?
    `),

// ── RGPD — Apagamento ──────────────────────────────────────
    apagarSessoesUser: db.prepare(`
        DELETE FROM sessoes WHERE user_id = ?
    `),

    apagarCodigosUser: db.prepare(`
        DELETE FROM codigos WHERE email = ?
    `),

    apagarTentativasUser: db.prepare(`
        DELETE FROM tentativas WHERE chave = ? OR chave LIKE ?
    `),

    apagarLogsUser: db.prepare(`
        DELETE FROM logs WHERE detalhe = ?
    `),

    apagarUser: db.prepare(`
        DELETE FROM users WHERE id = ?
    `),

    // ── Products / Purchases ─────────────────────────────────
    listarProducts: db.prepare(`
        SELECT id, slug, nome, descricao, stripe_price_id, ativo
        FROM products
        WHERE ativo = 1
        ORDER BY id
    `),

    buscarProductPorSlug: db.prepare(`
        SELECT * FROM products WHERE slug = ? AND ativo = 1
    `),

    buscarProductPorId: db.prepare(`
        SELECT * FROM products WHERE id = ?
    `),

    registarPurchase: db.prepare(`
        INSERT OR IGNORE INTO purchases (user_id, product_id, stripe_id)
        VALUES (@user_id, @product_id, @stripe_id)
    `),

    userTemProduto: db.prepare(`
        SELECT 1 AS ok
        FROM purchases
        WHERE user_id = ? AND product_id = ?
        LIMIT 1
    `),

    listarPurchasesDoUser: db.prepare(`
        SELECT p.id, p.slug, p.nome, p.descricao, pu.criado_em AS comprado_em
        FROM purchases pu
        JOIN products p ON p.id = pu.product_id
        WHERE pu.user_id = ?
        ORDER BY pu.criado_em DESC
    `),

};

function gerarCodigo() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

function gerarExpiracao(minutos = 15) {
    const d = new Date();
    d.setMinutes(d.getMinutes() + minutos);
    return d.toISOString();
}

function gerarExpiracaoHoras(horas = 720) {
    const d = new Date();
    d.setHours(d.getHours() + horas);
    return d.toISOString();
}

function validarSessao(token) {
    if (!token) return { valido: false };
    const sessao = stmts.buscarSessao.get(token);
    if (!sessao) return { valido: false };
    if (new Date() > new Date(sessao.expira_em)) {
        stmts.eliminarSessao.run(token);
        return { valido: false };
    }
    return { valido: true, sessao };
}

module.exports = { db, stmts, gerarCodigo, gerarExpiracao, gerarExpiracaoHoras, validarSessao };