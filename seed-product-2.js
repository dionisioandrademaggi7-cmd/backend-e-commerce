const Database = require('better-sqlite3');
const db = new Database('data/vendas.db');

db.prepare(`
  INSERT OR IGNORE INTO products (slug, nome, descricao)
  VALUES (?, ?, ?)
`).run(
    'curso-exemplo',
    'Curso Exemplo',
    'Segundo produto de teste — substituir pelo nome real depois'
);

console.log(db.prepare('SELECT id, slug, nome FROM products ORDER BY id').all());
db.close();