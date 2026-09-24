const Database = require('better-sqlite3');
const db = new Database('data/vendas.db');

db.prepare(`
  INSERT OR IGNORE INTO products (slug, nome, descricao)
  VALUES ('harmonizacao-milhoes', 'Harmonização de Milhões', 'eBook + videoaulas')
`).run();

console.log(db.prepare('SELECT id, slug, nome FROM products').all());
db.close();