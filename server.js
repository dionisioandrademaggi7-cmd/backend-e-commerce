// server.js — Harmonização de Milhões — Dr Marco Maggi
require('dotenv').config();


const express      = require('express');
const helmet       = require('helmet');
const path         = require('path');
const bcrypt       = require('bcrypt');
const { v4: uuid } = require('uuid');
const nodemailer   = require('nodemailer');
const Stripe       = require('stripe');
const crypto       = require('crypto');
const rateLimit    = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const { stmts, gerarExpiracaoHoras, validarSessao } = require('./database');

const limiterRegisto = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { erro: 'Demasiados registos. Tenta novamente em 15 minutos.' },
    standardHeaders: true,
    legacyHeaders: false,
});

const limiterCheckout = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 10,
    message: { erro: 'Demasiadas tentativas de pagamento. Tenta novamente em 1 hora.' },
    standardHeaders: true,
    legacyHeaders: false,
});

const limiterRecuperar = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 5,
    message: { erro: 'Demasiados pedidos de recuperação. Tenta novamente em 1 hora.' },
    standardHeaders: true,
    legacyHeaders: false,
});

const app    = express();
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const isProduction = process.env.NODE_ENV === 'production';
app.use((req, res, next) => {
    const writeHead = res.writeHead;

    res.writeHead = function (...args) {
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader(
            'Permissions-Policy',
            'camera=(), microphone=(), geolocation=(), payment=(), usb=(), fullscreen=(self)'
        );
        return writeHead.apply(this, args);
    };

    next();
});
app.use(
    helmet({
        contentSecurityPolicy: {
            useDefaults: false,
            directives: {
                defaultSrc: ["'self'"],
                baseUri: ["'self'"],
                objectSrc: ["'none'"],
                frameAncestors: ["'self'"],

                scriptSrc: ["'self'", "'unsafe-inline'"],
                scriptSrcAttr: ["'unsafe-inline'"],

                styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
                fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],

                imgSrc: ["'self'", "data:", "blob:", "https:"],
                connectSrc: ["'self'"],

                frameSrc: [
                    "'self'",
                    "https://www.youtube.com",
                    "https://www.youtube-nocookie.com",
                ],

                formAction: ["'self'"],
                upgradeInsecureRequests: isProduction ? [] : null,
            },
        },

        xContentTypeOptions: true,
        referrerPolicy: { policy: "strict-origin-when-cross-origin" },
        crossOriginOpenerPolicy: { policy: "same-origin" },

        // Nikto marca Origin-Agent-Cluster como "uncommon".
        // Não é falha, mas desativar remove esse ruído.
        originAgentCluster: false,
    })
);

const PORT      = process.env.PORT || 3000;
const BASE_URL  = process.env.BASE_URL || `http://localhost:${PORT}`;
const COOKIE_MS = 30 * 24 * 60 * 60 * 1000;

app.use(express.json());

// ── Mailer ────────────────────────────────────────────────────
const mailer = nodemailer.createTransport({
    host:   process.env.MAIL_HOST,
    port:   parseInt(process.env.MAIL_PORT || '587'),
    secure: false,
    auth:   { user: process.env.MAIL_USER, pass: process.env.MAIL_PASS },
});

async function enviarEmail({ para, assunto, html }) {
    try {
        await mailer.sendMail({ from: process.env.MAIL_FROM, to: para, subject: assunto, html });
        console.log(`📧 Email enviado para ${para}`);
    } catch (err) {
        console.error('Erro ao enviar email:', err.message);
    }
}

// ── Tentativas de login falhadas (em memória) ─────────────────
// Estrutura: { email: { tentativas: N, bloqueadoAte: Date|null } }
const MAX_TENTATIVAS        = 3;
const MAX_TENTATIVAS_CODIGO = 5;
const BLOQUEIO_MS           = 15 * 60 * 1000;

function verificarBloqueio(email) {
    const r = stmts.buscarTentativa.get(email, 'login');
    if (!r) return { bloqueado: false };
    if (r.bloqueado_ate && new Date() < new Date(r.bloqueado_ate)) {
        const mins = Math.ceil((new Date(r.bloqueado_ate) - Date.now()) / 60000);
        return { bloqueado: true, minutosRestantes: mins };
    }
    return { bloqueado: false };
}

function registarTentativaFalhada(email) {
    const r = stmts.buscarTentativa.get(email, 'login');
    const contador = (r?.contador || 0) + 1;
    const bloqueado_ate = contador >= MAX_TENTATIVAS
        ? new Date(Date.now() + BLOQUEIO_MS).toISOString()
        : null;
    stmts.upsertTentativa.run({ chave: email, tipo: 'login', bloqueado_ate });
    return { tentativas: contador, bloqueadoAte: bloqueado_ate };
}

function limparTentativas(email) {
    stmts.limparTentativa.run(email, 'login');
}

function chaveCodigo(email, req) {
    return `${String(email || '').trim().toLowerCase()}:${req.ip}`;
}

function verificarBloqueioCodigo(email, req) {
    const chave = chaveCodigo(email, req);
    const r = stmts.buscarTentativa.get(chave, 'codigo');
    if (!r) return { bloqueado: false };
    if (r.bloqueado_ate && new Date() < new Date(r.bloqueado_ate)) {
        const mins = Math.ceil((new Date(r.bloqueado_ate) - Date.now()) / 60000);
        return { bloqueado: true, minutosRestantes: mins };
    }
    return { bloqueado: false };
}

function registarTentativaCodigoFalhada(email, req) {
    const chave = chaveCodigo(email, req);
    const r = stmts.buscarTentativa.get(chave, 'codigo');
    const contador = (r?.contador || 0) + 1;
    const bloqueado_ate = contador >= MAX_TENTATIVAS_CODIGO
        ? new Date(Date.now() + BLOQUEIO_MS).toISOString()
        : null;
    stmts.upsertTentativa.run({ chave, tipo: 'codigo', bloqueado_ate });
    return { tentativas: contador, bloqueadoAte: bloqueado_ate };
}

function limparTentativasCodigo(email, req) {
    stmts.limparTentativa.run(chaveCodigo(email, req), 'codigo');
}
// ── Webhook RAW ───────────────────────────────────────────────
app.post('/webhook', express.raw({ type: 'application/json' }), webhookHandler);

// ── Cookies ───────────────────────────────────────────────────
app.use(cookieParser());

app.use(express.static(path.join(__dirname, 'public')));
app.use('/css',    express.static(path.join(__dirname, 'css')));
app.use('/assets', (req, res, next) => {
    if (req.path.endsWith('.pdf')) return res.status(403).json({ erro: 'Acesso negado' });
    next();
}, express.static(path.join(__dirname, 'assets')));

// ── Middlewares de auth ───────────────────────────────────────
function auth(req, res, next) {
    const r = validarSessao(req.cookies?.sessao);
    if (!r.valido) return res.status(401).json({ erro: 'Não autenticado' });
    req.user = r.sessao;
    next();
}

function requireProduct(slug) {
    return function (req, res, next) {
        const r = validarSessao(req.cookies?.sessao);
        if (!r.valido) {
            if (req.path.startsWith('/api/')) {
                return res.status(401).json({ erro: 'Não autenticado' });
            }
            return res.redirect('/login');
        }

        const user = stmts.buscarUserPorEmail.get(r.sessao.email);
        if (!user) {
            if (req.path.startsWith('/api/')) {
                return res.status(401).json({ erro: 'Não autenticado' });
            }
            return res.redirect('/login');
        }

        const product = stmts.buscarProductPorSlug.get(slug);
        if (!product) {
            if (req.path.startsWith('/api/')) {
                return res.status(404).json({ erro: 'Produto não encontrado' });
            }
            return res.redirect('/');
        }

        const tem = stmts.userTemProduto.get(user.id, product.id);
        const legadoOk = user.pagou && product.slug === 'harmonizacao-milhoes';

        if (!tem && !legadoOk) {
            if (req.path.startsWith('/api/')) {
                return res.status(403).json({ erro: 'Sem acesso a este curso' });
            }
            return res.redirect('/sem-acesso');
        }

        req.user = user;
        req.product = product;
        next();
    };
}

function authPago(req, res, next) {
    const r = validarSessao(req.cookies?.sessao);
    if (!r.valido) return res.redirect('/login');
    const user = stmts.buscarUserPorEmail.get(r.sessao.email);
    if (!user || !user.pagou) return res.redirect('/sem-acesso');
    req.user = user;
    next();
}

function noStore(req, res, next) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    next();
}

// ── Páginas públicas ──────────────────────────────────────────

app.get('/curso/:slug', (req, res, next) => {
    requireProduct(req.params.slug)(req, res, next);
}, noStore, (req, res) => {
    // Por agora só prova o acesso; depois serves HTML por slug
    res.json({
        ok: true,
        curso: req.product.slug,
        nome: req.product.nome,
        user: req.user.email,
    });
});



app.use((req, res, next) => {
    if (req.path.length > 1 && req.path.endsWith('/')) {
        const query = req.url.slice(req.path.length);
        return res.redirect(301, req.path.slice(0, -1) + query);
    }

    next();
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/registrar', (req, res) => res.sendFile(path.join(__dirname, 'public', 'registrar.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/recuperar', (req, res) => res.sendFile(path.join(__dirname, 'public', 'recuperar.html')));
app.get('/sem-acesso', (req, res) => res.sendFile(path.join(__dirname, 'public', 'sem-acesso.html')));
app.get('/privacidade', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'privacidade.html'));
});
// ── Página produto (protegida) ────────────────────────────────
app.get('/produto', authPago, noStore, (req, res) => res.sendFile(path.join(__dirname, 'private', 'produto.html')));
app.get('/private/ebook', authPago, noStore, (req, res) => res.sendFile(path.join(__dirname, 'private', 'ebook.html')));
app.get('/private/video/:nome', authPago, noStore, (req, res) => {
    const nomesPermitidos = ['aula1', 'aula2', 'aula3', 'aula4', 'aula5'];
    const nome = req.params.nome;
    if (!nomesPermitidos.includes(nome)) return res.status(404).send('Não encontrado');
    res.sendFile(path.join(__dirname, 'private', 'video', `${nome}.mp4`));
});

// ══════════════════════════════════════════════════════════════
// ROTA — Após pagamento Stripe
// ══════════════════════════════════════════════════════════════
app.get('/pagamento-confirmado', async (req, res) => {
    const sessao = validarSessao(req.cookies?.sessao);
    if (!sessao.valido) return res.redirect('/login');

    const email     = sessao.sessao.email;
    const sessionId = req.query.session_id;

    if (sessionId) {
        try {
            const checkoutSession = await stripe.checkout.sessions.retrieve(sessionId);

            // Segurança: a sessão de checkout tem de pertencer ao utilizador
            // que está autenticado agora — nunca confiar apenas no session_id da URL.
            const donoSessao = checkoutSession.metadata?.user_email || checkoutSession.customer_details?.email;
            const pertenceAoUser = donoSessao && donoSessao.toLowerCase() === email.toLowerCase();

            if (checkoutSession.payment_status === 'paid' && pertenceAoUser) {

                console.log(` Acesso ativado via redirect: ${email}`);
                stmts.ativarAcesso.run({ email, stripe_id: sessionId });

                const userRow = stmts.buscarUserPorEmail.get(email);
                const productId = Number(checkoutSession.metadata?.product_id);
                if (userRow && productId) {
                    stmts.registarPurchase.run({
                        user_id: userRow.id,
                        product_id: productId,
                        stripe_id: sessionId,
                    });
                } else if (userRow) {
                    const legacy = stmts.buscarProductPorSlug.get('harmonizacao-milhoes');
                    if (legacy) {
                        stmts.registarPurchase.run({
                            user_id: userRow.id,
                            product_id: legacy.id,
                            stripe_id: sessionId,
                        });
                    }
                }

                stmts.log.run('acesso_ativado', email);
                // Email de boas-vindas em background
                const user = stmts.buscarUserPorEmail.get(email);
                const nomeProprio = user?.nome?.split(' ')[0] || 'Doutor(a)';
                enviarEmail({
                    para: email,
                    assunto: ' Acesso liberado — Harmonização de Milhões',
                    html: `
                    <div style="font-family:sans-serif;max-width:560px;margin:0 auto;background:#0B1F3A;color:#FDFCFA;padding:48px 40px;border-radius:8px;">
                        <h2 style="font-family:Georgia,serif;color:#E2BF78;margin-bottom:4px;">Harmonização de Milhões</h2>
                        <p style="color:rgba(253,252,250,0.4);font-size:11px;letter-spacing:2px;text-transform:uppercase;margin-bottom:36px;">Dr. Marco Maggi</p>
                        <p style="font-size:17px;font-weight:600;margin-bottom:16px;">Olá, ${nomeProprio}! </p>
                        <p style="font-size:15px;line-height:1.75;color:rgba(253,252,250,0.8);margin-bottom:24px;">
                            O teu pagamento foi confirmado e o acesso ao <strong style="color:#E2BF78">eBook + Videoaulas</strong> foi ativado com sucesso.
                        </p>
                        <a href="${BASE_URL}/produto" style="display:inline-block;background:linear-gradient(135deg,#C8993A,#A87A20);color:#0B1F3A;font-weight:700;font-size:15px;padding:15px 32px;border-radius:6px;text-decoration:none;margin-bottom:32px;">
                            Aceder ao conteúdo →
                        </a>
                        <div style="border-top:1px solid rgba(200,153,58,0.15);padding-top:24px;margin-top:8px;">
                            <p style="font-size:13px;color:rgba(253,252,250,0.45);line-height:1.7;">
                                O teu acesso é vitalício — podes entrar a qualquer momento em <a href="${BASE_URL}/login" style="color:#C8993A;">${BASE_URL}/login</a>.<br>
                                Qualquer questão, responde a este email.
                            </p>
                        </div>
                    </div>`,
                });

                return res.redirect('/produto');
            }

            if (checkoutSession.payment_status === 'paid' && !pertenceAoUser) {
                console.warn(`⚠️ session_id não pertence ao utilizador autenticado (${email}). Ignorado — webhook é quem decide.`);
            }
        } catch(e) {
            console.error('Erro ao verificar sessão Stripe:', e.message);
        }
    }

    const user = stmts.buscarUserPorEmail.get(email);
    if (user?.pagou) return res.redirect('/produto');

    return res.redirect('/sem-acesso?processando=1');
});

// ══════════════════════════════════════════════════════════════
// API — Registar
// ══════════════════════════════════════════════════════════════
app.post('/api/registrar', limiterRegisto, async (req, res) => {
    const { nome, email, senha } = req.body;

    if (!nome || !email || !senha)
        return res.status(400).json({ erro: 'Todos os campos são obrigatórios.' });

    if (senha.length < 6)
        return res.status(400).json({ erro: 'A senha deve ter pelo menos 6 caracteres.' });

    const existente = stmts.buscarUserPorEmail.get(email);
    if (existente)
        return res.status(400).json({ erro: 'Este email já tem conta. Faz login.' });

    const senha_hash = await bcrypt.hash(senha, 12);
    stmts.criarUser.run({ nome, email, senha_hash });

    const user  = stmts.buscarUserPorEmail.get(email);

    const token = uuid();
    stmts.criarSessao.run({ user_id: user.id, token, expira_em: gerarExpiracaoHoras(720) });

    res.cookie('sessao', token, {
        httpOnly: true,
        secure:   process.env.NODE_ENV === 'production',
        maxAge:   COOKIE_MS,
        sameSite: 'lax',
        path:     '/',
    });

    stmts.log.run('user_criado', email);
    res.json({ ok: true, pagou: user.pagou });
});

// ── API — Catálogo de produtos ─────────────────────────────
app.get('/api/products', (req, res) => {
    try {
        const products = stmts.listarProducts.all();
        res.json({ products });
    } catch (err) {
        console.error('Erro /api/products:', err.message);
        res.status(500).json({ erro: 'Não foi possível listar os produtos.' });
    }
});


// ── API — Cursos do utilizador autenticado ─────────────────
app.get('/api/meus-cursos', auth, (req, res) => {
    try {
        const user = stmts.buscarUserPorEmail.get(req.user.email);
        if (!user) {
            return res.status(401).json({ erro: 'Não autenticado' });
        }

        const cursos = stmts.listarPurchasesDoUser.all(user.id);

        // Compatibilidade: se pagou o legado e ainda não há purchase
        if ((!cursos || cursos.length === 0) && user.pagou) {
            const legacy = stmts.buscarProductPorSlug.get('harmonizacao-milhoes');
            if (legacy) {
                return res.json({
                    cursos: [{
                        id: legacy.id,
                        slug: legacy.slug,
                        nome: legacy.nome,
                        descricao: legacy.descricao,
                        comprado_em: null,
                        legado: true,
                    }],
                });
            }
        }

        res.json({ cursos });
    } catch (err) {
        console.error('Erro /api/meus-cursos:', err.message);
        res.status(500).json({ erro: 'Não foi possível listar os cursos.' });
    }
});
// ══════════════════════════════════════════════════════════════
// API — Login (com proteção contra força bruta)
// ══════════════════════════════════════════════════════════════
app.post('/api/login', async (req, res) => {
    const { email, senha } = req.body;

    if (!email || !senha)
        return res.status(400).json({ erro: 'Email e senha obrigatórios.' });

    // Verificar se está bloqueado
    const bloqueio = verificarBloqueio(email);
    if (bloqueio.bloqueado) {
        return res.status(429).json({
            erro: `Demasiadas tentativas falhadas. Conta bloqueada por ${bloqueio.minutosRestantes} minuto(s).`,
            bloqueado: true,
        });
    }

    const user = stmts.buscarUserPorEmail.get(email);
    if (!user) {
        // Não revelar se o email existe — mensagem genérica
        registarTentativaFalhada(email);
        return res.status(401).json({ erro: 'Email ou senha incorretos.' });
    }

    const ok = await bcrypt.compare(senha, user.senha_hash);
    if (!ok) {
        const estado = registarTentativaFalhada(email);
        const restantes = MAX_TENTATIVAS - estado.tentativas;

        if (estado.bloqueadoAte) {
            // Atingiu o limite — envia email de aviso
            stmts.log.run('login_bloqueado', email);
            console.log(`🔒 Conta bloqueada por tentativas: ${email}`);

            // Envia email de aviso em background
            enviarEmail({
                para:    email,
                assunto: '⚠️ Acesso bloqueado temporariamente — Harmonização de Milhões',
                html: `
                <div style="font-family:sans-serif;max-width:520px;margin:0 auto;background:#0B1F3A;color:#FDFCFA;padding:48px 40px;border-radius:8px;">
                    <h2 style="font-family:Georgia,serif;color:#E2BF78;margin-bottom:8px;">Harmonização de Milhões</h2>
                    <p style="color:rgba(253,252,250,0.5);font-size:12px;margin-bottom:32px;">Dr. Marco Maggi</p>
                    <p style="font-size:15px;line-height:1.7;margin-bottom:24px;">
                        Detectámos várias tentativas de login falhadas na tua conta.<br><br>
                        O acesso foi bloqueado temporariamente por <strong style="color:#E2BF78">15 minutos</strong> por segurança.
                    </p>
                    <p style="font-size:14px;line-height:1.7;margin-bottom:24px;color:rgba(253,252,250,0.65);">
                        Se foste tu, aguarda 15 minutos e tenta novamente.<br>
                        Se não foste tu, recomendamos que alteres a tua senha em:
                    </p>
                    <a href="${BASE_URL}/recuperar" style="display:inline-block;background:linear-gradient(135deg,#C8993A,#A87A20);color:#0B1F3A;font-weight:700;font-size:15px;padding:14px 28px;border-radius:6px;text-decoration:none;">
                        Alterar senha →
                    </a>
                    <p style="font-size:12px;color:rgba(253,252,250,0.35);margin-top:28px;line-height:1.6;">
                        Se tiveres dificuldades, responde a este email.
                    </p>
                </div>`,
            });

            return res.status(429).json({
                erro: 'Demasiadas tentativas falhadas. Conta bloqueada por 15 minutos. Enviámos um email de aviso.',
                bloqueado: true,
            });
        }

        const msg = restantes > 0
            ? `Email ou senha incorretos. ${restantes} tentativa(s) restante(s).`
            : 'Email ou senha incorretos.';

        return res.status(401).json({ erro: msg });
    }

    // Login bem sucedido — limpar tentativas
    limparTentativas(email);

    const token = uuid();
    stmts.criarSessao.run({ user_id: user.id, token, expira_em: gerarExpiracaoHoras(720) });

    res.cookie('sessao', token, {
        httpOnly: true,
        secure:   process.env.NODE_ENV === 'production',
        maxAge:   COOKIE_MS,
        sameSite: 'lax',
        path:     '/',
    });

    stmts.log.run('login_ok', email);
    res.json({ ok: true, pagou: user.pagou });
});


// ══════════════════════════════════════════════════════════════
// API — Logout
// ══════════════════════════════════════════════════════════════
app.post('/api/logout', (req, res) => {
    const token = req.cookies?.sessao;
    if (token) stmts.eliminarSessao.run(token);
    res.clearCookie('sessao', {
        httpOnly: true,
        secure:   process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path:     '/',
    });
    res.json({ ok: true });
});


// ══════════════════════════════════════════════════════════════
// API — Quem sou eu
// ══════════════════════════════════════════════════════════════
app.get('/api/eu', (req, res) => {
    const r = validarSessao(req.cookies?.sessao);
    if (!r.valido) return res.json({ logado: false });
    const user = stmts.buscarUserPorEmail.get(r.sessao.email);
    if (!user) return res.json({ logado: false });
    res.json({ logado: true, nome: user.nome, email: user.email, pagou: user.pagou });
});


// ══════════════════════════════════════════════════════════════
// API — Recuperar senha
// ══════════════════════════════════════════════════════════════
app.post('/api/recuperar', limiterRecuperar, async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ erro: 'Email obrigatório.' });

    res.json({ ok: true });

    try {
        const user = stmts.buscarUserPorEmail.get(email);
        if (!user) return;

        const codigo    = crypto.randomInt(100000, 1000000).toString();
        const expira_em = new Date(Date.now() + 15 * 60 * 1000).toISOString();

        stmts.inserirCodigo.run({ email, codigo, tipo: 'recuperacao', expira_em });
        stmts.log.run('codigo_recuperacao', email);

        await enviarEmail({
            para:    email,
            assunto: '🔑 Recuperação de senha — Harmonização de Milhões',
            html: `
            <div style="font-family:sans-serif;max-width:520px;margin:0 auto;background:#0B1F3A;color:#FDFCFA;padding:48px 40px;border-radius:8px;">
                <h2 style="font-family:Georgia,serif;color:#E2BF78;margin-bottom:8px;">Harmonização de Milhões</h2>
                <p style="color:rgba(253,252,250,0.5);font-size:12px;margin-bottom:32px;">Dr. Marco Maggi</p>
                <p style="font-size:15px;line-height:1.7;margin-bottom:28px;">
                    Pediste a recuperação da tua senha.<br>O teu código é:
                </p>
                <div style="background:rgba(200,153,58,0.12);border:1px solid rgba(200,153,58,0.3);border-radius:8px;padding:24px;text-align:center;margin-bottom:28px;">
                    <span style="font-size:40px;font-weight:700;letter-spacing:12px;color:#E2BF78;">${codigo}</span>
                </div>
                <p style="font-size:12px;color:rgba(253,252,250,0.35);line-height:1.6;">
                    Válido por 15 minutos.<br>
                    Se não pediste esta recuperação, ignora este email.
                </p>
            </div>`,
        });
    } catch (err) {
        console.error('Erro recuperar senha:', err.message);
    }
});


// ══════════════════════════════════════════════════════════════
// API — Nova senha
// ══════════════════════════════════════════════════════════════
app.post('/api/nova-senha', async (req, res) => {
    const { email, codigo, senha } = req.body;

    if (!email || !codigo || !senha)
        return res.status(400).json({ erro: 'Dados incompletos.' });

    const bloqueioCodigo = verificarBloqueioCodigo(email, req);
    if (bloqueioCodigo.bloqueado) {
        return res.status(429).json({
            erro: `Demasiadas tentativas incorretas. Tenta novamente em ${bloqueioCodigo.minutosRestantes} minuto(s).`,
            bloqueado: true,
        });
    }

    if (senha.length < 6)
        return res.status(400).json({ erro: 'A senha deve ter pelo menos 6 caracteres.' });

    const registo = stmts.buscarCodigo.get(email, 'recuperacao');

    if (!registo)
        return res.status(400).json({ erro: 'Código inválido ou expirado.' });

    if (new Date() > new Date(registo.expira_em))
        return res.status(400).json({ erro: 'Código expirado. Pede um novo.' });

    if (registo.codigo !== codigo.trim()) {
        const estado = registarTentativaCodigoFalhada(email, req);

        if (estado.bloqueadoAte) {
            return res.status(429).json({
                erro: 'Demasiadas tentativas incorretas. Pede um novo código mais tarde.',
                bloqueado: true,
            });
        }

        const restantes = MAX_TENTATIVAS_CODIGO - estado.tentativas;

        return res.status(400).json({
            erro: `Código incorreto. ${restantes} tentativa(s) restante(s).`,
        });
    }

    stmts.marcarCodigoUsado.run(registo.id);

    const senha_hash = await bcrypt.hash(senha, 12);
    stmts.atualizarSenha.run({ senha_hash, email });
    const user = stmts.buscarUserPorEmail.get(email);
    if (user) stmts.eliminarSessoesDoUser.run(user.id);

    // Limpar tentativas de login após recuperação de senha
    limparTentativas(email);
    limparTentativasCodigo(email, req);
    stmts.log.run('senha_alterada', email);

    res.json({ ok: true });
});


// ══════════════════════════════════════════════════════════════
// API — Checkout Stripe
// ══════════════════════════════════════════════════════════════
app.post('/api/checkout', limiterCheckout, auth, async (req, res) => {
    try {
        const slug = (req.body?.slug || 'harmonizacao-milhoes').trim();
        const product = stmts.buscarProductPorSlug.get(slug);

        if (!product) {
            return res.status(404).json({ erro: 'Produto não encontrado.' });
        }

        const priceId = product.stripe_price_id || process.env.STRIPE_PRICE_ID;
        if (!priceId) {
            return res.status(500).json({ erro: 'Preço Stripe não configurado para este produto.' });
        }

        const session = await stripe.checkout.sessions.create({
            mode: 'payment',
            line_items: [{ price: priceId, quantity: 1 }],
            success_url: `${BASE_URL}/pagamento-confirmado?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url:  `${BASE_URL}/sem-acesso`,
            customer_email: req.user.email,
            metadata: {
                user_email: req.user.email,
                product_id: String(product.id),
                product_slug: product.slug,
            },
        });

        stmts.log.run('checkout_criado', `${req.user.email}:${product.slug}`);
        res.json({ url: session.url, product: product.slug });
    } catch (err) {
        console.error('Erro checkout:', err.message);
        res.status(500).json({ erro: 'Não foi possível iniciar o pagamento.' });
    }
});
// ══════════════════════════════════════════════════════════════
// API — RGPD: Apagar conta
// ══════════════════════════════════════════════════════════════
app.delete('/api/conta', auth, (req, res) => {
    const id    = req.user.uid;
    const email = req.user.email;

    try {
        stmts.apagarSessoesUser.run(id);
        stmts.apagarCodigosUser.run(email);
        stmts.apagarTentativasUser.run(email, `${email}:%`);
        stmts.apagarLogsUser.run(email);
        stmts.apagarUser.run(id);

        res.clearCookie('sessao', {
            httpOnly: true,
            secure:   process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            path:     '/',
        });

        res.json({ ok: true });
    } catch (err) {
        console.error('Erro ao apagar conta:', err.message);
        res.status(500).json({ erro: 'Erro ao apagar conta. Tenta novamente.' });
    }
});


// ══════════════════════════════════════════════════════════════
// API — RGPD: Meus dados
// ══════════════════════════════════════════════════════════════
app.get('/api/meus-dados', auth, (req, res) => {
    const user = stmts.buscarUserPorEmail.get(req.user.email);
    if (!user) return res.status(404).json({ erro: 'Utilizador não encontrado.' });

    res.json({
        nome:      user.nome,
        email:     user.email,
        verificado: user.verificado === 1,
        pagou:     user.pagou === 1,
        criado_em: user.criado_em,
        exportado_em: new Date().toISOString(),
    });
});

// ══════════════════════════════════════════════════════════════
// Webhook Stripe
// ══════════════════════════════════════════════════════════════
async function webhookHandler(req, res) {
    console.log('🔔 Webhook recebido');
    const sig = req.headers['stripe-signature'];
    let evento;
    try {
        evento = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
    } catch (err) {
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }
    if (evento.type === 'checkout.session.completed') {
        const email    = evento.data.object.customer_details?.email || evento.data.object.metadata?.user_email;
        const stripeId = evento.data.object.id;
        if (email) {
            stmts.ativarAcesso.run({ email, stripe_id: stripeId });

            const userRow = stmts.buscarUserPorEmail.get(email);
            const productId = Number(evento.data.object.metadata?.product_id);
            if (userRow && productId) {
                stmts.registarPurchase.run({
                    user_id: userRow.id,
                    product_id: productId,
                    stripe_id: stripeId,
                });
            } else if (userRow) {
                const legacy = stmts.buscarProductPorSlug.get('harmonizacao-milhoes');
                if (legacy) {
                    stmts.registarPurchase.run({
                        user_id: userRow.id,
                        product_id: legacy.id,
                        stripe_id: stripeId,
                    });
                }
            }

            stmts.log.run('acesso_ativado', email);
            console.log(`✅ Acesso ativado via webhook: ${email}`);

            // Email de boas-vindas
            const user = stmts.buscarUserPorEmail.get(email);
            const nomeProrio = user?.nome?.split(' ')[0] || 'Doutor(a)';
            enviarEmail({
                para: email,
                assunto: '🎉 Acesso liberado — Harmonização de Milhões',
                html: `
    <div style="font-family:sans-serif;max-width:560px;margin:0 auto;background:#0B1F3A;color:#FDFCFA;padding:48px 40px;border-radius:8px;">
        <h2 style="font-family:Georgia,serif;color:#E2BF78;margin-bottom:4px;">Harmonização de Milhões</h2>
        <p style="color:rgba(253,252,250,0.4);font-size:11px;letter-spacing:2px;text-transform:uppercase;margin-bottom:36px;">Dr. Marco Maggi</p>

        <p style="font-size:17px;font-weight:600;margin-bottom:16px;">Olá, ${nomeProrio}! 👋</p>

        <p style="font-size:15px;line-height:1.75;color:rgba(253,252,250,0.8);margin-bottom:24px;">
            O teu pagamento foi confirmado e o acesso ao <strong style="color:#E2BF78">eBook + Videoaulas</strong> foi ativado com sucesso.
        </p>

        <a href="${BASE_URL}/produto" style="display:inline-block;background:linear-gradient(135deg,#C8993A,#A87A20);color:#0B1F3A;font-weight:700;font-size:15px;padding:15px 32px;border-radius:6px;text-decoration:none;margin-bottom:32px;">
            Aceder ao conteúdo →
        </a>

        <div style="border-top:1px solid rgba(200,153,58,0.15);padding-top:24px;margin-top:8px;">
            <p style="font-size:13px;color:rgba(253,252,250,0.45);line-height:1.7;">
                O teu acesso é vitalício — podes entrar a qualquer momento em <a href="${BASE_URL}/login" style="color:#C8993A;">${BASE_URL}/login</a>.<br>
                Qualquer questão, responde a este email.
            </p>
        </div>
    </div>`,
            });
        }
    }

    // ── Reembolso ────────────────────────────────────────────
    if (evento.type === 'charge.refunded') {
        const charge = evento.data.object;
        const email  = charge.billing_details?.email || charge.receipt_email;

        if (email) {
            stmts.revogarAcesso.run({ email });
            stmts.log.run('acesso_revogado_reembolso', email);
            console.log(`↩️ Acesso revogado por reembolso: ${email}`);
        }
    }

    // ── Disputa / chargeback ────────────────────────────────
    if (evento.type === 'charge.dispute.created') {
        const dispute   = evento.data.object;
        const chargeId  = dispute.charge;
        try {
            const charge = await stripe.charges.retrieve(chargeId);
            const email  = charge.billing_details?.email || charge.receipt_email;
            if (email) {
                stmts.revogarAcesso.run({ email });
                stmts.log.run('acesso_revogado_disputa', email);
                console.log(`⚠️ Acesso revogado por disputa/chargeback: ${email}`);
            }
        } catch (err) {
            console.error('Erro ao buscar charge da disputa:', err.message);
        }
    }

    res.json({ recebido: true });
}


// ══════════════════════════════════════════════════════════════
// 404
// ══════════════════════════════════════════════════════════════
app.use((req, res) => res.status(404).redirect('/'));



// Limpa sessões expiradas uma vez por dia
setInterval(() => {
    stmts.limparSessoesExpiradas.run();
    console.log('🧹 Sessões expiradas limpas');
}, 24 * 60 * 60 * 1000);


app.listen(PORT, () => {
    console.log(`
  ╔══════════════════════════════════════╗
  ║   Harmonização de Milhões — Backend  ║
  ╠══════════════════════════════════════╣
  ║  http://localhost:${PORT}              ║
  ║  Base de dados: vendas.db            ║
  ║  Modo: ${process.env.NODE_ENV || 'development'}                   ║
  ╚══════════════════════════════════════╝
  `)
});
