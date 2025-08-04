const express = require('express');
const bodyParser = require('body-parser');
const OpenAI = require('openai');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

// Configuração do MySQL com pool de conexões
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'aluno',
  password: process.env.DB_PASSWORD || 'aluno',
  database: process.env.DB_NAME || 'cuidamente',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  acquireTimeout: 60000,
  timeout: 60000
});

// Configuração do OpenAI
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

const app = express();

// Middlewares básicos
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));
app.use(bodyParser.json({ limit: '10mb' }));
app.use(express.static('public')); // Para servir arquivos estáticos

// Rate limiting
const chatLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 50, // máximo 50 mensagens por IP
  message: { error: 'Muitas mensagens. Tente novamente em 15 minutos.' },
  standardHeaders: true,
  legacyHeaders: false
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 10, // máximo 10 tentativas de login/registro
  message: { error: 'Muitas tentativas. Tente novamente em 15 minutos.' }
});

// Middleware de autenticação JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token não fornecido' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido ou expirado' });
    }
    req.user = user;
    next();
  });
};

// Prompt base do sistema melhorado
const getSystemPrompt = (userProfile = null) => {
  let basePrompt = `Você é CuidaMente, um assistente de apoio emocional especializado em bem-estar mental.

SUAS ESPECIALIDADES:
- Ansiedade, depressão, TDAH e neurodivergência
- Técnicas de mindfulness e respiração
- Identificação de padrões emocionais
- Sugestões de atividades terapêuticas
- Apoio empático e acolhedor

DIRETRIZES IMPORTANTES:
1. Seja sempre empático, caloroso e compreensivo
2. Use linguagem acessível e acolhedora
3. Faça perguntas reflexivas quando apropriado
4. Sugira técnicas práticas quando relevante
5. NUNCA substitua terapia profissional - sempre incentive buscar ajuda especializada quando necessário
6. Se detectar sinais de crise ou pensamentos autodestrutivos, oriente imediatamente a procurar ajuda profissional

TÉCNICAS QUE VOCÊ PODE SUGERIR:
- Exercícios de respiração (4-7-8, respiração quadrada)
- Técnicas de grounding (5-4-3-2-1)
- Mindfulness básico
- Diário emocional
- Atividades de autocuidado
- Técnicas de relaxamento muscular

Responda de forma natural, empática e prática. Mantenha o foco no bem-estar emocional do usuário.`;

  if (userProfile && userProfile.emotional_state) {
    basePrompt += `\n\nCONTEXTO DO USUÁRIO: O usuário está passando por: ${userProfile.emotional_state}`;
    
    if (userProfile.conditions) {
      try {
        const conditions = JSON.parse(userProfile.conditions);
        basePrompt += `\nCondições relatadas: ${conditions.join(', ')}`;
      } catch (e) {
        basePrompt += `\nCondições relatadas: ${userProfile.conditions}`;
      }
    }
    
    if (userProfile.goals) {
      basePrompt += `\nObjetivos do usuário: ${userProfile.goals}`;
    }
  }

  return basePrompt;
};

// Middleware de logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// Rota de health check
app.get('/health', authenticateToken, (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ROTAS DE AUTENTICAÇÃO
app.post('/register', authLimiter, async (req, res) => {
  const { username, password } = req.body;

  // Validações
  if (!username || !password) {
    return res.status(400).json({ error: 'Usuário e senha são obrigatórios' });
  }

  if (username.length < 3) {
    return res.status(400).json({ error: 'Usuário deve ter pelo menos 3 caracteres' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: 'Senha deve ter pelo menos 6 caracteres' });
  }

  try {
    // Verificar se usuário já existe
    const [users] = await pool.query('SELECT id FROM users WHERE username = ?', [username]);
    if (users.length > 0) {
      return res.status(400).json({ error: 'Usuário já existe' });
    }

    // Criar usuário
    const hashedPassword = await bcrypt.hash(password, 12);
    const [result] = await pool.query(
      'INSERT INTO users (username, password, created_at) VALUES (?, ?, NOW())',
      [username, hashedPassword]
    );

    console.log(`Novo usuário registrado: ${username} (ID: ${result.insertId})`);
    res.status(201).json({ message: 'Usuário criado com sucesso' });

  } catch (error) {
    console.error('Erro no registro:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.post('/login', authLimiter, async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Usuário e senha são obrigatórios' });
  }

  try {
    const [users] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (users.length === 0) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    const user = users[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    // Atualizar último login
    await pool.query('UPDATE users SET last_login = NOW() WHERE id = ?', [user.id]);

    const token = jwt.sign(
      { userId: user.id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    console.log(`Login realizado: ${username} (ID: ${user.id})`);
    res.json({ 
      token,
      user: {
        id: user.id,
        username: user.username
      }
    });

  } catch (error) {
    console.error('Erro no login:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// ROTAS DE PERFIL
app.post('/profile', authenticateToken, async (req, res) => {
  const { age, emotional_state, conditions, goals } = req.body;
  const userId = req.user.userId;

  try {
    await pool.query(`
      INSERT INTO user_profiles (user_id, age, emotional_state, conditions, goals, updated_at) 
      VALUES (?, ?, ?, ?, ?, NOW())
      ON DUPLICATE KEY UPDATE 
        age = VALUES(age),
        emotional_state = VALUES(emotional_state),
        conditions = VALUES(conditions),
        goals = VALUES(goals),
        updated_at = NOW()
    `, [userId, age, emotional_state, JSON.stringify(conditions), goals]);

    res.json({ message: 'Perfil atualizado com sucesso' });
  } catch (error) {
    console.error('Erro ao salvar perfil:', error);
    res.status(500).json({ error: 'Erro ao salvar perfil' });
  }
});

app.get('/profile', authenticateToken, async (req, res) => {
  const userId = req.user.userId;

  try {
    const [profiles] = await pool.query('SELECT * FROM user_profiles WHERE user_id = ?', [userId]);
    
    if (profiles.length === 0) {
      return res.json({ profile: null });
    }

    const profile = profiles[0];
    if (profile.conditions) {
      try {
        profile.conditions = JSON.parse(profile.conditions);
      } catch (e) {
        // Se não conseguir fazer parse, manter como string
      }
    }

    res.json({ profile });
  } catch (error) {
    console.error('Erro ao buscar perfil:', error);
    res.status(500).json({ error: 'Erro ao buscar perfil' });
  }
});

// ROTA DO CHATBOT
app.post('/chat', chatLimiter, authenticateToken, async (req, res) => {
  try {
    const { message, history = [] } = req.body;
    const userId = req.user.userId;

    if (!message || message.trim().length === 0) {
      return res.status(400).json({ error: 'Mensagem não pode estar vazia' });
    }

    if (message.length > 1000) {
      return res.status(400).json({ error: 'Mensagem muito longa (máximo 1000 caracteres)' });
    }

    // Buscar perfil do usuário
    const [profiles] = await pool.query('SELECT * FROM user_profiles WHERE user_id = ?', [userId]);
    const userProfile = profiles[0] || null;

    // Preparar mensagens para OpenAI
    const messages = [
      { role: "system", content: getSystemPrompt(userProfile) },
      ...history.slice(-10), // Manter apenas últimas 10 mensagens para controle de contexto
      { role: "user", content: message }
    ];

    // Chamar OpenAI
    const completion = await openai.chat.completions.create({
      model: "gpt-4",
      messages,
      temperature: 0.7,
      max_tokens: 500,
      presence_penalty: 0.1,
      frequency_penalty: 0.1
    });

    const reply = completion.choices[0].message.content;

    // Salvar conversa no banco
    await pool.query(`
      INSERT INTO conversations (user_id, user_message, bot_response, created_at, tokens_used) 
      VALUES (?, ?, ?, NOW(), ?)
    `, [userId, message, reply, completion.usage.total_tokens]);

    console.log(`Conversa salva para usuário ${userId} - Tokens: ${completion.usage.total_tokens}`);

    res.json({ reply });

  } catch (error) {
    console.error('Erro no chat:', error);
    
    if (error.code === 'insufficient_quota' || error.status === 429) {
      res.status(429).json({ error: 'Serviço temporariamente indisponível. Tente novamente em alguns minutos.' });
    } else if (error.status === 401) {
      res.status(401).json({ error: 'Erro de autenticação com o serviço de IA' });
    } else {
      res.status(500).json({ error: 'Erro ao processar sua mensagem. Tente novamente.' });
    }
  }
});

// ROTA PARA HISTÓRICO DE CONVERSAS
app.get('/conversations', authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  const { limit = 50, offset = 0 } = req.query;

  try {
    const [conversations] = await pool.query(`
      SELECT user_message, bot_response, created_at 
      FROM conversations 
      WHERE user_id = ? 
      ORDER BY created_at DESC 
      LIMIT ? OFFSET ?
    `, [userId, parseInt(limit), parseInt(offset)]);

    res.json({ conversations });
  } catch (error) {
    console.error('Erro ao buscar conversas:', error);
    res.status(500).json({ error: 'Erro ao buscar histórico' });
  }
});

// ROTA PARA ESTATÍSTICAS DO USUÁRIO
app.get('/stats', authenticateToken, async (req, res) => {
  const userId = req.user.userId;

  try {
    const [stats] = await pool.query(`
      SELECT 
        COUNT(*) as total_conversations,
        DATE(created_at) as conversation_date,
        COUNT(*) as daily_count
      FROM conversations 
      WHERE user_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
      GROUP BY DATE(created_at)
      ORDER BY conversation_date DESC
    `, [userId]);

    const [totalStats] = await pool.query(`
      SELECT 
        COUNT(*) as total_messages,
        SUM(tokens_used) as total_tokens,
        MIN(created_at) as first_conversation
      FROM conversations 
      WHERE user_id = ?
    `, [userId]);

    res.json({ 
      daily_stats: stats,
      total_stats: totalStats[0] 
    });
  } catch (error) {
    console.error('Erro ao buscar estatísticas:', error);
    res.status(500).json({ error: 'Erro ao buscar estatísticas' });
  }
});

// Middleware de tratamento de erros
app.use((error, req, res, next) => {
  console.error('Erro não tratado:', error);
  res.status(500).json({ error: 'Erro interno do servidor' });
});

// Middleware para rotas não encontradas
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Rota não encontrada' });
});

// Inicialização do servidor
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`🧠 CuidaMente Server rodando na porta ${PORT}`);
  console.log(`📅 Iniciado em: ${new Date().toISOString()}`);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('Encerrando servidor...');
  await pool.end();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('Encerrando servidor...');
  await pool.end();
  process.exit(0);
});