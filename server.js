'use strict';

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const OpenAI = require('openai');
const admin = require('firebase-admin');
const { Pool } = require('pg');

const app = express();

app.disable('x-powered-by');
app.set('trust proxy', 1);

const PORT = Number(process.env.PORT || 3000);
const MODEL = process.env.OPENAI_MODEL || 'gpt-4o-mini';

const requiredEnv = [
  'OPENAI_API_KEY',
  'FIREBASE_SERVICE_ACCOUNT_JSON',
  'DATABASE_URL'
];

for (const key of requiredEnv) {
  if (!process.env[key]) {
    console.error(
      'FATAL: Required environment variable is missing:',
      key
    );
    process.exit(1);
  }
}

if (
  process.env.NODE_ENV === 'production' &&
  (
    !process.env.CORS_ORIGIN ||
    process.env.CORS_ORIGIN.includes('your-frontend-domain')
  )
) {
  console.error(
    'FATAL: Configure CORS_ORIGIN with your real frontend origin.'
  );
  process.exit(1);
}

// ========================================
// PostgreSQL
// ========================================

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: Number(process.env.PG_POOL_MAX || 10),
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

pool.on('error', (error) => {
  console.error(
    'Unexpected PostgreSQL pool error:',
    error.message
  );
});

// ========================================
// Firebase Admin
// ========================================

let serviceAccount;

try {
  serviceAccount = JSON.parse(
    process.env.FIREBASE_SERVICE_ACCOUNT_JSON
  );
} catch (error) {
  console.error(
    'FATAL: FIREBASE_SERVICE_ACCOUNT_JSON is not valid JSON.'
  );
  process.exit(1);
}

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}

// ========================================
// OpenAI
// ========================================

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

// ========================================
// Security
// ========================================

app.use(helmet());

const allowedOrigins = (
  process.env.CORS_ORIGIN || 'http://localhost:3000'
)
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    return callback(
      new Error('Origin not allowed by CORS')
    );
  },

  methods: ['GET', 'POST'],

  allowedHeaders: [
    'Content-Type',
    'Authorization'
  ]
}));

app.use(express.json({
  limit: '8mb'
}));

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-7',
  legacyHeaders: false,

  message: {
    error: 'تم تجاوز عدد الطلبات مؤقتًا. حاول مرة أخرى.'
  }
});

app.use('/api/', apiLimiter);

// ========================================
// Database transaction helper
// ========================================

async function withTransaction(callback) {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const result = await callback(client);

    await client.query('COMMIT');

    return result;

  } catch (error) {

    await client.query('ROLLBACK');

    throw error;

  } finally {

    client.release();

  }
}

// ========================================
// Firebase authentication
// ========================================

async function requireFirebaseAuth(req, res, next) {

  const authorization =
    req.headers.authorization || '';

  const match = authorization.match(
    /^Bearer (.+)$/i
  );

  if (!match) {
    return res.status(401).json({
      error: 'يلزم تسجيل الدخول أولًا.'
    });
  }

  let decoded;

  try {

    decoded = await admin
      .auth()
      .verifyIdToken(match[1], true);

  } catch (error) {

    return res.status(401).json({
      error: 'جلسة الدخول غير صالحة. سجّل الدخول مرة أخرى.'
    });

  }

  try {

    const result = await pool.query(

      `INSERT INTO app_users
       (firebase_uid, email)
       VALUES ($1, $2)

       ON CONFLICT (firebase_uid)
       DO UPDATE SET
         email = COALESCE(
           EXCLUDED.email,
           app_users.email
         ),
         updated_at = NOW()

       RETURNING
         id,
         firebase_uid,
         email,
         role,
         account_status`,

      [
        decoded.uid,
        decoded.email || null
      ]

    );

    const user = result.rows[0];

    if (user.account_status !== 'active') {

      return res.status(403).json({
        error: 'هذا الحساب غير متاح حاليًا. تواصل مع الدعم.'
      });

    }

    req.user = {
      id: user.id,
      uid: user.firebase_uid,
      email: user.email,
      role: user.role
    };

    return next();

  } catch (error) {

    console.error(
      'User database error:',
      error.message
    );

    return res.status(503).json({
      error: 'خدمة الحسابات غير متاحة مؤقتًا.'
    });

  }

}

// ========================================
// Health check
// ========================================

app.get('/api/health', async (req, res) => {

  try {

    await pool.query('SELECT 1');

    return res.json({
      status: 'ok',
      service: 'm3ak-api',
      database: 'connected'
    });

  } catch (error) {

    console.error(
      'Health database check failed:',
      error.message
    );

    return res.status(503).json({
      status: 'degraded',
      service: 'm3ak-api',
      database: 'disconnected'
    });

  }

});

// ========================================
// AI assistant
// ========================================

app.post(
  '/api/ai/chat',
  requireFirebaseAuth,
  async (req, res) => {

    let conversationId = null;

    try {

      const message =
        typeof req.body.message === 'string'
          ? req.body.message.trim()
          : '';

      const image =
        typeof req.body.image === 'string'
          ? req.body.image
          : null;

      if (!message && !image) {

        return res.status(400).json({
          error: 'اكتب سؤالك أو أرفق صورة.'
        });

      }

      if (message.length > 6000) {

        return res.status(400).json({
          error: 'الرسالة أطول من الحد المسموح.'
        });

      }

      if (image) {

        const validImage =
          /^data:image\/(png|jpeg|jpg|webp);base64,[A-Za-z0-9+/=]+$/
            .test(image);

        if (
          !validImage ||
          image.length > 7 * 1024 * 1024
        ) {

          return res.status(400).json({
            error: 'صيغة الصورة غير مدعومة أو حجمها كبير.'
          });

        }

      }

      const suppliedConversationId =
        req.body.conversationId;

      if (
        suppliedConversationId !== undefined &&
        (
          !/^\d+$/.test(
            String(suppliedConversationId)
          ) ||
          !Number.isSafeInteger(
            Number(suppliedConversationId)
          )
        )
      ) {

        return res.status(400).json({
          error: 'رقم المحادثة غير صالح.'
        });

      }

      // Find an existing conversation owned by this user,
      // or create a new conversation.

      if (suppliedConversationId !== undefined) {

        const existing = await pool.query(

          `SELECT id
           FROM conversations
           WHERE id = $1
           AND user_id = $2`,

          [
            String(suppliedConversationId),
            req.user.id
          ]

        );

        if (!existing.rowCount) {

          return res.status(404).json({
            error: 'المحادثة غير موجودة أو لا تملك صلاحية الوصول إليها.'
          });

        }

        conversationId = existing.rows[0].id;

      } else {

        const title = message
          ? message.slice(0, 80)
          : 'محادثة بصورة';

        const created = await pool.query(

          `INSERT INTO conversations
           (user_id, title)
           VALUES ($1, $2)
           RETURNING id`,

          [
            req.user.id,
            title
          ]

        );

        conversationId = created.rows[0].id;

      }

      // Save user message.

      await pool.query(

        `INSERT INTO conversation_messages
         (
           conversation_id,
           sender,
           message_text,
           image_reference
         )

         VALUES ($1, 'user', $2, $3)`,

        [
          conversationId,

          message ||
            (image ? '[صورة مرفقة]' : ''),

          image
            ? 'image_attached_not_persisted'
            : null
        ]

      );

      // Load recent conversation history.

      const historyResult = await pool.query(

        `SELECT sender, message_text

         FROM conversation_messages

         WHERE conversation_id = $1

         ORDER BY created_at DESC, id DESC

         LIMIT 20`,

        [conversationId]

      );

      const history = historyResult.rows
        .reverse()
        .map((row) => ({

          role:
            row.sender === 'assistant'
              ? 'assistant'
              : 'user',

          content: row.message_text || ''

        }));

      // Send image only to OpenAI.
      // Original image data is not stored in PostgreSQL.

      if (image && history.length) {

        const currentMessage =
          history[history.length - 1];

        const parts = [];

        if (currentMessage.content) {

          parts.push({
            type: 'text',
            text: currentMessage.content
          });

        }

        parts.push({

          type: 'image_url',

          image_url: {
            url: image,
            detail: 'auto'
          }

        });

        currentMessage.content = parts;

      }

      // Request AI response.

      const completion =
        await openai.chat.completions.create({

          model: MODEL,

          messages: [

            {
              role: 'system',

              content:
                'أنت المساعد الذكي داخل تطبيق معاك M3AK. ' +
                'أجب باللغة العربية الواضحة وبأسلوب مصري ودود. ' +
                'قدّم معلومات عملية ودقيقة. إذا لم تعرف الإجابة فقل ذلك بوضوح. ' +
                'لا تدّع تنفيذ حجز أو شراء أو إجراء لم تنفذه.'
            },

            ...history

          ],

          max_tokens: 1200

        });

      const reply =
        completion.choices?.[0]?.message?.content;

      if (!reply || typeof reply !== 'string') {

        throw new Error('Empty AI response');

      }

      const usage =
        completion.usage || {};

      // Save assistant response and token usage.

      await withTransaction(async (client) => {

        await client.query(

          `INSERT INTO conversation_messages
           (
             conversation_id,
             sender,
             message_text
           )

           VALUES ($1, 'assistant', $2)`,

          [
            conversationId,
            reply
          ]

        );

        await client.query(

          `UPDATE conversations

           SET updated_at = NOW()

           WHERE id = $1
           AND user_id = $2`,

          [
            conversationId,
            req.user.id
          ]

        );

        await client.query(

          `INSERT INTO ai_request_logs
           (
             user_id,
             model_name,
             input_tokens,
             output_tokens,
             request_status
           )

           VALUES ($1, $2, $3, $4, 'success')`,

          [
            req.user.id,
            MODEL,
            Number(usage.prompt_tokens || 0),
            Number(usage.completion_tokens || 0)
          ]

        );

      });

      return res.json({

        reply,

        conversationId,

        usage: completion.usage || null

      });

    } catch (error) {

      console.error(
        'AI chat/database error:',
        error.status ||
        error.code ||
        error.message ||
        'unknown'
      );

      if (req.user?.id) {

        try {

          await pool.query(

            `INSERT INTO ai_request_logs
             (user_id, model_name, request_status)

             VALUES ($1, $2, 'failed')`,

            [
              req.user.id,
              MODEL
            ]

          );

        } catch (logError) {

          console.error(
            'Failed to save AI error log:',
            logError.message
          );

        }

      }

      if (error.status === 429) {

        return res.status(503).json({
          error: 'المساعد مشغول حاليًا. حاول بعد قليل.'
        });

      }

      if (
        error.code === 'ECONNREFUSED' ||
        error.code === 'ENOTFOUND' ||
        error.code === 'ETIMEDOUT' ||
        error.code === '57P01'
      ) {

        return res.status(503).json({
          error: 'قاعدة البيانات غير متاحة حاليًا. حاول بعد قليل.'
        });

      }

      return res.status(502).json({
        error: 'تعذر الحصول على رد الآن. حاول مرة أخرى.'
      });

    }

  }

);

// ========================================
// Central error handler
// ========================================

app.use((err, req, res, next) => {

  if (err.message === 'Origin not allowed by CORS') {

    return res.status(403).json({
      error: 'هذا النطاق غير مسموح له بالاتصال بالخادم.'
    });

  }

  if (err.type === 'entity.too.large') {

    return res.status(413).json({
      error: 'حجم الطلب أكبر من الحد المسموح.'
    });

  }

  console.error(
    'Request error:',
    err.message
  );

  return res.status(500).json({
    error: 'حدث خطأ داخلي.'
  });

});

// ========================================
// Start server
// ========================================

async function startServer() {

  try {

    // Do not start API until PostgreSQL is reachable.

    await pool.query('SELECT 1');

    console.log(
      'PostgreSQL connection established.'
    );

    const server = app.listen(
      PORT,
      () => {
        console.log(
          'M3AK API listening on port ' + PORT
        );
      }
    );

    const shutdown = (signal) => {

      console.log(
        signal + ' received. Shutting down gracefully.'
      );

      server.close(async () => {

        await pool.end();

        process.exit(0);

      });

    };

    process.once(
      'SIGTERM',
      () => shutdown('SIGTERM')
    );

    process.once(
      'SIGINT',
      () => shutdown('SIGINT')
    );

  } catch (error) {

    console.error(
      'FATAL: Could not connect to PostgreSQL:',
      error.message
    );

    await pool.end().catch(() => {});

    process.exit(1);

  }

}

startServer();
