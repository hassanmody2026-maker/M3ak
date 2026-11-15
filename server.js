'use strict';

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const OpenAI = require('openai');
const admin = require('firebase-admin');

const app = express();

app.disable('x-powered-by');
app.set('trust proxy', 1);

const PORT = Number(process.env.PORT || 3000);
const MODEL = process.env.OPENAI_MODEL || 'gpt-4o-mini';

if (!process.env.OPENAI_API_KEY) {
  console.error('FATAL: OPENAI_API_KEY is missing.');
  process.exit(1);
}

if (!process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
  console.error('FATAL: Firebase credentials are missing.');
  process.exit(1);
}

if (
  process.env.NODE_ENV === 'production' &&
  (!process.env.CORS_ORIGIN ||
   process.env.CORS_ORIGIN.includes('YOUR-FRONTEND'))
) {
  console.error('FATAL: Configure CORS_ORIGIN.');
  process.exit(1);
}

// Firebase Admin initialization
let serviceAccount;

try {
  serviceAccount = JSON.parse(
    process.env.FIREBASE_SERVICE_ACCOUNT_JSON
  );
} catch (error) {
  console.error('FATAL: Invalid Firebase service account JSON.');
  process.exit(1);
}

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}

// OpenAI initialization
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

// Security
app.use(helmet());

const allowedOrigins = (process.env.CORS_ORIGIN ||
  'http://localhost:3000')
  .split(',')
  .map(origin => origin.trim())
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
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({
  limit: '8mb'
}));

// API rate limiting
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

// Firebase authentication middleware
async function requireFirebaseAuth(req, res, next) {
  const authorization = req.headers.authorization || '';
  const match = authorization.match(/^Bearer (.+)$/i);

  if (!match) {
    return res.status(401).json({
      error: 'يلزم تسجيل الدخول أولًا.'
    });
  }

  try {
    const decoded = await admin.auth().verifyIdToken(
      match[1],
      true
    );

    req.user = {
      uid: decoded.uid,
      email: decoded.email || null
    };

    next();

  } catch (error) {
    return res.status(401).json({
      error: 'جلسة الدخول غير صالحة. سجّل الدخول مرة أخرى.'
    });
  }
}

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'm3ak-api'
  });
});

// AI assistant endpoint
app.post(
  '/api/ai/chat',
  requireFirebaseAuth,
  async (req, res) => {

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

      const content = [];

      if (message) {
        content.push({
          type: 'text',
          text: message
        });
      }

      if (image) {
        const validImage =
          /^data:image\/(png|jpeg|jpg|webp);base64,[A-Za-z0-9+/=]+$/
            .test(image);

        if (!validImage || image.length > 7 * 1024 * 1024) {
          return res.status(400).json({
            error: 'صيغة الصورة غير مدعومة أو حجمها كبير.'
          });
        }

        content.push({
          type: 'image_url',
          image_url: {
            url: image,
            detail: 'auto'
          }
        });
      }

      const completion =
        await openai.chat.completions.create({

          model: MODEL,

          messages: [
            {
              role: 'system',
              content:
                'أنت المساعد الذكي داخل تطبيق معاك M3AK. ' +
                'أجب باللغة العربية الواضحة وبأسلوب مصري ودود. ' +
                'قدّم معلومات عملية ودقيقة. ' +
                'إذا لم تعرف الإجابة فقل ذلك بوضوح. ' +
                'لا تدّع تنفيذ حجز أو شراء أو إجراء لم تنفذه.'
            },
            {
              role: 'user',
              content
            }
          ],

          max_tokens: 1200
        });

      const reply =
        completion.choices?.[0]?.message?.content;

      if (!reply) {
        throw new Error('Empty AI response');
      }

      return res.json({
        reply,
        usage: completion.usage || null
      });

    } catch (error) {

      console.error(
        'AI chat error:',
        error.status || error.message || 'unknown'
      );

      if (error.status === 429) {
        return res.status(503).json({
          error: 'المساعد مشغول حاليًا. حاول بعد قليل.'
        });
      }

      return res.status(502).json({
        error: 'تعذر الحصول على رد الآن. حاول مرة أخرى.'
      });
    }
  }
);

// General error handler
app.use((err, req, res, next) => {

  if (err.message === 'Origin not allowed by CORS') {
    return res.status(403).json({
      error: 'هذا النطاق غير مسموح له بالاتصال بالخادم.'
    });
  }

  console.error('Request error:', err.message);

  return res.status(500).json({
    error: 'حدث خطأ داخلي.'
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`M3AK API listening on port ${PORT}`);
});
