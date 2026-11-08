/**
 * M3AK - Backend API
 * PostgreSQL + Firebase Auth + Paymob
 */

require('dotenv').config();

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto');
const axios = require('axios');
const {
  QuotaError,
  reserveAiQuota,
  markProviderSucceeded,
  settleAiReservation,
  refundAiReservation,
  markAiReservationUnknown
} = require('./services/ai_quota_service');
const nodemailer = require('nodemailer');
const admin = require('firebase-admin');
const { Pool } = require('pg');

const app = express();

const PORT = Number(process.env.PORT || 3000);
const TRUST_PROXY = process.env.TRUST_PROXY === 'true';
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const JWT_SECRET = process.env.JWT_SECRET;

if (TRUST_PROXY) {
  app.set('trust proxy', 1);
}

if (IS_PRODUCTION && (!JWT_SECRET || JWT_SECRET.length < 32)) {
  throw new Error('JWT_SECRET must be set to a random value of at least 32 characters in production.');
}

if (!JWT_SECRET) {
  console.warn('WARNING: Using a development-only JWT secret.');
}

const ACTIVE_JWT_SECRET = JWT_SECRET || crypto.randomBytes(48).toString('hex');

if (!process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL is required.');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: IS_PRODUCTION ? { rejectUnauthorized: true } : false,
  max: Number(process.env.DB_POOL_MAX || 10),
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

pool.on('error', err => {
  console.error('Unexpected PostgreSQL pool error:', err);
});

const allowedOrigins = (process.env.FRONTEND_URL || '')
  .split(',')
  .map(v => v.trim())
  .filter(Boolean);

app.use(cors({
  origin(origin, callback) {
    if (!origin || !IS_PRODUCTION || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('Origin not allowed by CORS'));
  },
  optionsSuccessStatus: 200
}));

app.use(express.json({ limit: '2mb' }));

// Firebase Admin
let firebaseReady = false;

if (
  process.env.FIREBASE_PROJECT_ID &&
  process.env.FIREBASE_CLIENT_EMAIL &&
  process.env.FIREBASE_PRIVATE_KEY
) {
  if (!admin.apps.length) {
    admin.initializeApp({
      credential: admin.credential.cert({
        projectId: process.env.FIREBASE_PROJECT_ID,
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
        privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n')
      })
    });
  }

  firebaseReady = true;
}

// Email transporter
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: Number(process.env.SMTP_PORT || 587) === 465,
  auth: process.env.SMTP_USER
    ? {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    : undefined
});

const TRIAL_HOURS = 96;
const PASSWORD_RESET_MINUTES = 15;

function asyncRoute(handler) {
  return (req, res, next) =>
    Promise.resolve(handler(req, res, next)).catch(next);
}

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function normalizePaymobPhone(value) {
  let phone = String(value || '').replace(/[\s()-]/g, '');

  if (/^01[0125]\d{8}$/.test(phone)) {
    phone = `+2${phone}`;
  }

  if (/^20\d{10}$/.test(phone)) {
    phone = `+${phone}`;
  }

  if (!/^\+?\d{8,15}$/.test(phone)) {
    throw new Error(
      'رقم الهاتف المسجل غير صالح لإتمام الدفع. حدّث رقمك من الملف الشخصي.'
    );
  }

  return phone.startsWith('+') ? phone : `+${phone}`;
}

function safeEqualHex(a, b) {
  if (
    typeof a !== 'string' ||
    typeof b !== 'string' ||
    !/^[a-f0-9]{128}$/i.test(a) ||
    !/^[a-f0-9]{128}$/i.test(b)
  ) {
    return false;
  }

  const aa = Buffer.from(a, 'hex');
  const bb = Buffer.from(b, 'hex');

  return crypto.timingSafeEqual(aa, bb);
}

// Rate limiter
function atomicRateLimiter(windowMs, maxHits, endpointName) {
  return asyncRoute(async (req, res, next) => {
    const ip = String(
      req.ip || req.socket.remoteAddress || 'unknown'
    ).slice(0, 45);

    const now = Date.now();

    const result = await pool.query(
      `INSERT INTO rate_limits
       (ip, endpoint, hit_count, window_start)
       VALUES ($1, $2, 1, $3)
       ON CONFLICT (ip, endpoint) DO UPDATE
       SET hit_count = CASE
             WHEN rate_limits.window_start <= $3 - $4 THEN 1
             ELSE rate_limits.hit_count + 1
           END,
           window_start = CASE
             WHEN rate_limits.window_start <= $3 - $4 THEN $3
             ELSE rate_limits.window_start
           END
       RETURNING hit_count`,
      [ip, endpointName, now, windowMs]
    );

    if (Number(result.rows[0].hit_count) > maxHits) {
      return res.status(429).json({
        error: 'تم تجاوز الحد الأقصى للطلبات. يرجى المحاولة لاحقاً.'
      });
    }

    return next();
  });
}

// Authentication
const verifyToken = asyncRoute(async (req, res, next) => {
  const authHeader = req.headers.authorization || '';
  const [scheme, token, extra] = authHeader.trim().split(/\s+/);

  if (scheme !== 'Bearer' || !token || extra) {
    return res.status(401).json({
      error: 'مطلوب توكن المصادقة.'
    });
  }

  let decoded;

  try {
    decoded = jwt.verify(token, ACTIVE_JWT_SECRET);
  } catch {
    return res.status(401).json({
      error: 'جلسة العمل منتهية أو غير صالحة.'
    });
  }

  const result = await pool.query(
    `SELECT id, email, phone, role, token_version,
            is_subscribed, trial_started_at,
            subscription_expires_at
     FROM users
     WHERE id = $1`,
    [decoded.id]
  );

  if (!result.rows.length) {
    return res.status(401).json({
      error: 'المستخدم غير موجود.'
    });
  }

  const user = result.rows[0];

  if (
    Number(decoded.tokenVersion) !==
    Number(user.token_version)
  ) {
    return res.status(401).json({
      error: 'تم إبطال هذه الجلسة. يرجى تسجيل الدخول مجدداً.'
    });
  }

  req.user = {
    id: user.id,
    email: user.email,
    phone: user.phone,
    role: user.role,
    is_subscribed: user.is_subscribed,
    trial_started_at: user.trial_started_at,
    subscription_expires_at: user.subscription_expires_at
  };

  return next();
});

// Admin authorization
const verifyAdmin = [
  verifyToken,
  (req, res, next) => {
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        error: 'غير مسموح. صلاحيات مدير مطلوبة.'
      });
    }

    return next();
  }
];

// Trial and subscription verification
const verifyTrialOrSubscription = asyncRoute(async (req, res, next) => {
  if (req.user.role === 'admin') {
    return next();
  }

  const now = Date.now();

  if (
    req.user.is_subscribed &&
    req.user.subscription_expires_at &&
    new Date(req.user.subscription_expires_at).getTime() > now
  ) {
    return next();
  }

  if (!req.user.trial_started_at) {
    return res.status(403).json({
      error: 'لم تبدأ فترة التجربة المجانية بعد.'
    });
  }

  const trialEnd =
    new Date(req.user.trial_started_at).getTime() +
    TRIAL_HOURS * 60 * 60 * 1000;

  if (now >= trialEnd) {
    return res.status(403).json({
      error: 'انتهت فترة التجربة المجانية (96 ساعة). يرجى الاشتراك للاستمرار.'
    });
  }

  return next();
});

// JWT creation
function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      tokenVersion: Number(user.token_version)
    },
    ACTIVE_JWT_SECRET,
    { expiresIn: '7d' }
  );
}

// Get package
async function getPackageById(packageId) {
  const result = await pool.query(
    `SELECT id, name, price, duration_days,
            max_words, max_images
     FROM packages
     WHERE id = $1`,
    [packageId]
  );

  return result.rows[0] || null;
                          }
// Health check
app.get('/health', asyncRoute(async (req, res) => {
  await pool.query('SELECT 1');

  res.json({
    success: true,
    status: 'ok'
  });
}));

// Registration
app.post(
  '/api/auth/register',
  atomicRateLimiter(15 * 60 * 1000, 5, 'register'),
  asyncRoute(async (req, res) => {
    const {
      name,
      phone,
      password,
      firebaseIdToken,
      agreedTerms,
      agreedPrivacy
    } = req.body;

    const email = normalizeEmail(req.body.email);

    if (
      !name ||
      !email ||
      !phone ||
      !password ||
      !firebaseIdToken ||
      agreedTerms !== true ||
      agreedPrivacy !== true
    ) {
      return res.status(400).json({
        error: 'جميع الحقول وموافقة الشروط وسياسة الخصوصية والتحقق من البريد إجبارية.'
      });
    }

    if (String(password).length < 8) {
      return res.status(400).json({
        error: 'يجب ألا تقل كلمة المرور عن 8 أحرف.'
      });
    }

    if (!firebaseReady) {
      return res.status(503).json({
        error: 'خدمة التحقق من البريد غير مهيأة حالياً.'
      });
    }

    let decoded;

    try {
      decoded = await admin.auth().verifyIdToken(firebaseIdToken);
    } catch {
      return res.status(403).json({
        error: 'فشل التحقق من مصادقة Firebase.'
      });
    }

    if (
      normalizeEmail(decoded.email) !== email ||
      decoded.email_verified !== true
    ) {
      return res.status(403).json({
        error: 'يجب تأكيد البريد الإلكتروني نفسه أولاً عبر Firebase.'
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    try {
      const result = await pool.query(
        `INSERT INTO users
         (name, email, phone, password, role, firebase_uid,
          is_verified, trial_started_at, package_id,
          agreed_terms, agreed_privacy)
         SELECT $1, $2, $3, $4, 'user', $5, TRUE,
                CURRENT_TIMESTAMP, p.id, TRUE, TRUE
         FROM packages p
         WHERE p.name = 'trial'
         RETURNING id`,
        [
          String(name).trim(),
          email,
          String(phone).trim(),
          hashedPassword,
          decoded.uid
        ]
      );

      if (!result.rows.length) {
        return res.status(500).json({
          error: 'باقة التجربة غير موجودة في قاعدة البيانات.'
        });
      }

      return res.status(201).json({
        success: true,
        message: 'تم إنشاء الحساب وبدء التجربة المجانية بنجاح.'
      });

    } catch (err) {
      if (err.code === '23505') {
        return res.status(409).json({
          error: 'البريد الإلكتروني أو حساب Firebase مسجل مسبقاً.'
        });
      }

      throw err;
    }
  })
);

// Login
app.post(
  '/api/auth/login',
  atomicRateLimiter(10 * 60 * 1000, 5, 'login'),
  asyncRoute(async (req, res) => {
    const email = normalizeEmail(req.body.email);
    const { password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: 'البريد الإلكتروني وكلمة المرور مطلوبان.'
      });
    }

    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    if (!result.rows.length) {
      return res.status(401).json({
        error: 'بيانات الاعتماد غير صالحة.'
      });
    }

    const user = result.rows[0];

    if (!user.is_verified) {
      return res.status(403).json({
        error: 'الحساب غير مفعل.'
      });
    }

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(401).json({
        error: 'بيانات الاعتماد غير صالحة.'
      });
    }

    const activeSubscription = Boolean(
      user.is_subscribed &&
      user.subscription_expires_at &&
      new Date(user.subscription_expires_at).getTime() > Date.now()
    );

    const trialExpired =
      user.role !== 'admin' &&
      !activeSubscription &&
      (
        !user.trial_started_at ||
        Date.now() >=
          new Date(user.trial_started_at).getTime() +
          TRIAL_HOURS * 60 * 60 * 1000
      );

    return res.json({
      success: true,
      token: createToken(user),
      isTrialExpired: trialExpired,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        role: user.role,
        isSubscribed: activeSubscription
      }
    });
  })
);

// Forgot password
app.post(
  '/api/auth/forgot-password',
  atomicRateLimiter(15 * 60 * 1000, 3, 'forgot-password'),
  asyncRoute(async (req, res) => {
    const email = normalizeEmail(req.body.email);

    if (!email) {
      return res.status(400).json({
        error: 'البريد الإلكتروني مطلوب.'
      });
    }

    const userResult = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );

    if (!userResult.rows.length) {
      return res.json({
        success: true,
        message: 'إذا كان البريد مسجلاً، فستصلك تعليمات الاستعادة.'
      });
    }

    const rawToken = crypto.randomBytes(32).toString('hex');

    const tokenHash = crypto
      .createHash('sha256')
      .update(rawToken)
      .digest('hex');

    const expiresAt =
      Date.now() + PASSWORD_RESET_MINUTES * 60 * 1000;

    await pool.query(
      'DELETE FROM password_resets WHERE email = $1',
      [email]
    );

    await pool.query(
      `INSERT INTO password_resets
       (email, token_hash, expires_at, is_used)
       VALUES ($1, $2, $3, FALSE)`,
      [email, tokenHash, expiresAt]
    );

    const frontend = (process.env.FRONTEND_URL || '')
      .split(',')[0]
      .trim();

    if (!frontend) {
      throw new Error(
        'FRONTEND_URL is required to build password reset links.'
      );
    }

    const resetLink =
      `${frontend.replace(/\/$/, '')}/reset-password?token=${encodeURIComponent(rawToken)}`;

    try {
      await transporter.sendMail({
        from:
          process.env.SMTP_FROM ||
          process.env.SMTP_USER ||
          'no-reply@m3ak.app',
        to: email,
        subject: 'استعادة كلمة المرور - منصة معاك M3AK',
        text:
          `لتغيير كلمة المرور، افتح الرابط التالي. ` +
          `الرابط صالح لمدة 15 دقيقة ولمرة واحدة: ${resetLink}`
      });

    } catch (err) {
      await pool.query(
        'DELETE FROM password_resets WHERE token_hash = $1',
        [tokenHash]
      );

      console.error(
        'Password reset email failed:',
        err.message
      );

      return res.status(503).json({
        error: 'تعذر إرسال بريد الاستعادة حالياً. حاول لاحقاً.'
      });
    }

    return res.json({
      success: true,
      message: 'إذا كان البريد مسجلاً، فستصلك تعليمات الاستعادة.'
    });
  })
);

// Reset password
app.post(
  '/api/auth/reset-password',
  atomicRateLimiter(10 * 60 * 1000, 5, 'reset-password'),
  asyncRoute(async (req, res) => {
    const { token, newPassword } = req.body;

    if (
      !token ||
      !newPassword ||
      String(newPassword).length < 8
    ) {
      return res.status(400).json({
        error: 'رابط الاستعادة مطلوب وكلمة المرور يجب ألا تقل عن 8 أحرف.'
      });
    }

    const tokenHash = crypto
      .createHash('sha256')
      .update(String(token))
      .digest('hex');

    const hashedPassword = await bcrypt.hash(
      newPassword,
      12
    );

    const client = await pool.connect();

    try {
      await client.query('BEGIN');

      const recordResult = await client.query(
        `SELECT id, email, expires_at, is_used
         FROM password_resets
         WHERE token_hash = $1
         FOR UPDATE`,
        [tokenHash]
      );

      if (!recordResult.rows.length) {
        await client.query('ROLLBACK');

        return res.status(400).json({
          error: 'رابط الاستعادة غير صالح.'
        });
      }

      const record = recordResult.rows[0];

      if (
        record.is_used ||
        Date.now() >= Number(record.expires_at)
      ) {
        await client.query('ROLLBACK');

        return res.status(400).json({
          error: 'رابط الاستعادة منتهي الصلاحية أو تم استخدامه مسبقاً.'
        });
      }

      const update = await client.query(
        `UPDATE users
         SET password = $1,
             token_version = token_version + 1
         WHERE email = $2
         RETURNING id`,
        [hashedPassword, record.email]
      );

      if (!update.rows.length) {
        await client.query('ROLLBACK');

        return res.status(400).json({
          error: 'الحساب المرتبط بالرابط غير موجود.'
        });
      }

      await client.query(
        'UPDATE password_resets SET is_used = TRUE WHERE id = $1',
        [record.id]
      );

      await client.query(
        'DELETE FROM password_resets WHERE email = $1 AND id <> $2',
        [record.email, record.id]
      );

      await client.query('COMMIT');

      return res.json({
        success: true,
        message: 'تم تحديث كلمة المرور وإبطال الجلسات القديمة.'
      });

    } catch (err) {
      await client.query('ROLLBACK');
      throw err;

    } finally {
      client.release();
    }
  })
);
// Profile
app.get(
  '/api/user/profile',
  verifyToken,
  asyncRoute(async (req, res) => {
    const result = await pool.query(
      `SELECT
         u.id,
         u.name,
         u.email,
         u.phone,
         u.created_at,
         u.trial_started_at,
         u.is_subscribed,
         u.subscription_expires_at,
         u.words_used_count,
         u.images_used_count,
         p.name AS package_name,
         p.max_words,
         p.max_images,
         p.price,
         p.duration_days
       FROM users u
       LEFT JOIN packages p ON u.package_id = p.id
       WHERE u.id = $1`,
      [req.user.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        error: 'المستخدم غير موجود.'
      });
    }

    return res.json({
      success: true,
      profile: result.rows[0]
    });
  })
);

app.put(
  '/api/user/profile',
  verifyToken,
  asyncRoute(async (req, res) => {
    const {
      name,
      phone,
      currentPassword,
      newPassword
    } = req.body;

    if (
      newPassword &&
      (!currentPassword || String(newPassword).length < 8)
    ) {
      return res.status(400).json({
        error: 'أدخل كلمة المرور الحالية، واجعل الجديدة 8 أحرف على الأقل.'
      });
    }

    if (
      name !== undefined &&
      !String(name).trim()
    ) {
      return res.status(400).json({
        error: 'الاسم غير صالح.'
      });
    }

    if (
      phone !== undefined &&
      !String(phone).trim()
    ) {
      return res.status(400).json({
        error: 'رقم الهاتف غير صالح.'
      });
    }

    const client = await pool.connect();

    try {
      await client.query('BEGIN');

      const result = await client.query(
        'SELECT * FROM users WHERE id = $1 FOR UPDATE',
        [req.user.id]
      );

      if (!result.rows.length) {
        await client.query('ROLLBACK');

        return res.status(404).json({
          error: 'المستخدم غير موجود.'
        });
      }

      const user = result.rows[0];

      let passwordHash = user.password;
      let tokenVersion = Number(user.token_version);

      if (newPassword) {
        const passwordMatch = await bcrypt.compare(
          currentPassword,
          user.password
        );

        if (!passwordMatch) {
          await client.query('ROLLBACK');

          return res.status(400).json({
            error: 'كلمة المرور الحالية غير صحيحة.'
          });
        }

        passwordHash = await bcrypt.hash(
          newPassword,
          12
        );

        tokenVersion += 1;
      }

      await client.query(
        `UPDATE users
         SET name = $1,
             phone = $2,
             password = $3,
             token_version = $4
         WHERE id = $5`,
        [
          name === undefined
            ? user.name
            : String(name).trim(),

          phone === undefined
            ? user.phone
            : String(phone).trim(),

          passwordHash,
          tokenVersion,
          req.user.id
        ]
      );

      await client.query('COMMIT');

      return res.json({
        success: true,
        message: 'تم تحديث الملف الشخصي بنجاح.',
        sessionInvalidated: Boolean(newPassword)
      });

    } catch (err) {
      await client.query('ROLLBACK');
      throw err;

    } finally {
      client.release();
    }
  })
);

// Price comparison
app.get(
  '/api/compare-prices',
  verifyToken,
  verifyTrialOrSubscription,
  asyncRoute(async (req, res) => {
    const query = String(req.query.query || '').trim();

    if (!query) {
      return res.status(400).json({
        error: 'مصطلح البحث مطلوب.'
      });
    }

    if (
      !process.env.EXTERNAL_MARKET_API_KEY ||
      !process.env.EXTERNAL_MARKET_API_URL
    ) {
      return res.status(503).json({
        error: 'خدمة مقارنة الأسعار غير مربوطة بمزود بيانات حتى الآن.'
      });
    }

    const result = await axios.get(
      process.env.EXTERNAL_MARKET_API_URL,
      {
        params: { query },
        headers: {
          Authorization:
            `Bearer ${process.env.EXTERNAL_MARKET_API_KEY}`
        },
        timeout: 15000
      }
    );

    return res.json({
      success: true,
      query,
      results: result.data
    });
  })
);

// Booking/order request
app.post(
  '/api/services/book',
  verifyToken,
  verifyTrialOrSubscription,
  asyncRoute(async (req, res) => {
    const {
      sectionName,
      itemDetails,
      total
    } = req.body;

    const numericTotal = Number(total);

    if (
      !sectionName ||
      !itemDetails ||
      total === undefined ||
      !Number.isFinite(numericTotal) ||
      numericTotal < 0
    ) {
      return res.status(400).json({
        error: 'بيانات الحجز غير مكتملة أو المبلغ غير صالح.'
      });
    }

    const orderNumber =
      `BK-${crypto.randomBytes(6).toString('hex').toUpperCase()}`;

    await pool.query(
      `INSERT INTO orders
       (user_id, order_number, section_name, details, total, status)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        req.user.id,
        orderNumber,
        String(sectionName),
        String(itemDetails),
        numericTotal,
        'قيد المراجعة'
      ]
    );

    return res.status(201).json({
      success: true,
      orderNumber,
      message: 'تم استلام طلبك وهو قيد المراجعة.'
    });
  })
);

// AI assistant - Durable quota reservation and safe settlement
app.post(
  '/api/ai/chat',
  verifyToken,
  verifyTrialOrSubscription,
  asyncRoute(async (req, res) => {
    const message = String(req.body.message || '').trim();

    const imageUrl = req.body.imageUrl
      ? String(req.body.imageUrl).trim()
      : null;

    if (!message) {
      return res.status(400).json({
        error: 'الرسالة مطلوبة.'
      });
    }

    if (message.length > 12000) {
      return res.status(413).json({
        error: 'الرسالة أطول من الحد المسموح.'
      });
    }

    if (imageUrl) {
      let parsed;

      try {
        parsed = new URL(imageUrl);
      } catch {
        return res.status(400).json({
          error: 'رابط الصورة غير صالح.'
        });
      }

      if (parsed.protocol !== 'https:') {
        return res.status(400).json({
          error: 'يجب أن يكون رابط الصورة آمناً HTTPS.'
        });
      }
    }

    if (!process.env.OPENAI_API_KEY) {
      return res.status(503).json({
        error: 'خدمة المساعد الذكي غير مفعلة حالياً.'
      });
    }

    // Use a client-provided idempotency key when available.
    // A generated key protects this execution, but not a client retry.
    const idempotencyKey = String(
      req.get('Idempotency-Key') ||
      req.body.requestId ||
      crypto.randomUUID()
    ).trim();

    if (
      idempotencyKey.length < 8 ||
      idempotencyKey.length > 200
    ) {
      return res.status(400).json({
        error: 'معرف الطلب غير صالح.'
      });
    }

    const inputWords = message
      .split(/\s+/)
      .filter(Boolean).length;

    // Reserve enough words for the maximum provider output.
    const reservedWords = inputWords + 1200;
    const reservedImages = imageUrl ? 1 : 0;

    let packageResult;

    try {
      packageResult = await pool.query(
        `SELECT
           p.max_words,
           p.max_images
         FROM users u
         JOIN packages p ON p.id = u.package_id
         WHERE u.id = $1`,
        [req.user.id]
      );
    } catch (error) {
      console.error('AI package lookup failed:', error.message);

      return res.status(500).json({
        error: 'تعذر التحقق من حدود الباقة.'
      });
    }

    if (packageResult.rowCount === 0) {
      return res.status(404).json({
        error: 'المستخدم أو الباقة غير موجودين.'
      });
    }

    const wordsLimit = Number(packageResult.rows[0].max_words);
    const imagesLimit = Number(packageResult.rows[0].max_images);

    if (
      !Number.isSafeInteger(wordsLimit) ||
      wordsLimit < 0 ||
      !Number.isSafeInteger(imagesLimit) ||
      imagesLimit < 0
    ) {
      console.error('Invalid AI package quota configuration.');

      return res.status(500).json({
        error: 'إعدادات رصيد الباقة غير صالحة.'
      });
    }

    // Reserve quota atomically before calling OpenAI.
    let reservation;

    try {
      const reservationResult = await reserveAiQuota(pool, {
        userId: Number(req.user.id),
        idempotencyKey,
        wordsLimit,
        imagesLimit,
        reservedWords,
        reservedImages,
        leaseSeconds: 180,
        metadata: {
          source: 'api/ai/chat',
          model: process.env.OPENAI_MODEL || 'gpt-4o-mini'
        }
      });

      if (!reservationResult.created) {
        return res.status(409).json({
          error: 'هذا الطلب سبق تسجيله أو ما زال قيد المعالجة.',
          code: 'DUPLICATE_AI_REQUEST'
        });
      }

      reservation = reservationResult.reservation;

    } catch (error) {
      if (error instanceof QuotaError) {
        return res.status(error.statusCode || 400).json({
          error:
            error.code === 'QUOTA_EXCEEDED'
              ? 'رصيد الباقة لا يكفي لهذه المحادثة.'
              : error.message,
          code: error.code
        });
      }

      console.error('AI quota reservation failed:', error.message);

      return res.status(500).json({
        error: 'تعذر حجز رصيد المساعد الذكي.'
      });
    }

    // Call the provider only after successful reservation.
    let aiResponse;

    try {
      const content = [
        {
          type: 'text',
          text: message
        }
      ];

      if (imageUrl) {
        content.push({
          type: 'image_url',
          image_url: {
            url: imageUrl
          }
        });
      }

      aiResponse = await axios.post(
        'https://api.openai.com/v1/chat/completions',
        {
          model: process.env.OPENAI_MODEL || 'gpt-4o-mini',
          messages: [
            {
              role: 'user',
              content
            }
          ],
          max_tokens: 1200
        },
        {
          headers: {
            Authorization: `Bearer ${process.env.OPENAI_API_KEY}`
          },
          timeout: 45000
        }
      );

    } catch (error) {
      const providerStatus = Number(error.response?.status);

      // A definite client rejection is safe to refund.
      // Timeouts, network failures and server errors are uncertain.
      const definiteRejection =
        Number.isInteger(providerStatus) &&
        providerStatus >= 400 &&
        providerStatus < 500 &&
        providerStatus !== 408;

      try {
        if (definiteRejection) {
          await refundAiReservation(pool, {
            reservationId: reservation.reservation_id,
            reason: `Provider rejected request with HTTP ${providerStatus}`
          });
        } else {
          await markAiReservationUnknown(pool, {
            reservationId: reservation.reservation_id,
            reason:
              'Provider outcome uncertain: ' +
              String(error.message || 'Unknown provider error')
          });
        }
      } catch (quotaError) {
        console.error(
          'AI reservation recovery update failed:',
          quotaError.message
        );
      }

      console.error(
        'AI provider request failed:',
        error.response?.data || error.message
      );

      return res.status(502).json({
        error: 'تعذر إكمال الطلب عبر خدمة الذكاء الاصطناعي.'
      });
    }

    // The provider returned a successful HTTP response.
    // Record provider success BEFORE settlement or chat-history saving.
    try {
      await markProviderSucceeded(pool, {
        reservationId: reservation.reservation_id,
        providerRequestId:
          aiResponse.headers?.['x-request-id'] || null
      });
    } catch (error) {
      // Never refund after a successful provider response.
      console.error(
        'Could not record AI provider success:',
        error.message
      );

      return res.status(502).json({
        error: 'تم تنفيذ الطلب، لكن تعذر تأكيد تسجيله محاسبياً.'
      });
    }

    const replyText =
      aiResponse.data?.choices?.[0]?.message?.content;

    if (typeof replyText !== 'string') {
      // Keep the reservation in provider_succeeded state.
      // It must not be refunded automatically.
      console.error('OpenAI returned an invalid successful response.');

      return res.status(502).json({
        error: 'وصل رد غير مكتمل من خدمة الذكاء الاصطناعي.'
      });
    }

    const outputWords = replyText
      .split(/\s+/)
      .filter(Boolean).length;

    const actualWords = inputWords + outputWords;

    // Settle quota. A settlement failure must never trigger a refund
    // because provider success has already been recorded.
    try {
      await settleAiReservation(pool, {
    reservationId: reservation.reservation_id,
    actualWords,
    actualImages: reservedImages,
    responseText: replyText,
    metadata: {
          model: process.env.OPENAI_MODEL || 'gpt-4o-mini',
          providerRequestId:
            aiResponse.headers?.['x-request-id'] || null
        }
      });
    } catch (error) {
      console.error(
        'AI quota settlement failed after provider success:',
        error.message
      );

      return res.status(502).json({
        error: 'تم تنفيذ الطلب، لكن تعذر إتمام تسوية الرصيد.'
      });
    }

    // Chat history is saved AFTER successful quota settlement.
    // A history failure must not refund already consumed AI usage.
    try {
      await pool.query(
        `INSERT INTO chat_history
         (user_id, prompt, response, image_url)
         VALUES ($1, $2, $3, $4)`,
        [
          req.user.id,
          message,
          replyText,
          imageUrl
        ]
      );
    } catch (error) {
      console.error(
        'AI chat history save failed:',
        error.message
      );
    }

    return res.json({
      success: true,
      reply: replyText
    });
  })
);
// إنشاء جلسة دفع Paymob
app.post(
  '/api/payments/paymob-checkout',
  verifyToken,
  atomicRateLimiter(
    10 * 60 * 1000,
    5,
    'paymob-checkout'
  ),
  asyncRoute(async (req, res) => {
    const packageId = Number(req.body.packageId);

    if (!Number.isInteger(packageId) || packageId <= 0) {
      return res.status(400).json({
        error: 'معرف الباقة غير صالح.'
      });
    }

    const selectedPackage =
      await getPackageById(packageId);

    if (
      !selectedPackage ||
      selectedPackage.name === 'trial' ||
      !Number.isFinite(Number(selectedPackage.price)) ||
      Number(selectedPackage.price) <= 0
    ) {
      return res.status(400).json({
        error: 'معرف الباقة غير صالح.'
      });
    }

    const requiredEnv = [
      'PAYMOB_API_KEY',
      'PAYMOB_INTEGRATION_ID',
      'PAYMOB_IFRAME_ID',
      'PAYMOB_HMAC_SECRET'
    ];

    if (requiredEnv.some(key => !process.env[key])) {
      return res.status(503).json({
        error: 'إعدادات بوابة الدفع غير مكتملة.'
      });
    }

    let phoneNumber;

    try {
      phoneNumber = normalizePaymobPhone(req.user.phone);
    } catch {
      return res.status(400).json({
        error: 'رقم الهاتف المسجل غير صالح لإتمام الدفع. حدّث رقمك من الملف الشخصي.'
      });
    }

    const integrationId =
      Number(process.env.PAYMOB_INTEGRATION_ID);

    if (
      !Number.isSafeInteger(integrationId) ||
      integrationId <= 0
    ) {
      return res.status(503).json({
        error: 'معرف تكامل Paymob غير صالح.'
      });
    }

    const merchantOrderId =
      `M3AK-${req.user.id}-${selectedPackage.id}-${crypto.randomBytes(8).toString('hex')}`;

    const amountCents =
      Math.round(Number(selectedPackage.price) * 100);

    if (
      !Number.isSafeInteger(amountCents) ||
      amountCents <= 0
    ) {
      return res.status(400).json({
        error: 'قيمة الباقة غير صالحة للدفع.'
      });
    }

    await pool.query(
      `INSERT INTO subscriptions_payments
       (user_id, transaction_id, merchant_order_id,
        package_id, amount, currency, status, gateway)
       VALUES ($1, $2, $3, $4, $5, 'EGP', 'pending', 'paymob')`,
      [
        req.user.id,
        `pending:${merchantOrderId}`,
        merchantOrderId,
        selectedPackage.id,
        selectedPackage.price
      ]
    );

    try {
      const auth = await axios.post(
        'https://accept.paymob.com/api/auth/tokens',
        {
          api_key: process.env.PAYMOB_API_KEY
        },
        { timeout: 20000 }
      );

      const paymobToken = auth.data?.token;

      if (!paymobToken) {
        throw new Error('Paymob authentication token missing.');
      }

      const order = await axios.post(
        'https://accept.paymob.com/api/ecommerce/orders',
        {
          auth_token: paymobToken,
          delivery_needed: false,
          amount_cents: amountCents,
          currency: 'EGP',
          merchant_order_id: merchantOrderId,
          items: []
        },
        { timeout: 20000 }
      );

      const paymobOrderId = order.data?.id;

      if (!paymobOrderId) {
        throw new Error('Paymob order ID missing.');
      }

      const orderUpdate = await pool.query(
        `UPDATE subscriptions_payments
         SET paymob_order_id = $1
         WHERE merchant_order_id = $2
           AND status = 'pending'
         RETURNING id`,
        [
          String(paymobOrderId),
          merchantOrderId
        ]
      );

      if (!orderUpdate.rows.length) {
        throw new Error('Local payment record could not be updated.');
      }

      const billingName =
        String(req.user.email)
          .split('@')[0]
          .replace(/[^a-z0-9]/gi, '') || 'M3AK';

      const keyResponse = await axios.post(
        'https://accept.paymob.com/api/acceptance/payment_keys',
        {
          auth_token: paymobToken,
          amount_cents: amountCents,
          expiration: 3600,
          order_id: paymobOrderId,

          billing_data: {
            apartment: 'NA',
            email: req.user.email,
            floor: 'NA',
            first_name: billingName.slice(0, 50),
            street: 'NA',
            building: 'NA',
            phone_number: phoneNumber,
            shipping_method: 'NA',
            postal_code: '00000',
            city: 'Cairo',
            country: 'EG',
            last_name: 'Customer',
            state: 'Cairo'
          },

          currency: 'EGP',
          integration_id: integrationId
        },
        { timeout: 20000 }
      );

      const paymentToken = keyResponse.data?.token;

      if (!paymentToken) {
        throw new Error('Paymob payment token missing.');
      }

      const checkoutUrl =
        `https://accept.paymob.com/api/acceptance/iframes/${encodeURIComponent(process.env.PAYMOB_IFRAME_ID)}?payment_token=${encodeURIComponent(paymentToken)}`;

      return res.json({
        success: true,
        checkoutUrl,
        package: selectedPackage.name
      });

    } catch (err) {
      await pool.query(
        `UPDATE subscriptions_payments
         SET status = 'failed'
         WHERE merchant_order_id = $1
           AND status = 'pending'`,
        [merchantOrderId]
      );

      console.error(
        'Paymob checkout failed:',
        err.response?.data || err.message
      );

      return res.status(502).json({
        error: 'فشل إنشاء جلسة الدفع عبر Paymob.'
      });
    }
  })
);


// استقبال إشعار الدفع والتحقق من HMAC
app.post(
  '/api/payments/paymob-webhook',
  asyncRoute(async (req, res) => {
    const obj = req.body?.obj;

    const receivedHmac = String(
      req.query.hmac || req.headers.hmac || ''
    ).toLowerCase();

    const hmacSecret = process.env.PAYMOB_HMAC_SECRET;

    if (!obj || !hmacSecret || !receivedHmac) {
      return res.status(400).json({
        error: 'بيانات إشعار الدفع أو إعدادات التحقق غير مكتملة.'
      });
    }

    const hmacFields = [
      obj.amount_cents,
      obj.created_at,
      obj.currency,
      obj.error_occured,
      obj.has_parent_transaction,
      obj.id,
      obj.integration_id,
      obj.is_3d_secure,
      obj.is_auth,
      obj.is_capture,
      obj.is_refunded,
      obj.is_standalone_payment,
      obj.is_voided,
      obj.order?.id,
      obj.owner,
      obj.pending,
      obj.source_data?.pan,
      obj.source_data?.sub_type,
      obj.source_data?.type,
      obj.success
    ];

    const concatenated = hmacFields
      .map(value =>
        value === undefined || value === null
          ? ''
          : String(value)
      )
      .join('');

    const calculated = crypto
      .createHmac('sha512', hmacSecret)
      .update(concatenated)
      .digest('hex');

    if (!safeEqualHex(calculated, receivedHmac)) {
      return res.status(403).json({
        error: 'فشل التحقق من توقيع إشعار الدفع.'
      });
    }

    // رفض العمليات غير الناجحة أو الملغاة أو المستردة
    if (
      obj.success !== true ||
      obj.pending === true ||
      obj.is_capture !== true ||
      obj.is_voided === true ||
      obj.is_refunded === true ||
      obj.error_occured === true ||
      obj.error_occured === 'true'
    ) {
      return res.status(200).json({
        received: true,
        ignored: true
      });
    }

    if (
      String(obj.currency || '').toUpperCase() !== 'EGP'
    ) {
      return res.status(400).json({
        error: 'عملة الدفع غير متوقعة.'
      });
    }

    if (
      Number(obj.integration_id) !==
      Number(process.env.PAYMOB_INTEGRATION_ID)
    ) {
      return res.status(403).json({
        error: 'معرف تكامل الدفع غير صحيح.'
      });
    }

    const merchantOrderId =
      String(obj.order?.merchant_order_id || '');

    const transactionId = String(obj.id || '');

    const paymobOrderId = String(obj.order?.id || '');

    if (
      !merchantOrderId ||
      !transactionId ||
      !paymobOrderId
    ) {
      return res.status(400).json({
        error: 'بيانات ربط المعاملة غير مكتملة.'
      });
    }

    if (
      !/^\d+$/.test(transactionId) ||
      !/^\d+$/.test(paymobOrderId)
    ) {
      return res.status(400).json({
        error: 'معرف معاملة الدفع غير صالح.'
      });
    }

    const client = await pool.connect();

    try {
      await client.query('BEGIN');

      const paymentResult = await client.query(
        `SELECT
           id,
           user_id,
           package_id,
           amount,
           status,
           paymob_order_id
         FROM subscriptions_payments
         WHERE merchant_order_id = $1
         FOR UPDATE`,
        [merchantOrderId]
      );

      if (!paymentResult.rows.length) {
        await client.query('ROLLBACK');

        return res.status(404).json({
          error: 'طلب الدفع غير معروف.'
        });
      }

      const payment = paymentResult.rows[0];

      // منع إعادة تفعيل الاشتراك
      if (payment.status === 'success') {
        await client.query('COMMIT');

        return res.status(200).json({
          received: true,
          duplicate: true
        });
      }

      // لا نسمح بتفعيل أي سجل ليس قيد الانتظار
      if (payment.status !== 'pending') {
        await client.query('ROLLBACK');

        return res.status(409).json({
          error: 'حالة طلب الدفع لا تسمح بتفعيله.'
        });
      }

      // مطابقة رقم طلب Paymob مع الرقم المحفوظ محلياً
      if (
        !payment.paymob_order_id ||
        String(payment.paymob_order_id) !== paymobOrderId
      ) {
        await client.query('ROLLBACK');

        return res.status(400).json({
          error: 'رقم طلب Paymob لا يطابق سجل الدفع.'
        });
      }

      const paidAmount =
        Number(obj.amount_cents) / 100;

      if (
        !Number.isFinite(paidAmount) ||
        Math.round(paidAmount * 100) !==
        Math.round(Number(payment.amount) * 100)
      ) {
        await client.query(
          `UPDATE subscriptions_payments
           SET status = 'amount_mismatch'
           WHERE id = $1
             AND status = 'pending'`,
          [payment.id]
        );

        await client.query('COMMIT');

        return res.status(400).json({
          error: 'المبلغ المدفوع لا يطابق قيمة الباقة.'
        });
      }

      // منع ربط معاملة واحدة بأكثر من طلب دفع
      const duplicateTransaction = await client.query(
        `SELECT id
         FROM subscriptions_payments
         WHERE transaction_id = $1
           AND id <> $2
         LIMIT 1`,
        [
          transactionId,
          payment.id
        ]
      );

      if (duplicateTransaction.rows.length) {
        await client.query('ROLLBACK');

        return res.status(409).json({
          error: 'رقم معاملة الدفع مستخدم بالفعل.'
        });
      }

      const packageResult = await client.query(
        `SELECT duration_days
         FROM packages
         WHERE id = $1`,
        [payment.package_id]
      );

      if (!packageResult.rows.length) {
        await client.query('ROLLBACK');

        return res.status(500).json({
          error: 'الباقة المرتبطة بالدفع غير موجودة.'
        });
      }

      const durationDays =
        Number(packageResult.rows[0].duration_days);

      if (
        !Number.isInteger(durationDays) ||
        durationDays <= 0
      ) {
        await client.query('ROLLBACK');

        return res.status(500).json({
          error: 'مدة الباقة غير صالحة.'
        });
      }

      // تفعيل الاشتراك
      const userUpdate = await client.query(
        `UPDATE users
         SET is_subscribed = TRUE,
             package_id = $1,
             subscription_expires_at =
               GREATEST(
                 COALESCE(subscription_expires_at, CURRENT_TIMESTAMP),
                 CURRENT_TIMESTAMP
               ) + ($2::text || ' days')::interval,
             words_used_count = 0,
             images_used_count = 0
         WHERE id = $3
         RETURNING id`,
        [
          payment.package_id,
          durationDays,
          payment.user_id
        ]
      );

      if (!userUpdate.rows.length) {
        await client.query('ROLLBACK');

        return res.status(500).json({
          error: 'تعذر العثور على المستخدم لتفعيل الاشتراك.'
        });
      }

      const paymentUpdate = await client.query(
        `UPDATE subscriptions_payments
         SET transaction_id = $1,
             status = 'success'
         WHERE id = $2
           AND status = 'pending'
         RETURNING id`,
        [
          transactionId,
          payment.id
        ]
      );

      if (!paymentUpdate.rows.length) {
        await client.query('ROLLBACK');

        return res.status(409).json({
          error: 'تعذر تحديث سجل الدفع.'
        });
      }

      await client.query('COMMIT');

      return res.status(200).json({
        received: true,
        success: true
      });

    } catch (err) {
      await client.query('ROLLBACK');
      throw err;

    } finally {
      client.release();
    }
  })
);
// طلبات المستخدم
app.get(
  '/api/orders',
  verifyToken,
  asyncRoute(async (req, res) => {
    const result = await pool.query(
      `SELECT *
       FROM orders
       WHERE user_id = $1
       ORDER BY created_at DESC`,
      [req.user.id]
    );

    return res.json({
      success: true,
      orders: result.rows
    });
  })
);

// إشعارات المستخدم
app.get(
  '/api/notifications',
  verifyToken,
  asyncRoute(async (req, res) => {
    const result = await pool.query(
      `SELECT *
       FROM notifications
       WHERE user_id = $1
       ORDER BY created_at DESC`,
      [req.user.id]
    );

    return res.json({
      success: true,
      notifications: result.rows
    });
  })
);

// تحديد الإشعار كمقروء
app.patch(
  '/api/notifications/:id/read',
  verifyToken,
  asyncRoute(async (req, res) => {
    const result = await pool.query(
      `UPDATE notifications
       SET is_read = TRUE
       WHERE id = $1 AND user_id = $2
       RETURNING id`,
      [req.params.id, req.user.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        error: 'الإشعار غير موجود.'
      });
    }

    return res.json({
      success: true
    });
  })
);

// تذاكر الدعم
app.post(
  '/api/support',
  verifyToken,
  asyncRoute(async (req, res) => {
    const subject =
      String(req.body.subject || '').trim();

    const message =
      String(req.body.message || '').trim();

    if (!subject || !message) {
      return res.status(400).json({
        error: 'الموضوع والرسالة مطلوبان.'
      });
    }

    if (
      subject.length > 255 ||
      message.length > 10000
    ) {
      return res.status(400).json({
        error: 'حجم الرسالة أكبر من الحد المسموح.'
      });
    }

    await pool.query(
      `INSERT INTO support_tickets
       (user_id, subject, message)
       VALUES ($1, $2, $3)`,
      [req.user.id, subject, message]
    );

    return res.status(201).json({
      success: true,
      message: 'تم إرسال تذكرة الدعم بنجاح.'
    });
  })
);

// إحصائيات لوحة الإدارة
app.get(
  '/api/admin/stats',
  verifyAdmin,
  asyncRoute(async (req, res) => {
    const [users, orders, tickets, payments] =
      await Promise.all([
        pool.query(
          'SELECT COUNT(*)::int AS count FROM users'
        ),
        pool.query(
          'SELECT COUNT(*)::int AS count FROM orders'
        ),
        pool.query(
          'SELECT COUNT(*)::int AS count FROM support_tickets'
        ),
        pool.query(
          `SELECT COALESCE(SUM(amount), 0)::numeric(12,2) AS total
           FROM subscriptions_payments
           WHERE status = 'success'`
        )
      ]);

    return res.json({
      success: true,
      stats: {
        users: users.rows[0].count,
        orders: orders.rows[0].count,
        tickets: tickets.rows[0].count,
        revenue: Number(payments.rows[0].total)
      }
    });
  })
);

// عرض المستخدمين في لوحة الإدارة
app.get(
  '/api/admin/users',
  verifyAdmin,
  asyncRoute(async (req, res) => {
    const requestedLimit = Number(req.query.limit);
    const requestedOffset = Number(req.query.offset);

    const limit = Math.min(
      Math.max(
        Number.isInteger(requestedLimit) ? requestedLimit : 25,
        1
      ),
      100
    );

    const offset =
      Number.isSafeInteger(requestedOffset) &&
      requestedOffset >= 0
        ? requestedOffset
        : 0;

    const result = await pool.query(
      `SELECT
         id, name, email, phone, role,
         is_verified, is_subscribed,
         trial_started_at,
         subscription_expires_at,
         created_at
       FROM users
       ORDER BY created_at DESC
       LIMIT $1 OFFSET $2`,
      [limit, offset]
    );

    return res.json({
      success: true,
      users: result.rows,
      limit,
      offset
    });
  })
);

// أي مسار غير موجود
app.use((req, res) => {
  res.status(404).json({
    error: 'المسار المطلوب غير موجود.'
  });
});

// معالجة الأخطاء
app.use((err, req, res, next) => {
  console.error('Unhandled API error:', err);

  if (res.headersSent) {
    return next(err);
  }

  return res.status(500).json({
    error: IS_PRODUCTION
      ? 'حدث خطأ غير متوقع في الخادم.'
      : (err.message || 'Server error')
  });
});

// تشغيل الخادم
const server = app.listen(PORT, () => {
  console.log(`M3AK API listening on port ${PORT}`);
});

// إغلاق آمن عند إيقاف الخادم
async function shutdown(signal) {
  console.log(`${signal} received. Closing server...`);

  server.close(async () => {
    await pool.end();
    process.exit(0);
  });

  setTimeout(() => process.exit(1), 10000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
