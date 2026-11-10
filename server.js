'use strict';

/*
 * M3AK BACKEND
 * Node.js 20+
 * Express + PostgreSQL
 *
 * Authentication: Email/Password + JWT
 * Email verification: SMTP + OTP
 * AI: OpenAI API
 * Payments: Paymob webhook verification
 *
 * IMPORTANT:
 * Never run in production without configuring .env.
 */

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { Pool } = require('pg');
const nodemailer = require('nodemailer');
const OpenAI = require('openai');
const { z } = require('zod');

const app = express();

const PORT = Number(process.env.PORT || 3000);
const NODE_ENV = process.env.NODE_ENV || 'development';

const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;

function validateEnvironment() {
  const requiredEnvironment = [
    'DATABASE_URL',
    'JWT_SECRET'
  ];

  for (const key of requiredEnvironment) {
    if (!process.env[key]) {
      throw new Error(
        `Missing required environment variable: ${key}`
      );
    }
  }

  if (JWT_SECRET.length < 32) {
    throw new Error(
      'JWT_SECRET must contain at least 32 characters.'
    );
  }

  if (NODE_ENV === 'production' && !process.env.APP_ORIGIN) {
    throw new Error(
      'APP_ORIGIN is required in production.'
    );
  }
}

/* =========================================================
   DATABASE
========================================================= */

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.DB_SSL === 'true'
    ? { rejectUnauthorized: true }
    : undefined,
  max: 15,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

pool.on('error', error => {
  console.error('Unexpected PostgreSQL pool error:', error);
});


/* =========================================================
   EMAIL
========================================================= */

let mailer = null;

const smtpConfigured = Boolean(
  process.env.SMTP_HOST &&
  process.env.SMTP_PORT &&
  process.env.SMTP_USER &&
  process.env.SMTP_PASS &&
  process.env.SMTP_FROM
);

if (smtpConfigured) {
  mailer = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT),
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });
}

async function sendEmail(to, subject, text) {
  if (!mailer) {
    throw new Error('EMAIL_SERVICE_NOT_CONFIGURED');
  }

  await mailer.sendMail({
    from: process.env.SMTP_FROM,
    to,
    subject,
    text
  });
}


/* =========================================================
   OPENAI
========================================================= */

const openai = process.env.OPENAI_API_KEY
  ? new OpenAI({
      apiKey: process.env.OPENAI_API_KEY
    })
  : null;


/* =========================================================
   SECURITY MIDDLEWARE
========================================================= */

app.disable('x-powered-by');

app.use(helmet());

const allowedOrigins = (process.env.APP_ORIGIN || '')
  .split(',')
  .map(value => value.trim())
  .filter(Boolean);

app.use(cors({
  origin(origin, callback) {
    if (!origin) {
      return callback(null, true);
    }

    if (
      NODE_ENV !== 'production' &&
      allowedOrigins.length === 0
    ) {
      return callback(null, true);
    }

    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    return callback(new Error('CORS_ORIGIN_NOT_ALLOWED'));
  },
  credentials: true
}));

/*
 * Paymob webhook needs the original raw request body.
 * It is mounted before express.json().
 */

app.use(
  '/api/payments/paymob/webhook',
  express.raw({
    type: 'application/json',
    limit: '1mb'
  })
);

app.use(express.json({
  limit: '2mb'
}));

app.use(express.urlencoded({
  extended: false,
  limit: '100kb'
}));


/* =========================================================
   COMMON HELPERS
========================================================= */

class ApiError extends Error {
  constructor(status, message, code) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

function sendError(res, status, message, code) {
  return res.status(status).json({
    success: false,
    message,
    code
  });
}

function asyncRoute(handler) {
  return (req, res, next) => {
    Promise.resolve(handler(req, res, next)).catch(next);
  };
}

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function normalizePhone(phone) {
  return String(phone || '').replace(/[^\d+]/g, '');
}

function hashValue(value) {
  return crypto
    .createHash('sha256')
    .update(String(value))
    .digest('hex');
}

function generateOtp() {
  return crypto
    .randomInt(100000, 1000000)
    .toString();
}

function signToken(user) {
  return jwt.sign(
    {
      sub: user.id,
      role: user.role
    },
    JWT_SECRET,
    {
      expiresIn: process.env.JWT_EXPIRES_IN || '7d',
      issuer: 'm3ak-api',
      audience: 'm3ak-app'
    }
  );
}

function safeUser(user) {
  return {
    id: user.id,
    fullName: user.full_name,
    email: user.email,
    phone: user.phone,
    role: user.role,
    emailVerified: user.email_verified,
    phoneVerified: user.phone_verified,
    accountStatus: user.account_status
  };
}

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


/* =========================================================
   DATABASE-BACKED RATE LIMITER
========================================================= */

function databaseRateLimit({
  keyPrefix,
  limit,
  windowSeconds
}) {
  return asyncRoute(async (req, res, next) => {
    const identity =
      req.user?.id ||
      req.ip ||
      'unknown';

    const rateKey = `${keyPrefix}:${identity}`;

    const result = await pool.query(
      `
      INSERT INTO api_rate_limits (
        rate_key,
        request_count,
        window_started_at,
        expires_at
      )
      VALUES (
        $1,
        1,
        NOW(),
        NOW() + ($2 * INTERVAL '1 second')
      )
      ON CONFLICT (rate_key)
      DO UPDATE SET
        request_count = CASE
          WHEN api_rate_limits.expires_at <= NOW()
          THEN 1
          ELSE api_rate_limits.request_count + 1
        END,

        window_started_at = CASE
          WHEN api_rate_limits.expires_at <= NOW()
          THEN NOW()
          ELSE api_rate_limits.window_started_at
        END,

        expires_at = CASE
          WHEN api_rate_limits.expires_at <= NOW()
          THEN NOW() + ($2 * INTERVAL '1 second')
          ELSE api_rate_limits.expires_at
        END

      RETURNING request_count, expires_at
      `,
      [rateKey, windowSeconds]
    );

    const row = result.rows[0];

    if (Number(row.request_count) > limit) {
      res.setHeader(
        'Retry-After',
        Math.max(
          1,
          Math.ceil(
            (new Date(row.expires_at).getTime() - Date.now()) / 1000
          )
        )
      );

      return sendError(
        res,
        429,
        'تم تجاوز عدد المحاولات المسموح بها. حاول لاحقًا.',
        'RATE_LIMIT_EXCEEDED'
      );
    }

    next();
  });
}


/* =========================================================
   AUTHENTICATION
========================================================= */

async function authenticate(req, res, next) {
  try {
    const header = req.headers.authorization || '';

    if (!header.startsWith('Bearer ')) {
      return sendError(
        res,
        401,
        'يجب تسجيل الدخول أولًا.',
        'AUTH_REQUIRED'
      );
    }

    const token = header.slice(7);

    const payload = jwt.verify(token, JWT_SECRET, {
      issuer: 'm3ak-api',
      audience: 'm3ak-app'
    });

    const result = await pool.query(
      `
      SELECT
        id,
        full_name,
        email,
        phone,
        role,
        email_verified,
        phone_verified,
        account_status
      FROM users
      WHERE id = $1
      LIMIT 1
      `,
      [payload.sub]
    );

    if (!result.rowCount) {
      return sendError(
        res,
        401,
        'الحساب غير موجود.',
        'USER_NOT_FOUND'
      );
    }

    const user = result.rows[0];

    if (user.account_status !== 'active') {
      return sendError(
        res,
        403,
        'الحساب غير متاح حاليًا.',
        'ACCOUNT_NOT_ACTIVE'
      );
    }

    if (!user.email_verified) {
      return sendError(
        res,
        403,
        'يجب تأكيد البريد الإلكتروني أولًا.',
        'EMAIL_NOT_VERIFIED'
      );
    }

    req.user = user;

    next();
  } catch (error) {
    if (
      error.name === 'TokenExpiredError' ||
      error.name === 'JsonWebTokenError'
    ) {
      return sendError(
        res,
        401,
        'جلسة الدخول غير صالحة أو انتهت.',
        'INVALID_TOKEN'
      );
    }

    next(error);
  }
}


function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return sendError(
      res,
      403,
      'هذه العملية مخصصة للإدارة فقط.',
      'ADMIN_REQUIRED'
    );
  }

  next();
}
/* =========================================================
   MERCHANT AUTHORIZATION
   التاجر يستقبل الطلبات ويتابع الرسائل فقط
   لا يملك صلاحيات إدارة المنتجات أو العروض
========================================================= */

const requireMerchant = asyncRoute(async (req, res, next) => {
  if (!req.user || req.user.role !== 'merchant') {
    return sendError(
      res,
      403,
      'هذه العملية مخصصة لحسابات التجار فقط.',
      'MERCHANT_REQUIRED'
    );
  }

  const result = await pool.query(
    `
    SELECT
      m.id,
      m.business_name,
      m.status,
      ms.status AS subscription_status,
      ms.ends_at
    FROM merchants m
    LEFT JOIN LATERAL (
      SELECT status, ends_at
      FROM merchant_subscriptions
      WHERE merchant_id = m.id
      ORDER BY created_at DESC
      LIMIT 1
    ) ms ON TRUE
    WHERE m.user_id = $1
    LIMIT 1
    `,
    [req.user.id]
  );

  if (!result.rowCount) {
    return sendError(
      res,
      403,
      'لا يوجد متجر مرتبط بحسابك.',
      'MERCHANT_PROFILE_NOT_FOUND'
    );
  }

  const merchant = result.rows[0];

  if (merchant.status !== 'active') {
    return sendError(
      res,
      403,
      'المتجر غير نشط حاليًا.',
      'MERCHANT_NOT_ACTIVE'
    );
  }

  if (
    !['trial', 'active'].includes(merchant.subscription_status) ||
    !merchant.ends_at ||
    new Date(merchant.ends_at) <= new Date()
  ) {
    return sendError(
      res,
      403,
      'اشتراك المتجر منتهٍ أو غير نشط. يرجى التجديد.',
      'MERCHANT_SUBSCRIPTION_INACTIVE'
    );
  }

  req.merchant = merchant;
  next();
});


/* =========================================================
   OTP MANAGEMENT
========================================================= */

async function createVerificationCode(
  client,
  userId,
  destination,
  purpose
) {
  const code = generateOtp();

  await client.query(
    `
    INSERT INTO verification_codes (
      user_id,
      destination,
      code_hash,
      purpose,
      expires_at
    )
    VALUES ($1, $2, $3, $4, NOW() + INTERVAL '10 minutes')
    `,
    [
      userId,
      destination,
      hashValue(code),
      purpose
    ]
  );

  return code;
}

async function verifyCode(
  client,
  destination,
  code,
  purpose
) {
  const result = await client.query(
    `
    SELECT *
    FROM verification_codes
    WHERE destination = $1
      AND purpose = $2
      AND verified_at IS NULL
      AND expires_at > NOW()
      AND attempts < 5
    ORDER BY created_at DESC
    LIMIT 1
    FOR UPDATE
    `,
    [destination, purpose]
  );

  if (!result.rowCount) {
    throw new ApiError(
      400,
      'رمز التحقق غير صالح أو انتهت صلاحيته.',
      'OTP_INVALID'
    );
  }

  const record = result.rows[0];

  if (
    !crypto.timingSafeEqual(
      Buffer.from(record.code_hash),
      Buffer.from(hashValue(code))
    )
  ) {
    await client.query(
      `
      UPDATE verification_codes
      SET attempts = attempts + 1
      WHERE id = $1
      `,
      [record.id]
    );

    throw new ApiError(
      400,
      'رمز التحقق غير صحيح.',
      'OTP_INCORRECT'
    );
  }

  await client.query(
    `
    UPDATE verification_codes
    SET verified_at = NOW()
    WHERE id = $1
    `,
    [record.id]
  );

  return record;
}


/* =========================================================
   TRIAL ACTIVATION
========================================================= */

async function activateTrial(client, userId) {
  const packageResult = await client.query(
    `
    SELECT id
    FROM packages
    WHERE code = 'TRIAL'
      AND is_active = TRUE
      AND is_trial = TRUE
    LIMIT 1
    `
  );

  if (!packageResult.rowCount) {
    throw new ApiError(
      500,
      'باقة التجربة غير مهيأة في قاعدة البيانات.',
      'TRIAL_PACKAGE_MISSING'
    );
  }

  const packageId = packageResult.rows[0].id;

  const existing = await client.query(
    `
    SELECT id
    FROM subscriptions
    WHERE user_id = $1
      AND package_id = $2
    LIMIT 1
    `,
    [userId, packageId]
  );

  if (existing.rowCount) {
    throw new ApiError(
      409,
      'تم استخدام التجربة المجانية لهذا الحساب من قبل.',
      'TRIAL_ALREADY_USED'
    );
  }

  await client.query(
    `
    INSERT INTO subscriptions (
      user_id,
      package_id,
      billing_cycle,
      status,
      started_at,
      ends_at,
      trial_expires_at,
      auto_renew
    )
    VALUES (
      $1,
      $2,
      'trial',
      'active',
      NOW(),
      NOW() + INTERVAL '96 hours',
      NOW() + INTERVAL '96 hours',
      FALSE
    )
    `,
    [userId, packageId]
  );
}


/* =========================================================
   SIGNUP
========================================================= */

const signupSchema = z.object({
  fullName: z.string().trim().min(2).max(150),
  email: z.string().email().max(255),
  phone: z.string().min(8).max(30),
  countryCode: z.string().max(8).optional(),
  password: z.string().min(8).max(128),
  confirmPassword: z.string().min(8).max(128)
});

app.post(
  '/api/auth/signup',
  databaseRateLimit({
    keyPrefix: 'signup',
    limit: 5,
    windowSeconds: 3600
  }),
  asyncRoute(async (req, res) => {
    const parsed = signupSchema.safeParse(req.body);

    if (!parsed.success) {
      return sendError(
        res,
        400,
        'راجع بيانات التسجيل وحاول مرة أخرى.',
        'VALIDATION_ERROR'
      );
    }

    const data = parsed.data;

    if (data.password !== data.confirmPassword) {
      return sendError(
        res,
        400,
        'كلمتا المرور غير متطابقتين.',
        'PASSWORD_MISMATCH'
      );
    }

    const email = normalizeEmail(data.email);

    const phone = normalizePhone(
      `${data.countryCode || ''}${data.phone}`
    );

    const passwordHash = await bcrypt.hash(data.password, 12);

    const code = generateOtp();

    const user = await withTransaction(async client => {
      const existing = await client.query(
        `
        SELECT id
        FROM users
        WHERE email = $1 OR phone = $2
        LIMIT 1
        `,
        [email, phone]
      );

      if (existing.rowCount) {
        throw new ApiError(
          409,
          'البريد الإلكتروني أو رقم الهاتف مسجل بالفعل.',
          'ACCOUNT_EXISTS'
        );
      }

      const inserted = await client.query(
        `
        INSERT INTO users (
          full_name,
          email,
          phone,
          password_hash,
          email_verified,
          phone_verified
        )
        VALUES ($1, $2, $3, $4, FALSE, FALSE)
        RETURNING id, full_name, email, phone
        `,
        [
          data.fullName,
          email,
          phone,
          passwordHash
        ]
      );

      const newUser = inserted.rows[0];

      await client.query(
        `
        INSERT INTO verification_codes (
          user_id,
          destination,
          code_hash,
          purpose,
          expires_at
        )
        VALUES (
          $1,
          $2,
          $3,
          'email_verification',
          NOW() + INTERVAL '10 minutes'
        )
        `,
        [
          newUser.id,
          email,
          hashValue(code)
        ]
      );

      return newUser;
    });

    try {
      await sendEmail(
        email,
        'رمز تأكيد حساب معاك',
        `رمز تأكيد حسابك هو: ${code}\n\nصلاحية الرمز 10 دقائق.`
      );
    } catch (error) {
      console.error('Signup email error:', error.message);

      return sendError(
        res,
        503,
        'تعذر إرسال رمز التحقق حاليًا. لم يتم تفعيل الحساب. يرجى المحاولة لاحقًا.',
        'EMAIL_DELIVERY_FAILED'
      );
    }

    return res.status(201).json({
      success: true,
      message: 'تم إنشاء طلب الحساب وإرسال رمز التحقق إلى بريدك الإلكتروني.',
      destination: email,
      next: 'verify.html'
    });
  })
);


/* =========================================================
   VERIFY EMAIL
========================================================= */

app.post(
  '/api/auth/verify',
  databaseRateLimit({
    keyPrefix: 'verify',
    limit: 10,
    windowSeconds: 900
  }),
  asyncRoute(async (req, res) => {
    const email = normalizeEmail(req.body.email);
    const code = String(req.body.code || '').trim();

    if (
      !z.string().email().safeParse(email).success ||
      !/^\d{6}$/.test(code)
    ) {
      return sendError(
        res,
        400,
        'بيانات التحقق غير صحيحة.',
        'VALIDATION_ERROR'
      );
    }

    const user = await withTransaction(async client => {
      const found = await client.query(
        `
        SELECT id, full_name, email, phone, role
        FROM users
        WHERE email = $1
        FOR UPDATE
        `,
        [email]
      );

      if (!found.rowCount) {
        throw new ApiError(
          404,
          'الحساب غير موجود.',
          'USER_NOT_FOUND'
        );
      }

      const account = found.rows[0];

      await verifyCode(
        client,
        email,
        code,
        'email_verification'
      );

      await client.query(
        `
        UPDATE users
        SET email_verified = TRUE
        WHERE id = $1
        `,
        [account.id]
      );

      await activateTrial(client, account.id);

      await client.query(
        `
        INSERT INTO subscription_members (
          subscription_id,
          user_id,
          member_email,
          member_role,
          status,
          joined_at
        )
        SELECT
          id,
          $1,
          $2,
          'owner',
          'active',
          NOW()
        FROM subscriptions
        WHERE user_id = $1
          AND status = 'active'
          AND billing_cycle = 'trial'
        ORDER BY created_at DESC
        LIMIT 1
        `,
        [account.id, account.email]
      );

      return account;
    });

    const token = signToken(user);

    return res.json({
      success: true,
      message: 'تم تأكيد حسابك وتفعيل تجربتك المجانية لمدة 4 أيام.',
      token,
      user: safeUser({
        ...user,
        email_verified: true,
        account_status: 'active'
      })
    });
  })
);


/* =========================================================
   LOGIN
========================================================= */

app.post(
  '/api/auth/login',
  databaseRateLimit({
    keyPrefix: 'login',
    limit: 5,
    windowSeconds: 900
  }),
  asyncRoute(async (req, res) => {
    const identity = String(req.body.identity || '').trim();
    const password = String(req.body.password || '');

    if (!identity || !password) {
      return sendError(
        res,
        400,
        'أدخل بيانات تسجيل الدخول.',
        'VALIDATION_ERROR'
      );
    }

    const isEmail = identity.includes('@');

    const result = await pool.query(
      `
      SELECT *
      FROM users
      WHERE ${
        isEmail
          ? 'email = $1'
          : 'phone = $1'
      }
      LIMIT 1
      `,
      [
        isEmail
          ? normalizeEmail(identity)
          : normalizePhone(identity)
      ]
    );

    if (!result.rowCount) {
      return sendError(
        res,
        401,
        'بيانات تسجيل الدخول غير صحيحة.',
        'INVALID_CREDENTIALS'
      );
    }

    const user = result.rows[0];

    const validPassword = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!validPassword) {
      return sendError(
        res,
        401,
        'بيانات تسجيل الدخول غير صحيحة.',
        'INVALID_CREDENTIALS'
      );
    }

    if (user.account_status !== 'active') {
      return sendError(
        res,
        403,
        'الحساب غير متاح.',
        'ACCOUNT_NOT_ACTIVE'
      );
    }

    if (!user.email_verified) {
      return sendError(
        res,
        403,
        'يجب تأكيد البريد الإلكتروني قبل تسجيل الدخول.',
        'EMAIL_NOT_VERIFIED'
      );
    }

    const token = signToken(user);

    return res.json({
      success: true,
      token,
      user: safeUser(user)
    });
  })
);


/* =========================================================
   PASSWORD RESET REQUEST
========================================================= */

app.post(
  '/api/auth/password-reset/request',
  databaseRateLimit({
    keyPrefix: 'password-reset',
    limit: 5,
    windowSeconds: 3600
  }),
  asyncRoute(async (req, res) => {
    const identity = String(req.body.identity || '').trim();

    if (!identity) {
      return sendError(
        res,
        400,
        'أدخل البريد الإلكتروني أو رقم الهاتف.',
        'VALIDATION_ERROR'
      );
    }

    const isEmail = identity.includes('@');

    const result = await pool.query(
      `
      SELECT id, email
      FROM users
      WHERE ${
        isEmail
          ? 'email = $1'
          : 'phone = $1'
      }
        AND email_verified = TRUE
        AND account_status = 'active'
      LIMIT 1
      `,
      [
        isEmail
          ? normalizeEmail(identity)
          : normalizePhone(identity)
      ]
    );

    /*
     * Generic response prevents account enumeration.
     */

    if (!result.rowCount) {
      return res.json({
        success: true,
        message: 'إذا كانت البيانات مرتبطة بحساب، فستصلك تعليمات الاستعادة.'
      });
    }

    const user = result.rows[0];
    const code = generateOtp();

    await pool.query(
      `
      INSERT INTO verification_codes (
        user_id,
        destination,
        code_hash,
        purpose,
        expires_at
      )
      VALUES (
        $1,
        $2,
        $3,
        'password_reset',
        NOW() + INTERVAL '10 minutes'
      )
      `,
      [
        user.id,
        user.email,
        hashValue(code)
      ]
    );

    await sendEmail(
      user.email,
      'استعادة كلمة مرور معاك',
      `رمز استعادة كلمة المرور هو: ${code}\n\nصلاحية الرمز 10 دقائق.`
    );

    return res.json({
      success: true,
      message: 'تم إرسال رمز الاستعادة إلى البريد الإلكتروني المسجل.',
      destination: user.email
    });
  })
);


/* =========================================================
   PASSWORD RESET CONFIRM
========================================================= */

app.post(
  '/api/auth/password-reset/confirm',
  databaseRateLimit({
    keyPrefix: 'password-reset-confirm',
    limit: 5,
    windowSeconds: 900
  }),
  asyncRoute(async (req, res) => {
    const email = normalizeEmail(req.body.email);
    const code = String(req.body.code || '');
    const password = String(req.body.password || '');

    if (
      !z.string().email().safeParse(email).success ||
      !/^\d{6}$/.test(code) ||
      password.length < 8 ||
      password.length > 128
    ) {
      return sendError(
        res,
        400,
        'راجع بيانات الاستعادة وكلمة المرور.',
        'VALIDATION_ERROR'
      );
    }

    const passwordHash = await bcrypt.hash(password, 12);

    await withTransaction(async client => {
      const userResult = await client.query(
        `
        SELECT id
        FROM users
        WHERE email = $1
        FOR UPDATE
        `,
        [email]
      );

      if (!userResult.rowCount) {
        throw new ApiError(
          400,
          'تعذر إتمام عملية الاستعادة.',
          'RESET_FAILED'
        );
      }

      const userId = userResult.rows[0].id;

      await verifyCode(
        client,
        email,
        code,
        'password_reset'
      );

      await client.query(
        `
        UPDATE users
        SET password_hash = $1
        WHERE id = $2
        `,
        [passwordHash, userId]
      );

      await client.query(
        `
        INSERT INTO audit_logs (
          user_id,
          action,
          entity_type
        )
        VALUES ($1, 'password_reset', 'user')
        `,
        [userId]
      );
    });

    return res.json({
      success: true,
      message: 'تم تغيير كلمة المرور بنجاح.'
    });
  })
);


/* =========================================================
   CURRENT USER
========================================================= */
/* =========================================================
   MERCHANT ORDERS
   التاجر يرى طلبات متجره فقط
========================================================= */

// عرض طلبات المتجر
app.get(
  '/api/merchant/orders',
  authenticate,
  requireMerchant,
  asyncRoute(async (req, res) => {
    const result = await pool.query(
      `
      SELECT DISTINCT
        o.id,
        o.order_number,
        o.user_id,
        o.order_type,
        o.description,
        o.status,
        o.total_amount,
        o.currency,
        o.created_at,
        u.full_name AS customer_name,
        u.phone AS customer_phone
      FROM orders o
      INNER JOIN order_items oi ON oi.order_id = o.id
      INNER JOIN catalog_items ci ON ci.id = oi.item_id
      WHERE ci.merchant_id = $1
      ORDER BY o.created_at DESC
      LIMIT 100
      `,
      [req.merchant.id]
    );

    res.json({
      success: true,
      orders: result.rows
    });
  })
);


// تحديث حالة طلب تابع للمتجر فقط
app.patch(
  '/api/merchant/orders/:id/status',
  authenticate,
  requireMerchant,
  asyncRoute(async (req, res) => {
    const allowedStatuses = [
      'confirmed',
      'processing',
      'completed',
      'rejected'
    ];

    const { status } = req.body;

    if (!allowedStatuses.includes(status)) {
      return sendError(
        res,
        400,
        'حالة الطلب غير مسموح بها.',
        'INVALID_ORDER_STATUS'
      );
    }

    const result = await pool.query(
      `
      UPDATE orders o
      SET
        status = $1,
        updated_at = NOW()
      WHERE o.id = $2
        AND EXISTS (
          SELECT 1
          FROM order_items oi
          INNER JOIN catalog_items ci ON ci.id = oi.item_id
          WHERE oi.order_id = o.id
            AND ci.merchant_id = $3
        )
      RETURNING o.id, o.order_number, o.status
      `,
      [status, req.params.id, req.merchant.id]
    );

    if (!result.rowCount) {
      return sendError(
        res,
        404,
        'الطلب غير موجود أو لا يتبع متجرك.',
        'MERCHANT_ORDER_NOT_FOUND'
      );
    }

    res.json({
      success: true,
      message: 'تم تحديث حالة الطلب.',
      order: result.rows[0]
    });
  })
);


/* =========================================================
   MERCHANT CONVERSATIONS
   التاجر يتابع محادثات متجره فقط
========================================================= */

// عرض محادثات المتجر
app.get(
  '/api/merchant/conversations',
  authenticate,
  requireMerchant,
  asyncRoute(async (req, res) => {
    const result = await pool.query(
      `
      SELECT
        c.id,
        c.customer_id,
        c.order_id,
        c.status,
        c.created_at,
        c.updated_at,
        u.full_name AS customer_name,
        (
          SELECT message_text
          FROM conversation_messages cm
          WHERE cm.conversation_id = c.id
          ORDER BY cm.created_at DESC
          LIMIT 1
        ) AS last_message
      FROM conversations c
      INNER JOIN users u ON u.id = c.customer_id
      WHERE c.merchant_id = $1
      ORDER BY c.updated_at DESC
      LIMIT 100
      `,
      [req.merchant.id]
    );

    res.json({
      success: true,
      conversations: result.rows
    });
  })
);


// عرض رسائل محادثة تخص المتجر
app.get(
  '/api/merchant/conversations/:id/messages',
  authenticate,
  requireMerchant,
  asyncRoute(async (req, res) => {
    const conversation = await pool.query(
      `
      SELECT id
      FROM conversations
      WHERE id = $1
        AND merchant_id = $2
      LIMIT 1
      `,
      [req.params.id, req.merchant.id]
    );

    if (!conversation.rowCount) {
      return sendError(
        res,
        404,
        'المحادثة غير موجودة.',
        'MERCHANT_CONVERSATION_NOT_FOUND'
      );
    }

    const result = await pool.query(
      `
      SELECT
        cm.id,
        cm.sender_user_id,
        cm.message_text,
        cm.attachment_url,
        cm.is_read,
        cm.created_at,
        u.role AS sender_role
      FROM conversation_messages cm
      INNER JOIN users u ON u.id = cm.sender_user_id
      WHERE cm.conversation_id = $1
      ORDER BY cm.created_at ASC
      LIMIT 200
      `,
      [req.params.id]
    );

    res.json({
      success: true,
      messages: result.rows
    });
  })
);


// إرسال رد من التاجر
app.post(
  '/api/merchant/conversations/:id/messages',
  authenticate,
  requireMerchant,
  asyncRoute(async (req, res) => {
    const message = String(req.body.message || '').trim();

    if (!message || message.length > 5000) {
      return sendError(
        res,
        400,
        'اكتب رسالة صحيحة لا تتجاوز 5000 حرف.',
        'INVALID_MESSAGE'
      );
    }

    const result = await pool.query(
      `
      INSERT INTO conversation_messages (
        conversation_id,
        sender_user_id,
        message_text
      )
      SELECT
        c.id,
        $3,
        $4
      FROM conversations c
      WHERE c.id = $1
        AND c.merchant_id = $2
        AND c.status = 'open'
      RETURNING id, conversation_id, message_text, created_at
      `,
      [
        req.params.id,
        req.merchant.id,
        req.user.id,
        message
      ]
    );

    if (!result.rowCount) {
      return sendError(
        res,
        404,
        'المحادثة غير موجودة أو مغلقة.',
        'CONVERSATION_NOT_AVAILABLE'
      );
    }

    await pool.query(
      `
      UPDATE conversations
      SET updated_at = NOW()
      WHERE id = $1
      `,
      [req.params.id]
    );

    res.status(201).json({
      success: true,
      message: 'تم إرسال الرد.',
      data: result.rows[0]
    });
  })
);
/* =========================================================
   ADMIN ORDERS MANAGEMENT
   إدارة جميع طلبات العملاء
========================================================= */

// عرض جميع الطلبات للإدارة
app.get(
  '/api/admin/orders',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const conditions = [];
    const values = [];

    const allowedStatuses = [
      'pending',
      'confirmed',
      'processing',
      'completed',
      'cancelled',
      'rejected'
    ];

    if (req.query.status) {
      if (!allowedStatuses.includes(req.query.status)) {
        return sendError(
          res,
          400,
          'حالة الطلب غير صحيحة.',
          'INVALID_ORDER_STATUS'
        );
      }

      values.push(req.query.status);
      conditions.push(`o.status = $${values.length}`);
    }

    if (req.query.merchant_id) {
      values.push(req.query.merchant_id);
      conditions.push(`
        EXISTS (
          SELECT 1
          FROM order_items oi
          JOIN catalog_items ci ON ci.id = oi.item_id
          WHERE oi.order_id = o.id
            AND ci.merchant_id = $${values.length}
        )
      `);
    }

    const whereClause = conditions.length
      ? `WHERE ${conditions.join(' AND ')}`
      : '';

    const result = await pool.query(
      `
      SELECT
        o.*,
        u.full_name AS customer_name,
        u.email AS customer_email,
        u.phone AS customer_phone,

        (
          SELECT COUNT(*)
          FROM order_items oi
          WHERE oi.order_id = o.id
        ) AS items_count,

        (
          SELECT jsonb_agg(
            DISTINCT jsonb_build_object(
              'merchant_id', m.id,
              'business_name', m.business_name
            )
          )
          FROM order_items oi
          JOIN catalog_items ci ON ci.id = oi.item_id
          JOIN merchants m ON m.id = ci.merchant_id
          WHERE oi.order_id = o.id
        ) AS merchants

      FROM orders o
      JOIN users u ON u.id = o.user_id

      ${whereClause}

      ORDER BY o.created_at DESC
      LIMIT 200
      `,
      values
    );

    res.json({
      success: true,
      total: result.rowCount,
      orders: result.rows
    });
  })
);


// تفاصيل طلب معين للإدارة
app.get(
  '/api/admin/orders/:id',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const orderResult = await pool.query(
      `
      SELECT
        o.*,
        u.full_name AS customer_name,
        u.email AS customer_email,
        u.phone AS customer_phone
      FROM orders o
      JOIN users u ON u.id = o.user_id
      WHERE o.id = $1
      LIMIT 1
      `,
      [req.params.id]
    );

    if (!orderResult.rowCount) {
      return sendError(
        res,
        404,
        'الطلب غير موجود.',
        'ORDER_NOT_FOUND'
      );
    }

    const itemsResult = await pool.query(
      `
      SELECT
        oi.*,
        ci.section_code,
        ci.category_name,
        m.id AS merchant_id,
        m.business_name
      FROM order_items oi
      LEFT JOIN catalog_items ci ON ci.id = oi.item_id
      LEFT JOIN merchants m ON m.id = ci.merchant_id
      WHERE oi.order_id = $1
      ORDER BY oi.created_at ASC
      `,
      [req.params.id]
    );

    res.json({
      success: true,
      order: orderResult.rows[0],
      items: itemsResult.rows
    });
  })
);


// تحديث حالة الطلب من الإدارة
app.patch(
  '/api/admin/orders/:id/status',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const allowedStatuses = [
      'pending',
      'confirmed',
      'processing',
      'completed',
      'cancelled',
      'rejected'
    ];

    const { status } = req.body;

    if (!allowedStatuses.includes(status)) {
      return sendError(
        res,
        400,
        'حالة الطلب غير صحيحة.',
        'INVALID_ORDER_STATUS'
      );
    }

    const result = await pool.query(
      `
      UPDATE orders
      SET
        status = $1,
        updated_at = NOW()
      WHERE id = $2
      RETURNING *
      `,
      [status, req.params.id]
    );

    if (!result.rowCount) {
      return sendError(
        res,
        404,
        'الطلب غير موجود.',
        'ORDER_NOT_FOUND'
      );
    }

    res.json({
      success: true,
      message: 'تم تحديث حالة الطلب.',
      order: result.rows[0]
    });
  })
);
/* =========================================================
   ADMIN CATALOG MANAGEMENT
   الإدارة وحدها تتحكم في المنتجات والخدمات
========================================================= */

// عرض جميع المنتجات والخدمات للإدارة
app.get(
  '/api/admin/catalog',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const result = await pool.query(`
      SELECT
        ci.*,
        m.business_name,
        (
          SELECT COUNT(*)
          FROM catalog_item_images img
          WHERE img.item_id = ci.id
        ) AS images_count
      FROM catalog_items ci
      INNER JOIN merchants m ON m.id = ci.merchant_id
      ORDER BY ci.created_at DESC
      LIMIT 500
    `);

    res.json({
      success: true,
      items: result.rows
    });
  })
);

// إضافة منتج أو خدمة
app.post(
  '/api/admin/catalog',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const {
      merchant_id,
      section_code,
      category_name,
      item_type,
      name,
      description,
      specifications,
      price,
      currency,
      stock_quantity,
      main_image_url
    } = req.body;

    if (
      !merchant_id ||
      !section_code ||
      !name ||
      !['product', 'service'].includes(item_type)
    ) {
      return sendError(
        res,
        400,
        'بيانات المنتج أو الخدمة غير مكتملة.',
        'INVALID_CATALOG_DATA'
      );
    }

    if (
      price !== undefined &&
      price !== null &&
      (!Number.isFinite(Number(price)) || Number(price) < 0)
    ) {
      return sendError(
        res,
        400,
        'السعر غير صحيح.',
        'INVALID_PRICE'
      );
    }

    const result = await pool.query(
      `
      INSERT INTO catalog_items (
        merchant_id,
        section_code,
        category_name,
        item_type,
        name,
        description,
        specifications,
        price,
        currency,
        stock_quantity,
        main_image_url,
        status,
        created_by_admin,
        updated_by_admin
      )
      SELECT
        m.id,
        $2, $3, $4, $5, $6,
        $7::jsonb,
        $8, $9, $10, $11,
        'draft',
        $12,
        $12
      FROM merchants m
      WHERE m.id = $1
      RETURNING *
      `,
      [
        merchant_id,
        section_code,
        category_name || null,
        item_type,
        name.trim(),
        description || null,
        JSON.stringify(specifications || {}),
        price ?? null,
        currency || 'EGP',
        stock_quantity ?? null,
        main_image_url || null,
        req.user.id
      ]
    );

    if (!result.rowCount) {
      return sendError(
        res,
        404,
        'المتجر غير موجود.',
        'MERCHANT_NOT_FOUND'
      );
    }

    res.status(201).json({
      success: true,
      message: 'تمت إضافة المنتج أو الخدمة.',
      item: result.rows[0]
    });
  })
);


// تعديل بيانات منتج أو خدمة
app.patch(
  '/api/admin/catalog/:id',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const {
      section_code,
      category_name,
      item_type,
      name,
      description,
      specifications,
      price,
      currency,
      stock_quantity,
      main_image_url,
      status
    } = req.body;

    if (
      item_type !== undefined &&
      !['product', 'service'].includes(item_type)
    ) {
      return sendError(
        res,
        400,
        'نوع المنتج غير صحيح.',
        'INVALID_ITEM_TYPE'
      );
    }

    if (
      status !== undefined &&
      !['draft', 'published', 'hidden', 'archived'].includes(status)
    ) {
      return sendError(
        res,
        400,
        'حالة النشر غير صحيحة.',
        'INVALID_ITEM_STATUS'
      );
    }

    if (
      price !== undefined &&
      price !== null &&
      (!Number.isFinite(Number(price)) || Number(price) < 0)
    ) {
      return sendError(
        res,
        400,
        'السعر غير صحيح.',
        'INVALID_PRICE'
      );
    }

    const result = await pool.query(
      `
      UPDATE catalog_items
      SET
        section_code = COALESCE($2, section_code),
        category_name = COALESCE($3, category_name),
        item_type = COALESCE($4, item_type),
        name = COALESCE($5, name),
        description = COALESCE($6, description),
        specifications = COALESCE($7::jsonb, specifications),
        price = COALESCE($8, price),
        currency = COALESCE($9, currency),
        stock_quantity = COALESCE($10, stock_quantity),
        main_image_url = COALESCE($11, main_image_url),
        status = COALESCE($12, status),
        published_at = CASE
          WHEN $12 = 'published' AND published_at IS NULL
          THEN NOW()
          ELSE published_at
        END,
        updated_by_admin = $13,
        updated_at = NOW()
      WHERE id = $1
      RETURNING *
      `,
      [
        req.params.id,
        section_code ?? null,
        category_name ?? null,
        item_type ?? null,
        name?.trim() || null,
        description ?? null,
        specifications === undefined
          ? null
          : JSON.stringify(specifications),
        price ?? null,
        currency ?? null,
        stock_quantity ?? null,
        main_image_url ?? null,
        status ?? null,
        req.user.id
      ]
    );

    if (!result.rowCount) {
      return sendError(
        res,
        404,
        'المنتج أو الخدمة غير موجود.',
        'CATALOG_ITEM_NOT_FOUND'
      );
    }

    res.json({
      success: true,
      message: 'تم تحديث البيانات.',
      item: result.rows[0]
    });
  })
);


// أرشفة منتج أو خدمة بدل الحذف النهائي
app.delete(
  '/api/admin/catalog/:id',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const result = await pool.query(
      `
      UPDATE catalog_items
      SET
        status = 'archived',
        updated_by_admin = $2,
        updated_at = NOW()
      WHERE id = $1
      RETURNING id, name, status
      `,
      [req.params.id, req.user.id]
    );

    if (!result.rowCount) {
      return sendError(
        res,
        404,
        'المنتج أو الخدمة غير موجود.',
        'CATALOG_ITEM_NOT_FOUND'
      );
    }

    res.json({
      success: true,
      message: 'تمت أرشفة المنتج أو الخدمة.',
      item: result.rows[0]
    });
  })
);
/* =========================================================
   ADMIN CATALOG IMAGES
========================================================= */

// عرض صور منتج أو خدمة
app.get(
  '/api/admin/catalog/:id/images',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const result = await pool.query(
      `
      SELECT *
      FROM catalog_item_images
      WHERE item_id = $1
      ORDER BY sort_order ASC, created_at ASC
      `,
      [req.params.id]
    );

    res.json({
      success: true,
      images: result.rows
    });
  })
);


// إضافة صورة
app.post(
  '/api/admin/catalog/:id/images',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const { image_url, alt_text, sort_order, is_primary } = req.body;

    if (!image_url || typeof image_url !== 'string') {
      return sendError(res, 400, 'رابط الصورة مطلوب.', 'IMAGE_URL_REQUIRED');
    }

    const item = await pool.query(
      'SELECT id FROM catalog_items WHERE id = $1',
      [req.params.id]
    );

    if (!item.rowCount) {
      return sendError(res, 404, 'المنتج غير موجود.', 'CATALOG_ITEM_NOT_FOUND');
    }

    const client = await pool.connect();

    try {
      await client.query('BEGIN');

      if (is_primary === true) {
        await client.query(
          'UPDATE catalog_item_images SET is_primary = FALSE WHERE item_id = $1',
          [req.params.id]
        );
      }

      const result = await client.query(
        `
        INSERT INTO catalog_item_images (
          item_id,
          image_url,
          alt_text,
          sort_order,
          is_primary
        )
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *
        `,
        [
          req.params.id,
          image_url.trim(),
          alt_text || null,
          Number.isInteger(sort_order) && sort_order >= 0 ? sort_order : 0,
          is_primary === true
        ]
      );

      await client.query('COMMIT');

      res.status(201).json({
        success: true,
        message: 'تمت إضافة الصورة.',
        image: result.rows[0]
      });
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  })
);


// تحديد الصورة الرئيسية
app.patch(
  '/api/admin/catalog/:id/images/:imageId/primary',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const client = await pool.connect();

    try {
      await client.query('BEGIN');

      const image = await client.query(
        `
        SELECT id
        FROM catalog_item_images
        WHERE id = $1 AND item_id = $2
        FOR UPDATE
        `,
        [req.params.imageId, req.params.id]
      );

      if (!image.rowCount) {
        await client.query('ROLLBACK');
        return sendError(res, 404, 'الصورة غير موجودة.', 'IMAGE_NOT_FOUND');
      }

      await client.query(
        'UPDATE catalog_item_images SET is_primary = FALSE WHERE item_id = $1',
        [req.params.id]
      );

      await client.query(
        `
        UPDATE catalog_item_images
        SET is_primary = TRUE
        WHERE id = $1 AND item_id = $2
        `,
        [req.params.imageId, req.params.id]
      );

      await client.query('COMMIT');

      res.json({
        success: true,
        message: 'تم تحديد الصورة الرئيسية.'
      });
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  })
);


// حذف صورة
app.delete(
  '/api/admin/catalog/:id/images/:imageId',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const result = await pool.query(
      `
      DELETE FROM catalog_item_images
      WHERE id = $1 AND item_id = $2
      RETURNING id
      `,
      [req.params.imageId, req.params.id]
    );

    if (!result.rowCount) {
      return sendError(res, 404, 'الصورة غير موجودة.', 'IMAGE_NOT_FOUND');
    }

    res.json({
      success: true,
      message: 'تم حذف الصورة.'
    });
  })
);


/* =========================================================
   ADMIN OFFERS AND DISCOUNTS
========================================================= */

// عرض جميع العروض
app.get(
  '/api/admin/offers',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const result = await pool.query(`
      SELECT
        o.*,
        m.business_name,
        ci.name AS item_name
      FROM offers o
      INNER JOIN merchants m ON m.id = o.merchant_id
      LEFT JOIN catalog_items ci ON ci.id = o.item_id
      ORDER BY o.created_at DESC
      LIMIT 500
    `);

    res.json({
      success: true,
      offers: result.rows
    });
  })
);


// إنشاء عرض أو خصم
app.post(
  '/api/admin/offers',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const {
      merchant_id,
      item_id,
      title,
      description,
      image_url,
      original_price,
      discounted_price,
      starts_at,
      ends_at
    } = req.body;

    const original = Number(original_price);
    const discounted = Number(discounted_price);
    const startDate = new Date(starts_at);
    const endDate = new Date(ends_at);

    if (
      !merchant_id ||
      !title ||
      !Number.isFinite(original) ||
      !Number.isFinite(discounted) ||
      original <= 0 ||
      discounted < 0 ||
      discounted >= original ||
      !starts_at ||
      !ends_at ||
      Number.isNaN(startDate.getTime()) ||
      Number.isNaN(endDate.getTime()) ||
      endDate <= startDate
    ) {
      return sendError(
        res,
        400,
        'بيانات العرض أو الأسعار أو التواريخ غير صحيحة.',
        'INVALID_OFFER_DATA'
      );
    }

    const merchant = await pool.query(
      'SELECT id FROM merchants WHERE id = $1',
      [merchant_id]
    );

    if (!merchant.rowCount) {
      return sendError(res, 404, 'المتجر غير موجود.', 'MERCHANT_NOT_FOUND');
    }

    if (item_id) {
      const item = await pool.query(
        `
        SELECT id
        FROM catalog_items
        WHERE id = $1 AND merchant_id = $2
        `,
        [item_id, merchant_id]
      );

      if (!item.rowCount) {
        return sendError(
          res,
          400,
          'المنتج لا يتبع المتجر المحدد.',
          'OFFER_ITEM_MERCHANT_MISMATCH'
        );
      }
    }

    const result = await pool.query(
      `
      INSERT INTO offers (
        merchant_id,
        item_id,
        title,
        description,
        image_url,
        original_price,
        discounted_price,
        starts_at,
        ends_at,
        status,
        created_by_admin
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'draft', $10)
      RETURNING *
      `,
      [
        merchant_id,
        item_id || null,
        title.trim(),
        description || null,
        image_url || null,
        original,
        discounted,
        starts_at,
        ends_at,
        req.user.id
      ]
    );

    res.status(201).json({
      success: true,
      message: 'تم إنشاء العرض. وهو محفوظ كمسودة حتى تنشره الإدارة.',
      offer: result.rows[0]
    });
  })
);


// تعديل عرض
app.patch(
  '/api/admin/offers/:id',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const {
      title,
      description,
      image_url,
      original_price,
      discounted_price,
      starts_at,
      ends_at,
      status
    } = req.body;

    const current = await pool.query(
      'SELECT * FROM offers WHERE id = $1',
      [req.params.id]
    );

    if (!current.rowCount) {
      return sendError(res, 404, 'العرض غير موجود.', 'OFFER_NOT_FOUND');
    }

    const old = current.rows[0];

    const original = original_price === undefined
      ? Number(old.original_price)
      : Number(original_price);

    const discounted = discounted_price === undefined
      ? Number(old.discounted_price)
      : Number(discounted_price);

    const start = starts_at === undefined ? old.starts_at : starts_at;
    const end = ends_at === undefined ? old.ends_at : ends_at;

    if (
      !Number.isFinite(original) ||
      !Number.isFinite(discounted) ||
      original <= 0 ||
      discounted < 0 ||
      discounted >= original ||
      new Date(end) <= new Date(start)
    ) {
      return sendError(res, 400, 'بيانات العرض غير صحيحة.', 'INVALID_OFFER_DATA');
    }

    if (
      status !== undefined &&
      !['draft', 'published', 'hidden', 'expired'].includes(status)
    ) {
      return sendError(res, 400, 'حالة العرض غير صحيحة.', 'INVALID_OFFER_STATUS');
    }

    const result = await pool.query(
      `
      UPDATE offers
      SET
        title = COALESCE($2, title),
        description = COALESCE($3, description),
        image_url = COALESCE($4, image_url),
        original_price = $5,
        discounted_price = $6,
        starts_at = $7,
        ends_at = $8,
        status = COALESCE($9, status),
        updated_at = NOW()
      WHERE id = $1
      RETURNING *
      `,
      [
        req.params.id,
        title?.trim() || null,
        description ?? null,
        image_url ?? null,
        original,
        discounted,
        start,
        end,
        status ?? null
      ]
    );

    res.json({
      success: true,
      message: 'تم تحديث العرض.',
      offer: result.rows[0]
    });
  })
);


// إخفاء عرض
app.delete(
  '/api/admin/offers/:id',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const result = await pool.query(
      `
      UPDATE offers
      SET status = 'hidden', updated_at = NOW()
      WHERE id = $1
      RETURNING id, title, status
      `,
      [req.params.id]
    );

    if (!result.rowCount) {
      return sendError(res, 404, 'العرض غير موجود.', 'OFFER_NOT_FOUND');
    }

    res.json({
      success: true,
      message: 'تم إخفاء العرض.',
      offer: result.rows[0]
    });
  })
);
/* =========================================================
   FREE TRIAL REMINDERS
   تذكيرات التجارب المجانية للمستخدمين والتجار
   إرسال قبل الانتهاء بـ 48 ساعة
========================================================= */

app.post(
  '/api/internal/trial-expiry-reminders',
  asyncRoute(async (req, res) => {

    // حماية المسار بمفتاح CRON_SECRET
    const secret = process.env.CRON_SECRET;
    const provided = req.get('x-cron-secret') || '';

    if (
      !secret ||
      !provided ||
      Buffer.byteLength(secret) !== Buffer.byteLength(provided) ||
      !crypto.timingSafeEqual(
        Buffer.from(secret),
        Buffer.from(provided)
      )
    ) {
      return sendError(
        res,
        401,
        'غير مصرح بتنفيذ العملية.',
        'UNAUTHORIZED'
      );
    }

    const results = {
      users: { checked: 0, sent: 0, failed: 0, skipped: 0 },
      merchants: { checked: 0, sent: 0, failed: 0, skipped: 0 }
    };

    /*
      =====================================================
      1. USER TRIALS
      تجارب المستخدمين - 4 أيام
      =====================================================
    */

    const userTrials = await pool.query(`
      SELECT
        s.id AS subscription_id,
        s.user_id,
        COALESCE(s.trial_expires_at, s.ends_at) AS ends_at,
        u.email,
        u.full_name
      FROM subscriptions s
      JOIN packages p ON p.id = s.package_id
      JOIN users u ON u.id = s.user_id
      WHERE p.code = 'TRIAL'
        AND s.status = 'active'
        AND COALESCE(s.trial_expires_at, s.ends_at) > NOW()
        AND COALESCE(s.trial_expires_at, s.ends_at)
            <= NOW() + INTERVAL '48 hours'
        AND u.email_verified = TRUE
        AND u.account_status = 'active'
        AND NOT EXISTS (
          SELECT 1
          FROM trial_reminder_logs l
          WHERE l.trial_type = 'user'
            AND l.subscription_id = s.id
            AND l.reminder_hours = 48
            AND l.channel = 'email'
            AND l.status = 'sent'
        )
      ORDER BY ends_at ASC
      LIMIT 100
    `);

    results.users.checked = userTrials.rowCount;

    for (const item of userTrials.rows) {
      try {
        // قفل لمنع تنفيذ التذكير مرتين بالتزامن
        const lockClient = await pool.connect();

const lock = await lockClient.query(
  `SELECT pg_try_advisory_lock(hashtext($1)) AS locked`,
  [`user-trial-reminder:${item.subscription_id}`]
);

if (!lock.rows[0].locked) {
  lockClient.release();
  results.users.skipped++;
  continue;
}

        try {
          const alreadySent = await pool.query(
            `
            SELECT id
            FROM trial_reminder_logs
            WHERE trial_type = 'user'
              AND subscription_id = $1
              AND reminder_hours = 48
              AND channel = 'email'
              AND status = 'sent'
            LIMIT 1
            `,
            [item.subscription_id]
          );

          if (alreadySent.rowCount) {
            results.users.skipped++;
            continue;
          }

          const expiryDate = new Date(item.ends_at)
            .toLocaleString('ar-EG', {
              dateStyle: 'long',
              timeStyle: 'short',
              timeZone: 'Africa/Cairo'
            });

          await sendEmail(
            item.email,
            'تذكير: تجربتك المجانية في معاك تقترب من الانتهاء',
            `مرحباً ${item.full_name || ''}،

نذكرك بأن تجربتك المجانية في تطبيق معاك ستنتهي خلال 48 ساعة.

موعد انتهاء التجربة: ${expiryDate}.

يمكنك الاشتراك للاستمرار في الاستفادة من خدمات معاك دون انقطاع.

مع تحيات فريق معاك.`
          );

          await withTransaction(async client => {
            await client.query(
              `
              INSERT INTO notifications (
                user_id,
                title,
                message,
                notification_type,
                metadata
              )
              VALUES (
                $1,
                $2,
                $3,
                'subscription',
                $4::jsonb
              )
              `,
              [
                item.user_id,
                'تجربتك المجانية تقترب من الانتهاء',
                'تبقى 48 ساعة على انتهاء تجربتك المجانية في معاك.',
                JSON.stringify({
                  subscription_id: item.subscription_id,
                  ends_at: item.ends_at
                })
              ]
            );

            await client.query(
              `
              INSERT INTO trial_reminder_logs (
                trial_type,
                subscription_id,
                user_id,
                reminder_hours,
                channel,
                status,
                recipient,
                sent_at
              )
              VALUES (
                'user',
                $1,
                $2,
                48,
                'email',
                'sent',
                $3,
                NOW()
              )
              `,
              [
                item.subscription_id,
                item.user_id,
                item.email
              ]
            );
          });

          results.users.sent++;

        } finally {
          await pool.query(
            `SELECT pg_advisory_unlock(hashtext($1))`,
            [`user-trial-reminder:${item.subscription_id}`]
          );
        }

      } catch (error) {
        results.users.failed++;

        console.error(
          'User trial reminder failed:',
          item.subscription_id,
          error.message
        );

        await pool.query(
          `
          INSERT INTO trial_reminder_logs (
            trial_type,
            subscription_id,
            user_id,
            reminder_hours,
            channel,
            status,
            recipient,
            failure_reason
          )
          VALUES (
            'user',
            $1,
            $2,
            48,
            'email',
            'failed',
            $3,
            $4
          )
          `,
          [
            item.subscription_id,
            item.user_id,
            item.email,
            String(error.message).slice(0, 2000)
          ]
        ).catch(logError => {
          console.error('Failed to save user reminder log:', logError.message);
        });
      }
    }

    /*
      =====================================================
      2. MERCHANT TRIALS
      تجارب التجار - 30 يومًا
      =====================================================
    */

    const merchantTrials = await pool.query(`
      SELECT
        ms.id AS subscription_id,
        ms.merchant_id,
        ms.ends_at,
        m.business_name,
        u.id AS user_id,
        u.email,
        u.full_name
      FROM merchant_subscriptions ms
      JOIN merchants m ON m.id = ms.merchant_id
      JOIN users u ON u.id = m.user_id
      WHERE ms.billing_cycle = 'free_trial'
        AND ms.status IN ('trial', 'active')
        AND ms.ends_at > NOW()
        AND ms.ends_at <= NOW() + INTERVAL '48 hours'
        AND ms.reminder_sent_at IS NULL
        AND u.email_verified = TRUE
        AND u.account_status = 'active'
      ORDER BY ms.ends_at ASC
      LIMIT 100
    `);

    results.merchants.checked = merchantTrials.rowCount;

    for (const item of merchantTrials.rows) {
      try {
        const lock = await pool.query(
          `SELECT pg_try_advisory_lock(hashtext($1)) AS locked`,
          [`merchant-trial-reminder:${item.subscription_id}`]
        );

        if (!lock.rows[0].locked) {
          results.merchants.skipped++;
          continue;
        }

        try {
          const alreadySent = await pool.query(
            `
            SELECT id
            FROM trial_reminder_logs
            WHERE trial_type = 'merchant'
              AND subscription_id = $1
              AND reminder_hours = 48
              AND channel = 'email'
              AND status = 'sent'
            LIMIT 1
            `,
            [item.subscription_id]
          );

          if (alreadySent.rowCount) {
            results.merchants.skipped++;
            continue;
          }

          const expiryDate = new Date(item.ends_at)
            .toLocaleString('ar-EG', {
              dateStyle: 'long',
              timeStyle: 'short',
              timeZone: 'Africa/Cairo'
            });

          await sendEmail(
            item.email,
            'تذكير: الفترة التجريبية لمتجرك في معاك تقترب من الانتهاء',
            `مرحباً ${item.full_name || ''}،

نذكرك بأن الفترة التجريبية لمتجرك (${item.business_name}) ستنتهي خلال 48 ساعة.

موعد انتهاء التجربة: ${expiryDate}.

يرجى التواصل مع إدارة معاك لتجديد الاشتراك وتجنب توقف ظهور متجرك للعملاء.

مع تحيات فريق معاك.`
          );

          await withTransaction(async client => {
            await client.query(
              `
              INSERT INTO notifications (
                user_id,
                title,
                message,
                notification_type,
                metadata
              )
              VALUES (
                $1,
                $2,
                $3,
                'merchant_subscription',
                $4::jsonb
              )
              `,
              [
                item.user_id,
                'الفترة التجريبية لمتجرك تقترب من الانتهاء',
                `الفترة التجريبية لمتجرك ${item.business_name} ستنتهي خلال 48 ساعة.`,
                JSON.stringify({
                  subscription_id: item.subscription_id,
                  merchant_id: item.merchant_id,
                  ends_at: item.ends_at
                })
              ]
            );

            await client.query(
              `
              INSERT INTO trial_reminder_logs (
                trial_type,
                subscription_id,
                user_id,
                reminder_hours,
                channel,
                status,
                recipient,
                sent_at
              )
              VALUES (
                'merchant',
                $1,
                $2,
                48,
                'email',
                'sent',
                $3,
                NOW()
              )
              `,
              [
                item.subscription_id,
                item.user_id,
                item.email
              ]
            );

            await client.query(
              `
              UPDATE merchant_subscriptions
              SET reminder_sent_at = NOW(),
                  updated_at = NOW()
              WHERE id = $1
                AND reminder_sent_at IS NULL
              `,
              [item.subscription_id]
            );
          });

          results.merchants.sent++;

        } finally {
          await pool.query(
            `SELECT pg_advisory_unlock(hashtext($1))`,
            [`merchant-trial-reminder:${item.subscription_id}`]
          );
        }

      } catch (error) {
        results.merchants.failed++;

        console.error(
          'Merchant trial reminder failed:',
          item.subscription_id,
          error.message
        );

        await pool.query(
          `
          INSERT INTO trial_reminder_logs (
            trial_type,
            subscription_id,
            user_id,
            reminder_hours,
            channel,
            status,
            recipient,
            failure_reason
          )
          VALUES (
            'merchant',
            $1,
            $2,
            48,
            'email',
            'failed',
            $3,
            $4
          )
          `,
          [
            item.subscription_id,
            item.user_id,
            item.email,
            String(error.message).slice(0, 2000)
          ]
        ).catch(logError => {
          console.error('Failed to save merchant reminder log:', logError.message);
        });
      }
    }

    res.json({
      success: true,
      message: 'انتهى فحص تذكيرات التجارب المجانية.',
      results
    });
  })
);
/* =========================================================
   ADMIN MERCHANT SUBSCRIPTIONS MANAGEMENT
   إدارة اشتراكات التجار - الإدارة فقط
========================================================= */

// عرض اشتراكات التجار
app.get(
  '/api/admin/merchant-subscriptions',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const allowedStatuses = [
      'trial',
      'active',
      'expired',
      'suspended',
      'cancelled'
    ];

    const conditions = [];
    const values = [];

    if (req.query.status) {
      if (!allowedStatuses.includes(req.query.status)) {
        return sendError(
          res,
          400,
          'حالة الاشتراك غير صحيحة.',
          'INVALID_SUBSCRIPTION_STATUS'
        );
      }

      values.push(req.query.status);
      conditions.push(`ms.status = $${values.length}`);
    }

    if (req.query.merchant_id) {
      values.push(req.query.merchant_id);
      conditions.push(`ms.merchant_id = $${values.length}`);
    }

    const whereClause = conditions.length
      ? `WHERE ${conditions.join(' AND ')}`
      : '';

    const result = await pool.query(
      `
      SELECT
        ms.*,
        m.business_name,
        m.status AS merchant_status,
        u.full_name AS owner_name,
        u.email AS owner_email,
        mp.name AS plan_name,
        mp.code AS plan_code
      FROM merchant_subscriptions ms
      JOIN merchants m ON m.id = ms.merchant_id
      JOIN users u ON u.id = m.user_id
      LEFT JOIN merchant_plans mp ON mp.id = ms.plan_id
      ${whereClause}
      ORDER BY ms.created_at DESC
      `,
      values
    );

    res.json({
      success: true,
      total: result.rowCount,
      subscriptions: result.rows
    });
  })
);


// تجديد اشتراك تاجر
app.post(
  '/api/admin/merchants/:id/subscriptions/renew',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const {
      plan_id,
      billing_cycle,
      payment_method,
      payment_confirmed
    } = req.body;

    const cycles = {
      monthly: {
        column: 'monthly_price',
        days: 30
      },
      quarterly: {
        column: 'quarterly_price',
        days: 90
      },
      semiannual: {
        column: 'semiannual_price',
        days: 180
      },
      annual: {
        column: 'annual_price',
        days: 365
      }
    };

    const cycle = cycles[billing_cycle];

    if (!plan_id || !cycle) {
      return sendError(
        res,
        400,
        'اختر باقة وفترة اشتراك صحيحة.',
        'INVALID_RENEWAL_DATA'
      );
    }

    if (payment_confirmed !== true) {
      return sendError(
        res,
        400,
        'يجب تأكيد استلام الدفع من الإدارة قبل تفعيل الاشتراك.',
        'PAYMENT_NOT_CONFIRMED'
      );
    }

    if (
      typeof payment_method !== 'string' ||
      !payment_method.trim() ||
      payment_method.trim().length > 50
    ) {
      return sendError(
        res,
        400,
        'يجب تحديد وسيلة الدفع.',
        'INVALID_PAYMENT_METHOD'
      );
    }

    const planResult = await pool.query(
      `
      SELECT id, name, is_active, ${cycle.column} AS price
      FROM merchant_plans
      WHERE id = $1
      LIMIT 1
      `,
      [plan_id]
    );

    if (!planResult.rowCount || !planResult.rows[0].is_active) {
      return sendError(
        res,
        404,
        'الباقة غير موجودة أو غير مفعلة.',
        'MERCHANT_PLAN_UNAVAILABLE'
      );
    }

    const plan = planResult.rows[0];

    if (
      plan.price === null ||
      plan.price === undefined ||
      !Number.isFinite(Number(plan.price)) ||
      Number(plan.price) <= 0
    ) {
      return sendError(
        res,
        409,
        'سعر هذه الباقة لم يتم تحديده واعتماده بعد.',
        'MERCHANT_PLAN_PRICE_NOT_SET'
      );
    }

    const result = await withTransaction(async (client) => {
      const merchantResult = await client.query(
        `
        SELECT id
        FROM merchants
        WHERE id = $1
        FOR UPDATE
        `,
        [req.params.id]
      );

      if (!merchantResult.rowCount) {
        return { notFound: true };
      }

      const currentResult = await client.query(
        `
        SELECT status, ends_at
        FROM merchant_subscriptions
        WHERE merchant_id = $1
        ORDER BY created_at DESC
        LIMIT 1
        FOR UPDATE
        `,
        [req.params.id]
      );

      const current = currentResult.rows[0];
      const now = new Date();

      let startDate = now;

      if (
        current &&
        ['trial', 'active'].includes(current.status) &&
        new Date(current.ends_at) > now
      ) {
        startDate = new Date(current.ends_at);
      }

      const endDate = new Date(
        startDate.getTime() + cycle.days * 24 * 60 * 60 * 1000
      );

      const inserted = await client.query(
        `
        INSERT INTO merchant_subscriptions (
          merchant_id,
          plan_id,
          billing_cycle,
          status,
          amount,
          currency,
          started_at,
          ends_at,
          renewed_at,
          payment_method,
          auto_renew
        )
        VALUES (
          $1, $2, $3, 'active', $4, 'EGP',
          $5, $6, NOW(), $7, FALSE
        )
        RETURNING *
        `,
        [
          req.params.id,
          plan_id,
          billing_cycle,
          Number(plan.price),
          startDate,
          endDate,
          payment_method.trim()
        ]
      );

      return {
        subscription: inserted.rows[0]
      };
    });

    if (result.notFound) {
      return sendError(
        res,
        404,
        'التاجر غير موجود.',
        'MERCHANT_NOT_FOUND'
      );
    }

    res.status(201).json({
      success: true,
      message: 'تم تسجيل تجديد الاشتراك بعد تأكيد الإدارة للدفع.',
      subscription: result.subscription
    });
  })
);


// إيقاف أو إلغاء أو إعادة تفعيل اشتراك تاجر
app.patch(
  '/api/admin/merchant-subscriptions/:id',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const {
      status,
      payment_method,
      auto_renew,
      ends_at
    } = req.body;

    const allowedStatuses = [
      'active',
      'suspended',
      'cancelled'
    ];

    if (status !== undefined && !allowedStatuses.includes(status)) {
      return sendError(
        res,
        400,
        'حالة الاشتراك المطلوبة غير مسموح بها.',
        'INVALID_SUBSCRIPTION_STATUS'
      );
    }

    if (
      payment_method !== undefined &&
      payment_method !== null &&
      (
        typeof payment_method !== 'string' ||
        payment_method.length > 50
      )
    ) {
      return sendError(
        res,
        400,
        'وسيلة الدفع غير صحيحة.',
        'INVALID_PAYMENT_METHOD'
      );
    }

    if (
      auto_renew !== undefined &&
      typeof auto_renew !== 'boolean'
    ) {
      return sendError(
        res,
        400,
        'قيمة التجديد التلقائي غير صحيحة.',
        'INVALID_AUTO_RENEW'
      );
    }

    if (ends_at !== undefined) {
      const parsedDate = new Date(ends_at);

      if (Number.isNaN(parsedDate.getTime())) {
        return sendError(
          res,
          400,
          'تاريخ انتهاء الاشتراك غير صحيح.',
          'INVALID_END_DATE'
        );
      }

      if (status === 'active' && parsedDate <= new Date()) {
        return sendError(
          res,
          400,
          'لا يمكن تفعيل اشتراك بتاريخ انتهاء سابق أو حالي.',
          'INVALID_ACTIVE_END_DATE'
        );
      }
    }

    if (
      status === undefined &&
      payment_method === undefined &&
      auto_renew === undefined &&
      ends_at === undefined
    ) {
      return sendError(
        res,
        400,
        'لم يتم إرسال أي تعديل.',
        'NO_UPDATE_FIELDS'
      );
    }

    const result = await pool.query(
      `
      UPDATE merchant_subscriptions
      SET
        status = COALESCE($1, status),
        payment_method = CASE
          WHEN $2::boolean THEN $3
          ELSE payment_method
        END,
        auto_renew = COALESCE($4, auto_renew),
        ends_at = COALESCE($5, ends_at),
        updated_at = NOW()
      WHERE id = $6
      RETURNING *
      `,
      [
        status ?? null,
        payment_method !== undefined,
        payment_method ?? null,
        auto_renew ?? null,
        ends_at ?? null,
        req.params.id
      ]
    );

    if (!result.rowCount) {
      return sendError(
        res,
        404,
        'اشتراك التاجر غير موجود.',
        'MERCHANT_SUBSCRIPTION_NOT_FOUND'
      );
    }

    res.json({
      success: true,
      message: 'تم تحديث اشتراك التاجر.',
      subscription: result.rows[0]
    });
  })
);
/* =========================================================
   ADMIN MERCHANT PLANS MANAGEMENT
   الإدارة وحدها تتحكم في باقات التجار وأسعارها
========================================================= */

// عرض جميع باقات التجار
app.get(
  '/api/admin/merchant-plans',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const result = await pool.query(`
      SELECT *
      FROM merchant_plans
      ORDER BY created_at DESC
    `);

    res.json({
      success: true,
      total: result.rowCount,
      plans: result.rows
    });
  })
);


// إضافة باقة تاجر جديدة
app.post(
  '/api/admin/merchant-plans',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const {
      code,
      name,
      monthly_price,
      quarterly_price,
      semiannual_price,
      annual_price,
      description,
      features
    } = req.body;

    if (
      typeof code !== 'string' ||
      !/^[A-Z0-9_]{2,30}$/.test(code) ||
      typeof name !== 'string' ||
      name.trim().length < 2 ||
      name.trim().length > 100
    ) {
      return sendError(
        res,
        400,
        'كود الباقة أو اسمها غير صحيح.',
        'INVALID_PLAN_DATA'
      );
    }

    const prices = {
      monthly_price,
      quarterly_price,
      semiannual_price,
      annual_price
    };

    for (const [key, value] of Object.entries(prices)) {
      if (
        value !== undefined &&
        value !== null &&
        (!Number.isFinite(Number(value)) || Number(value) < 0)
      ) {
        return sendError(
          res,
          400,
          `قيمة ${key} غير صحيحة.`,
          'INVALID_PLAN_PRICE'
        );
      }
    }

    if (
      features !== undefined &&
      (
        features === null ||
        typeof features !== 'object' ||
        Array.isArray(features)
      )
    ) {
      return sendError(
        res,
        400,
        'مميزات الباقة يجب أن تكون بيانات صحيحة.',
        'INVALID_PLAN_FEATURES'
      );
    }

    const result = await pool.query(
      `
      INSERT INTO merchant_plans (
        code,
        name,
        monthly_price,
        quarterly_price,
        semiannual_price,
        annual_price,
        description,
        features,
        is_active
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,TRUE)
      RETURNING *
      `,
      [
        code.trim(),
        name.trim(),
        monthly_price ?? null,
        quarterly_price ?? null,
        semiannual_price ?? null,
        annual_price ?? null,
        description || null,
        JSON.stringify(features || {})
      ]
    );

    res.status(201).json({
      success: true,
      message: 'تم إنشاء باقة التاجر.',
      plan: result.rows[0]
    });
  })
);


// تعديل بيانات وأسعار باقة
app.patch(
  '/api/admin/merchant-plans/:id',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const allowedFields = [
      'name',
      'monthly_price',
      'quarterly_price',
      'semiannual_price',
      'annual_price',
      'description',
      'features',
      'is_active'
    ];

    const updates = [];
    const values = [];

    for (const field of allowedFields) {
      if (!Object.prototype.hasOwnProperty.call(req.body, field)) {
        continue;
      }

      const value = req.body[field];

      if (
        field === 'name' &&
        (
          typeof value !== 'string' ||
          value.trim().length < 2 ||
          value.trim().length > 100
        )
      ) {
        return sendError(
          res,
          400,
          'اسم الباقة غير صحيح.',
          'INVALID_PLAN_NAME'
        );
      }

      if (
        field.endsWith('_price') &&
        value !== null &&
        (!Number.isFinite(Number(value)) || Number(value) < 0)
      ) {
        return sendError(
          res,
          400,
          'سعر الباقة غير صحيح.',
          'INVALID_PLAN_PRICE'
        );
      }

      if (
        field === 'features' &&
        (
          value === null ||
          typeof value !== 'object' ||
          Array.isArray(value)
        )
      ) {
        return sendError(
          res,
          400,
          'مميزات الباقة غير صحيحة.',
          'INVALID_PLAN_FEATURES'
        );
      }

      if (
        field === 'is_active' &&
        typeof value !== 'boolean'
      ) {
        return sendError(
          res,
          400,
          'حالة الباقة غير صحيحة.',
          'INVALID_PLAN_STATUS'
        );
      }

      values.push(
        field === 'name' && typeof value === 'string'
          ? value.trim()
          : field === 'features'
            ? JSON.stringify(value)
            : value
      );

      const column = field === 'features'
        ? 'features'
        : field;

      updates.push(
        `${column} = $${values.length}${field === 'features' ? '::jsonb' : ''}`
      );
    }

    if (!updates.length) {
      return sendError(
        res,
        400,
        'لم يتم إرسال أي تعديلات.',
        'NO_CHANGES'
      );
    }

    values.push(req.params.id);

    const result = await pool.query(
      `
      UPDATE merchant_plans
      SET ${updates.join(', ')},
          updated_at = NOW()
      WHERE id = $${values.length}
      RETURNING *
      `,
      values
    );

    if (!result.rowCount) {
      return sendError(
        res,
        404,
        'باقة التاجر غير موجودة.',
        'MERCHANT_PLAN_NOT_FOUND'
      );
    }

    res.json({
      success: true,
      message: 'تم تحديث باقة التاجر.',
      plan: result.rows[0]
    });
  })
);
/* =========================================================
   ADMIN MERCHANT MANAGEMENT
========================================================= */

// عرض التجار وطلبات الانضمام
app.get(
  '/api/admin/merchants',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const allowedStatuses = [
      'pending',
      'active',
      'suspended',
      'closed'
    ];

    const status = req.query.status;

    if (status && !allowedStatuses.includes(status)) {
      return sendError(
        res,
        400,
        'حالة المتجر غير صحيحة.',
        'INVALID_MERCHANT_STATUS'
      );
    }

    const result = await pool.query(
      `
      SELECT
        m.*,
        u.full_name AS owner_name,
        u.email AS owner_email,
        u.phone AS owner_phone,

        ms.id AS subscription_id,
        ms.status AS subscription_status,
        ms.billing_cycle,
        ms.started_at AS subscription_started_at,
        ms.ends_at AS subscription_ends_at,
        ms.amount AS subscription_amount,
        ms.payment_method

      FROM merchants m

      JOIN users u ON u.id = m.user_id

      LEFT JOIN LATERAL (
        SELECT *
        FROM merchant_subscriptions
        WHERE merchant_id = m.id
        ORDER BY created_at DESC
        LIMIT 1
      ) ms ON TRUE

      WHERE ($1::varchar IS NULL OR m.status = $1)

      ORDER BY
        CASE WHEN m.status = 'pending' THEN 0 ELSE 1 END,
        m.created_at DESC

      LIMIT 500
      `,
      [status || null]
    );

    res.json({
      success: true,
      total: result.rowCount,
      merchants: result.rows
    });
  })
);


// عرض التفاصيل الكاملة لمتجر
app.get(
  '/api/admin/merchants/:id',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const result = await pool.query(
      `
      SELECT
        m.*,
        u.full_name AS owner_name,
        u.email AS owner_email,
        u.phone AS owner_phone,
        u.account_status AS owner_account_status

      FROM merchants m
      JOIN users u ON u.id = m.user_id

      WHERE m.id = $1
      `,
      [req.params.id]
    );

    if (!result.rowCount) {
      return sendError(
        res,
        404,
        'المتجر غير موجود.',
        'MERCHANT_NOT_FOUND'
      );
    }

    const subscriptions = await pool.query(
      `
      SELECT
        ms.*,
        mp.name AS plan_name,
        mp.code AS plan_code

      FROM merchant_subscriptions ms

      LEFT JOIN merchant_plans mp ON mp.id = ms.plan_id

      WHERE ms.merchant_id = $1

      ORDER BY ms.created_at DESC
      `,
      [req.params.id]
    );

    res.json({
      success: true,
      merchant: result.rows[0],
      subscriptions: subscriptions.rows
    });
  })
);


// قبول أو إيقاف أو إغلاق متجر والتحكم في ظهوره
app.patch(
  '/api/admin/merchants/:id/status',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const {
      status,
      is_visible
    } = req.body;

    const allowedStatuses = [
      'pending',
      'active',
      'suspended',
      'closed'
    ];

    if (
      status !== undefined &&
      !allowedStatuses.includes(status)
    ) {
      return sendError(
        res,
        400,
        'حالة المتجر غير صحيحة.',
        'INVALID_MERCHANT_STATUS'
      );
    }

    if (
      is_visible !== undefined &&
      typeof is_visible !== 'boolean'
    ) {
      return sendError(
        res,
        400,
        'قيمة الظهور يجب أن تكون true أو false.',
        'INVALID_VISIBILITY'
      );
    }

    if (status === undefined && is_visible === undefined) {
      return sendError(
        res,
        400,
        'لم يتم إرسال أي تعديل.',
        'NO_CHANGES'
      );
    }

    const client = await pool.connect();

    try {
      await client.query('BEGIN');

      const merchantResult = await client.query(
        `
        SELECT *
        FROM merchants
        WHERE id = $1
        FOR UPDATE
        `,
        [req.params.id]
      );

      if (!merchantResult.rowCount) {
        await client.query('ROLLBACK');

        return sendError(
          res,
          404,
          'المتجر غير موجود.',
          'MERCHANT_NOT_FOUND'
        );
      }

      const merchant = merchantResult.rows[0];

      const newStatus = status || merchant.status;

      // لا يظهر المتجر إلا بعد موافقة الإدارة وتفعيله
      const newVisibility =
      newStatus !== 'active'
         ? false
        : (is_visible === undefined
        ? merchant.is_visible
        : is_visible);

      if (
        newVisibility === true &&
        newStatus !== 'active'
      ) {
        await client.query('ROLLBACK');

        return sendError(
          res,
          400,
          'لا يمكن إظهار متجر غير نشط.',
          'MERCHANT_MUST_BE_ACTIVE'
        );
      }

      await client.query(
        `
        UPDATE merchants
        SET
          status = $2,
          is_visible = $3,
          updated_at = NOW()
        WHERE id = $1
        `,
        [
          req.params.id,
          newStatus,
          newVisibility
        ]
      );

      /*
       * عند التفعيل لأول مرة:
       * يبدأ شهر التجربة المجانية للتاجر.
       * لا ننشئ تجربة جديدة إذا كان له اشتراك سابق.
       */

      if (
        newStatus === 'active' &&
        merchant.status !== 'active'
      ) {
        const existingSubscription = await client.query(
          `
          SELECT id
          FROM merchant_subscriptions
          WHERE merchant_id = $1
          LIMIT 1
          `,
          [req.params.id]
        );

        if (!existingSubscription.rowCount) {
          await client.query(
            `
            INSERT INTO merchant_subscriptions (
              merchant_id,
              billing_cycle,
              status,
              amount,
              started_at,
              ends_at,
              auto_renew
            )
            VALUES (
              $1,
              'free_trial',
              'trial',
              0,
              NOW(),
              NOW() + INTERVAL '30 days',
              FALSE
            )
            `,
            [req.params.id]
          );
        }
      }

      // عند إيقاف المتجر نوقف ظهوره
      if (newStatus !== 'active') {
        await client.query(
          `
          UPDATE merchants
          SET is_visible = FALSE
          WHERE id = $1
          `,
          [req.params.id]
        );
      }

      await client.query('COMMIT');

      const updated = await pool.query(
        `
        SELECT *
        FROM merchants
        WHERE id = $1
        `,
        [req.params.id]
      );

      res.json({
        success: true,
        message: 'تم تحديث حالة المتجر.',
        merchant: updated.rows[0]
      });

    } catch (error) {
      await client.query('ROLLBACK');
      throw error;

    } finally {
      client.release();
    }
  })
);
app.get(
  '/api/auth/me',
  authenticate,
  asyncRoute(async (req, res) => {
    res.json({
      success: true,
      user: safeUser(req.user)
    });
  })
);


/* =========================================================
   LOGOUT
========================================================= */

app.post(
  '/api/auth/logout',
  authenticate,
  asyncRoute(async (req, res) => {
    /*
     * JWT is stateless.
     * Client must remove its stored token.
     * Server-side revocation can be added with a token table.
     */

    await pool.query(
      `
      INSERT INTO audit_logs (
        user_id,
        action,
        entity_type
      )
      VALUES ($1, 'logout', 'user')
      `,
      [req.user.id]
    );

    res.json({
      success: true,
      message: 'تم تسجيل الخروج.'
    });
  })
);


/* =========================================================
   SUBSCRIPTION STATUS
========================================================= */

app.get(
  '/api/subscriptions/current',
  authenticate,
  asyncRoute(async (req, res) => {
    const result = await pool.query(
      `
      SELECT
        s.id,
        s.status,
        s.billing_cycle,
        s.started_at,
        s.ends_at,
        s.trial_expires_at,
        p.code,
        p.name,
        p.daily_word_limit,
        p.daily_image_limit,
        p.daily_product_search_limit,
        p.daily_out_of_range_limit,
        p.max_devices,
        p.max_members
      FROM subscriptions s
      JOIN packages p ON p.id = s.package_id
      WHERE s.user_id = $1
        AND s.status IN ('active', 'pending')
      ORDER BY s.created_at DESC
      LIMIT 1
      `,
      [req.user.id]
    );

    if (!result.rowCount) {
      return res.json({
        success: true,
        subscription: null
      });
    }

    const subscription = result.rows[0];

    if (
      subscription.status === 'active' &&
      subscription.ends_at &&
      new Date(subscription.ends_at) <= new Date()
    ) {
      await pool.query(
        `
        UPDATE subscriptions
        SET status = 'expired'
        WHERE id = $1
          AND status = 'active'
        `,
        [subscription.id]
      );

      subscription.status = 'expired';
    }

    res.json({
      success: true,
      subscription
    });
  })
);


/* =========================================================
   AVAILABLE PACKAGES
========================================================= */

app.get(
  '/api/packages',
  asyncRoute(async (req, res) => {
    const result = await pool.query(
      `
      SELECT
        code,
        name,
        monthly_price,
        quarterly_price,
        semiannual_price,
        annual_price,
        duration_days,
        daily_word_limit,
        daily_image_limit,
        daily_product_search_limit,
        daily_out_of_range_limit,
        max_devices,
        max_members,
        is_trial
      FROM packages
      WHERE is_active = TRUE
      ORDER BY
        CASE code
          WHEN 'TRIAL' THEN 0
          WHEN 'PLUS' THEN 1
          WHEN 'FAMILY' THEN 2
          WHEN 'ELITE' THEN 3
          ELSE 4
        END
      `
    );

    res.json({
      success: true,
      packages: result.rows
    });
  })
);


/* =========================================================
   DAILY USAGE
========================================================= */

async function getActiveSubscription(client, userId) {
  const result = await client.query(
    `
    SELECT
      s.id,
      s.status,
      s.ends_at,
      p.code,
      p.daily_word_limit,
      p.daily_image_limit,
      p.daily_product_search_limit,
      p.daily_out_of_range_limit
    FROM subscriptions s
    JOIN packages p ON p.id = s.package_id
    WHERE s.user_id = $1
      AND s.status = 'active'
      AND s.ends_at > NOW()
    ORDER BY s.created_at DESC
    LIMIT 1
    FOR UPDATE OF s
    `,
    [userId]
  );

  if (!result.rowCount) {
    throw new ApiError(
      403,
      'انتهى اشتراكك أو تجربتك. اختر باقة للاستمرار.',
      'SUBSCRIPTION_INACTIVE'
    );
  }

  return result.rows[0];
}

async function consumeUsage(
  userId,
  type,
  amount
) {
  return withTransaction(async client => {
    const subscription = await getActiveSubscription(
      client,
      userId
    );

    const usageResult = await client.query(
      `
      INSERT INTO usage_daily (user_id, usage_date)
      VALUES ($1, CURRENT_DATE)
      ON CONFLICT (user_id, usage_date)
      DO UPDATE SET updated_at = NOW()
      RETURNING *
      `,
      [userId]
    );

    const usage = usageResult.rows[0];

    const columns = {
      words: {
        column: 'words_used',
        limit: 'daily_word_limit'
      },
      images: {
        column: 'images_used',
        limit: 'daily_image_limit'
      },
      products: {
        column: 'product_searches_used',
        limit: 'daily_product_search_limit'
      },
      outOfRange: {
        column: 'out_of_range_searches_used',
        limit: 'daily_out_of_range_limit'
      }
    };

    const config = columns[type];

    if (!config) {
      throw new ApiError(
        400,
        'نوع الاستهلاك غير معروف.',
        'INVALID_USAGE_TYPE'
      );
    }

    const current = Number(usage[config.column]);
    const maximum = Number(subscription[config.limit]);

    if (current + amount > maximum) {
      throw new ApiError(
        429,
        'وصلت إلى الحد اليومي المسموح به لهذه الخدمة.',
        'DAILY_LIMIT_REACHED'
      );
    }

    const updated = await client.query(
      `
      UPDATE usage_daily
      SET ${config.column} = ${config.column} + $1
      WHERE id = $2
      RETURNING *
      `,
      [amount, usage.id]
    );

    return {
      usage: updated.rows[0],
      subscription
    };
  });
}


app.get(
  '/api/usage/today',
  authenticate,
  asyncRoute(async (req, res) => {
    const result = await pool.query(
      `
      SELECT
        words_used,
        images_used,
        product_searches_used,
        out_of_range_searches_used
      FROM usage_daily
      WHERE user_id = $1
        AND usage_date = CURRENT_DATE
      `,
      [req.user.id]
    );

    res.json({
      success: true,
      usage: result.rows[0] || {
        words_used: 0,
        images_used: 0,
        product_searches_used: 0,
        out_of_range_searches_used: 0
      }
    });
  })
);


/* =========================================================
   AI ASSISTANT
========================================================= */

app.post(
  '/api/assistant/chat',
  authenticate,
  databaseRateLimit({
    keyPrefix: 'assistant',
    limit: 60,
    windowSeconds: 3600
  }),
  asyncRoute(async (req, res) => {
    if (!openai) {
      return sendError(
        res,
        503,
        'خدمة المساعد الذكي غير مهيأة على الخادم.',
        'AI_NOT_CONFIGURED'
      );
    }

    const message = String(req.body.message || '').trim();

    if (!message || message.length > 4000) {
      return sendError(
        res,
        400,
        'اكتب سؤالًا صحيحًا لا يتجاوز 4000 حرف.',
        'INVALID_MESSAGE'
      );
    }

    const wordCount = message
      .split(/\s+/)
      .filter(Boolean).length;

    const consumption = await consumeUsage(
      req.user.id,
      'words',
      wordCount
    );

    try {
      const completion = await openai.chat.completions.create({
        model: process.env.OPENAI_MODEL || 'gpt-4o',
        messages: [
          {
            role: 'system',
            content:
              'أنت مساعد معاك الذكي. ساعد المستخدم بوضوح وحياد، وقدم معلومات عملية. لا تدّع تنفيذ عمليات شراء أو حجز أو دفع لم تتم فعليًا.'
          },
          {
            role: 'user',
            content: message
          }
        ],
        max_tokens: 1200
      });

      const answer =
        completion.choices?.[0]?.message?.content || '';

      res.json({
        success: true,
        answer,
        usage: {
          wordsUsed: consumption.usage.words_used
        }
      });
    } catch (error) {
      console.error('OpenAI error:', error.message);

      throw new ApiError(
        502,
        'تعذر الحصول على رد من المساعد الذكي حاليًا.',
        'AI_PROVIDER_ERROR'
      );
    }
  })
);


/* =========================================================
   AI IMAGE ANALYSIS
========================================================= */

app.post(
  '/api/assistant/analyze-image',
  authenticate,
  databaseRateLimit({
    keyPrefix: 'image-analysis',
    limit: 20,
    windowSeconds: 3600
  }),
  asyncRoute(async (req, res) => {
    if (!openai) {
      return sendError(
        res,
        503,
        'خدمة تحليل الصور غير مهيأة.',
        'AI_NOT_CONFIGURED'
      );
    }

    const imageUrl = String(req.body.imageUrl || '');
    const question = String(
      req.body.question || 'حلل الصورة واشرح ما يظهر فيها.'
    );

    if (
      !/^https:\/\//i.test(imageUrl) ||
      imageUrl.length > 2000
    ) {
      return sendError(
        res,
        400,
        'رابط الصورة غير صالح.',
        'INVALID_IMAGE_URL'
      );
    }

    await consumeUsage(
      req.user.id,
      'images',
      1
    );

    const completion = await openai.chat.completions.create({
      model: process.env.OPENAI_VISION_MODEL || 'gpt-4o',
      messages: [
        {
          role: 'user',
          content: [
            {
              type: 'text',
              text: question.slice(0, 2000)
            },
            {
              type: 'image_url',
              image_url: {
                url: imageUrl
              }
            }
          ]
        }
      ],
      max_tokens: 1200
    });

    res.json({
      success: true,
      answer:
        completion.choices?.[0]?.message?.content || ''
    });
  })
);


/* =========================================================
   PROFILE
========================================================= */

app.get(
  '/api/profile',
  authenticate,
  asyncRoute(async (req, res) => {
    const subscriptionResult = await pool.query(
      `
      SELECT
        s.id,
        s.status,
        s.billing_cycle,
        s.started_at,
        s.ends_at,
        s.trial_expires_at,
        p.code,
        p.name
      FROM subscriptions s
      JOIN packages p ON p.id = s.package_id
      WHERE s.user_id = $1
      ORDER BY s.created_at DESC
      LIMIT 1
      `,
      [req.user.id]
    );

    res.json({
      success: true,
      user: safeUser(req.user),
      subscription: subscriptionResult.rows[0] || null
    });
  })
);


/* =========================================================
   ORDERS
========================================================= */

app.get(
  '/api/orders',
  authenticate,
  asyncRoute(async (req, res) => {
    const result = await pool.query(
      `
      SELECT *
      FROM orders
      WHERE user_id = $1
      ORDER BY created_at DESC
      LIMIT 100
      `,
      [req.user.id]
    );

    res.json({
      success: true,
      orders: result.rows
    });
  })
);


/* =========================================================
   NOTIFICATIONS
========================================================= */

app.get(
  '/api/notifications',
  authenticate,
  asyncRoute(async (req, res) => {
    const result = await pool.query(
      `
      SELECT *
      FROM notifications
      WHERE user_id = $1
      ORDER BY created_at DESC
      LIMIT 100
      `,
      [req.user.id]
    );

    res.json({
      success: true,
      notifications: result.rows
    });
  })
);


app.patch(
  '/api/notifications/:id/read',
  authenticate,
  asyncRoute(async (req, res) => {
    const result = await pool.query(
      `
      UPDATE notifications
      SET is_read = TRUE,
          read_at = NOW()
      WHERE id = $1
        AND user_id = $2
      RETURNING id
      `,
      [req.params.id, req.user.id]
    );

    if (!result.rowCount) {
      return sendError(
        res,
        404,
        'الإشعار غير موجود.',
        'NOTIFICATION_NOT_FOUND'
      );
    }

    res.json({
      success: true
    });
  })
);
/* =========================================================
   ADMIN FREE TRIAL MONITORING
   متابعة التجارب المجانية للمستخدمين والتجار
========================================================= */

app.get(
  '/api/admin/trial-monitoring',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const allowedTypes = ['all', 'users', 'merchants'];
    const type = req.query.type || 'all';

    if (!allowedTypes.includes(type)) {
      return sendError(
        res,
        400,
        'نوع التجربة غير صحيح.',
        'INVALID_TRIAL_TYPE'
      );
    }

    const [userTrials, merchantTrials] = await Promise.all([
      type === 'merchants'
        ? Promise.resolve({ rows: [] })
        : pool.query(`
          SELECT
            s.id AS trial_id,
            s.user_id,
            s.started_at,
            s.ends_at,
            s.trial_expires_at,
            s.status AS subscription_status,

            u.full_name,
            u.email,
            u.phone,
            u.account_status,

            p.code AS package_code,
            p.name AS package_name,

            EXISTS (
              SELECT 1
              FROM subscriptions paid
              JOIN packages paid_package
                ON paid_package.id = paid.package_id
              WHERE paid.user_id = s.user_id
                AND paid.id <> s.id
                AND paid_package.code <> 'TRIAL'
                AND paid.status IN ('active', 'pending')
            ) AS converted_to_paid,

            GREATEST(
              0,
              EXTRACT(
                EPOCH FROM (
                  COALESCE(s.trial_expires_at, s.ends_at) - NOW()
                )
              )
            )::BIGINT AS remaining_seconds,

            CASE
              WHEN EXISTS (
                SELECT 1
                FROM subscriptions paid
                JOIN packages paid_package
                  ON paid_package.id = paid.package_id
                WHERE paid.user_id = s.user_id
                  AND paid.id <> s.id
                  AND paid_package.code <> 'TRIAL'
                  AND paid.status IN ('active', 'pending')
              ) THEN 'converted'

              WHEN COALESCE(s.trial_expires_at, s.ends_at) <= NOW()
                THEN 'expired'

              WHEN COALESCE(s.trial_expires_at, s.ends_at)
                   <= NOW() + INTERVAL '48 hours'
                THEN 'ending_soon'

              ELSE 'active'
            END AS trial_state

          FROM subscriptions s
          JOIN packages p ON p.id = s.package_id
          JOIN users u ON u.id = s.user_id
          WHERE p.code = 'TRIAL'
          ORDER BY s.created_at DESC
          LIMIT 500
        `),

      type === 'users'
        ? Promise.resolve({ rows: [] })
        : pool.query(`
          SELECT
            ms.id AS trial_id,
            ms.merchant_id,
            ms.started_at,
            ms.ends_at,
            ms.status AS subscription_status,

            m.business_name,
            m.status AS merchant_status,

            u.id AS user_id,
            u.full_name,
            u.email,
            u.phone,
            u.account_status,

            EXISTS (
              SELECT 1
              FROM merchant_subscriptions paid
              WHERE paid.merchant_id = ms.merchant_id
                AND paid.id <> ms.id
                AND paid.status = 'active'
                AND paid.billing_cycle <> 'free_trial'
            ) AS converted_to_paid,

            GREATEST(
              0,
              EXTRACT(
                EPOCH FROM (ms.ends_at - NOW())
              )
            )::BIGINT AS remaining_seconds,

            CASE
              WHEN EXISTS (
                SELECT 1
                FROM merchant_subscriptions paid
                WHERE paid.merchant_id = ms.merchant_id
                  AND paid.id <> ms.id
                  AND paid.status = 'active'
                  AND paid.billing_cycle <> 'free_trial'
              ) THEN 'converted'

              WHEN ms.ends_at <= NOW()
                THEN 'expired'

              WHEN ms.ends_at <= NOW() + INTERVAL '48 hours'
                THEN 'ending_soon'

              ELSE 'active'
            END AS trial_state

          FROM merchant_subscriptions ms
          JOIN merchants m ON m.id = ms.merchant_id
          JOIN users u ON u.id = m.user_id
          WHERE ms.billing_cycle = 'free_trial'
          ORDER BY ms.created_at DESC
          LIMIT 500
        `)
    ]);

    const users = userTrials.rows.map(row => ({
      ...row,
      trial_type: 'user'
    }));

    const merchants = merchantTrials.rows.map(row => ({
      ...row,
      trial_type: 'merchant'
    }));

    const trials = [...users, ...merchants];

    const stats = {
      total: trials.length,
      users: users.length,
      merchants: merchants.length,
      active: trials.filter(x => x.trial_state === 'active').length,
      ending_soon: trials.filter(x => x.trial_state === 'ending_soon').length,
      expired: trials.filter(x => x.trial_state === 'expired').length,
      converted: trials.filter(x => x.trial_state === 'converted').length
    };

    res.json({
      success: true,
      stats,
      trials
    });
  })
);
/* =========================================================
   ADMIN USER ACCOUNTS MANAGEMENT
========================================================= */

// عرض الحسابات والبحث والفلترة
app.get(
  '/api/admin/users',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const allowedStatuses = [
      'active',
      'suspended',
      'deleted'
    ];

    const allowedRoles = [
      'user',
      'admin',
      'support',
      'merchant'
    ];

    const values = [];
    const conditions = [];

    if (req.query.status) {
      if (!allowedStatuses.includes(req.query.status)) {
        return sendError(
          res,
          400,
          'حالة الحساب غير صحيحة.',
          'INVALID_ACCOUNT_STATUS'
        );
      }

      values.push(req.query.status);
      conditions.push(`u.account_status = $${values.length}`);
    }

    if (req.query.role) {
      if (!allowedRoles.includes(req.query.role)) {
        return sendError(
          res,
          400,
          'نوع الحساب غير صحيح.',
          'INVALID_USER_ROLE'
        );
      }

      values.push(req.query.role);
      conditions.push(`u.role = $${values.length}`);
    }

    if (req.query.search) {
      values.push(`%${String(req.query.search).trim().slice(0, 100)}%`);
      conditions.push(`
        (
          u.full_name ILIKE $${values.length}
          OR u.email ILIKE $${values.length}
          OR COALESCE(u.phone, '') ILIKE $${values.length}
        )
      `);
    }

    const whereClause = conditions.length
      ? `WHERE ${conditions.join(' AND ')}`
      : '';

    const result = await pool.query(
      `
      SELECT
        u.id,
        u.full_name,
        u.email,
        u.phone,
        u.role,
        u.account_status,
        u.email_verified,
        u.phone_verified,
        u.created_at,

        latest.package_name,
        latest.subscription_status,
        latest.subscription_ends_at,

        COALESCE(device_stats.active_devices, 0)::int
          AS active_devices

      FROM users u

      LEFT JOIN LATERAL (
        SELECT
          p.name AS package_name,
          s.status AS subscription_status,
          s.ends_at AS subscription_ends_at
        FROM subscriptions s
        JOIN packages p ON p.id = s.package_id
        WHERE s.user_id = u.id
        ORDER BY s.created_at DESC
        LIMIT 1
      ) latest ON TRUE

      LEFT JOIN LATERAL (
        SELECT COUNT(*) AS active_devices
        FROM devices d
        WHERE d.user_id = u.id
          AND d.is_active = TRUE
      ) device_stats ON TRUE

      ${whereClause}

      ORDER BY u.created_at DESC
      LIMIT 200
      `,
      values
    );

    res.json({
      success: true,
      total: result.rowCount,
      users: result.rows
    });
  })
);


// عرض ملف مستخدم بالتفصيل
app.get(
  '/api/admin/users/:id',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const userResult = await pool.query(
      `
      SELECT
        id,
        full_name,
        email,
        phone,
        role,
        account_status,
        email_verified,
        phone_verified,
        created_at,
        updated_at
      FROM users
      WHERE id = $1
      LIMIT 1
      `,
      [req.params.id]
    );

    if (!userResult.rowCount) {
      return sendError(
        res,
        404,
        'الحساب غير موجود.',
        'USER_NOT_FOUND'
      );
    }

    const [subscriptions, devices, usage, merchant] =
      await Promise.all([
        pool.query(
          `
          SELECT
            s.id,
            p.code AS package_code,
            p.name AS package_name,
            s.billing_cycle,
            s.status,
            s.started_at,
            s.ends_at,
            s.trial_expires_at,
            s.auto_renew,
            s.created_at
          FROM subscriptions s
          JOIN packages p ON p.id = s.package_id
          WHERE s.user_id = $1
          ORDER BY s.created_at DESC
          LIMIT 50
          `,
          [req.params.id]
        ),

        pool.query(
          `
          SELECT
            id,
            device_name,
            platform,
            is_active,
            last_seen_at,
            created_at
          FROM devices
          WHERE user_id = $1
          ORDER BY last_seen_at DESC
          `,
          [req.params.id]
        ),

        pool.query(
          `
          SELECT
            usage_date,
            words_used,
            images_used,
            product_searches_used,
            out_of_range_searches_used
          FROM usage_daily
          WHERE user_id = $1
          ORDER BY usage_date DESC
          LIMIT 30
          `,
          [req.params.id]
        ),

        pool.query(
          `
          SELECT
            id,
            business_name,
            status,
            is_visible,
            created_at
          FROM merchants
          WHERE user_id = $1
          LIMIT 1
          `,
          [req.params.id]
        )
      ]);

    res.json({
      success: true,
      user: userResult.rows[0],
      subscriptions: subscriptions.rows,
      devices: devices.rows,
      usage: usage.rows,
      merchant: merchant.rows[0] || null
    });
  })
);


// إيقاف حساب أو إعادة تفعيله
app.patch(
  '/api/admin/users/:id/status',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const { account_status } = req.body;

    if (
      !['active', 'suspended'].includes(account_status)
    ) {
      return sendError(
        res,
        400,
        'يمكن تفعيل الحساب أو إيقافه فقط.',
        'INVALID_ACCOUNT_STATUS'
      );
    }

    if (req.params.id === req.user.id) {
      return sendError(
        res,
        400,
        'لا يمكن للإدارة إيقاف حسابها من هذه العملية.',
        'SELF_STATUS_CHANGE_NOT_ALLOWED'
      );
    }

    const result = await pool.query(
      `
      UPDATE users
      SET
        account_status = $1,
        updated_at = NOW()
      WHERE id = $2
        AND account_status <> 'deleted'
      RETURNING
        id,
        full_name,
        email,
        role,
        account_status,
        updated_at
      `,
      [
        account_status,
        req.params.id
      ]
    );

    if (!result.rowCount) {
      return sendError(
        res,
        404,
        'الحساب غير موجود أو محذوف.',
        'USER_NOT_FOUND'
      );
    }

    res.json({
      success: true,
      message: account_status === 'active'
        ? 'تم إعادة تفعيل الحساب.'
        : 'تم إيقاف الحساب.',
      user: result.rows[0]
    });
  })
);
/* =========================================================
   ADMIN PACKAGES MANAGEMENT
   إدارة باقات المستخدمين
========================================================= */

// عرض جميع الباقات
app.get(
  '/api/admin/packages',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const result = await pool.query(`
      SELECT
        id,
        code,
        name,
        monthly_price,
        quarterly_price,
        semiannual_price,
        annual_price,
        duration_days,
        daily_word_limit,
        daily_image_limit,
        daily_product_search_limit,
        daily_out_of_range_limit,
        max_devices,
        max_members,
        is_trial,
        is_active,
        created_at,
        updated_at
      FROM packages
      ORDER BY
        CASE code
          WHEN 'TRIAL' THEN 1
          WHEN 'PLUS' THEN 2
          WHEN 'FAMILY' THEN 3
          WHEN 'ELITE' THEN 4
          ELSE 5
        END
    `);

    res.json({
      success: true,
      total: result.rowCount,
      packages: result.rows
    });
  })
);


// تعديل أسعار وحدود الباقة
app.patch(
  '/api/admin/packages/:id',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const allowedFields = [
      'name',
      'monthly_price',
      'quarterly_price',
      'semiannual_price',
      'annual_price',
      'duration_days',
      'daily_word_limit',
      'daily_image_limit',
      'daily_product_search_limit',
      'daily_out_of_range_limit',
      'is_active'
    ];

    const updates = Object.keys(req.body || {});

    if (
      !updates.length ||
      updates.some(field => !allowedFields.includes(field))
    ) {
      return sendError(
        res,
        400,
        'حقول التعديل غير صحيحة.',
        'INVALID_PACKAGE_FIELDS'
      );
    }

    const currentResult = await pool.query(
      `
      SELECT *
      FROM packages
      WHERE id = $1
      LIMIT 1
      `,
      [req.params.id]
    );

    if (!currentResult.rowCount) {
      return sendError(
        res,
        404,
        'الباقة غير موجودة.',
        'PACKAGE_NOT_FOUND'
      );
    }

    const current = currentResult.rows[0];

    if (
      current.code === 'TRIAL' &&
      req.body.is_active === false
    ) {
      return sendError(
        res,
        400,
        'لا يمكن إيقاف باقة التجربة المجانية.',
        'TRIAL_PACKAGE_REQUIRED'
      );
    }

    const numericFields = [
      'monthly_price',
      'quarterly_price',
      'semiannual_price',
      'annual_price',
      'duration_days',
      'daily_word_limit',
      'daily_image_limit',
      'daily_product_search_limit',
      'daily_out_of_range_limit'
    ];

    for (const field of numericFields) {
      if (req.body[field] !== undefined) {
        const value = req.body[field];

        if (
          typeof value !== 'number' ||
          !Number.isFinite(value) ||
          value < 0
        ) {
          return sendError(
            res,
            400,
            `القيمة المدخلة للحقل ${field} غير صحيحة.`,
            'INVALID_PACKAGE_VALUE'
          );
        }

        if (
          field === 'duration_days' &&
          (!Number.isInteger(value) || value < 1)
        ) {
          return sendError(
            res,
            400,
            'مدة الباقة يجب أن تكون يومًا واحدًا على الأقل.',
            'INVALID_PACKAGE_DURATION'
          );
        }

        if (
          field !== 'duration_days' &&
          !Number.isInteger(value) &&
          field !== 'monthly_price' &&
          field !== 'quarterly_price' &&
          field !== 'semiannual_price' &&
          field !== 'annual_price'
        ) {
          return sendError(
            res,
            400,
            'حدود الاستخدام يجب أن تكون أرقامًا صحيحة.',
            'INVALID_PACKAGE_LIMIT'
          );
        }
      }
    }

    if (
      req.body.name !== undefined &&
      (
        typeof req.body.name !== 'string' ||
        req.body.name.trim().length < 2 ||
        req.body.name.trim().length > 100
      )
    ) {
      return sendError(
        res,
        400,
        'اسم الباقة غير صحيح.',
        'INVALID_PACKAGE_NAME'
      );
    }

    if (
      req.body.is_active !== undefined &&
      typeof req.body.is_active !== 'boolean'
    ) {
      return sendError(
        res,
        400,
        'حالة تفعيل الباقة غير صحيحة.',
        'INVALID_PACKAGE_STATUS'
      );
    }

    const values = [];
    const setParts = [];

    for (const field of updates) {
      values.push(
        field === 'name'
          ? req.body[field].trim()
          : req.body[field]
      );

      setParts.push(
        `${field} = $${values.length}`
      );
    }

    values.push(req.params.id);

    const result = await pool.query(
      `
      UPDATE packages
      SET
        ${setParts.join(', ')},
        updated_at = NOW()
      WHERE id = $${values.length}
      RETURNING *
      `,
      values
    );

    res.json({
      success: true,
      message: 'تم تحديث الباقة بنجاح.',
      package: result.rows[0]
    });
  })
);
/* =========================================================
   ADMIN USER SUBSCRIPTIONS MANAGEMENT
   إدارة اشتراكات المستخدمين
========================================================= */

// عرض اشتراكات المستخدمين
app.get(
  '/api/admin/user-subscriptions',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const allowedStatuses = [
      'pending',
      'active',
      'expired',
      'cancelled',
      'suspended'
    ];

    const conditions = [];
    const values = [];

    if (req.query.status) {
      if (!allowedStatuses.includes(req.query.status)) {
        return sendError(
          res,
          400,
          'حالة الاشتراك غير صحيحة.',
          'INVALID_SUBSCRIPTION_STATUS'
        );
      }

      values.push(req.query.status);
      conditions.push(`s.status = $${values.length}`);
    }

    if (req.query.package) {
      values.push(String(req.query.package).toUpperCase());
      conditions.push(`p.code = $${values.length}`);
    }

    if (req.query.search) {
      values.push(`%${String(req.query.search).trim()}%`);
      conditions.push(`
        (
          u.full_name ILIKE $${values.length}
          OR u.email ILIKE $${values.length}
          OR u.phone ILIKE $${values.length}
        )
      `);
    }

    const whereClause = conditions.length
      ? `WHERE ${conditions.join(' AND ')}`
      : '';

    const result = await pool.query(
      `
      SELECT
        s.id,
        s.user_id,
        s.package_id,
        s.billing_cycle,
        s.status,
        s.started_at,
        s.ends_at,
        s.trial_expires_at,
        s.auto_renew,
        s.created_at,

        u.full_name AS user_name,
        u.email AS user_email,
        u.phone AS user_phone,
        u.account_status,

        p.code AS package_code,
        p.name AS package_name,
        p.monthly_price,
        p.quarterly_price,
        p.semiannual_price,
        p.annual_price,
        p.max_devices,
        p.max_members,

        (
          SELECT COUNT(*)::int
          FROM devices d
          WHERE d.subscription_id = s.id
            AND d.is_active = TRUE
        ) AS active_devices,

        (
          SELECT COUNT(*)::int
          FROM subscription_members sm
          WHERE sm.subscription_id = s.id
            AND sm.status = 'active'
        ) AS active_members

      FROM subscriptions s
      JOIN users u ON u.id = s.user_id
      JOIN packages p ON p.id = s.package_id

      ${whereClause}

      ORDER BY s.created_at DESC
      LIMIT 200
      `,
      values
    );

    res.json({
      success: true,
      total: result.rowCount,
      subscriptions: result.rows
    });
  })
);


// تفاصيل اشتراك مستخدم
app.get(
  '/api/admin/user-subscriptions/:id',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const subscriptionResult = await pool.query(
      `
      SELECT
        s.*,

        u.full_name AS user_name,
        u.email AS user_email,
        u.phone AS user_phone,
        u.account_status,

        p.code AS package_code,
        p.name AS package_name,
        p.monthly_price,
        p.quarterly_price,
        p.semiannual_price,
        p.annual_price,
        p.daily_word_limit,
        p.daily_image_limit,
        p.daily_product_search_limit,
        p.daily_out_of_range_limit,
        p.max_devices,
        p.max_members

      FROM subscriptions s
      JOIN users u ON u.id = s.user_id
      JOIN packages p ON p.id = s.package_id

      WHERE s.id = $1
      LIMIT 1
      `,
      [req.params.id]
    );

    if (!subscriptionResult.rowCount) {
      return sendError(
        res,
        404,
        'الاشتراك غير موجود.',
        'SUBSCRIPTION_NOT_FOUND'
      );
    }

    const subscription = subscriptionResult.rows[0];

    const [devicesResult, membersResult] = await Promise.all([
      pool.query(
        `
        SELECT
          id,
          device_name,
          platform,
          is_active,
          last_seen_at,
          created_at
        FROM devices
        WHERE subscription_id = $1
        ORDER BY created_at DESC
        `,
        [req.params.id]
      ),

      pool.query(
        `
        SELECT
          id,
          user_id,
          member_email,
          member_role,
          status,
          invited_at,
          joined_at
        FROM subscription_members
        WHERE subscription_id = $1
        ORDER BY invited_at DESC
        `,
        [req.params.id]
      )
    ]);

    res.json({
      success: true,
      subscription,
      devices: devicesResult.rows,
      members: membersResult.rows
    });
  })
);


// إيقاف الاشتراك أو إعادة تفعيله
app.patch(
  '/api/admin/user-subscriptions/:id/status',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const allowedStatuses = [
      'active',
      'suspended',
      'cancelled',
      'expired'
    ];

    const { status } = req.body;

    if (!allowedStatuses.includes(status)) {
      return sendError(
        res,
        400,
        'حالة الاشتراك المطلوبة غير صحيحة.',
        'INVALID_SUBSCRIPTION_STATUS'
      );
    }

    const result = await pool.query(
      `
      UPDATE subscriptions
      SET
        status = $1,
        updated_at = NOW()
      WHERE id = $2
        AND (
          $1 <> 'active'
          OR (
            ends_at IS NOT NULL
            AND ends_at > NOW()
          )
        )
      RETURNING *
      `,
      [status, req.params.id]
    );

    if (!result.rowCount) {
      const exists = await pool.query(
        `
        SELECT id, ends_at
        FROM subscriptions
        WHERE id = $1
        LIMIT 1
        `,
        [req.params.id]
      );

      if (!exists.rowCount) {
        return sendError(
          res,
          404,
          'الاشتراك غير موجود.',
          'SUBSCRIPTION_NOT_FOUND'
        );
      }

      return sendError(
        res,
        400,
        'لا يمكن تفعيل اشتراك انتهت مدته. يجب تجديده أولًا.',
        'SUBSCRIPTION_EXPIRED'
      );
    }

    res.json({
      success: true,
      message: 'تم تحديث حالة الاشتراك بنجاح.',
      subscription: result.rows[0]
    });
  })
);
/* =========================================================
   ADMIN PAYMENT TRANSACTIONS
   إدارة ومراجعة مدفوعات المستخدمين
========================================================= */

// عرض سجل المدفوعات مع البحث والتصفية
app.get(
  '/api/admin/payments',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const allowedStatuses = [
      'pending',
      'paid',
      'failed',
      'cancelled',
      'refunded'
    ];

    const conditions = [];
    const values = [];

    if (req.query.status) {
      if (!allowedStatuses.includes(req.query.status)) {
        return sendError(
          res,
          400,
          'حالة الدفع غير صحيحة.',
          'INVALID_PAYMENT_STATUS'
        );
      }

      values.push(req.query.status);
      conditions.push(`pt.status = $${values.length}`);
    }

    if (req.query.user_id) {
      values.push(req.query.user_id);
      conditions.push(`pt.user_id = $${values.length}`);
    }

    if (req.query.provider) {
      values.push(String(req.query.provider).slice(0, 50));
      conditions.push(`pt.provider = $${values.length}`);
    }

    if (req.query.search) {
      values.push(`%${String(req.query.search).trim()}%`);
      conditions.push(`
        (
          u.full_name ILIKE $${values.length}
          OR u.email ILIKE $${values.length}
          OR pt.provider_transaction_id ILIKE $${values.length}
          OR pt.provider_order_id ILIKE $${values.length}
        )
      `);
    }

    const whereClause = conditions.length
      ? `WHERE ${conditions.join(' AND ')}`
      : '';

    const [paymentsResult, statsResult] = await Promise.all([
      pool.query(
        `
        SELECT
          pt.id,
          pt.user_id,
          pt.subscription_id,
          pt.order_id,
          pt.provider,
          pt.provider_transaction_id,
          pt.provider_order_id,
          pt.amount,
          pt.currency,
          pt.status,
          pt.payment_method,
          pt.webhook_verified,
          pt.paid_at,
          pt.created_at,
          pt.updated_at,

          u.full_name AS customer_name,
          u.email AS customer_email,
          u.phone AS customer_phone,

          s.status AS subscription_status,
          s.billing_cycle,
          p.code AS package_code,
          p.name AS package_name

        FROM payment_transactions pt

        JOIN users u ON u.id = pt.user_id

        LEFT JOIN subscriptions s
          ON s.id = pt.subscription_id

        LEFT JOIN packages p
          ON p.id = s.package_id

        ${whereClause}

        ORDER BY pt.created_at DESC
        LIMIT 200
        `,
        values
      ),

      pool.query(`
        SELECT
          COUNT(*)::int AS total,

          COUNT(*) FILTER (
            WHERE status = 'paid'
          )::int AS paid,

          COUNT(*) FILTER (
            WHERE status = 'pending'
          )::int AS pending,

          COUNT(*) FILTER (
            WHERE status = 'failed'
          )::int AS failed,

          COUNT(*) FILTER (
            WHERE status = 'cancelled'
          )::int AS cancelled,

          COUNT(*) FILTER (
            WHERE status = 'refunded'
          )::int AS refunded,

          COALESCE(
            SUM(amount) FILTER (
              WHERE status = 'paid'
            ),
            0
          ) AS total_paid_amount

        FROM payment_transactions
      `)
    ]);

    res.json({
      success: true,
      stats: statsResult.rows[0],
      total: paymentsResult.rowCount,
      payments: paymentsResult.rows
    });
  })
);


// عرض تفاصيل عملية دفع واحدة
app.get(
  '/api/admin/payments/:id',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const result = await pool.query(
      `
      SELECT
        pt.id,
        pt.user_id,
        pt.subscription_id,
        pt.order_id,
        pt.provider,
        pt.provider_transaction_id,
        pt.provider_order_id,
        pt.amount,
        pt.currency,
        pt.status,
        pt.payment_method,
        pt.webhook_verified,
        pt.paid_at,
        pt.created_at,
        pt.updated_at,

        u.full_name AS customer_name,
        u.email AS customer_email,
        u.phone AS customer_phone,
        u.account_status,

        s.status AS subscription_status,
        s.billing_cycle,
        s.started_at AS subscription_started_at,
        s.ends_at AS subscription_ends_at,

        p.code AS package_code,
        p.name AS package_name

      FROM payment_transactions pt

      JOIN users u ON u.id = pt.user_id

      LEFT JOIN subscriptions s
        ON s.id = pt.subscription_id

      LEFT JOIN packages p
        ON p.id = s.package_id

      WHERE pt.id = $1
      LIMIT 1
      `,
      [req.params.id]
    );

    if (!result.rowCount) {
      return sendError(
        res,
        404,
        'عملية الدفع غير موجودة.',
        'PAYMENT_NOT_FOUND'
      );
    }

    res.json({
      success: true,
      payment: result.rows[0]
    });
  })
);
/* =========================================================
   ADMIN NOTIFICATIONS MANAGEMENT
========================================================= */

// عرض الإشعارات ومتابعة قراءتها من لوحة الإدارة
app.get(
  '/api/admin/notifications',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const values = [];
    const conditions = [];

    if (req.query.user_id) {
      values.push(req.query.user_id);
      conditions.push(`n.user_id = $${values.length}`);
    }

    if (req.query.is_read !== undefined) {
      if (!['true', 'false'].includes(req.query.is_read)) {
        return sendError(
          res,
          400,
          'قيمة حالة القراءة غير صحيحة.',
          'INVALID_READ_FILTER'
        );
      }

      values.push(req.query.is_read === 'true');
      conditions.push(`n.is_read = $${values.length}`);
    }

    if (req.query.notification_type) {
      values.push(String(req.query.notification_type).slice(0, 50));
      conditions.push(`n.notification_type = $${values.length}`);
    }

    const whereClause = conditions.length
      ? `WHERE ${conditions.join(' AND ')}`
      : '';

    const result = await pool.query(
      `
      SELECT
        n.*,
        u.full_name AS recipient_name,
        u.email AS recipient_email,
        u.phone AS recipient_phone,
        u.role AS recipient_role
      FROM notifications n
      JOIN users u ON u.id = n.user_id
      ${whereClause}
      ORDER BY n.created_at DESC
      LIMIT 200
      `,
      values
    );

    const stats = await pool.query(
      `
      SELECT
        COUNT(*)::int AS total,
        COUNT(*) FILTER (
          WHERE is_read = FALSE
        )::int AS unread,
        COUNT(*) FILTER (
          WHERE is_read = TRUE
        )::int AS read
      FROM notifications
      `
    );

    res.json({
      success: true,
      stats: stats.rows[0],
      notifications: result.rows
    });
  })
);


// إنشاء إشعار لعميل أو تاجر
app.post(
  '/api/admin/notifications',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const {
      user_id,
      title,
      message,
      notification_type,
      metadata
    } = req.body;

    if (
      !user_id ||
      typeof title !== 'string' ||
      title.trim().length < 2 ||
      title.trim().length > 200 ||
      typeof message !== 'string' ||
      message.trim().length < 2 ||
      message.trim().length > 5000
    ) {
      return sendError(
        res,
        400,
        'راجع بيانات الإشعار والمستلم.',
        'INVALID_NOTIFICATION_DATA'
      );
    }

    const recipient = await pool.query(
      `
      SELECT id, role, full_name
      FROM users
      WHERE id = $1
        AND account_status = 'active'
      LIMIT 1
      `,
      [user_id]
    );

    if (!recipient.rowCount) {
      return sendError(
        res,
        404,
        'المستخدم غير موجود أو حسابه غير نشط.',
        'RECIPIENT_NOT_FOUND'
      );
    }

    const safeMetadata =
      metadata &&
      typeof metadata === 'object' &&
      !Array.isArray(metadata)
        ? metadata
        : {};

    const result = await pool.query(
      `
      INSERT INTO notifications (
        user_id,
        title,
        message,
        notification_type,
        metadata
      )
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *
      `,
      [
        user_id,
        title.trim(),
        message.trim(),
        String(notification_type || 'general').slice(0, 50),
        JSON.stringify(safeMetadata)
      ]
    );

    res.status(201).json({
      success: true,
      message: 'تم إنشاء الإشعار داخل التطبيق.',
      recipient: recipient.rows[0],
      notification: result.rows[0]
    });
  })
);

/* =========================================================
   SUPPORT
========================================================= */

app.post(
  '/api/support/tickets',
  authenticate,
  asyncRoute(async (req, res) => {
    const subject = String(req.body.subject || '').trim();
    const message = String(req.body.message || '').trim();
    const category = String(req.body.category || 'general');

    if (
      subject.length < 3 ||
      subject.length > 200 ||
      message.length < 5 ||
      message.length > 5000
    ) {
      return sendError(
        res,
        400,
        'راجع عنوان الرسالة ومحتواها.',
        'VALIDATION_ERROR'
      );
    }

    const result = await pool.query(
      `
      INSERT INTO support_tickets (
        user_id,
        subject,
        message,
        category
      )
      VALUES ($1, $2, $3, $4)
      RETURNING id, status, created_at
      `,
      [
        req.user.id,
        subject,
        message,
        category.slice(0, 50)
      ]
    );

    res.status(201).json({
      success: true,
      ticket: result.rows[0]
    });
  })
);
/* =========================================================
   ADMIN PURCHASE PROTECTION MANAGEMENT
========================================================= */

// عرض مشتريات العملاء المسجلة في حماية المشتريات
app.get(
  '/api/admin/protected-purchases',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const result = await pool.query(
      `
      SELECT
        p.*,
        u.full_name AS customer_name,
        u.email AS customer_email,
        u.phone AS customer_phone,
        m.business_name AS merchant_name,
        (
          SELECT COUNT(*)
          FROM warranties w
          WHERE w.purchase_id = p.id
        ) AS warranties_count,
        (
          SELECT COUNT(*)
          FROM purchase_complaints c
          WHERE c.purchase_id = p.id
        ) AS complaints_count
      FROM protected_purchases p
      JOIN users u ON u.id = p.user_id
      LEFT JOIN merchants m ON m.id = p.merchant_id
      ORDER BY p.created_at DESC
      LIMIT 200
      `
    );

    res.json({
      success: true,
      purchases: result.rows
    });
  })
);


// تفاصيل عملية شراء مع الضمانات والشكاوى
app.get(
  '/api/admin/protected-purchases/:id',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const purchaseResult = await pool.query(
      `
      SELECT
        p.*,
        u.full_name AS customer_name,
        u.email AS customer_email,
        u.phone AS customer_phone,
        m.business_name AS merchant_name
      FROM protected_purchases p
      JOIN users u ON u.id = p.user_id
      LEFT JOIN merchants m ON m.id = p.merchant_id
      WHERE p.id = $1
      LIMIT 1
      `,
      [req.params.id]
    );

    if (!purchaseResult.rowCount) {
      return sendError(
        res,
        404,
        'عملية الشراء غير موجودة.',
        'PURCHASE_NOT_FOUND'
      );
    }

    const [warranties, complaints] = await Promise.all([
      pool.query(
        `
        SELECT *
        FROM warranties
        WHERE purchase_id = $1
        ORDER BY created_at DESC
        `,
        [req.params.id]
      ),
      pool.query(
        `
        SELECT
          c.*,
          u.full_name AS customer_name,
          u.email AS customer_email
        FROM purchase_complaints c
        JOIN users u ON u.id = c.user_id
        WHERE c.purchase_id = $1
        ORDER BY c.created_at DESC
        `,
        [req.params.id]
      )
    ]);

    res.json({
      success: true,
      purchase: purchaseResult.rows[0],
      warranties: warranties.rows,
      complaints: complaints.rows
    });
  })
);


// إضافة ضمان لعملية شراء
app.post(
  '/api/admin/protected-purchases/:id/warranties',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const {
      provider_name,
      warranty_number,
      starts_at,
      ends_at,
      terms,
      document_url,
      status
    } = req.body;

    const allowedStatuses = [
      'active',
      'expired',
      'claimed',
      'cancelled'
    ];

    if (
      status !== undefined &&
      !allowedStatuses.includes(status)
    ) {
      return sendError(
        res,
        400,
        'حالة الضمان غير صحيحة.',
        'INVALID_WARRANTY_STATUS'
      );
    }

    if (
      starts_at &&
      ends_at &&
      new Date(ends_at) < new Date(starts_at)
    ) {
      return sendError(
        res,
        400,
        'تاريخ انتهاء الضمان لا يمكن أن يسبق بدايته.',
        'INVALID_WARRANTY_DATES'
      );
    }

    const purchase = await pool.query(
      `SELECT id FROM protected_purchases WHERE id = $1`,
      [req.params.id]
    );

    if (!purchase.rowCount) {
      return sendError(
        res,
        404,
        'عملية الشراء غير موجودة.',
        'PURCHASE_NOT_FOUND'
      );
    }

    const result = await pool.query(
      `
      INSERT INTO warranties (
        purchase_id,
        provider_name,
        warranty_number,
        starts_at,
        ends_at,
        terms,
        document_url,
        status
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *
      `,
      [
        req.params.id,
        provider_name || null,
        warranty_number || null,
        starts_at || null,
        ends_at || null,
        terms || null,
        document_url || null,
        status || 'active'
      ]
    );

    res.status(201).json({
      success: true,
      message: 'تم تسجيل الضمان.',
      warranty: result.rows[0]
    });
  })
);


// تعديل بيانات أو حالة الضمان
app.patch(
  '/api/admin/warranties/:id',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const {
      provider_name,
      warranty_number,
      starts_at,
      ends_at,
      terms,
      document_url,
      status
    } = req.body;

    const allowedStatuses = [
      'active',
      'expired',
      'claimed',
      'cancelled'
    ];

    if (
      status !== undefined &&
      !allowedStatuses.includes(status)
    ) {
      return sendError(
        res,
        400,
        'حالة الضمان غير صحيحة.',
        'INVALID_WARRANTY_STATUS'
      );
    }

    const existing = await pool.query(
      `SELECT * FROM warranties WHERE id = $1`,
      [req.params.id]
    );

    if (!existing.rowCount) {
      return sendError(
        res,
        404,
        'الضمان غير موجود.',
        'WARRANTY_NOT_FOUND'
      );
    }

    const current = existing.rows[0];

    const nextStart = starts_at !== undefined
      ? starts_at
      : current.starts_at;

    const nextEnd = ends_at !== undefined
      ? ends_at
      : current.ends_at;

    if (
      nextStart &&
      nextEnd &&
      new Date(nextEnd) < new Date(nextStart)
    ) {
      return sendError(
        res,
        400,
        'تاريخ انتهاء الضمان لا يمكن أن يسبق بدايته.',
        'INVALID_WARRANTY_DATES'
      );
    }

    const result = await pool.query(
      `
      UPDATE warranties
      SET
        provider_name = COALESCE($1, provider_name),
        warranty_number = COALESCE($2, warranty_number),
        starts_at = CASE WHEN $3::boolean THEN $4::date ELSE starts_at END,
        ends_at = CASE WHEN $5::boolean THEN $6::date ELSE ends_at END,
        terms = COALESCE($7, terms),
        document_url = COALESCE($8, document_url),
        status = COALESCE($9, status),
        updated_at = NOW()
      WHERE id = $10
      RETURNING *
      `,
      [
        provider_name ?? null,
        warranty_number ?? null,
        starts_at !== undefined,
        starts_at ?? null,
        ends_at !== undefined,
        ends_at ?? null,
        terms ?? null,
        document_url ?? null,
        status ?? null,
        req.params.id
      ]
    );

    res.json({
      success: true,
      message: 'تم تحديث بيانات الضمان.',
      warranty: result.rows[0]
    });
  })
);


// عرض جميع شكاوى حماية المشتريات للإدارة
app.get(
  '/api/admin/purchase-complaints',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const allowedStatuses = [
      'open',
      'under_review',
      'waiting_customer',
      'resolved',
      'rejected',
      'closed'
    ];

    if (
      req.query.status &&
      !allowedStatuses.includes(req.query.status)
    ) {
      return sendError(
        res,
        400,
        'حالة الشكوى غير صحيحة.',
        'INVALID_COMPLAINT_STATUS'
      );
    }

    const values = [];
    let whereClause = '';

    if (req.query.status) {
      values.push(req.query.status);
      whereClause = `WHERE c.status = $1`;
    }

    const result = await pool.query(
      `
      SELECT
        c.*,
        p.product_name,
        p.purchase_date,
        p.purchase_price,
        u.full_name AS customer_name,
        u.email AS customer_email,
        u.phone AS customer_phone
      FROM purchase_complaints c
      JOIN protected_purchases p ON p.id = c.purchase_id
      JOIN users u ON u.id = c.user_id
      ${whereClause}
      ORDER BY c.created_at DESC
      LIMIT 200
      `,
      values
    );

    res.json({
      success: true,
      complaints: result.rows
    });
  })
);


// رد الإدارة وتحديث شكوى حماية المشتريات
app.patch(
  '/api/admin/purchase-complaints/:id',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const {
      admin_response,
      status
    } = req.body;

    const allowedStatuses = [
      'open',
      'under_review',
      'waiting_customer',
      'resolved',
      'rejected',
      'closed'
    ];

    if (
      status !== undefined &&
      !allowedStatuses.includes(status)
    ) {
      return sendError(
        res,
        400,
        'حالة الشكوى غير صحيحة.',
        'INVALID_COMPLAINT_STATUS'
      );
    }

    if (
      admin_response !== undefined &&
      (
        typeof admin_response !== 'string' ||
        admin_response.trim().length > 5000
      )
    ) {
      return sendError(
        res,
        400,
        'نص رد الإدارة غير صحيح.',
        'INVALID_ADMIN_RESPONSE'
      );
    }

    if (
      status === undefined &&
      admin_response === undefined
    ) {
      return sendError(
        res,
        400,
        'لم يتم إرسال أي تعديل.',
        'NO_UPDATE_FIELDS'
      );
    }

    const result = await pool.query(
      `
      UPDATE purchase_complaints
      SET
        admin_response = CASE
          WHEN $1::boolean THEN $2
          ELSE admin_response
        END,
        status = COALESCE($3, status),
        resolved_at = CASE
          WHEN $3 IN ('resolved', 'rejected', 'closed')
            THEN COALESCE(resolved_at, NOW())
          WHEN $3 IS NOT NULL
            THEN NULL
          ELSE resolved_at
        END,
        updated_at = NOW()
      WHERE id = $4
      RETURNING *
      `,
      [
        admin_response !== undefined,
        admin_response?.trim() || null,
        status ?? null,
        req.params.id
      ]
    );

    if (!result.rowCount) {
      return sendError(
        res,
        404,
        'الشكوى غير موجودة.',
        'COMPLAINT_NOT_FOUND'
      );
    }

    res.json({
      success: true,
      message: 'تم تحديث شكوى حماية المشتريات.',
      complaint: result.rows[0]
    });
  })
);
/* =========================================================
   ADMIN SUPPORT TICKETS MANAGEMENT
   إدارة شكاوى واستفسارات العملاء
========================================================= */

// عرض جميع الشكاوى للإدارة
app.get(
  '/api/admin/support/tickets',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const allowedStatuses = [
      'open',
      'in_progress',
      'waiting_user',
      'resolved',
      'closed'
    ];

    const conditions = [];
    const values = [];

    if (req.query.status) {
      if (!allowedStatuses.includes(req.query.status)) {
        return sendError(
          res,
          400,
          'حالة الشكوى غير صحيحة.',
          'INVALID_TICKET_STATUS'
        );
      }

      values.push(req.query.status);
      conditions.push(`t.status = $${values.length}`);
    }

    const whereClause = conditions.length
      ? `WHERE ${conditions.join(' AND ')}`
      : '';

    const result = await pool.query(
      `
      SELECT
        t.*,
        u.full_name AS customer_name,
        u.email AS customer_email,
        u.phone AS customer_phone
      FROM support_tickets t
      JOIN users u ON u.id = t.user_id
      ${whereClause}
      ORDER BY
        CASE t.priority
          WHEN 'urgent' THEN 1
          WHEN 'high' THEN 2
          WHEN 'normal' THEN 3
          WHEN 'low' THEN 4
        END,
        t.created_at DESC
      LIMIT 200
      `,
      values
    );

    res.json({
      success: true,
      total: result.rowCount,
      tickets: result.rows
    });
  })
);


// تفاصيل شكوى معينة للإدارة
app.get(
  '/api/admin/support/tickets/:id',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const result = await pool.query(
      `
      SELECT
        t.*,
        u.full_name AS customer_name,
        u.email AS customer_email,
        u.phone AS customer_phone
      FROM support_tickets t
      JOIN users u ON u.id = t.user_id
      WHERE t.id = $1
      LIMIT 1
      `,
      [req.params.id]
    );

    if (!result.rowCount) {
      return sendError(
        res,
        404,
        'الشكوى غير موجودة.',
        'TICKET_NOT_FOUND'
      );
    }

    res.json({
      success: true,
      ticket: result.rows[0]
    });
  })
);


// رد الإدارة وتحديث حالة الشكوى
app.patch(
  '/api/admin/support/tickets/:id',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const {
      admin_reply,
      status,
      priority
    } = req.body;

    const allowedStatuses = [
      'open',
      'in_progress',
      'waiting_user',
      'resolved',
      'closed'
    ];

    const allowedPriorities = [
      'low',
      'normal',
      'high',
      'urgent'
    ];

    if (
      status !== undefined &&
      !allowedStatuses.includes(status)
    ) {
      return sendError(
        res,
        400,
        'حالة الشكوى غير صحيحة.',
        'INVALID_TICKET_STATUS'
      );
    }

    if (
      priority !== undefined &&
      !allowedPriorities.includes(priority)
    ) {
      return sendError(
        res,
        400,
        'أولوية الشكوى غير صحيحة.',
        'INVALID_TICKET_PRIORITY'
      );
    }

    if (
      admin_reply !== undefined &&
      (
        typeof admin_reply !== 'string' ||
        admin_reply.trim().length > 5000
      )
    ) {
      return sendError(
        res,
        400,
        'نص الرد غير صحيح.',
        'INVALID_ADMIN_REPLY'
      );
    }

    if (
      status === undefined &&
      priority === undefined &&
      admin_reply === undefined
    ) {
      return sendError(
        res,
        400,
        'لم يتم إرسال أي تعديل.',
        'NO_UPDATE_FIELDS'
      );
    }

    const result = await pool.query(
      `
      UPDATE support_tickets
      SET
        admin_reply = CASE
          WHEN $1::boolean THEN $2
          ELSE admin_reply
        END,
        replied_at = CASE
          WHEN $1::boolean THEN NOW()
          ELSE replied_at
        END,
        status = COALESCE($3, status),
        priority = COALESCE($4, priority),
        updated_at = NOW()
      WHERE id = $5
      RETURNING *
      `,
      [
        admin_reply !== undefined,
        admin_reply?.trim() || null,
        status ?? null,
        priority ?? null,
        req.params.id
      ]
    );

    if (!result.rowCount) {
      return sendError(
        res,
        404,
        'الشكوى غير موجودة.',
        'TICKET_NOT_FOUND'
      );
    }

    const ticket = result.rows[0];

    res.json({
      success: true,
      message: 'تم تحديث الشكوى.',
      ticket
    });
  })
);


// العميل يتابع شكاواه وردود الإدارة
app.get(
  '/api/support/tickets',
  authenticate,
  asyncRoute(async (req, res) => {
    const result = await pool.query(
      `
      SELECT
        id,
        subject,
        message,
        category,
        status,
        priority,
        admin_reply,
        replied_at,
        created_at,
        updated_at
      FROM support_tickets
      WHERE user_id = $1
      ORDER BY created_at DESC
      LIMIT 100
      `,
      [req.user.id]
    );

    res.json({
      success: true,
      tickets: result.rows
    });
  })
);
/* =========================================================
   PAYMOB WEBHOOK
========================================================= */

const PAYMOB_HMAC_FIELDS = [
  'amount_cents',
  'created_at',
  'currency',
  'error_occured',
  'has_parent_transaction',
  'id',
  'integration_id',
  'is_3d_secure',
  'is_auth',
  'is_capture',
  'is_refunded',
  'is_standalone_payment',
  'is_voided',
  'order.id',
  'owner',
  'pending',
  'source_data.pan',
  'source_data.sub_type',
  'source_data.type',
  'success'
];

function getNestedValue(object, path) {
  return path.split('.').reduce(
    (value, key) => value?.[key],
    object
  );
}

function verifyPaymobHmac(transaction, receivedHmac) {
  const secret = process.env.PAYMOB_HMAC_SECRET;

  if (!secret || !receivedHmac) {
    return false;
  }

  const concatenated = PAYMOB_HMAC_FIELDS
    .map(field => {
      const value = getNestedValue(transaction, field);

      if (value === undefined || value === null) {
        return '';
      }

      return String(value);
    })
    .join('');

  const calculated = crypto
    .createHmac('sha512', secret)
    .update(concatenated)
    .digest('hex');

  const received = String(receivedHmac).toLowerCase();

  if (
    !/^[a-f0-9]{128}$/.test(received) ||
    received.length !== calculated.length
  ) {
    return false;
  }

  return crypto.timingSafeEqual(
    Buffer.from(calculated, 'hex'),
    Buffer.from(received, 'hex')
  );
}


app.post(
  '/api/payments/paymob/webhook',
  asyncRoute(async (req, res) => {
    if (!Buffer.isBuffer(req.body)) {
      return sendError(
        res,
        400,
        'صيغة إشعار الدفع غير صحيحة.',
        'INVALID_WEBHOOK_BODY'
      );
    }

    let body;

    try {
      body = JSON.parse(req.body.toString('utf8'));
    } catch {
      return sendError(
        res,
        400,
        'تعذر قراءة إشعار الدفع.',
        'INVALID_WEBHOOK_JSON'
      );
    }

    const transaction = body.obj;

    if (!transaction || typeof transaction !== 'object') {
      return sendError(
        res,
        400,
        'بيانات عملية الدفع غير مكتملة.',
        'INVALID_TRANSACTION'
      );
    }

    const receivedHmac =
      req.query.hmac ||
      body.hmac;

    if (!verifyPaymobHmac(transaction, receivedHmac)) {
      return sendError(
        res,
        403,
        'فشل التحقق من توقيع بوابة الدفع.',
        'INVALID_PAYMOB_HMAC'
      );
    }

    const transactionId = String(transaction.id || '');

    const success = transaction.success === true;
    const pending = transaction.pending === true;
    const errorOccurred = transaction.error_occured === true;

    if (!transactionId) {
      return sendError(
        res,
        400,
        'رقم المعاملة غير موجود.',
        'TRANSACTION_ID_MISSING'
      );
    }

    const paymentResult = await pool.query(
      `
      SELECT *
      FROM payment_transactions
      WHERE provider = 'paymob'
        AND provider_transaction_id = $1
      LIMIT 1
      `,
      [transactionId]
    );

    if (!paymentResult.rowCount) {
      return sendError(
        res,
        404,
        'معاملة الدفع غير مسجلة.',
        'PAYMENT_NOT_FOUND'
      );
    }

    const payment = paymentResult.rows[0];

    const receivedAmount = Number(transaction.amount_cents);
    const expectedAmount = Math.round(
      Number(payment.amount) * 100
    );

    if (
      !Number.isFinite(receivedAmount) ||
      receivedAmount !== expectedAmount
    ) {
      return sendError(
        res,
        400,
        'قيمة الدفع لا تطابق قيمة الطلب.',
        'PAYMENT_AMOUNT_MISMATCH'
      );
    }

    if (
      transaction.currency &&
      String(transaction.currency).toUpperCase() !==
        String(payment.currency).toUpperCase()
    ) {
      return sendError(
        res,
        400,
        'عملة الدفع غير مطابقة.',
        'PAYMENT_CURRENCY_MISMATCH'
      );
    }

    await withTransaction(async client => {
      const locked = await client.query(
        `
        SELECT *
        FROM payment_transactions
        WHERE id = $1
        FOR UPDATE
        `,
        [payment.id]
      );

      if (!locked.rowCount) {
        throw new ApiError(
          404,
          'معاملة الدفع غير موجودة.',
          'PAYMENT_NOT_FOUND'
        );
      }

      const current = locked.rows[0];

      if (current.status === 'paid') {
        return;
      }

      let status = 'pending';

      if (success && !pending && !errorOccurred) {
        status = 'paid';
      } else if (errorOccurred || transaction.success === false) {
        status = 'failed';
      }

      await client.query(
        `
        UPDATE payment_transactions
        SET status = $1,
            webhook_verified = TRUE,
            webhook_payload = $2::jsonb,
            paid_at = CASE
              WHEN $1 = 'paid' THEN NOW()
              ELSE paid_at
            END
        WHERE id = $3
        `,
        [
          status,
          JSON.stringify(body),
          current.id
        ]
      );

      /*
       * Activate subscription only after verified successful payment.
       */

      if (status === 'paid' && current.subscription_id) {
        await client.query(
          `
          UPDATE subscriptions
          SET status = 'active',
              started_at = NOW(),
              ends_at = CASE billing_cycle
                WHEN 'monthly' THEN NOW() + INTERVAL '30 days'
                WHEN 'quarterly' THEN NOW() + INTERVAL '90 days'
                WHEN 'semiannual' THEN NOW() + INTERVAL '180 days'
                WHEN 'annual' THEN NOW() + INTERVAL '365 days'
                ELSE NOW() + INTERVAL '30 days'
              END
          WHERE id = $1
            AND status IN ('pending', 'active')
          `,
          [current.subscription_id]
        );
      }

      await client.query(
        `
        INSERT INTO audit_logs (
          user_id,
          action,
          entity_type,
          entity_id,
          details
        )
        VALUES (
          $1,
          'paymob_webhook_processed',
          'payment',
          $2,
          $3::jsonb
        )
        `,
        [
          current.user_id,
          current.id,
          JSON.stringify({
            transactionId,
            status
          })
        ]
      );
    });

    return res.json({
      success: true,
      received: true
    });
  })
);


/* =========================================================
   ADMIN
========================================================= */

app.get(
  '/api/admin/overview',
  authenticate,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const result = await pool.query(`
      SELECT
        (SELECT COUNT(*) FROM users) AS total_users,
        (SELECT COUNT(*) FROM users WHERE account_status = 'active') AS active_users,
        (SELECT COUNT(*) FROM subscriptions WHERE status = 'active') AS active_subscriptions,
        (SELECT COUNT(*) FROM payment_transactions WHERE status = 'paid') AS successful_payments,
        (SELECT COUNT(*) FROM support_tickets WHERE status = 'open') AS open_tickets
    `);

    res.json({
      success: true,
      overview: result.rows[0]
    });
  })
);


/* =========================================================
   HEALTH
========================================================= */

app.get(
  '/api/health',
  asyncRoute(async (req, res) => {
    await pool.query('SELECT 1');

    res.json({
      success: true,
      service: 'M3AK API',
      status: 'healthy',
      timestamp: new Date().toISOString()
    });
  })
);


/* =========================================================
   API DOCUMENTATION SUMMARY
========================================================= */

app.get('/api/docs', (req, res) => {
  res.json({
    name: 'M3AK API',
    version: '1.0.0',
    authentication: 'Bearer JWT',
    endpoints: {
      auth: [
        'POST /api/auth/signup',
        'POST /api/auth/verify',
        'POST /api/auth/login',
        'POST /api/auth/password-reset/request',
        'POST /api/auth/password-reset/confirm',
        'GET /api/auth/me',
        'POST /api/auth/logout'
      ],
      subscriptions: [
        'GET /api/subscriptions/current',
        'GET /api/packages',
        'GET /api/usage/today'
      ],
      assistant: [
        'POST /api/assistant/chat',
        'POST /api/assistant/analyze-image'
      ],
      account: [
        'GET /api/profile',
        'GET /api/orders',
        'GET /api/notifications',
        'PATCH /api/notifications/:id/read',
        'POST /api/support/tickets'
      ],
      payments: [
        'POST /api/payments/paymob/webhook'
      ],
      admin: [
        'GET /api/admin/overview'
      ]
    }
  });
});


/* =========================================================
   NOT FOUND
========================================================= */

app.use((req, res) => {
  sendError(
    res,
    404,
    'المسار المطلوب غير موجود.',
    'ROUTE_NOT_FOUND'
  );
});


/* =========================================================
   GLOBAL ERROR HANDLER
========================================================= */

app.use((error, req, res, next) => {
  console.error(
    'API error:',
    error.message
  );

  if (res.headersSent) {
    return next(error);
  }

  if (error instanceof ApiError) {
    return sendError(
      res,
      error.status,
      error.message,
      error.code
    );
  }

  if (error.message === 'CORS_ORIGIN_NOT_ALLOWED') {
    return sendError(
      res,
      403,
      'مصدر الطلب غير مسموح.',
      'CORS_FORBIDDEN'
    );
  }

  return sendError(
    res,
    500,
    NODE_ENV === 'production'
      ? 'حدث خطأ داخلي. حاول مرة أخرى.'
      : error.message,
    'INTERNAL_SERVER_ERROR'
  );
});


/* =========================================================
   SERVER START
========================================================= */

/* =========================================================
   SERVER START
========================================================= */

async function startServer() {
  validateEnvironment();

  await pool.query('SELECT 1');

  if (mailer) {
    await mailer.verify();
    console.log('Email service connection verified.');
  } else {
    console.warn('Email service is not configured.');
  }

  const server = app.listen(PORT, () => {
    console.log(`M3AK API running on port ${PORT}`);
    console.log(`Environment: ${NODE_ENV}`);
  });

  return server;
}


/* =========================================================
   EXPORTS FOR TESTING
========================================================= */

module.exports = {
  app,
  pool,
  startServer,
  verifyPaymobHmac,
  hashValue,
  signToken
};


/* =========================================================
   START ONLY WHEN EXECUTED DIRECTLY
========================================================= */

if (require.main === module) {
  startServer().catch(error => {
    console.error(
      'Failed to start M3AK API:',
      error.message
    );

    process.exit(1);
  });
}
