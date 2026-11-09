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

const requiredEnvironment = [
  'DATABASE_URL',
  'JWT_SECRET'
];

for (const key of requiredEnvironment) {
  if (!process.env[key]) {
    console.error(`Missing required environment variable: ${key}`);
    process.exit(1);
  }
}

if (JWT_SECRET.length < 32) {
  console.error('JWT_SECRET must contain at least 32 characters.');
  process.exit(1);
}

if (NODE_ENV === 'production' && !process.env.APP_ORIGIN) {
  console.error('APP_ORIGIN is required in production.');
  process.exit(1);
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

async function startServer() {
  await pool.query('SELECT 1');

  if (mailer) {
    await mailer.verify();
    console.log('Email service connection verified.');
  } else {
    console.warn('Email service is not configured.');
  }

  app.listen(PORT, () => {
    console.log(`M3AK API running on port ${PORT}`);
    console.log(`Environment: ${NODE_ENV}`);
  });
}

startServer().catch(error => {
  console.error('Failed to start M3AK API:', error.message);
  process.exit(1);
});


/* =========================================================
   EXPORTS FOR TESTING
========================================================= */

module.exports = {
  app,
  pool,
  verifyPaymobHmac,
  hashValue,
  signToken
};
