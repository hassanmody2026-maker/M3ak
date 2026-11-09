'use strict';

/**
 * M3AK Static Project Test Runner
 * Node.js 20+
 *
 * Checks:
 * - Package configuration
 * - Database schema structure
 * - Subscription package limits
 * - Trial configuration
 * - Backend security configuration
 *
 * These are static checks only.
 * They do not replace live API/database/payment tests.
 */

const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');

const ROOT = __dirname;

const files = {
  package: path.join(ROOT, 'package.json'),
  schema: path.join(ROOT, 'database_schema.sql'),
  server: path.join(ROOT, 'server.js')
};

let passed = 0;
let failed = 0;

function readRequiredFile(filePath, label) {
  assert.ok(
    fs.existsSync(filePath),
    `${label} is missing`
  );

  return fs.readFileSync(filePath, 'utf8');
}

function test(name, callback) {
  try {
    callback();
    passed++;
    console.log(`PASS: ${name}`);
  } catch (error) {
    failed++;
    console.error(`FAIL: ${name}`);
    console.error(`      ${error.message}`);
  }
}

function extractPackageBlock(schema, packageCode) {
  const escaped = packageCode.replace(
    /[.*+?^${}()|[\]\\]/g,
    '\\$&'
  );

  const regex = new RegExp(
    "\\(\\s*'" + escaped + "'[\\s\\S]*?\\n\\s*\\)",
    'i'
  );

  const match = schema.match(regex);

  assert.ok(
    match,
    `Package ${packageCode} was not found in SQL seed`
  );

  return match[0];
}

function extractNumbers(block) {
  return block.match(/(?<![A-Za-z_])\d+(?:\.\d+)?/g)
    .map(Number);
}

console.log('');
console.log('====================================');
console.log('       M3AK PROJECT TESTS');
console.log('====================================');
console.log('');

let packageJson;
let schema;
let server;

try {
  packageJson = JSON.parse(
    readRequiredFile(files.package, 'package.json')
  );

  schema = readRequiredFile(
    files.schema,
    'database_schema.sql'
  );

  server = readRequiredFile(
    files.server,
    'server.js'
  );
} catch (error) {
  console.error('Cannot start tests:');
  console.error(error.message);
  process.exit(1);
}


/* =====================================
   1. PROJECT CONFIGURATION
===================================== */

test('Project uses CommonJS modules', () => {
  assert.equal(packageJson.type, 'commonjs');
});

test('Project requires Node.js 20 or newer', () => {
  assert.match(
    packageJson.engines.node,
    />=20/
  );
});

test('Test script is configured', () => {
  assert.equal(
    packageJson.scripts.test,
    'node test_runner.js'
  );
});

test('Syntax check script is configured', () => {
  assert.ok(
    packageJson.scripts.check.includes('node --check server.js')
  );

  assert.ok(
    packageJson.scripts.check.includes('node --check test_runner.js')
  );
});


/* =====================================
   2. DATABASE TABLES
===================================== */

const requiredTables = [
  'users',
  'packages',
  'subscriptions',
  'subscription_members',
  'devices',
  'verification_codes',
  'password_reset_tokens',
  'usage_daily',
  'api_rate_limits',
  'orders',
  'notifications',
  'support_tickets',
  'payment_transactions',
  'audit_logs'
];

for (const table of requiredTables) {
  test(`Database table exists: ${table}`, () => {
    const regex = new RegExp(
      `CREATE\\s+TABLE\\s+IF\\s+NOT\\s+EXISTS\\s+${table}\\s*\\(`,
      'i'
    );

    assert.match(schema, regex);
  });
}


/* =====================================
   3. SUBSCRIPTION PACKAGES
===================================== */

test('TRIAL package has four-day duration', () => {
  const block = extractPackageBlock(schema, 'TRIAL');
  const values = extractNumbers(block);

  assert.equal(values[0], 0);
  assert.equal(values[4], 4);
});

test('TRIAL package has approved daily limits', () => {
  const block = extractPackageBlock(schema, 'TRIAL');
  const values = extractNumbers(block);

  assert.deepEqual(
    values.slice(5, 9),
    [1000, 2, 75, 150]
  );
});

test('PLUS package has approved prices', () => {
  const block = extractPackageBlock(schema, 'PLUS');
  const values = extractNumbers(block);

  assert.deepEqual(
    values.slice(0, 4),
    [120, 300, 650, 1350]
  );
});

test('PLUS package has approved daily limits', () => {
  const block = extractPackageBlock(schema, 'PLUS');
  const values = extractNumbers(block);

  assert.deepEqual(
    values.slice(5, 9),
    [2000, 3, 10, 30]
  );
});

test('PLUS is limited to one device', () => {
  const block = extractPackageBlock(schema, 'PLUS');
  const values = extractNumbers(block);

  assert.equal(values[9], 1);
  assert.equal(values[10], 1);
});

test('FAMILY package has approved prices', () => {
  const block = extractPackageBlock(schema, 'FAMILY');
  const values = extractNumbers(block);

  assert.deepEqual(
    values.slice(0, 4),
    [230, 650, 1300, 2750]
  );
});

test('FAMILY package has approved daily limits', () => {
  const block = extractPackageBlock(schema, 'FAMILY');
  const values = extractNumbers(block);

  assert.deepEqual(
    values.slice(5, 9),
    [5000, 6, 20, 50]
  );
});

test('FAMILY is limited to three devices', () => {
  const block = extractPackageBlock(schema, 'FAMILY');
  const values = extractNumbers(block);

  assert.equal(values[9], 3);
});

test('ELITE package has approved prices', () => {
  const block = extractPackageBlock(schema, 'ELITE');
  const values = extractNumbers(block);

  assert.deepEqual(
    values.slice(0, 4),
    [400, 1100, 2200, 4500]
  );
});

test('ELITE package has approved daily limits', () => {
  const block = extractPackageBlock(schema, 'ELITE');
  const values = extractNumbers(block);

  assert.deepEqual(
    values.slice(5, 9),
    [10000, 11, 35, 75]
  );
});

test('ELITE supports three members', () => {
  const block = extractPackageBlock(schema, 'ELITE');
  const values = extractNumbers(block);

  assert.equal(values[10], 3);
});


/* =====================================
   4. DATABASE SECURITY AND INTEGRITY
===================================== */

test('Users have unique email addresses', () => {
  assert.match(
    schema,
    /CONSTRAINT\s+users_email_unique\s+UNIQUE\s*\(\s*email\s*\)/i
  );
});

test('Payment transaction IDs have unique protection', () => {
  assert.match(
    schema,
    /payment_provider_transaction_unique/i
  );
});

test('Payment order IDs have unique protection', () => {
  assert.match(
    schema,
    /payment_provider_order_unique/i
  );
});

test('Daily usage prevents duplicate user/date records', () => {
  assert.match(
    schema,
    /UNIQUE\s*\(\s*user_id\s*,\s*usage_date\s*\)/i
  );
});

test('Database updated_at trigger function exists', () => {
  assert.match(
    schema,
    /CREATE\s+OR\s+REPLACE\s+FUNCTION\s+set_updated_at/i
  );
});

test('Subscriptions contain trial expiration field', () => {
  assert.match(
    schema,
    /trial_expires_at\s+TIMESTAMPTZ/i
  );
});


/* =====================================
   5. BACKEND SECURITY CONFIGURATION
===================================== */

test('Backend loads environment variables', () => {
  assert.match(
    server,
    /require\(['"]dotenv['"]\)\.config\(\)/
  );
});

test('Backend requires DATABASE_URL', () => {
  assert.match(
    server,
    /'DATABASE_URL'/
  );
});

test('Backend requires JWT_SECRET', () => {
  assert.match(
    server,
    /'JWT_SECRET'/
  );
});

test('Backend checks JWT secret length', () => {
  assert.match(
    server,
    /JWT_SECRET\.length\s*<\s*32/
  );
});

test('Backend uses Helmet security middleware', () => {
  assert.match(
    server,
    /app\.use\(helmet\(\)\)/
  );
});

test('Backend uses database connection pool', () => {
  assert.match(
    server,
    /new Pool\(\{/
  );
});

test('Backend verifies Paymob HMAC', () => {
  assert.match(
    server,
    /function verifyPaymobHmac/
  );
});

test('Backend uses timing-safe HMAC comparison', () => {
  assert.match(
    server,
    /crypto\.timingSafeEqual/
  );
});

test('Backend has health endpoint', () => {
  assert.match(
    server,
    /app\.get\(\s*['"]\/api\/health['"]/
  );
});

test('Backend has authentication middleware', () => {
  assert.match(
    server,
    /function authenticate/
  );
});


/* =====================================
   6. RESULTS
===================================== */

console.log('');
console.log('====================================');
console.log('           TEST RESULTS');
console.log('====================================');

console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);
console.log(`Total:  ${passed + failed}`);

console.log('====================================');
console.log('');

if (failed > 0) {
  console.error('M3AK tests failed. Review the errors above.');
  process.exit(1);
}

console.log('All static checks passed.');
console.log('Live database and API tests are still required.');

process.exit(0);
