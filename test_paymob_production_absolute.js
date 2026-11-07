'use strict';

/**
 * M3AK Paymob webhook contract checks.
 *
 * Run: node test_paymob_production_absolute.js
 *
 * Source-level checks only.
 * No real payments, Paymob API calls, or database connections.
 */

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const serverPath = path.join(__dirname, 'server.js');
const source = fs.readFileSync(serverPath, 'utf8');

const checks = [
  [
    'Paymob webhook route is registered',
    /app\.post\(\s*['"]\/api\/payments\/paymob-webhook['"]/s
  ],
  [
    'HMAC uses SHA-512',
    /createHmac\(['"]sha512['"]/
  ],
  [
    'HMAC comparison uses timing-safe comparison',
    /safeEqualHex\(calculated,\s*receivedHmac\)/
  ],
  [
    'Only successful, captured, non-pending payments are processed',
    /obj\.success !== true[\s\S]*?obj\.pending === true[\s\S]*?obj\.is_capture !== true/
  ],
  [
    'Currency is checked against EGP',
    /obj\.currency[\s\S]{0,160}EGP/
  ],
  [
    'Integration ID is checked',
    /obj\.integration_id[\s\S]{0,160}PAYMOB_INTEGRATION_ID/
  ],
  [
    'Payment row is locked and matched by merchant order ID',
    /FROM subscriptions_payments[\s\S]{0,180}WHERE merchant_order_id = \$1[\s\S]{0,80}FOR UPDATE/
  ],
  [
    'Paid amount is compared with stored payment amount',
    /amount_cents[\s\S]{0,260}payment\.amount/
  ],
  [
    'Subscription duration comes from the selected package',
    /SELECT duration_days FROM packages WHERE id = \$1[\s\S]{0,500}durationDays/
  ],
  [
    'Subscription and payment updates are committed transactionally',
    /UPDATE users[\s\S]{0,900}UPDATE subscriptions_payments[\s\S]{0,400}COMMIT/
  ],
  [
    'Existing atomic rate limiter remains present',
    /function atomicRateLimiter\(/
  ]
];

let failures = 0;

for (const [label, pattern] of checks) {
  try {
    assert.match(source, pattern);
    console.log('PASS  ' + label);
  } catch {
    failures++;
    console.error('FAIL  ' + label);
  }
}

console.log(
  '\n' + (checks.length - failures) +
  '/' + checks.length + ' checks passed.'
);

if (failures > 0) {
  process.exitCode = 1;
} else {
  console.log(
    'Source contract checks passed. Runtime/database integration is not tested by this script.'
  );
}
