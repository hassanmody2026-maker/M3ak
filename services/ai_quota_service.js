'use strict';

const crypto = require('crypto');

class QuotaError extends Error {
    constructor(message, code, statusCode = 400) {
        super(message);
        this.name = 'QuotaError';
        this.code = code;
        this.statusCode = statusCode;
    }
}

function assertPositiveInteger(value, name, allowZero = false) {
    if (
        !Number.isSafeInteger(value) ||
        (allowZero ? value < 0 : value <= 0)
    ) {
        throw new QuotaError(
            `Invalid ${name}`,
            'INVALID_ARGUMENT'
        );
    }
}

function addMonthsClamped(date, months, anchorDay) {
    const year = date.getUTCFullYear();
    const month = date.getUTCMonth() + months;

    const firstOfTargetMonth = new Date(
        Date.UTC(year, month, 1)
    );

    const targetYear = firstOfTargetMonth.getUTCFullYear();
    const targetMonth = firstOfTargetMonth.getUTCMonth();

    const lastDay = new Date(
        Date.UTC(targetYear, targetMonth + 1, 0)
    ).getUTCDate();

    const day = Math.min(anchorDay, lastDay);

    return new Date(Date.UTC(
        targetYear,
        targetMonth,
        day,
        date.getUTCHours(),
        date.getUTCMinutes(),
        date.getUTCSeconds(),
        date.getUTCMilliseconds()
    ));
}

function calculateQuotaPeriod(now, anchorAt, anchorDay) {
    const anchor = new Date(anchorAt);

    if (Number.isNaN(anchor.getTime())) {
        throw new QuotaError(
            'Invalid quota anchor date',
            'INVALID_ANCHOR'
        );
    }

    let monthDifference =
        (now.getUTCFullYear() - anchor.getUTCFullYear()) * 12 +
        (now.getUTCMonth() - anchor.getUTCMonth());

    let periodStart = addMonthsClamped(
        anchor,
        monthDifference,
        anchorDay
    );

    if (periodStart > now) {
        monthDifference--;
        periodStart = addMonthsClamped(
            anchor,
            monthDifference,
            anchorDay
        );
    }

    const periodEnd = addMonthsClamped(
        anchor,
        monthDifference + 1,
        anchorDay
    );

    return {
        periodStart,
        periodEnd
    };
}

async function withTransaction(pool, callback) {
    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        const result = await callback(client);

        await client.query('COMMIT');

        return result;
    } catch (error) {
        try {
            await client.query('ROLLBACK');
        } catch (_) {
            // Preserve the original error.
        }

        throw error;
    } finally {
        client.release();
    }
}

async function getOrCreatePeriod(
    client,
    userId,
    wordsLimit,
    imagesLimit,
    requestedAnchorAt
) {
    const userResult = await client.query(
        `SELECT
            id,
            ai_quota_anchor_at,
            ai_quota_anchor_day
         FROM users
         WHERE id = $1
         FOR UPDATE`,
        [userId]
    );

    if (userResult.rowCount === 0) {
        throw new QuotaError(
            'User not found',
            'USER_NOT_FOUND',
            404
        );
    }

    let user = userResult.rows[0];

    if (
        !user.ai_quota_anchor_at ||
        !user.ai_quota_anchor_day
    ) {
        const initialAnchor = requestedAnchorAt
            ? new Date(requestedAnchorAt)
            : new Date();

        if (Number.isNaN(initialAnchor.getTime())) {
            throw new QuotaError(
                'Invalid initial anchor date',
                'INVALID_ANCHOR'
            );
        }

        const anchorDay = initialAnchor.getUTCDate();

        await client.query(
            `UPDATE users
             SET
                ai_quota_anchor_at = $2,
                ai_quota_anchor_day = $3
             WHERE id = $1`,
            [
                userId,
                initialAnchor.toISOString(),
                anchorDay
            ]
        );

        user.ai_quota_anchor_at = initialAnchor;
        user.ai_quota_anchor_day = anchorDay;
    }

    const now = new Date();

    const period = calculateQuotaPeriod(
        now,
        user.ai_quota_anchor_at,
        Number(user.ai_quota_anchor_day)
    );

    await client.query(
        `INSERT INTO ai_quota_periods (
            user_id,
            period_start,
            period_end,
            anchor_day,
            words_limit,
            images_limit
         )
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (user_id, period_start)
         DO NOTHING`,
        [
            userId,
            period.periodStart.toISOString(),
            period.periodEnd.toISOString(),
            Number(user.ai_quota_anchor_day),
            wordsLimit,
            imagesLimit
        ]
    );

    const periodResult = await client.query(
        `SELECT *
         FROM ai_quota_periods
         WHERE user_id = $1
           AND period_start = $2
         FOR UPDATE`,
        [
            userId,
            period.periodStart.toISOString()
        ]
    );

    if (periodResult.rowCount === 0) {
        throw new QuotaError(
            'Could not initialize quota period',
            'PERIOD_INITIALIZATION_FAILED',
            500
        );
    }

    return periodResult.rows[0];
}

async function insertLedgerEvent(
    client,
    {
        eventKey,
        reservationId,
        userId,
        periodId,
        eventType,
        wordsDelta,
        imagesDelta,
        metadata = {}
    }
) {
    const result = await client.query(
        `INSERT INTO ai_usage_ledger (
            event_key,
            reservation_id,
            user_id,
            period_id,
            event_type,
            words_delta,
            images_delta,
            metadata
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (event_key)
         DO NOTHING
         RETURNING id`,
        [
            eventKey,
            reservationId,
            userId,
            periodId,
            eventType,
            wordsDelta,
            imagesDelta,
            JSON.stringify(metadata)
        ]
    );

    return result.rowCount === 1;
}

/**
 * Reserve quota before calling the AI provider.
 *
 * Required:
 * pool, userId, idempotencyKey, wordsLimit,
 * imagesLimit, reservedWords, reservedImages.
 *
 * Optional:
 * anchorAt, leaseSeconds, metadata.
 */
async function reserveAiQuota(pool, options) {
    const {
        userId,
        idempotencyKey,
        wordsLimit,
        imagesLimit,
        reservedWords,
        reservedImages,
        anchorAt,
        leaseSeconds = 180,
        metadata = {}
    } = options || {};

    assertPositiveInteger(userId, 'userId');
    assertPositiveInteger(wordsLimit, 'wordsLimit', true);
    assertPositiveInteger(imagesLimit, 'imagesLimit', true);
    assertPositiveInteger(reservedWords, 'reservedWords', true);
    assertPositiveInteger(reservedImages, 'reservedImages', true);
    assertPositiveInteger(leaseSeconds, 'leaseSeconds');

    if (
        typeof idempotencyKey !== 'string' ||
        idempotencyKey.trim().length < 8 ||
        idempotencyKey.length > 200
    ) {
        throw new QuotaError(
            'A valid idempotency key is required',
            'INVALID_IDEMPOTENCY_KEY'
        );
    }

    return withTransaction(pool, async client => {
        // Locking the user serializes period creation and reservations
        // for this user.
        const period = await getOrCreatePeriod(
            client,
            userId,
            wordsLimit,
            imagesLimit,
            anchorAt
        );

        const existing = await client.query(
            `SELECT *
             FROM ai_request_reservations
             WHERE user_id = $1
               AND idempotency_key = $2`,
            [userId, idempotencyKey]
        );

        if (existing.rowCount > 0) {
            const reservation = existing.rows[0];

            if (
                Number(reservation.reserved_words) !== reservedWords ||
                Number(reservation.reserved_images) !== reservedImages
            ) {
                throw new QuotaError(
                    'Idempotency key was already used with different quota values',
                    'IDEMPOTENCY_CONFLICT',
                    409
                );
            }

            return {
                created: false,
                reservation
            };
        }

        const availableWords =
            Number(period.words_limit) -
            Number(period.words_consumed) -
            Number(period.words_reserved);

        const availableImages =
            Number(period.images_limit) -
            Number(period.images_consumed) -
            Number(period.images_reserved);

        if (
            reservedWords > availableWords ||
            reservedImages > availableImages
        ) {
            throw new QuotaError(
                'Monthly AI quota exceeded',
                'QUOTA_EXCEEDED',
                429
            );
        }

        const reservationId = crypto.randomUUID();

        const leaseExpiresAt = new Date(
            Date.now() + leaseSeconds * 1000
        );

        await client.query(
            `UPDATE ai_quota_periods
             SET
                words_reserved = words_reserved + $2,
                images_reserved = images_reserved + $3,
                updated_at = CURRENT_TIMESTAMP
             WHERE id = $1`,
            [
                period.id,
                reservedWords,
                reservedImages
            ]
        );

        const reservationResult = await client.query(
            `INSERT INTO ai_request_reservations (
                reservation_id,
                user_id,
                period_id,
                idempotency_key,
                reserved_words,
                reserved_images,
                status,
                lease_expires_at,
                metadata
             )
             VALUES ($1, $2, $3, $4, $5, $6, 'reserved', $7, $8)
             RETURNING *`,
            [
                reservationId,
                userId,
                period.id,
                idempotencyKey,
                reservedWords,
                reservedImages,
                leaseExpiresAt.toISOString(),
                JSON.stringify(metadata)
            ]
        );

        await insertLedgerEvent(client, {
            eventKey: `reserve:${reservationId}`,
            reservationId,
            userId,
            periodId: period.id,
            eventType: 'reserve',
            wordsDelta: reservedWords,
            imagesDelta: reservedImages
        });

        await client.query(
            `INSERT INTO ai_recovery_jobs (
                reservation_id,
                status,
                next_attempt_at
             )
             VALUES ($1, 'pending', $2)
             ON CONFLICT (reservation_id)
             DO NOTHING`,
            [
                reservationId,
                leaseExpiresAt.toISOString()
            ]
        );

        return {
            created: true,
            reservation: reservationResult.rows[0]
        };
    });
}

/**
 * Record that the AI provider successfully completed the request.
 * This must happen before settlement.
 */
async function markProviderSucceeded(
    pool,
    {
        reservationId,
        providerRequestId = null
    }
) {
    if (!reservationId) {
        throw new QuotaError(
            'reservationId is required',
            'INVALID_ARGUMENT'
        );
    }

    return withTransaction(pool, async client => {
        const result = await client.query(
            `UPDATE ai_request_reservations
             SET
                status = 'provider_succeeded',
                provider_request_id = COALESCE($2, provider_request_id),
                provider_succeeded_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
             WHERE reservation_id = $1
               AND status = 'reserved'
             RETURNING *`,
            [reservationId, providerRequestId]
        );

        if (result.rowCount === 0) {
            const existing = await client.query(
                `SELECT *
                 FROM ai_request_reservations
                 WHERE reservation_id = $1`,
                [reservationId]
            );

            if (
                existing.rowCount &&
                [
                    'provider_succeeded',
                    'settled'
                ].includes(existing.rows[0].status)
            ) {
                return existing.rows[0];
            }

            throw new QuotaError(
                'Reservation cannot be marked as provider succeeded',
                'INVALID_RESERVATION_STATE',
                409
            );
        }

        return result.rows[0];
    });
}

/**
 * Settle a successful provider request.
 *
 * actualWords and actualImages must not exceed reserved amounts.
 * Reserve enough capacity before calling the provider.
 */
async function settleAiReservation(
    pool,
    {
        reservationId,
        actualWords,
                actualImages = 0,
        metadata = {},
        responseText = null
    }
) {
    if (!reservationId) {
        throw new QuotaError(
            'reservationId is required',
            'INVALID_ARGUMENT'
        );
    }

    assertPositiveInteger(actualWords, 'actualWords', true);
    assertPositiveInteger(actualImages, 'actualImages', true);

    return withTransaction(pool, async client => {
        const reservationResult = await client.query(
            `SELECT *
             FROM ai_request_reservations
             WHERE reservation_id = $1
             FOR UPDATE`,
            [reservationId]
        );

        if (reservationResult.rowCount === 0) {
            throw new QuotaError(
                'Reservation not found',
                'RESERVATION_NOT_FOUND',
                404
            );
        }

        const reservation = reservationResult.rows[0];

        if (reservation.status === 'settled') {
            return {
                settled: false,
                alreadySettled: true,
                reservation
            };
        }

        if (reservation.status !== 'provider_succeeded') {
            throw new QuotaError(
                'Provider success must be recorded before settlement',
                'INVALID_RESERVATION_STATE',
                409
            );
        }

        if (
            actualWords > Number(reservation.reserved_words) ||
            actualImages > Number(reservation.reserved_images)
        ) {
            throw new QuotaError(
                'Actual usage exceeds reserved quota',
                'RESERVATION_UNDERFUNDED',
                409
            );
        }

        const periodResult = await client.query(
            `SELECT *
             FROM ai_quota_periods
             WHERE id = $1
               AND user_id = $2
             FOR UPDATE`,
            [
                reservation.period_id,
                reservation.user_id
            ]
        );

        if (periodResult.rowCount === 0) {
            throw new QuotaError(
                'Quota period not found',
                'PERIOD_NOT_FOUND',
                500
            );
        }

        await client.query(
            `UPDATE ai_quota_periods
             SET
                words_reserved = words_reserved - $2,
                images_reserved = images_reserved - $3,
                words_consumed = words_consumed + $4,
                images_consumed = images_consumed + $5,
                updated_at = CURRENT_TIMESTAMP
             WHERE id = $1`,
            [
                reservation.period_id,
                reservation.reserved_words,
                reservation.reserved_images,
                actualWords,
                actualImages
            ]
        );

        const ledgerInserted = await insertLedgerEvent(client, {
            eventKey: `settle:${reservationId}`,
            reservationId,
            userId: reservation.user_id,
            periodId: reservation.period_id,
            eventType: 'settle',
            wordsDelta: actualWords - Number(reservation.reserved_words),
            imagesDelta: actualImages - Number(reservation.reserved_images),
            metadata
        });

        if (!ledgerInserted) {
            throw new QuotaError(
                'Settlement ledger event already exists unexpectedly',
                'LEDGER_CONFLICT',
                409
            );
        }

        const updated = await client.query(
            `UPDATE ai_request_reservations
             SET
                actual_words = $2,
                actual_images = $3,
                status = 'settled',
                updated_at = CURRENT_TIMESTAMP
             WHERE reservation_id = $1
             RETURNING *`,
            [
                reservationId,
                actualWords,
                actualImages
            ]
        );

        await client.query(
            `UPDATE ai_recovery_jobs
             SET
                status = 'completed',
                updated_at = CURRENT_TIMESTAMP,
                locked_at = NULL,
                locked_by = NULL
             WHERE reservation_id = $1`,
            [reservationId]
        );

        return {
            settled: true,
            reservation: updated.rows[0]
        };
    });
}

/**
 * Refund a reservation only when provider execution is known
 * not to have succeeded.
 *
 * Never use this for provider_succeeded or unknown requests.
 */
async function refundAiReservation(
    pool,
    {
        reservationId,
        reason = 'Request failed before provider success'
    }
) {
    if (!reservationId) {
        throw new QuotaError(
            'reservationId is required',
            'INVALID_ARGUMENT'
        );
    }

    return withTransaction(pool, async client => {
        const reservationResult = await client.query(
            `SELECT *
             FROM ai_request_reservations
             WHERE reservation_id = $1
             FOR UPDATE`,
            [reservationId]
        );

        if (reservationResult.rowCount === 0) {
            throw new QuotaError(
                'Reservation not found',
                'RESERVATION_NOT_FOUND',
                404
            );
        }

        const reservation = reservationResult.rows[0];

        if (reservation.status === 'refunded') {
            return {
                refunded: false,
                alreadyRefunded: true,
                reservation
            };
        }

        if (
            reservation.status !== 'reserved' &&
            reservation.status !== 'failed'
        ) {
            throw new QuotaError(
                'Cannot refund a request with uncertain or successful provider execution',
                'REFUND_NOT_ALLOWED',
                409
            );
        }

        const periodResult = await client.query(
            `SELECT id
             FROM ai_quota_periods
             WHERE id = $1
               AND user_id = $2
             FOR UPDATE`,
            [
                reservation.period_id,
                reservation.user_id
            ]
        );

        if (periodResult.rowCount === 0) {
            throw new QuotaError(
                'Quota period not found',
                'PERIOD_NOT_FOUND',
                500
            );
        }

        await client.query(
            `UPDATE ai_quota_periods
             SET
                words_reserved = words_reserved - $2,
                images_reserved = images_reserved - $3,
                updated_at = CURRENT_TIMESTAMP
             WHERE id = $1`,
            [
                reservation.period_id,
                reservation.reserved_words,
                reservation.reserved_images
            ]
        );

        const ledgerInserted = await insertLedgerEvent(client, {
            eventKey: `refund:${reservationId}`,
            reservationId,
            userId: reservation.user_id,
            periodId: reservation.period_id,
            eventType: 'refund',
            wordsDelta: -Number(reservation.reserved_words),
            imagesDelta: -Number(reservation.reserved_images),
            metadata: { reason }
        });

        if (!ledgerInserted) {
            throw new QuotaError(
                'Refund ledger event already exists unexpectedly',
                'LEDGER_CONFLICT',
                409
            );
        }

        const updated = await client.query(
            `UPDATE ai_request_reservations
             SET
                status = 'refunded',
                last_error = $2,
                updated_at = CURRENT_TIMESTAMP
             WHERE reservation_id = $1
             RETURNING *`,
            [reservationId, reason]
        );

        await client.query(
            `UPDATE ai_recovery_jobs
             SET
                status = 'completed',
                updated_at = CURRENT_TIMESTAMP,
                locked_at = NULL,
                locked_by = NULL
             WHERE reservation_id = $1`,
            [reservationId]
        );

        return {
            refunded: true,
            reservation: updated.rows[0]
        };
    });
}

/**
 * Mark execution uncertain.
 *
 * Use this when a network timeout or connection loss means
 * the provider may have processed the request.
 * Do not refund until the outcome is established.
 */
async function markAiReservationUnknown(
    pool,
    {
        reservationId,
        reason = 'Provider execution outcome is unknown'
    }
) {
    return withTransaction(pool, async client => {
        const result = await client.query(
            `UPDATE ai_request_reservations
             SET
                status = 'unknown',
                last_error = $2,
                updated_at = CURRENT_TIMESTAMP
             WHERE reservation_id = $1
               AND status = 'reserved'
             RETURNING *`,
            [reservationId, reason]
        );

        if (result.rowCount === 0) {
            const existing = await client.query(
                `SELECT *
                 FROM ai_request_reservations
                 WHERE reservation_id = $1`,
                [reservationId]
            );

            if (
                existing.rowCount &&
                existing.rows[0].status === 'unknown'
            ) {
                return existing.rows[0];
            }

            throw new QuotaError(
                'Reservation cannot be marked unknown',
                'INVALID_RESERVATION_STATE',
                409
            );
        }

        await client.query(
            `UPDATE ai_recovery_jobs
             SET
                next_attempt_at = CURRENT_TIMESTAMP,
                status = 'pending',
                last_error = $2,
                updated_at = CURRENT_TIMESTAMP,
                locked_at = NULL,
                locked_by = NULL
             WHERE reservation_id = $1`,
            [reservationId, reason]
        );

        return result.rows[0];
    });
}

module.exports = {
    QuotaError,
    calculateQuotaPeriod,
    reserveAiQuota,
    markProviderSucceeded,
    settleAiReservation,
    refundAiReservation,
    markAiReservationUnknown
};
