'use strict';

/**
 * M3AK - Component 3
 * AI Reservation Recovery Worker
 *
 * Responsibilities:
 * 1. Find expired AI reservations.
 * 2. Detect interrupted provider executions.
 * 3. Preserve uncertain reservations safely.
 * 4. Retry recovery checks with exponential backoff.
 * 5. Never refund a request whose provider outcome is unknown.
 *
 * IMPORTANT:
 * This worker does not automatically refund unknown requests.
 * Provider reconciliation must be implemented using the actual
 * provider request ID and provider API capabilities.
 */

const crypto = require('crypto');

const TERMINAL_RESERVATION_STATES = [
    'settled',
    'refunded',
    'failed'
];

const DEFAULT_BATCH_SIZE = 20;
const DEFAULT_INTERVAL_MS = 30000;
const DEFAULT_RETRY_SECONDS = 60;
const MAX_RETRY_SECONDS = 3600;

function validatePositiveInteger(value, name, maximum) {
    if (
        !Number.isSafeInteger(value) ||
        value <= 0 ||
        (maximum && value > maximum)
    ) {
        throw new Error(`Invalid ${name}`);
    }
}

function calculateRetryDelay(attempts) {
    const exponent = Math.min(Math.max(attempts - 1, 0), 10);

    return Math.min(
        DEFAULT_RETRY_SECONDS * Math.pow(2, exponent),
        MAX_RETRY_SECONDS
    );
}

/**
 * Claim one recovery job.
 *
 * SKIP LOCKED allows multiple worker instances to operate
 * without processing the same job simultaneously.
 */
async function claimRecoveryJob(pool, workerId) {
    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        const result = await client.query(
            `
            SELECT
                j.id,
                j.reservation_id,
                j.attempts,
                j.status AS job_status,
                r.user_id,
                r.period_id,
                r.status AS reservation_status,
                r.lease_expires_at,
                r.provider_request_id,
                r.provider_succeeded_at
            FROM ai_recovery_jobs j
            JOIN ai_request_reservations r
                ON r.reservation_id = j.reservation_id
            WHERE
                (
                    j.status = 'pending'
                    AND j.next_attempt_at <= CURRENT_TIMESTAMP
                )
                OR
                (
                    j.status = 'processing'
                    AND j.locked_at < CURRENT_TIMESTAMP - INTERVAL '5 minutes'
                )
            ORDER BY
    j.next_attempt_at ASC,
    j.id ASC
LIMIT 1
FOR UPDATE OF j SKIP LOCKED
        );

        if (result.rowCount === 0) {
            await client.query('COMMIT');
            return null;
        }

        const job = result.rows[0];

        await client.query(
            `
            UPDATE ai_recovery_jobs
            SET
                status = 'processing',
                attempts = attempts + 1,
                locked_at = CURRENT_TIMESTAMP,
                locked_by = $2,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = $1
            `,
            [job.id, workerId]
        );

        await client.query('COMMIT');

        return {
            ...job,
            attempts: Number(job.attempts) + 1
        };
    } catch (error) {
        try {
            await client.query('ROLLBACK');
        } catch (_) {
            // Preserve original error.
        }

        throw error;
    } finally {
        client.release();
    }
}

/**
 * Complete a job that belongs to a terminal reservation.
 */
async function completeRecoveryJob(pool, jobId, workerId) {
    const result = await pool.query(
        `
        UPDATE ai_recovery_jobs
        SET
            status = 'completed',
            locked_at = NULL,
            locked_by = NULL,
            last_error = NULL,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
          AND status = 'processing'
          AND locked_by = $2
        `,
        [jobId, workerId]
    );

    return result.rowCount === 1;
}

/**
 * Schedule another recovery attempt.
 */
async function rescheduleRecoveryJob(
    pool,
    job,
    workerId,
    reason
) {
    const delaySeconds = calculateRetryDelay(job.attempts);

    const result = await pool.query(
        `
        UPDATE ai_recovery_jobs
        SET
            status = 'pending',
            next_attempt_at =
                CURRENT_TIMESTAMP + ($3 * INTERVAL '1 second'),
            locked_at = NULL,
            locked_by = NULL,
            last_error = $4,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
          AND status = 'processing'
          AND locked_by = $2
        `,
        [
            job.id,
            workerId,
            delaySeconds,
            String(reason).slice(0, 4000)
        ]
    );

    return {
        rescheduled: result.rowCount === 1,
        delaySeconds
    };
}

/**
 * Safely inspect and classify one claimed reservation.
 *
 * No automatic refund is performed for uncertain requests.
 */
async function processRecoveryJob(pool, job, workerId) {
    if (
        TERMINAL_RESERVATION_STATES.includes(
            job.reservation_status
        )
    ) {
        await completeRecoveryJob(pool, job.id, workerId);

        return {
            reservationId: job.reservation_id,
            action: 'completed',
            reason: 'Reservation is already in a terminal state'
        };
    }

    if (job.reservation_status === 'reserved') {
        const client = await pool.connect();

        try {
            await client.query('BEGIN');

            const reservationResult = await client.query(
                `
                SELECT
                    reservation_id,
                    status,
                    lease_expires_at
                FROM ai_request_reservations
                WHERE reservation_id = $1
                FOR UPDATE
                `,
                [job.reservation_id]
            );

            if (reservationResult.rowCount === 0) {
                throw new Error('Reservation not found');
            }

            const reservation = reservationResult.rows[0];

            if (
                TERMINAL_RESERVATION_STATES.includes(
                    reservation.status
                )
            ) {
                await client.query(
                    `
                    UPDATE ai_recovery_jobs
                    SET
                        status = 'completed',
                        locked_at = NULL,
                        locked_by = NULL,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = $1
                      AND locked_by = $2
                    `,
                    [job.id, workerId]
                );

                await client.query('COMMIT');

                return {
                    reservationId: job.reservation_id,
                    action: 'completed',
                    reason: 'Reservation became terminal'
                };
            }

            if (reservation.status === 'reserved') {
                const expiredResult = await client.query(
                    `
                    SELECT
                        lease_expires_at <= CURRENT_TIMESTAMP AS expired
                    FROM ai_request_reservations
                    WHERE reservation_id = $1
                    `,
                    [job.reservation_id]
                );

                if (!expiredResult.rows[0].expired) {
                    await client.query(
                        `
                        UPDATE ai_recovery_jobs
                        SET
                            status = 'pending',
                            next_attempt_at = $3,
                            locked_at = NULL,
                            locked_by = NULL,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE id = $1
                          AND locked_by = $2
                        `,
                        [
                            job.id,
                            workerId,
                            reservation.lease_expires_at
                        ]
                    );

                    await client.query('COMMIT');

                    return {
                        reservationId: job.reservation_id,
                        action: 'rescheduled',
                        reason: 'Reservation lease has not expired'
                    };
                }

                // A crashed process may have called the provider
                // immediately before or after the interruption.
                // Therefore the outcome is uncertain.
                await client.query(
                    `
                    UPDATE ai_request_reservations
                    SET
                        status = 'unknown',
                        last_error =
                            'Recovery detected an expired reservation; provider outcome requires reconciliation',
                        updated_at = CURRENT_TIMESTAMP
                    WHERE reservation_id = $1
                      AND status = 'reserved'
                    `,
                    [job.reservation_id]
                );
            }

            await client.query(
                `
                UPDATE ai_recovery_jobs
                SET
                    status = 'pending',
                    attempts = attempts,
                    next_attempt_at =
                        CURRENT_TIMESTAMP + INTERVAL '5 minutes',
                    locked_at = NULL,
                    locked_by = NULL,
                    last_error =
                        'Reservation requires provider reconciliation; automatic refund prohibited',
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = $1
                  AND locked_by = $2
                `,
                [job.id, workerId]
            );

            await client.query('COMMIT');

            return {
                reservationId: job.reservation_id,
                action: 'awaiting_reconciliation',
                reason: 'Provider outcome is not safely known'
            };
        } catch (error) {
            try {
                await client.query('ROLLBACK');
            } catch (_) {
                // Preserve original error.
            }

            throw error;
        } finally {
            client.release();
        }
    }

    if (
        job.reservation_status === 'provider_succeeded' ||
        job.reservation_status === 'unknown'
    ) {
        const result = await rescheduleRecoveryJob(
            pool,
            job,
            workerId,
            'Provider result requires reconciliation before settlement or refund'
        );

        return {
            reservationId: job.reservation_id,
            action: 'awaiting_reconciliation',
            retryInSeconds: result.delaySeconds,
            reason: 'No automatic settlement or refund is safe'
        };
    }

    const result = await rescheduleRecoveryJob(
        pool,
        job,
        workerId,
        `Unhandled reservation state: ${job.reservation_status}`
    );

    return {
        reservationId: job.reservation_id,
        action: 'rescheduled',
        retryInSeconds: result.delaySeconds,
        reason: 'Unhandled reservation state'
    };
}

/**
 * Process a batch of recovery jobs.
 */
async function runRecoveryBatch(
    pool,
    {
        workerId = `m3ak-recovery-${crypto.randomUUID()}`,
        batchSize = DEFAULT_BATCH_SIZE
    } = {}
) {
    validatePositiveInteger(batchSize, 'batchSize', 500);

    if (!pool || typeof pool.connect !== 'function') {
        throw new Error('A valid PostgreSQL pool is required');
    }

    const results = [];

    for (let index = 0; index < batchSize; index++) {
        const job = await claimRecoveryJob(pool, workerId);

        if (!job) {
            break;
        }

        try {
            const result = await processRecoveryJob(
                pool,
                job,
                workerId
            );

            results.push({
                success: true,
                ...result
            });
        } catch (error) {
            const recovery = await rescheduleRecoveryJob(
                pool,
                job,
                workerId,
                error.message
            ).catch(() => ({
                rescheduled: false
            }));

            results.push({
                success: false,
                reservationId: job.reservation_id,
                error: error.message,
                rescheduled: recovery.rescheduled
            });
        }
    }

    return {
        workerId,
        processed: results.length,
        results
    };
}

/**
 * Start periodic recovery processing.
 *
 * Do not start this until database migration and integration
 * tests have passed.
 */
function startRecoveryWorker(
    pool,
    {
        intervalMs = DEFAULT_INTERVAL_MS,
        batchSize = DEFAULT_BATCH_SIZE,
        workerId = `m3ak-recovery-${crypto.randomUUID()}`,
        onError = console.error
    } = {}
) {
    validatePositiveInteger(intervalMs, 'intervalMs', 3600000);
    validatePositiveInteger(batchSize, 'batchSize', 500);

    let stopped = false;
    let timer = null;
    let running = false;

    async function tick() {
        if (stopped || running) {
            return;
        }

        running = true;

        try {
            await runRecoveryBatch(pool, {
                workerId,
                batchSize
            });
        } catch (error) {
            onError(
                '[M3AK Recovery Worker]',
                error
            );
        } finally {
            running = false;

            if (!stopped) {
                timer = setTimeout(tick, intervalMs);
            }
        }
    }

    timer = setTimeout(tick, 0);

    return {
        workerId,

        stop() {
            stopped = true;

            if (timer) {
                clearTimeout(timer);
                timer = null;
            }
        },

        isRunning() {
            return running;
        }
    };
}

module.exports = {
    runRecoveryBatch,
    processRecoveryJob,
    startRecoveryWorker
};
