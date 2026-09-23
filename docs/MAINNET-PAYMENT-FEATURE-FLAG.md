# Mainnet Payment Feature Flag

This document describes the feature flag / kill-switch that gates money-path and
mainnet-affecting behavior in `mux-backend`. It is the source of truth for
operators and Stellar Wave contributors working on payment, wallet, and webhook
delivery paths.

## Flag

| Name | Env var | Default | Scope |
| --- | --- | --- | --- |
| Mainnet payments | `MAINNET_PAYMENTS_ENABLED` | `false` | Spends, recovery, admin, and outbound webhook delivery on mainnet |

- **Deny-by-default.** When unset or `false`, mainnet money-path writes and
  outbound webhook delivery are disabled. Testnet behavior is unaffected.
- **Fail-closed.** If the flag cannot be read (config/RPC/DB outage), treat it as
  `false` and reject the write rather than proceeding.
- **Kill-switch.** Setting the flag to `false` at runtime must stop new mainnet
  writes and webhook deliveries without a redeploy; in-flight retries drain to
  the dead-letter queue instead of being re-sent.

## Webhook delivery (retries / idempotency)

Outbound webhook delivery is a money-path-adjacent surface and is gated by the
same flag on mainnet.

- **Idempotency.** Every delivery carries a stable idempotency key derived from
  the event id. Replayed or concurrent deliveries with the same key are deduped
  so side effects happen at most once. Consumers should treat the key as the
  dedupe token.
- **Retries.** Failed deliveries are retried with exponential backoff, bounded
  attempts, and jitter. Exhausted deliveries are moved to the dead-letter queue
  as terminal failures; they are never retried unbounded.
- **Fail-closed on outage.** If RPC/DB/Horizon is unavailable, writes fail
  closed and deliveries are not acknowledged as delivered.
- **Adversarial input.** Oversized batches and spoofed webhooks are rejected
  before any side effect; signatures are verified and secrets are never logged.
- **Observability.** Delivery attempts, retries, dedupe hits, and terminal
  failures emit metrics and structured logs with correlation ids. Webhook
  secrets, JWTs, and key material are redacted.

## Rollback

1. Set `MAINNET_PAYMENTS_ENABLED=false` (kill-switch) to halt new mainnet writes
   and webhook deliveries.
2. Let in-flight retries drain to the dead-letter queue.
3. Re-enable only after the readiness checklist passes.

## References

- `test/webhooks.integration.e2e-spec.ts`
- `SECURITY.md`
- `README.md`
