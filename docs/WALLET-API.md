# Wallet API behavior

All Wallet API routes require a valid API key and are rate-limited. The API
never returns encrypted key material on read endpoints. The only operation
that returns a `privateKey` is a successful first wallet-creation response;
clients must consume it immediately and must not expect it to be replayed.

## Endpoints

| Method | Route | Behavior |
| --- | --- | --- |
| `POST` | `/wallets` | Creates one active wallet per user/network pair. Duplicate user/network requests return `409`. |
| `GET` | `/wallets` | Lists wallets. Supports `userId`, `network`, `status` filters and `limit`/`offset` pagination (default `limit=20`, max `100`). Returns `{ data, total, limit, offset, hasMore }`. |
| `GET` | `/wallets/:id` | Returns a wallet or `404`. |
| `GET` | `/wallets/:id/status` | Returns lifecycle status without decrypting the private key. |
| `PATCH` | `/wallets/:id` | Updates wallet lifecycle status. |
| `PATCH` | `/wallets/:id/activate` | Activates a `PROVISIONING` wallet. Any other current state is rejected. |
| `DELETE` | `/wallets/:id` | Removes a wallet record. |
| `POST` | `/wallets/orchestration/create` | Runs the provisioning flow and accepts an optional `idempotencyKey`. |
| `GET` | `/wallets/orchestration/user/:userId/:network` | Returns the wallet for a user/network pair or `404`. |
| `GET` | `/wallets/orchestration/validate/:userId/:network` | Reports whether a new wallet may be created. |

`network` is `TESTNET` or `MAINNET`. `POST /wallets/orchestration/create`
creates a wallet as `PROVISIONING`, then promotes it to `ACTIVE` in the same
database transaction. Testnet funding is best effort: a disconnected or
failed Friendbot call is logged and does not undo a committed wallet.

## Authorization

Wallet orchestration is deny-by-default. Every orchestration entrypoint
requires a valid API key **and** an authenticated principal, and the caller
must be the wallet owner or an explicitly granted delegate/guardian for the
target `userId`/`network` pair. Requests that present a valid API key but no
matching owner/delegate/guardian grant are rejected with `403`; requests with
no credentials at all are rejected with `401`. A revoked delegate is treated
exactly like a missing grant. Clients cannot bypass policy by supplying a
`userId` in the body or path that they do not own.

## Error codes

Orchestration responses use a stable error envelope. Every error carries a
`code`, a human-readable `message`, and a `correlationId` that matches the
`X-Request-Id` response header so operators can trace a single request across
logs and metrics.

| Code | HTTP | Meaning |
| --- | --- | --- |
| `WALLET_UNAUTHORIZED` | `401` | Missing or invalid credentials. |
| `WALLET_FORBIDDEN` | `403` | Authenticated but not owner/delegate/guardian. |
| `WALLET_NOT_FOUND` | `404` | No wallet for the requested user/network. |
| `WALLET_ALREADY_EXISTS` | `409` | Active wallet already exists for the pair. |
| `WALLET_IDEMPOTENCY_CONFLICT` | `409` | Idempotency key reused for a different user/network. |
| `WALLET_DEPENDENCY_UNAVAILABLE` | `503` | Key-management or RPC dependency failed; write was not committed. |
| `WALLET_ORCHESTRATION_DISABLED` | `503` | Feature flag is off for this network. |

## Idempotency

For orchestration creation, an `idempotencyKey` is scoped to one
`userId`/`network` operation for 24 hours.

- Repeating the same operation returns the cached wallet result with
  `privateKey: ""`.
- Reusing the key for another user or network returns `409`
  (`WALLET_IDEMPOTENCY_CONFLICT`).
- Expired keys are treated as new requests.
- Concurrent requests that share a key are serialized: the first commits and
  the rest observe the cached result rather than creating a second wallet.

## Feature flag and kill switch

Orchestration is gated per network so a money-path change can be disabled
without a deploy. When the flag is off, `POST /wallets/orchestration/create`
fails closed with `WALLET_ORCHESTRATION_DISABLED` and no wallet is written;
read-only orchestration lookups continue to work.

| Variable | Default |
| --- | --- |
| `WALLET_ORCHESTRATION_ENABLED` | `true` |
| `WALLET_ORCHESTRATION_MAINNET_ENABLED` | `false` |

Mainnet orchestration stays off until the readiness checklist is signed off.
Rollback is flipping the flag off; no data migration is required.

## Lifecycle events

The API emits webhook domain events after state has been durably persisted:
`wallet.created`, `wallet.activated`, `wallet.suspended`, and
`wallet.rotated`. Event dispatch is asynchronous; a webhook outage is logged
but never changes the response or rolls back wallet state. Creation events
from the orchestration endpoint are emitted only after its database
transaction commits, and are not repeated for idempotency replays.

## Dependency retries and metrics

Before any wallet write, transient key-management and testnet-funding failures
are retried with capped exponential backoff. Invalid requests and non-transient
4xx responses are not retried. If retries are exhausted the write fails closed
with `WALLET_DEPENDENCY_UNAVAILABLE` and no partial wallet is persisted.
Configure this behavior with:

| Variable | Default |
| --- | --- |
| `WALLET_API_RETRY_MAX_ATTEMPTS` | `3` |
| `WALLET_API_RETRY_BASE_DELAY_MS` | `100` |
| `WALLET_API_RETRY_MAX_DELAY_MS` | `2000` |

Wallet operations write structured `[wallet-api-metrics]` log records with
operation, outcome, duration, and network. Metrics intentionally exclude user
and wallet identifiers so they are safe to aggregate as low-cardinality
telemetry. Logs and metrics never include private keys, JWTs, API keys, or
webhook secrets; key material is redacted before it reaches any sink.
