-- name: CreateAuthRequest :exec
INSERT INTO auth_requests (id, request, created_at) VALUES ($1, $2, $3);

-- name: GetAuthRequestByID :one
SELECT * FROM auth_requests WHERE id = $1;

-- name: GetAuthRequestByCode :one
SELECT * FROM auth_requests WHERE code = $1;

-- name: UpdateAuthRequest :exec
UPDATE auth_requests SET request = $1 WHERE id = $2;

-- name: SetAuthRequestCode :exec
UPDATE auth_requests SET code = $1 WHERE id = $2;

-- name: DeleteAuthRequest :exec
DELETE FROM auth_requests WHERE id = $1;

-- name: DeleteExpiredAuthRequests :exec
DELETE FROM auth_requests WHERE created_at < $1;

-- name: CreateAccessToken :exec
INSERT INTO access_tokens (id, user_id, client_id, scopes, audience, refresh_token_id, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: GetAccessToken :one
SELECT * FROM access_tokens WHERE id = $1;

-- name: DeleteAccessToken :exec
DELETE FROM access_tokens WHERE id = $1;

-- name: DeleteAccessTokensByRefreshToken :exec
DELETE FROM access_tokens WHERE refresh_token_id = $1;

-- name: DeleteAccessTokensByUserClient :exec
DELETE FROM access_tokens WHERE user_id = $1 AND client_id = $2;

-- name: DeleteExpiredAccessTokens :exec
DELETE FROM access_tokens WHERE expires_at < $1;

-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (id, user_id, client_id, scopes, audience, amr, auth_time, expires_at, created_at, session_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

-- name: GetRefreshToken :one
SELECT * FROM refresh_tokens WHERE id = $1;

-- name: DeleteRefreshToken :execrows
-- Zero rows means the token was already rotated or revoked.
DELETE FROM refresh_tokens WHERE id = $1;

-- name: DeleteRefreshTokensByUserClient :exec
DELETE FROM refresh_tokens WHERE user_id = $1 AND client_id = $2;

-- name: DeleteExpiredRefreshTokens :exec
DELETE FROM refresh_tokens WHERE expires_at < $1;

-- name: CreateSigningKey :exec
INSERT INTO signing_keys (id, alg, private_key_enc, public_key_der, active, created_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: GetActiveSigningKeys :many
SELECT * FROM signing_keys WHERE active = TRUE ORDER BY created_at DESC;

-- name: RetireSigningKeysExcept :execrows
-- Unpublishes every active key but the signer.
UPDATE signing_keys SET active = FALSE WHERE active = TRUE AND id != $1;

-- name: RecordOIDCSession :exec
-- A repeat sign-in to the same application refreshes the timestamp, which
-- drives retention.
INSERT INTO oidc_sessions (sid, client_id, user_id, created_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (sid, client_id, user_id) DO UPDATE SET created_at = excluded.created_at;

-- name: ListOIDCSessionsBySID :many
SELECT s.sid, s.client_id, s.user_id, p.backchannel_logout_uri
FROM oidc_sessions s
JOIN providers p ON p.client_id = s.client_id
WHERE s.sid = $1;

-- name: ListOIDCSessionsByUser :many
SELECT s.sid, s.client_id, s.user_id, p.backchannel_logout_uri
FROM oidc_sessions s
JOIN providers p ON p.client_id = s.client_id
WHERE s.user_id = $1;

-- name: DeleteOIDCSessionsBySID :exec
DELETE FROM oidc_sessions WHERE sid = $1;

-- name: DeleteOIDCSessionsByUser :exec
DELETE FROM oidc_sessions WHERE user_id = $1;

-- name: DeleteOIDCSessionsBefore :exec
DELETE FROM oidc_sessions WHERE created_at < $1;
