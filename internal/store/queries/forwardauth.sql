-- name: CreateForwardAuthCode :exec
INSERT INTO forward_auth_codes (code_hash, user_id, sid, host, state, login_method, impersonator, session_expires_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: ConsumeForwardAuthCode :one
-- Single use: the row is deleted by the request that reads it.
DELETE FROM forward_auth_codes WHERE code_hash = $1 RETURNING *;

-- name: CreateForwardAuthSession :exec
INSERT INTO forward_auth_sessions (token_hash, user_id, sid, host, login_method, impersonator, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: GetForwardAuthSession :one
SELECT * FROM forward_auth_sessions WHERE token_hash = $1;

-- name: DeleteForwardAuthSessionsBySID :exec
DELETE FROM forward_auth_sessions WHERE sid = $1;

-- name: DeleteForwardAuthSessionsByUser :exec
DELETE FROM forward_auth_sessions WHERE user_id = $1;

-- name: DeleteExpiredForwardAuthCodes :exec
DELETE FROM forward_auth_codes WHERE expires_at < $1;

-- name: DeleteExpiredForwardAuthSessions :exec
DELETE FROM forward_auth_sessions WHERE expires_at < $1;
