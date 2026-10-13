-- OpenID Connect Back-Channel Logout: when a Kivraid session ends, each
-- application that signed in through it receives a logout token at its
-- back-channel logout URI (empty = not supported by the application).
ALTER TABLE providers ADD COLUMN backchannel_logout_uri TEXT NOT NULL DEFAULT '';

-- The Kivraid session (sid) a refresh token was issued in, so ID tokens
-- minted on refresh carry the same sid claim.
ALTER TABLE refresh_tokens ADD COLUMN session_id TEXT NOT NULL DEFAULT '';

-- Which applications each Kivraid session signed in to, and as which user
-- (an impersonating administrator signs in as someone else). These are
-- the logout token targets when the session or the account ends.
CREATE TABLE oidc_sessions (
    sid        TEXT NOT NULL,
    client_id  TEXT NOT NULL,
    user_id    TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    PRIMARY KEY (sid, client_id, user_id)
);
CREATE INDEX oidc_sessions_user_idx ON oidc_sessions (user_id);
