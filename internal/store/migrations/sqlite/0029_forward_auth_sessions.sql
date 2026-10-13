-- Forward auth across hosts. Kivraid's session cookie stays on Kivraid's
-- host, so a protected application on another host gets a session of its
-- own: a one-time code, issued by Kivraid to a signed-in user and bound to
-- the application's host and to a state cookie set there, is exchanged on
-- the application's host for a cookie scoped to it.
CREATE TABLE forward_auth_codes (
    code_hash          TEXT PRIMARY KEY,
    user_id            TEXT NOT NULL,
    sid                TEXT NOT NULL,
    host               TEXT NOT NULL,
    state              TEXT NOT NULL,
    login_method       TEXT NOT NULL,
    impersonator       TEXT NOT NULL DEFAULT '',
    session_expires_at TIMESTAMP NOT NULL,
    expires_at         TIMESTAMP NOT NULL
);

-- The application-host sessions. sid ties each to the Kivraid session it
-- came from, so signing out of Kivraid ends them; login_method and
-- impersonator carry what policy checks read from the Kivraid session.
CREATE TABLE forward_auth_sessions (
    token_hash   TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL,
    sid          TEXT NOT NULL,
    host         TEXT NOT NULL,
    login_method TEXT NOT NULL,
    impersonator TEXT NOT NULL DEFAULT '',
    expires_at   TIMESTAMP NOT NULL,
    created_at   TIMESTAMP NOT NULL
);
CREATE INDEX forward_auth_sessions_sid_idx ON forward_auth_sessions (sid);
CREATE INDEX forward_auth_sessions_user_idx ON forward_auth_sessions (user_id);
