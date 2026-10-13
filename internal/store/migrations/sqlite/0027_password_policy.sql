-- Password policy, set under Settings → Security. The minimum length
-- counts characters; 8 matches the rule that was previously hard-coded.
-- The breach check (Have I Been Pwned, k-anonymity range API) is off by
-- default because it needs outbound HTTPS.
ALTER TABLE instance_settings ADD COLUMN password_min_length INTEGER NOT NULL DEFAULT 8;
ALTER TABLE instance_settings ADD COLUMN password_breach_check BOOLEAN NOT NULL DEFAULT FALSE;
