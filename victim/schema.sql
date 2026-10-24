-- Case 2 victim: a small company's API data. Idempotent; run by the victim's
-- owner role at startup. The executor role (see roles.sql) gets only the
-- columns and tables it needs to respond, never `users`.

CREATE TABLE IF NOT EXISTS users (
    id            serial PRIMARY KEY,
    username      text UNIQUE NOT NULL,
    password_hash text NOT NULL,
    role          text NOT NULL CHECK (role IN ('admin', 'staff'))
);

CREATE TABLE IF NOT EXISTS api_keys (
    id         serial PRIMARY KEY,
    user_id    integer NOT NULL REFERENCES users(id),
    label      text NOT NULL,
    key_hash   char(64) UNIQUE NOT NULL,
    protected  boolean NOT NULL DEFAULT false,
    status     text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
    id         serial PRIMARY KEY,
    user_id    integer NOT NULL REFERENCES users(id),
    token_hash char(64) UNIQUE NOT NULL,
    ip         text,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ip_blocklist (
    ip         inet PRIMARY KEY,
    reason     text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Networks nobody may block (the office). The executor cannot read this table;
-- the trigger below checks it with the owner's rights.
CREATE TABLE IF NOT EXISTS protected_networks (
    cidr  cidr PRIMARY KEY,
    label text NOT NULL
);

-- HTTP access log. The User-Agent is attacker-controlled text: the reasoner
-- must treat it as data, never as instructions.
CREATE TABLE IF NOT EXISTS access_log (
    id         bigserial PRIMARY KEY,
    ts         timestamptz NOT NULL DEFAULT now(),
    ip         text,
    method     text NOT NULL,
    path       text NOT NULL,
    status     integer NOT NULL,
    user_agent text,
    user_id    integer,
    api_key_id integer
);

-- Last line of defense: protected keys cannot change status, for any role.
CREATE OR REPLACE FUNCTION guard_protected_key() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.protected AND NEW.status IS DISTINCT FROM OLD.status THEN
        RAISE EXCEPTION 'permission denied: api key % is a protected key', OLD.id
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS guard_protected_key ON api_keys;
CREATE TRIGGER guard_protected_key BEFORE UPDATE ON api_keys
    FOR EACH ROW EXECUTE FUNCTION guard_protected_key();

CREATE OR REPLACE FUNCTION guard_protected_network() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM protected_networks WHERE NEW.ip <<= cidr) THEN
        RAISE EXCEPTION 'permission denied: % is in a protected network', NEW.ip
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS guard_protected_network ON ip_blocklist;
CREATE TRIGGER guard_protected_network BEFORE INSERT OR UPDATE ON ip_blocklist
    FOR EACH ROW EXECUTE FUNCTION guard_protected_network();

-- suspend_user without touching `users`: a separate table the auth check reads.
CREATE TABLE IF NOT EXISTS user_suspensions (
    user_id    integer PRIMARY KEY REFERENCES users(id),
    reason     text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Exposes one boolean about a user (is it an admin?) to roles that cannot read `users`.
CREATE OR REPLACE FUNCTION is_protected_user(uid integer) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT EXISTS (SELECT 1 FROM users WHERE id = uid AND role = 'admin')
$$;

-- Admins cannot be suspended, and the executor cannot close their sessions.
-- (The app itself may still delete sessions, e.g. on logout.)
CREATE OR REPLACE FUNCTION guard_protected_user() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    uid integer := CASE WHEN TG_OP = 'DELETE' THEN OLD.user_id ELSE NEW.user_id END;
BEGIN
    IF (TG_TABLE_NAME = 'user_suspensions' OR session_user = 'centinela_executor')
            AND is_protected_user(uid) THEN
        RAISE EXCEPTION 'permission denied: user % is a protected user', uid
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END $$;
DROP TRIGGER IF EXISTS guard_protected_user ON user_suspensions;
CREATE TRIGGER guard_protected_user BEFORE INSERT OR UPDATE ON user_suspensions
    FOR EACH ROW EXECUTE FUNCTION guard_protected_user();
DROP TRIGGER IF EXISTS guard_protected_user ON sessions;
CREATE TRIGGER guard_protected_user BEFORE DELETE ON sessions
    FOR EACH ROW EXECUTE FUNCTION guard_protected_user();
