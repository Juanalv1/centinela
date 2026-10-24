-- Least-privilege role for Centinela's executor. Run after schema.sql by a role
-- with CREATEROLE. `{password}` is filled in by the victim from
-- EXECUTOR_DB_PASSWORD as a quoted literal.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'centinela_executor') THEN
        CREATE ROLE centinela_executor LOGIN;
    END IF;
END $$;
ALTER ROLE centinela_executor WITH LOGIN PASSWORD {password};

REVOKE ALL ON users, api_keys, sessions, ip_blocklist, protected_networks, access_log, user_suspensions
    FROM centinela_executor;
REVOKE ALL ON FUNCTION is_protected_user(integer) FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM centinela_executor;
GRANT USAGE ON SCHEMA public TO centinela_executor;

-- revocar_clave: read the columns needed to find and check the key, write only status.
GRANT SELECT (id, status, protected) ON api_keys TO centinela_executor;
GRANT UPDATE (status) ON api_keys TO centinela_executor;
-- bloquear_ip (and undo).
GRANT SELECT, INSERT, DELETE ON ip_blocklist TO centinela_executor;
-- cerrar_sesiones.
GRANT SELECT, DELETE ON sessions TO centinela_executor;
-- suspend_user: a suspension row (plus closing that user's sessions).
GRANT SELECT, INSERT, DELETE ON user_suspensions TO centinela_executor;
-- Policy check for admins without reading users: one boolean per id.
GRANT EXECUTE ON FUNCTION is_protected_user(integer) TO centinela_executor;
-- Nothing on users, access_log or protected_networks.
