-- Creates the least-privilege login role of the news worker (threat 15).
-- Run once per database cluster by an operator with CREATEROLE (or a
-- superuser; see the logging note below), BEFORE the
-- migrations: they only grant to this role and never create it.
--
--   psql -v ON_ERROR_STOP=1 -v app_password="$WORKER_NOTICIAS_DB_PASSWORD" \
--        -f scripts/create_role.sql
--
-- The password comes from the psql variable; there is no password in the repo.
-- The variable can be filled from an environment variable as above. Do not
-- type the password in the command line itself: it would stay in the shell
-- history (and be visible in the process list). Use a throwaway value for
-- development and CI; in production the secret manager provides it (E5).
-- The role cannot create anything: the migration grants it SELECT, INSERT and
-- DELETE on noticias.news_items and nothing else.
--
-- The password must have at least 16 characters. An empty one would be read by
-- PostgreSQL as "no password", so the script stops with an error instead.
--
-- Idempotent: if the role exists, nothing happens (it never resets a password).

-- The CREATE ROLE statement below carries the password in clear text. If it
-- failed, the server would write the whole statement, password included, to
-- its error log, and `log_statement` could log it too.
--  * Superuser: the session also disables statement logging (the two SETs
--    below need superuser, so they run only when current_user is one). They
--    run first, before the weak-password check and every other statement
--    that carries the password.
--  * CREATEROLE-only operator: protection relies on idempotence (an existing
--    role is skipped, so a rerun never fails with the password in the failing
--    statement), and the operator must make sure the server does not log
--    statements (`log_statement` other than `all` or `ddl`). Production uses
--    the secret manager (E5).
-- Must stay before ANY statement that mentions the password.
SELECT rolsuper AS is_superuser FROM pg_roles WHERE rolname = current_user \gset
\if :is_superuser
SET log_min_error_statement = panic;
SET log_statement = 'none';
\endif

-- Weak or empty password: fail, and create nothing even without ON_ERROR_STOP
-- (`\quit` would exit with status 0, so an error is raised instead).
SELECT length(:'app_password') < 16 AS weak \gset
\if :weak
DO $$ BEGIN
    RAISE EXCEPTION 'app_password must have at least 16 characters';
END $$;
\endif

SELECT format(
    'CREATE ROLE worker_noticias LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB '
    'NOCREATEROLE NOREPLICATION NOBYPASSRLS',
    :'app_password'
)
WHERE NOT :'weak'::boolean
  AND NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'worker_noticias')
\gexec
