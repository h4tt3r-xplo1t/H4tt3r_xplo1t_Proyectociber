-- Creates the least-privilege login role of the news worker (threat 15).
-- Run once per database cluster by an operator with CREATEROLE, BEFORE the
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
-- Idempotent: if the role exists, nothing happens (it never resets a password).

-- The CREATE ROLE statement below carries the password in clear text. If it
-- failed, the server would write the whole statement, password included, to
-- its error log, and `log_statement` could log it too. These session-level
-- settings (superuser only, so they apply to the operator running this
-- script) keep the statement out of the server log. Everything is skipped
-- when the role already exists, so a rerun cannot fail with the password in
-- the failing statement either.
SET log_min_error_statement = panic;
SET log_statement = 'none';

SELECT format(
    'CREATE ROLE worker_noticias LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB '
    'NOCREATEROLE NOREPLICATION NOBYPASSRLS',
    :'app_password'
)
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'worker_noticias')
\gexec
