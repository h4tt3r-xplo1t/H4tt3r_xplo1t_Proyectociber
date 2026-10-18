-- Creates the least-privilege login role of the news worker (threat 15).
-- Run once per database cluster by an operator with CREATEROLE, BEFORE the
-- migrations: they only grant to this role and never create it.
--
--   psql -v app_password="$WORKER_PASSWORD" -f scripts/create_role.sql
--
-- The password comes from the psql variable; there is no password in the repo.
-- Use a throwaway value for development and CI, and the secret manager's value
-- elsewhere (E5). The role cannot create anything: the migration grants it
-- SELECT, INSERT and DELETE on noticias.news_items and nothing else.
SELECT format(
    'CREATE ROLE worker_noticias LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB '
    'NOCREATEROLE NOREPLICATION NOBYPASSRLS',
    :'app_password'
) \gexec
