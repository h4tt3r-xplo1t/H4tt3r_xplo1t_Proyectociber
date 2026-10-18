"""Storage tests (threats 15 and 17): schema, least privilege, dedup, retention."""

from datetime import UTC, datetime, timedelta

import pytest
from alembic import command
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError, ProgrammingError

from tests.dbsupport import APP_ROLE, alembic_config
from worker_noticias import store
from worker_noticias.feeds import NewsItem

# Fresh on purpose: `save` drops items older than the retention window.
NOW = datetime.now(UTC).replace(microsecond=0)
RETENTION = timedelta(days=30)


def item(**kwargs) -> NewsItem:
    fields = {
        "outlet": "RCN",
        "title": "Titular de prueba",
        "link": "https://www.noticiasrcn.com/colombia/a-1",
        "published_at": NOW,
        "summary": "Resumen corto",
        "author": "Ana Perez",
        "source_id": "rcn-rss",
    }
    fields.update(kwargs)
    return NewsItem(**fields)


def rows(engine):
    with engine.connect() as conn:
        return conn.execute(
            text(
                "SELECT source_id, outlet, title, link, published_at, summary, "
                "author, fetched_at FROM noticias.news_items ORDER BY id"
            )
        ).all()


# --- save ------------------------------------------------------------------


def test_save_stores_every_field_and_returns_the_new_rows(app_engine):
    assert store.save([item()], RETENTION, engine=app_engine).new == 1
    (row,) = rows(app_engine)
    assert row.source_id == "rcn-rss"
    assert row.outlet == "RCN"
    assert row.title == "Titular de prueba"
    assert row.link == "https://www.noticiasrcn.com/colombia/a-1"
    assert row.published_at == NOW
    assert row.summary == "Resumen corto"
    assert row.author == "Ana Perez"
    assert row.fetched_at is not None


def test_optional_fields_are_stored_as_null(app_engine):
    store.save([item(summary=None, author=None)], RETENTION, engine=app_engine)
    (row,) = rows(app_engine)
    assert row.summary is None
    assert row.author is None


def test_reading_a_source_twice_does_not_duplicate_rows(app_engine):
    assert store.save([item()], RETENTION, engine=app_engine).new == 1
    assert store.save([item()], RETENTION, engine=app_engine).new == 0
    assert len(rows(app_engine)) == 1


def test_the_same_link_from_the_rcn_rss_and_sitemap_is_stored_once(app_engine):
    rss = item(source_id="rcn-rss")
    sitemap = item(source_id="rcn-sitemap", author=None)
    assert store.save([rss, sitemap], RETENTION, engine=app_engine).new == 1
    (row,) = rows(app_engine)
    assert row.source_id == "rcn-rss"


def test_save_of_nothing_returns_zero(app_engine):
    assert store.save([], RETENTION, engine=app_engine) == (0, 0)


def test_a_database_error_is_reported_without_row_content():
    engine = create_engine(
        "postgresql+psycopg://worker_noticias:not-a-real-secret@127.0.0.1:1/none",
        hide_parameters=True,
        connect_args={"connect_timeout": 1},
    )
    with pytest.raises(store.StoreError) as excinfo:
        store.save([item(title="XXXX secret title")], RETENTION, engine=engine)
    text_ = f"{excinfo.value!s} {excinfo.value!r}"
    assert "XXXX" not in text_
    assert "noticiasrcn" not in text_
    assert "not-a-real-secret" not in text_
    assert excinfo.value.__cause__ is None
    assert excinfo.value.__suppress_context__


def test_an_item_older_than_the_retention_is_neither_stored_nor_counted(app_engine):
    old = item(
        link="https://www.noticiasrcn.com/old", published_at=NOW - timedelta(days=31)
    )
    fresh = item(link="https://www.noticiasrcn.com/fresh")
    result = store.save([old, fresh], RETENTION, engine=app_engine)
    assert result == (1, 1)
    assert [r.link for r in rows(app_engine)] == ["https://www.noticiasrcn.com/fresh"]


def test_after_a_purge_the_same_feed_inserts_nothing_again(app_engine):
    feed = [
        item(link="https://www.noticiasrcn.com/a", published_at=NOW),
        item(
            link="https://www.noticiasrcn.com/b", published_at=NOW - timedelta(days=40)
        ),
    ]
    assert store.save(feed, timedelta(days=365), engine=app_engine).new == 2
    assert store.purge(timedelta(days=30), engine=app_engine) == 1
    again = store.save(feed, RETENTION, engine=app_engine)
    assert again == (0, 1)  # known link skipped as a duplicate, old one expired
    assert len(rows(app_engine)) == 1


def test_one_rejected_row_does_not_drop_the_rest_of_the_feed(app_engine, caplog):
    feed = [
        item(link="https://www.noticiasrcn.com/ok-1"),
        item(link="https://www.noticiasrcn.com/bad", title="SENTINEL" * 60),
        item(link="https://www.noticiasrcn.com/ok-2"),
    ]
    with caplog.at_level("DEBUG"):
        result = store.save(feed, RETENTION, engine=app_engine)
    assert result == (2, 1)
    assert [r.link for r in rows(app_engine)] == [
        "https://www.noticiasrcn.com/ok-1",
        "https://www.noticiasrcn.com/ok-2",
    ]
    assert "SENTINEL" not in caplog.text
    assert "1 row" in caplog.text


# --- CHECK constraints (mirror feeds.py caps) -------------------------------


@pytest.mark.parametrize(
    ("column", "limit"),
    [("title", 300), ("summary", 500), ("author", 120), ("link", 2000)],
)
def test_the_database_enforces_the_text_caps(admin_engine, app_engine, column, limit):
    prefix = f"https://x/{column}/"
    values = {"title": "t", "link": prefix, "summary": "s", "author": "a"}

    def build(length: int):
        v = dict(values)
        v[column] = (
            "a" * length if column != "link" else prefix + "a" * (length - len(prefix))
        )
        return v

    stmt = text(
        "INSERT INTO noticias.news_items "
        "(source_id, outlet, title, link, published_at, summary, author) "
        "VALUES ('s', 'o', :title, :link, now(), :summary, :author)"
    )
    with admin_engine.begin() as conn:
        conn.execute(stmt, build(limit))  # exactly at the cap: accepted
    with pytest.raises(DBAPIError, match="violates check constraint"):
        with admin_engine.begin() as conn:
            conn.execute(stmt, build(limit + 1))


# --- retention --------------------------------------------------------------


def test_purge_deletes_only_the_rows_older_than_the_retention(app_engine):
    now = datetime.now(UTC)
    store.save(
        [
            item(
                link="https://www.noticiasrcn.com/old",
                published_at=now - timedelta(days=40),
            ),
            item(
                link="https://www.noticiasrcn.com/edge",
                published_at=now - timedelta(days=31),
            ),
            item(
                link="https://www.noticiasrcn.com/new",
                published_at=now - timedelta(days=5),
            ),
        ],
        timedelta(days=365),
        engine=app_engine,
    )
    assert store.purge(timedelta(days=30), engine=app_engine) == 2
    assert [r.link for r in rows(app_engine)] == ["https://www.noticiasrcn.com/new"]


def test_purge_with_nothing_old_deletes_nothing(app_engine):
    store.save([item(published_at=datetime.now(UTC))], RETENTION, engine=app_engine)
    assert store.purge(timedelta(days=30), engine=app_engine) == 0
    assert len(rows(app_engine)) == 1


def test_purge_refuses_a_retention_shorter_than_a_day(app_engine):
    store.save(
        [item(published_at=datetime.now(UTC) - timedelta(days=2))],
        RETENTION,
        engine=app_engine,
    )
    with pytest.raises(ValueError, match="retention"):
        store.purge(timedelta(0), engine=app_engine)
    assert len(rows(app_engine)) == 1


# --- least privilege (threat 15) --------------------------------------------


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE noticias.news_items SET title = 'x'",
        "TRUNCATE noticias.news_items",
        "CREATE TABLE noticias.evil (a int)",
        "CREATE TABLE public.evil (a int)",
        "DROP TABLE noticias.news_items",
        "ALTER TABLE noticias.news_items ADD COLUMN body text",
        "SELECT * FROM noticias.alembic_version",
        "CREATE SCHEMA evil",
    ],
)
def test_the_app_role_cannot_do_more_than_select_insert_delete(app_engine, statement):
    with pytest.raises(ProgrammingError, match="permission denied|must be owner"):
        with app_engine.begin() as conn:
            conn.execute(text(statement))


def test_the_app_role_can_select_insert_and_delete(app_engine):
    with app_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO noticias.news_items "
                "(source_id, outlet, title, link, published_at) "
                "VALUES ('s', 'o', 't', 'https://x/1', now())"
            )
        )
        assert (
            conn.execute(text("SELECT count(*) FROM noticias.news_items")).scalar() == 1
        )
        conn.execute(text("DELETE FROM noticias.news_items"))


def test_the_app_role_cannot_read_a_table_it_was_not_granted(admin_engine, app_engine):
    # Stand-in for the gateway tables (users, refresh_tokens...) in the same database.
    with admin_engine.begin() as conn:
        conn.execute(text("CREATE TABLE public.admin_only_table (secret text)"))
    try:
        for verb in (
            "SELECT * FROM public.admin_only_table",
            "INSERT INTO public.admin_only_table VALUES ('x')",
            "DELETE FROM public.admin_only_table",
        ):
            with pytest.raises(ProgrammingError, match="permission denied"):
                with app_engine.begin() as conn:
                    conn.execute(text(verb))
    finally:
        with admin_engine.begin() as conn:
            conn.execute(text("DROP TABLE public.admin_only_table"))


PRIVILEGES = (
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "TRUNCATE",
    "REFERENCES",
    "TRIGGER",
)
ALLOWED = {("noticias.news_items", p) for p in ("SELECT", "INSERT", "DELETE")}


def test_the_role_privileges_are_exactly_select_insert_delete_on_news_items(app_engine):
    with app_engine.connect() as conn:
        tables = (
            conn.execute(
                text(
                    "SELECT format('%I.%I', n.nspname, c.relname) FROM pg_class c "
                    "JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f') "
                    "AND n.nspname NOT IN ('pg_catalog', 'information_schema') "
                    "AND n.nspname NOT LIKE 'pg_toast%'"
                )
            )
            .scalars()
            .all()
        )
        assert "noticias.news_items" in tables
        assert "noticias.alembic_version" in tables
        granted = {
            (t, p)
            for t in tables
            for p in PRIVILEGES
            if conn.execute(
                text("SELECT has_table_privilege(:t, :p)"), {"t": t, "p": p}
            ).scalar()
        }
    assert granted == ALLOWED


def test_the_app_role_is_not_a_superuser_nor_can_it_create_roles_or_databases(
    app_engine,
):
    with app_engine.connect() as conn:
        flags = conn.execute(
            text(
                "SELECT rolsuper, rolcreaterole, rolcreatedb, rolreplication, "
                "rolbypassrls "
                "FROM pg_roles WHERE rolname = current_user"
            )
        ).one()
        assert conn.execute(text("SELECT current_user")).scalar() == APP_ROLE
    assert tuple(flags) == (False, False, False, False, False)


def test_only_the_app_role_has_usage_on_the_schema_and_public_has_nothing(admin_engine):
    with admin_engine.connect() as conn:
        grants = conn.execute(
            text(
                "SELECT CASE WHEN a.grantee = 0 THEN 'PUBLIC' "
                "ELSE pg_get_userbyid(a.grantee) END, a.privilege_type "
                "FROM pg_namespace n, aclexplode(n.nspacl) a "
                "WHERE n.nspname = 'noticias' "
                "AND a.grantee <> n.nspowner"
            )
        ).all()
    assert [tuple(g) for g in grants] == [(APP_ROLE, "USAGE")]


# --- migrations -------------------------------------------------------------


def test_the_version_table_lives_in_the_worker_schema(admin_engine):
    with admin_engine.connect() as conn:
        assert conn.execute(
            text("SELECT to_regclass('noticias.alembic_version')")
        ).scalar()
        assert (
            conn.execute(text("SELECT to_regclass('public.alembic_version')")).scalar()
            is None
        )
        assert conn.execute(
            text("SELECT version_num FROM noticias.alembic_version")
        ).scalar()


def test_there_is_no_column_for_the_article_content(admin_engine):
    with admin_engine.connect() as conn:
        columns = (
            conn.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema = 'noticias' AND table_name = 'news_items'"
                )
            )
            .scalars()
            .all()
        )
    assert set(columns) == {
        "id",
        "source_id",
        "outlet",
        "title",
        "link",
        "published_at",
        "summary",
        "author",
        "fetched_at",
    }


def test_downgrade_drops_the_table_and_the_grants_and_upgrade_restores_them(
    admin_engine, migrated_db, monkeypatch
):
    monkeypatch.setenv("WORKER_NOTICIAS_MIGRATION_DATABASE_URL", migrated_db)
    command.downgrade(alembic_config(), "base")
    try:
        with admin_engine.connect() as conn:
            assert (
                conn.execute(text("SELECT to_regclass('noticias.news_items')")).scalar()
                is None
            )
            assert not conn.execute(
                text("SELECT has_schema_privilege(:r, 'noticias', 'USAGE')"),
                {"r": APP_ROLE},
            ).scalar()
            leftovers = (
                conn.execute(
                    text(
                        "SELECT c.relname FROM pg_class c JOIN pg_namespace n "
                        "ON n.oid = c.relnamespace WHERE n.nspname = 'noticias' "
                        "AND c.relkind IN ('r', 'p', 'v', 'm', 'S') "
                        "AND c.relname <> 'alembic_version'"
                    )
                )
                .scalars()
                .all()
            )
            assert leftovers == []
    finally:
        command.upgrade(alembic_config(), "head")
    with admin_engine.connect() as conn:
        assert conn.execute(text("SELECT to_regclass('noticias.news_items')")).scalar()


def test_the_migration_fails_clearly_when_the_app_role_does_not_exist(
    admin_engine, migrated_db, monkeypatch
):
    monkeypatch.setenv("WORKER_NOTICIAS_MIGRATION_DATABASE_URL", migrated_db)
    command.downgrade(alembic_config(), "base")
    with admin_engine.begin() as conn:
        conn.execute(text(f"ALTER ROLE {APP_ROLE} RENAME TO {APP_ROLE}_away"))
    try:
        with pytest.raises(DBAPIError, match=r"does not exist.*create_role\.sql"):
            command.upgrade(alembic_config(), "head")
    finally:
        with admin_engine.begin() as conn:
            conn.execute(text(f"ALTER ROLE {APP_ROLE}_away RENAME TO {APP_ROLE}"))
        command.upgrade(alembic_config(), "head")


def test_the_migrations_need_their_own_admin_url(monkeypatch):
    monkeypatch.delenv("WORKER_NOTICIAS_MIGRATION_DATABASE_URL", raising=False)
    with pytest.raises(RuntimeError, match="WORKER_NOTICIAS_MIGRATION_DATABASE_URL"):
        command.upgrade(alembic_config(), "head")


# --- settings ---------------------------------------------------------------


def test_the_retention_defaults_to_30_days(monkeypatch):
    monkeypatch.delenv("WORKER_NOTICIAS_RETENTION_DAYS", raising=False)
    assert store.retention() == timedelta(days=30)


@pytest.mark.parametrize(("raw", "days"), [("1", 1), ("365", 365), (" 90 ", 90)])
def test_valid_retention_values(monkeypatch, raw, days):
    monkeypatch.setenv("WORKER_NOTICIAS_RETENTION_DAYS", raw)
    assert store.retention() == timedelta(days=days)


@pytest.mark.parametrize("raw", ["0", "366", "-1", "abc", "", "30.5", "1e2", "٣٠"])
def test_invalid_retention_refuses_to_start_with_a_fixed_message(monkeypatch, raw):
    monkeypatch.setenv("WORKER_NOTICIAS_RETENTION_DAYS", raw)
    with pytest.raises(store.ConfigError) as excinfo:
        store.retention()
    assert (
        str(excinfo.value)
        == "WORKER_NOTICIAS_RETENTION_DAYS must be an integer from 1 to 365"
    )


def test_the_engine_needs_the_app_database_url(monkeypatch):
    store.get_engine.cache_clear()
    monkeypatch.delenv("WORKER_NOTICIAS_DATABASE_URL", raising=False)
    with pytest.raises(store.ConfigError) as excinfo:
        store.get_engine()
    assert str(excinfo.value) == "WORKER_NOTICIAS_DATABASE_URL is not set"


def test_the_engine_hides_parameters_and_never_echoes_the_url(monkeypatch):
    store.get_engine.cache_clear()
    monkeypatch.setenv(
        "WORKER_NOTICIAS_DATABASE_URL",
        "postgresql+psycopg://worker_noticias:not-a-real-secret@127.0.0.1:1/none",
    )
    try:
        engine = store.get_engine()
        assert engine.hide_parameters is True
        with pytest.raises(store.StoreError) as excinfo:
            store.save([item()], RETENTION, engine=engine)
        assert "not-a-real-secret" not in f"{excinfo.value!s}{excinfo.value!r}"
    finally:
        store.get_engine.cache_clear()


def test_an_unparsable_database_url_is_reported_without_the_password(monkeypatch):
    store.get_engine.cache_clear()
    monkeypatch.setenv(
        "WORKER_NOTICIAS_DATABASE_URL", "not a url://user:SENTINEL-PASSWORD@@host"
    )
    try:
        with pytest.raises(store.ConfigError) as excinfo:
            store.get_engine()
    finally:
        store.get_engine.cache_clear()
    assert str(excinfo.value) == "WORKER_NOTICIAS_DATABASE_URL is not valid"
    assert excinfo.value.__cause__ is None
    assert "SENTINEL" not in f"{excinfo.value!s}{excinfo.value!r}"
