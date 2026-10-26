"""Database engine, session and a tiny schema-revision guard."""
from __future__ import annotations

import logging
from collections.abc import Iterator

from sqlalchemy import inspect, text
from sqlmodel import Field, Session, SQLModel, create_engine

from app import SCHEMA_REVISION
from app.config import settings

log = logging.getLogger(__name__)

engine = create_engine(
    settings.resolved_database_url(),
    echo=False,
    connect_args={"check_same_thread": False},
)


class SchemaMeta(SQLModel, table=True):
    """Records the schema revision the database was created/migrated to."""

    id: int | None = Field(default=1, primary_key=True)
    revision: int = 0


def _add_missing_columns() -> None:
    """Add columns that models gained but an older DB lacks (SQLite ALTER ADD).

    ``create_all`` only creates missing *tables*, never missing *columns*. This
    lightweight additive migration keeps older databases working when models
    grow a new (nullable or defaulted) column. Breaking changes (dropping/retyping
    columns) would still need a real migration tool.
    """
    insp = inspect(engine)
    existing_tables = set(insp.get_table_names())
    with engine.begin() as conn:
        for table in SQLModel.metadata.sorted_tables:
            if table.name not in existing_tables:
                continue  # create_all will handle brand-new tables
            have = {c["name"] for c in insp.get_columns(table.name)}
            for col in table.columns:
                if col.name in have:
                    continue
                coltype = col.type.compile(dialect=engine.dialect)
                default_sql = ""
                if col.default is not None and getattr(col.default, "is_scalar", False):
                    val = col.default.arg
                    default_sql = f" DEFAULT {int(val) if isinstance(val, bool) else val!r}"
                elif not col.nullable:
                    default_sql = " DEFAULT 0"  # last resort for NOT NULL columns
                stmt = f'ALTER TABLE "{table.name}" ADD COLUMN "{col.name}" {coltype}{default_sql}'
                try:
                    conn.execute(text(stmt))
                    log.info("migrated: %s", stmt)
                except Exception as exc:  # pragma: no cover - defensive
                    log.warning("could not add column %s.%s: %s", table.name, col.name, exc)


def init_db() -> None:
    """Create tables, apply additive column migrations, record the revision."""
    SQLModel.metadata.create_all(engine)
    _add_missing_columns()
    with Session(engine) as session:
        meta = session.get(SchemaMeta, 1)
        if meta is None:
            session.add(SchemaMeta(id=1, revision=SCHEMA_REVISION))
            session.commit()
        elif meta.revision > SCHEMA_REVISION:
            raise RuntimeError(
                f"Database schema revision {meta.revision} is newer than this "
                f"application ({SCHEMA_REVISION}). Deploy a matching/newer image."
            )
        elif meta.revision < SCHEMA_REVISION:
            # Additive create_all already ran; just record the new revision.
            meta.revision = SCHEMA_REVISION
            session.add(meta)
            session.commit()


def get_session() -> Iterator[Session]:
    with Session(engine) as session:
        yield session
