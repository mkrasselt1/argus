"""Argus — read-only security & asset management dashboard."""

__version__ = "1.1.9"

# Database schema revision. Bump whenever models.py changes in a way that
# needs a migration. The running app records this in the `schema_meta` table
# so deployments stay revision-safe (see app/db.py).
SCHEMA_REVISION = 11
