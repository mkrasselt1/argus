"""Run the Argus server:  python -m app

Honors SECSCAN_HOST / SECSCAN_PORT and, for development, SECSCAN_RELOAD=1 which
makes the server watch its own source files and reload itself on any change
(no manual restart needed). Reload uses the import-string form required by
uvicorn's reloader.
"""
from __future__ import annotations

import uvicorn

from app.config import settings


def main() -> None:
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.reload,
        reload_dirs=["app"] if settings.reload else None,
    )


if __name__ == "__main__":
    main()
