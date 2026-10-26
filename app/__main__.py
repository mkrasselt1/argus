"""Run the Argus server:  python -m app

Honors SECSCAN_HOST / SECSCAN_PORT and, for development, SECSCAN_RELOAD=1 which
makes the server watch its own source files and reload itself on any change
(no manual restart needed). Reload uses the import-string form required by
uvicorn's reloader.
"""
from __future__ import annotations

import uvicorn

from app.config import enforce_startup_safety, settings, warn_weak_keys


def main() -> None:
    # Fail fast on an unauthenticated UI exposed to the network; warn on
    # derived crypto keys. Both run before the server binds a port.
    enforce_startup_safety()
    warn_weak_keys()
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.reload,
        reload_dirs=["app"] if settings.reload else None,
    )


if __name__ == "__main__":
    main()
