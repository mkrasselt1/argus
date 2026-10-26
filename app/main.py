"""FastAPI application: read-only dashboard + inventory management + scheduler."""
from __future__ import annotations

import hmac
import logging
import re
import secrets
from datetime import timezone
from contextlib import asynccontextmanager
from pathlib import Path

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import BackgroundTasks, Depends, FastAPI, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from markupsafe import Markup, escape
from sqlmodel import Session, select

from app import SCHEMA_REVISION, __version__
from app.collectors.base import available, load_builtin_collectors, run_collector
from app.config import settings
from app.db import engine, get_session, init_db
from app.models import (
    AgentCommand,
    Client,
    ClientStatus,
    CommandStatus,
    ComponentChange,
    Package,
    Scan,
    ScanStatus,
    Severity,
    System,
    SystemKind,
    Vulnerability,
    utcnow,
)
from app.services import enrollment, scanner
from app.services.ratelimit import enroll_limiter, login_limiter

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("argus")

BASE = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE / "web" / "templates"))
templates.env.globals["auth_enabled"] = settings.auth_enabled()


def _localdt(value, with_time: bool = True):
    """Render a UTC datetime as a <time> element that JS converts to the
    viewer's local timezone (see base.html). Stored timestamps are UTC; showing
    them raw confused users whose clock is CET/CEST. No-JS fallback shows UTC.
    """
    if value is None:
        return ""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc)
    iso = value.strftime("%Y-%m-%dT%H:%M:%SZ")
    fallback = value.strftime("%Y-%m-%d %H:%M" if with_time else "%Y-%m-%d")
    dateonly = "" if with_time else ' data-dateonly="1"'
    return Markup(
        f'<time datetime="{iso}" data-localdt{dateonly}>{escape(fallback)} UTC</time>'
    )


templates.env.filters["localdt"] = _localdt

scheduler = BackgroundScheduler()


@asynccontextmanager
async def lifespan(app: FastAPI):
    from app.config import warn_weak_keys

    warn_weak_keys()
    init_db()
    load_builtin_collectors()
    scanner.backfill_summaries()  # ensure dashboard rollups exist after migration
    started = False
    if settings.scan_interval_minutes > 0:
        scheduler.add_job(
            scanner.run_all_enabled, "interval", minutes=settings.scan_interval_minutes,
            id="scan_all", replace_existing=True,
        )
        started = True
    if settings.scan_retention > 0:
        scheduler.add_job(
            lambda: scanner.prune_old_scans(settings.scan_retention),
            "interval", hours=24, id="prune", replace_existing=True,
        )
        started = True
    if started:
        scheduler.start()
        log.info("Scheduler started (scan=%s min, retention=%s/system)",
                 settings.scan_interval_minutes, settings.scan_retention)
    yield
    if scheduler.running:
        scheduler.shutdown(wait=False)


app = FastAPI(title="argus", version=__version__, lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(BASE / "web" / "static")), name="static")

# ---- authentication ------------------------------------------------------
# When an admin password is set, the UI and management routes require a login.
# The machine-to-machine APIs (ingest/enroll/agent) keep their own tokens and
# stay reachable without a session.
from starlette.middleware.base import BaseHTTPMiddleware  # noqa: E402
from starlette.middleware.sessions import SessionMiddleware  # noqa: E402

_AUTH_EXEMPT = ("/login", "/logout", "/static", "/healthz", "/version",
                "/ingest", "/enroll", "/agent/", "/install.", "/dist/",
                "/credentials/upload")

# State-changing UI endpoints authenticate with a session cookie, so they need
# CSRF protection. The machine endpoints below authenticate with a token or a
# per-client credential (not a cookie) and are therefore exempt.
_CSRF_EXEMPT = ("/ingest", "/enroll", "/agent/", "/credentials/upload")


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _ensure_csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return token


def verify_csrf(request: Request, csrf_token: str = Form("")) -> None:
    """Reject a state-changing POST whose CSRF token doesn't match the session."""
    expected = request.session.get("csrf_token")
    if not expected or not hmac.compare_digest(csrf_token or "", expected):
        raise HTTPException(status_code=403, detail="CSRF token missing or invalid")


async def _auth_guard(request: Request, call_next):
    # Make a CSRF token available to every rendered form (per session).
    _ensure_csrf_token(request)
    if settings.auth_enabled() and not request.url.path.startswith(_AUTH_EXEMPT):
        if not request.session.get("auth"):
            if request.method == "GET" and "text/html" in request.headers.get("accept", ""):
                return RedirectResponse(f"/login?next={request.url.path}", status_code=303)
            return JSONResponse({"detail": "authentication required"}, status_code=401)
    response = await call_next(request)
    # Don't leak URLs (which could carry tokens) to third parties via Referer.
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    return response


async def _limit_body(request: Request, call_next):
    """Reject obviously oversized request bodies before they are buffered."""
    cl = request.headers.get("content-length")
    if cl is not None:
        try:
            if int(cl) > settings.max_body_bytes:
                return JSONResponse({"detail": "request body too large"}, status_code=413)
        except ValueError:
            return JSONResponse({"detail": "invalid content-length"}, status_code=400)
    return await call_next(request)


# Order matters: the LAST middleware added is the OUTERMOST. SessionMiddleware
# must wrap the auth guard so request.session is available inside it. The body
# limiter is outermost so it runs first.
app.add_middleware(BaseHTTPMiddleware, dispatch=_auth_guard)
app.add_middleware(SessionMiddleware, secret_key=settings.session_secret(),
                   session_cookie="argus_session", same_site="lax",
                   https_only=settings.secure_cookies)
app.add_middleware(BaseHTTPMiddleware, dispatch=_limit_body)


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request, next: str = "/", error: str = ""):
    if not settings.auth_enabled():
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(
        request, "login.html", {"request": request, "next": next, "error": error, "version": __version__}
    )


@app.post("/login")
def login(request: Request, password: str = Form(...), next: str = Form("/")):
    ip = _client_ip(request)
    if not login_limiter.check(ip):
        log.warning("login rate limit hit for %s", ip)
        return RedirectResponse("/login?error=locked", status_code=303)
    if settings.auth_enabled() and hmac.compare_digest(password, settings.admin_password):
        login_limiter.reset(ip)
        request.session["auth"] = True
        return RedirectResponse(next or "/", status_code=303)
    return RedirectResponse("/login?error=1", status_code=303)


@app.post("/logout")
def logout(request: Request, _: None = Depends(verify_csrf)):
    # Keep a fresh CSRF token after clearing auth state.
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# ---- health / meta -------------------------------------------------------

@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.get("/version")
def version() -> dict:
    return {"version": __version__, "schema_revision": SCHEMA_REVISION}


# ---- agent mode (receive & forward) --------------------------------------
# When SECSCAN_AGENT_TOKEN is set, this instance lets another argus
# collect *through* it: it runs a collector locally against devices only it can
# reach (e.g. an isolated customer network behind a VPN edge node) and returns
# the read-only result. No target is ever modified.

class AgentCollectRequest(BaseModel):
    collector: str
    config: dict = {}


def _require_agent_token(x_agent_token: str = Header(default="")) -> None:
    if not settings.agent_enabled():
        raise HTTPException(status_code=404, detail="agent mode disabled")
    import hmac

    if not hmac.compare_digest(x_agent_token, settings.agent_token):
        raise HTTPException(status_code=401, detail="invalid agent token")


@app.get("/agent/info")
def agent_info(_: None = Depends(_require_agent_token)) -> dict:
    return {"version": __version__, "collectors": available()}


@app.post("/agent/collect")
def agent_collect(
    req: AgentCollectRequest, _: None = Depends(_require_agent_token)
) -> JSONResponse:
    # Allow-list: only run collectors explicitly permitted on this agent. This
    # stops the endpoint from being abused as an open scan/SSRF proxy and (since
    # "relay" is excluded by default) from being chained/looped back on itself.
    allowed = settings.allowed_agent_collectors()
    if req.collector not in allowed:
        raise HTTPException(
            status_code=403,
            detail=f"collector '{req.collector}' not permitted on this agent "
                   f"(allowed: {', '.join(sorted(allowed)) or 'none'})",
        )
    try:
        result = run_collector(req.collector, req.config)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:  # collector failure surfaces as 502 to the caller
        log.exception("agent collect failed")
        raise HTTPException(status_code=502, detail=f"{type(exc).__name__}: {exc}")
    return JSONResponse(result.to_dict())


# ---- push / ingest mode (client -> server) -------------------------------
# A client runs a collector locally and POSTs the result here. The server
# never connects back to the client; any control command is returned in this
# response and the client acts on it on its next push. Secure: no inbound path
# to the client is ever opened.

class IngestRequest(BaseModel):
    system: str
    collector: str
    result: dict
    kind: str | None = None
    hostname: str | None = None
    ip_address: str | None = None


def _authenticate_ingest(
    request: Request,
    x_ingest_token: str = Header(default=""),
    x_client_id: str = Header(default=""),
    x_client_token: str = Header(default=""),
) -> None:
    """Accept either a per-client credential (preferred) or the shared token."""
    import hmac

    ip = request.client.host if request.client else None
    # Preferred: per-client credential from enrollment.
    if x_client_id and x_client_token:
        try:
            client = enrollment.authenticate(x_client_id, x_client_token, ip)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=f"client {exc}")
        if client is None:
            raise HTTPException(status_code=401, detail="invalid client credentials")
        request.state.client = client  # used to deliver this agent's secrets
        return
    # Fallback: shared ingest token (simple setups).
    if settings.ingest_enabled() and hmac.compare_digest(x_ingest_token, settings.ingest_token):
        return
    if not settings.ingest_enabled():
        raise HTTPException(status_code=404, detail="ingest mode disabled")
    raise HTTPException(status_code=401, detail="authentication required")


@app.post("/enroll")
def enroll_agent(payload: dict, request: Request) -> JSONResponse:
    """Exchange a valid enrollment code for a durable per-client credential.

    The agent also sends its X25519 public key (secrets are sealed to it) and
    the passphrase that unlocks its own private key (the server stores it and
    hands it back only to this authenticated agent at runtime).
    """
    ip = _client_ip(request)
    if not enroll_limiter.check(ip):
        log.warning("enroll rate limit hit for %s", ip)
        raise HTTPException(status_code=429, detail="too many enrollment attempts")
    code = payload.get("code", "")
    name = payload.get("name") or "Unbenannter Agent"
    try:
        creds = enrollment.enroll(code, name, payload.get("hostname"),
                                  pubkey=payload.get("pubkey"),
                                  key_passphrase=payload.get("key_passphrase"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return JSONResponse(creds)


@app.post("/ingest")
def ingest(req: IngestRequest, request: Request,
           _: None = Depends(_authenticate_ingest)) -> JSONResponse:
    from app.collectors.base import CollectResult

    # L1: a malformed result must not 500 — reject it as a 400.
    try:
        result = CollectResult.from_dict(req.result)
    except (TypeError, ValueError, KeyError, AttributeError) as exc:
        raise HTTPException(status_code=400, detail=f"malformed result: {exc}")

    # H4: bound the payload size so a misbehaving agent can't exhaust the server.
    if len(result.packages) > settings.ingest_max_packages:
        raise HTTPException(status_code=413,
                            detail=f"too many packages (>{settings.ingest_max_packages})")
    if len(result.vulnerabilities) > settings.ingest_max_vulnerabilities:
        raise HTTPException(status_code=413,
                            detail=f"too many vulnerabilities (>{settings.ingest_max_vulnerabilities})")

    client = getattr(request.state, "client", None)
    if client is None:
        # Shared-token (or no) auth: no agent<->system binding is enforced.
        log.warning("ingest for system %r via shared token (no per-client binding)", req.system)
    try:
        scan = scanner.ingest_result(
            system_name=req.system,
            collector=req.collector,
            result=result,
            kind=req.kind,
            hostname=req.hostname,
            ip_address=req.ip_address,
            auto_register=settings.ingest_auto_register,
            client_db_id=client.id if client is not None else None,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    with Session(engine) as session:
        commands = scanner.take_pending_commands(session, scan.system_id)
    from app.services import credentials

    resp = {"ok": True, "scan_id": scan.id, "commands": commands,
            "server_version": __version__}
    # Zero-knowledge credential delivery: only to a per-client-authenticated
    # agent. We hand it its own key passphrase + sealed blobs; the server never
    # sees plaintext (the agent opens them with its own private key in RAM).
    if client is not None:
        resp["key_passphrase"] = client.key_passphrase
        resp["sealed_credentials"] = credentials.delivery_for_client(client.id)
    return JSONResponse(resp)


# ---- agent distribution & one-line installers ----------------------------

@app.get("/dist/argus-agent.tar.gz")
def agent_tarball():
    """Serve a pip-installable sdist of the agent, built from the live source.

    Always matches this server's version, so `pip install <url>` gives an agent
    that lines up with the server (supports the self-update story too).
    """
    import io
    import tarfile

    root = BASE.parent  # project dir containing pyproject.toml + app/
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        tar.add(root / "pyproject.toml", arcname="argus/pyproject.toml")
        for path in (root / "app").rglob("*.py"):
            tar.add(path, arcname=f"argus/app/{path.relative_to(root / 'app')}")
    buf.seek(0)
    return Response(content=buf.getvalue(), media_type="application/gzip")


def _install_sh(server: str) -> str:
    return f"""#!/bin/sh
# Argus agent installer (Linux). Usage:
#   curl -fsSL {server}/install.sh | sh -s -- --join <token> [--collector network_discovery --config '{{...}}']
set -e
SERVER="{server}"
DIR="${{ARGUS_DIR:-/opt/argus-agent}}"
JOIN=""; EXTRA=""
while [ $# -gt 0 ]; do
  case "$1" in
    --join) JOIN="$2"; shift 2 ;;
    *) EXTRA="$EXTRA $1"; shift ;;
  esac
done
[ -z "$JOIN" ] && {{ echo "error: --join <token> required"; exit 1; }}
echo "Installing Argus agent into $DIR ..."
python3 -m venv "$DIR/venv"
"$DIR/venv/bin/python" -m pip install -q --upgrade pip || true
"$DIR/venv/bin/pip" install -q "$SERVER/dist/argus-agent.tar.gz"
export ARGUS_AGENT_CONFIG="$DIR/agent.json"
"$DIR/venv/bin/argus-agent" join "$JOIN" $EXTRA --interval 60
if [ "$(id -u)" = "0" ] && command -v systemctl >/dev/null 2>&1; then
  cat > /etc/systemd/system/argus-agent.service <<UNIT
[Unit]
Description=Argus Agent
After=network-online.target
[Service]
Environment=ARGUS_AGENT_CONFIG=$DIR/agent.json
ExecStart=$DIR/venv/bin/argus-agent run
Restart=always
[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload && systemctl enable --now argus-agent
  echo "Service 'argus-agent' installed and started."
else
  echo "Run the agent with: ARGUS_AGENT_CONFIG=$DIR/agent.json $DIR/venv/bin/argus-agent run"
fi
"""


def _install_ps1(server: str) -> str:
    return f"""# Argus agent installer (Windows). Usage:
#   iwr -useb {server}/install.ps1 | iex ; Install-ArgusAgent -Join '<token>'
function Install-ArgusAgent {{
  param([Parameter(Mandatory=$true)][string]$Join, [string]$Extra="")
  $Server = "{server}"
  $Dir = "$env:ProgramData\\argus-agent"
  Write-Host "Installing Argus agent into $Dir ..."
  python -m venv "$Dir\\venv"
  & "$Dir\\venv\\Scripts\\python.exe" -m pip install -q --upgrade pip 2>$null
  & "$Dir\\venv\\Scripts\\pip.exe" install -q "$Server/dist/argus-agent.tar.gz"
  $env:ARGUS_AGENT_CONFIG = "$Dir\\agent.json"
  & "$Dir\\venv\\Scripts\\argus-agent.exe" join $Join --kind windows --collector windows --interval 60
  # Heartbeat model: the scheduler just fires often; the agent decides whether
  # its own interval has elapsed (`run --once` is a no-op when not yet due).
  # So the cadence lives in the (centrally settable) agent config, and the task
  # is self-healing against crashes, sleep/hibernate and reboots.
  # The task runs as SYSTEM and may not see a freshly set env var, so the config
  # path is passed directly with --config (robust, no cmd wrapper needed).
  $action = New-ScheduledTaskAction -Execute "$Dir\\venv\\Scripts\\argus-agent.exe" -Argument "run --once --config `"$Dir\\agent.json`""
  $atStartup = New-ScheduledTaskTrigger -AtStartup
  $beat = New-ScheduledTaskTrigger -Once -At (Get-Date) `
      -RepetitionInterval (New-TimeSpan -Minutes 15) -RepetitionDuration (New-TimeSpan -Days 3650)
  $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries `
      -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew `
      -ExecutionTimeLimit (New-TimeSpan -Minutes 30) `
      -RestartInterval (New-TimeSpan -Minutes 5) -RestartCount 3
  $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
  Register-ScheduledTask -TaskName "ArgusAgent" -Action $action -Trigger $atStartup,$beat `
      -Settings $settings -Principal $principal -Force | Out-Null
  Start-ScheduledTask -TaskName "ArgusAgent"
  Write-Host "Scheduled task 'ArgusAgent' installed (15-min heartbeat, self-gated, self-healing) and started."
}}
"""


def _server_base(request: Request) -> str:
    """The server's public base URL (no trailing slash).

    Prefers SECSCAN_PUBLIC_URL so install scripts and join tokens don't trust a
    spoofable Host header; falls back to the request's own base URL.
    """
    return settings.public_base_url(str(request.base_url)).rstrip("/")


@app.get("/install.sh")
def install_sh(request: Request):
    return Response(_install_sh(_server_base(request)),
                    media_type="text/x-shellscript")


@app.get("/install.ps1")
def install_ps1(request: Request):
    return Response(_install_ps1(_server_base(request)),
                    media_type="text/plain")


# ---- agents / enrollment UI ----------------------------------------------

@app.get("/agents", response_class=HTMLResponse)
def agents_page(request: Request, session: Session = Depends(get_session)):
    from app.collectors.base import available as _avail, load_builtin_collectors
    from app.services import credentials as _creds

    load_builtin_collectors()
    from app.collectors.network_discovery import DEVICE_MODULES

    # M5: the join token is flashed via the session and shown exactly once, so
    # it never appears in a URL/query string (logs, history, Referer).
    join = request.session.pop("join_flash", "")
    clients = session.exec(select(Client).order_by(Client.enrolled_at.desc())).all()
    return templates.TemplateResponse(
        request, "agents.html",
        {"request": request, "clients": clients, "join": join,
         "base_url": _server_base(request) + "/",
         "credentials": _creds.list_credentials(),
         "modules": sorted(DEVICE_MODULES), "version": __version__},
    )


def _require_client(
    x_client_id: str = Header(default=""), x_client_token: str = Header(default=""),
):
    client = enrollment.authenticate(x_client_id, x_client_token) if x_client_id else None
    if client is None:
        raise HTTPException(status_code=401, detail="client auth required")
    return client


@app.get("/agents/{client_db_id}/pubkey")
def agent_pubkey(client_db_id: int, session: Session = Depends(get_session)):
    """The agent's public key, so the browser can seal a secret to it (E2E)."""
    client = session.get(Client, client_db_id)
    if client is None or not client.pubkey:
        raise HTTPException(status_code=404, detail="no pubkey for this agent")
    return {"client_id": client.client_id, "pubkey": client.pubkey}


@app.post("/credentials/upload")
def upload_sealed_credential(payload: dict, client=Depends(_require_client)):
    """CLI path: the agent uploads an already-sealed credential (opaque blob)."""
    from app.services import credentials

    if not payload.get("sealed") or not payload.get("module"):
        raise HTTPException(status_code=400, detail="module and sealed required")
    cid = credentials.add_sealed(client.id, payload["module"], payload["sealed"],
                                 payload.get("username"), payload.get("label"),
                                 payload.get("match"))
    return {"ok": True, "id": cid}


@app.post("/credentials")
def add_sealed_credential_ui(
    client_db_id: int = Form(...),
    module: str = Form(...),
    sealed: str = Form(...),   # already sealed in the browser to the agent pubkey
    username: str = Form(""),
    label: str = Form(""),
    match: str = Form(""),
    _: None = Depends(verify_csrf),
):
    from app.services import credentials

    credentials.add_sealed(client_db_id, module, sealed, username or None,
                           label or None, match or None)
    return RedirectResponse("/agents", status_code=303)


@app.post("/credentials/{cred_id}/delete")
def delete_credential(cred_id: int, _: None = Depends(verify_csrf)):
    from app.services import credentials

    credentials.delete_credential(cred_id)
    return RedirectResponse("/agents", status_code=303)


@app.post("/agents/code")
def create_enrollment_code(
    request: Request,
    label: str = Form(""),
    auto_approve: str = Form("on"),
    ttl_minutes: int = Form(60),
    max_uses: int = Form(1),
    group: str = Form(""),
    _: None = Depends(verify_csrf),
):
    code, _row = enrollment.create_code(
        label=label or None,
        auto_approve=(auto_approve == "on"),
        ttl_minutes=ttl_minutes,
        max_uses=max_uses,
        group=group or None,
    )
    # Build the join token from this server's public URL (prefer SECSCAN_PUBLIC_URL).
    base = _server_base(request)
    token = enrollment.encode_join_token(base, code)
    # M5: don't put the token in the redirect URL — flash it via the session.
    request.session["join_flash"] = token
    return RedirectResponse("/agents", status_code=303)


@app.post("/agents/{client_id}/approve")
def approve_client(client_id: int, _: None = Depends(verify_csrf)):
    enrollment.set_status(client_id, ClientStatus.approved)
    return RedirectResponse("/agents", status_code=303)


@app.post("/agents/{client_id}/revoke")
def revoke_client(client_id: int, _: None = Depends(verify_csrf)):
    enrollment.set_status(client_id, ClientStatus.revoked)
    return RedirectResponse("/agents", status_code=303)


# ---- helpers -------------------------------------------------------------

def _severity_counts(session: Session, scan_id: int) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    vulns = session.exec(select(Vulnerability).where(Vulnerability.scan_id == scan_id)).all()
    for v in vulns:
        counts[v.severity.value] = counts.get(v.severity.value, 0) + 1
    return counts


# ---- dashboard -----------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, updates: bool = False, session: Session = Depends(get_session)):
    # Read the denormalised rollup (one query) instead of per-system N+1.
    from app.models import SystemSummary

    systems = session.exec(select(System).order_by(System.name)).all()
    summaries = {s.system_id: s for s in session.exec(select(SystemSummary)).all()}
    rows = []
    for s in systems:
        summ = summaries.get(s.id)
        rows.append(
            {
                "system": s,
                "last_scan_at": summ.last_scan_at if summ else None,
                "status": summ.status if summ else None,
                "packages": summ.packages if summ else 0,
                "updates": summ.updates if summ else 0,
                "critical": summ.critical if summ else 0,
                "high": summ.high if summ else 0,
            }
        )
    if updates:  # standard filter: only systems with pending (un-snoozed) updates
        rows = [r for r in rows if r["updates"]]
    # Group by group name in Python (Jinja's groupby can't sort None vs str).
    groups: dict[str, list] = {}
    for r in rows:
        groups.setdefault(r["system"].group or "Ohne Gruppe", []).append(r)
    grouped = sorted(groups.items(), key=lambda kv: (kv[0] == "Ohne Gruppe", kv[0].lower()))
    return templates.TemplateResponse(
        request, "index.html",
        {"request": request, "rows": rows, "grouped": grouped,
         "updates_only": updates, "version": __version__},
    )


# ---- inventory management (config only; never controls targets) ----------
# NOTE: the static "/systems/new" route MUST be declared before the dynamic
# "/systems/{system_id}" route, otherwise "new" is matched as an int id.

@app.get("/systems/new", response_class=HTMLResponse)
def new_system_form(request: Request):
    return templates.TemplateResponse(
        request, "system_form.html",
        {
            "request": request,
            "kinds": [k.value for k in SystemKind],
            "collectors": available(),
        },
    )


@app.get("/systems/{system_id}", response_class=HTMLResponse)
def system_detail(system_id: int, request: Request, session: Session = Depends(get_session)):
    system = session.get(System, system_id)
    if system is None:
        return HTMLResponse("System not found", status_code=404)
    last = scanner.latest_scan(session, system_id)
    packages = (
        session.exec(
            select(Package).where(Package.scan_id == last.id).order_by(Package.type, Package.name)
        ).all()
        if last
        else []
    )
    vulns = (
        session.exec(
            select(Vulnerability)
            .where(Vulnerability.scan_id == last.id)
            .order_by(Vulnerability.severity.desc())
        ).all()
        if last
        else []
    )
    history = session.exec(
        select(Scan).where(Scan.system_id == system_id).order_by(Scan.started_at.desc())
    ).all()[:20]
    changes = scanner.recent_changes(session, system_id, limit=50)
    snoozes = scanner.active_snoozes(session, system_id)
    pending_commands = session.exec(
        select(AgentCommand).where(
            AgentCommand.system_id == system_id,
            AgentCommand.status == CommandStatus.pending,
        )
    ).all()
    return templates.TemplateResponse(
        request, "system.html",
        {
            "request": request,
            "system": system,
            "last": last,
            "packages": packages,
            "vulns": vulns,
            "history": history,
            "changes": changes,
            "snoozes": snoozes,
            "pending_commands": pending_commands,
            "current_targets": _targets_str(system),
            "severity": _severity_counts(session, last.id) if last else {},
        },
    )


def _targets_str(system: System) -> str:
    """Render the system's configured scan targets as a comma list for the UI."""
    targets = (system.collector_config or {}).get("targets")
    if not targets:
        return ""
    if isinstance(targets, list):
        return ", ".join(str(t) for t in targets)
    return str(targets)


def _parse_tags(raw: str) -> list[str]:
    return [t.strip() for t in (raw or "").replace(";", ",").split(",") if t.strip()]


def _parse_json(raw: str) -> dict:
    import json

    try:
        return json.loads(raw or "{}")
    except json.JSONDecodeError:
        return {}


def _validate_web_url(web_url: str) -> str | None:
    """L2: only accept http(s) web URLs; reject other schemes (javascript: etc.)."""
    url = (web_url or "").strip()
    if not url:
        return None
    if not (url.startswith("http://") or url.startswith("https://")):
        raise HTTPException(status_code=400,
                            detail="web_url must start with http:// or https://")
    return url


@app.post("/systems")
def create_system(
    name: str = Form(...),
    kind: str = Form("other"),
    hostname: str = Form(""),
    group: str = Form(""),
    tags: str = Form(""),
    web_url: str = Form(""),
    access_notes: str = Form(""),
    collector: str = Form("manual"),
    collector_config: str = Form("{}"),
    session: Session = Depends(get_session),
    _: None = Depends(verify_csrf),
):
    from app.services import crypto

    system = System(
        name=name,
        kind=SystemKind(kind) if kind in SystemKind._value2member_map_ else SystemKind.other,
        hostname=hostname or None,
        group=group or None,
        tags=_parse_tags(tags),
        web_url=_validate_web_url(web_url),
        access_notes=access_notes or None,
        collector=collector,
        # H2: encrypt secret fields (password/token/...) in collector_config at rest.
        collector_config=crypto.encrypt_config(_parse_json(collector_config)),
    )
    session.add(system)
    session.commit()
    session.refresh(system)
    return RedirectResponse(f"/systems/{system.id}", status_code=303)


@app.get("/systems/{system_id}/edit", response_class=HTMLResponse)
def edit_system_form(system_id: int, request: Request, session: Session = Depends(get_session)):
    system = session.get(System, system_id)
    if system is None:
        return HTMLResponse("System not found", status_code=404)
    return templates.TemplateResponse(
        request, "system_form.html",
        {
            "request": request,
            "system": system,
            "edit": True,
            "kinds": [k.value for k in SystemKind],
            "collectors": available(),
        },
    )


@app.post("/systems/{system_id}/edit")
def edit_system(
    system_id: int,
    name: str = Form(...),
    kind: str = Form("other"),
    hostname: str = Form(""),
    group: str = Form(""),
    tags: str = Form(""),
    web_url: str = Form(""),
    access_notes: str = Form(""),
    collector: str = Form("manual"),
    collector_config: str = Form("{}"),
    enabled: str = Form("on"),
    session: Session = Depends(get_session),
    _: None = Depends(verify_csrf),
):
    from app.services import crypto

    system = session.get(System, system_id)
    if system is None:
        return HTMLResponse("System not found", status_code=404)
    old_name = system.name
    new_tags = _parse_tags(tags)
    system.name = name
    system.kind = SystemKind(kind) if kind in SystemKind._value2member_map_ else SystemKind.other
    system.hostname = hostname or None
    system.group = group or None
    system.tags = new_tags
    system.web_url = _validate_web_url(web_url)
    system.access_notes = access_notes or None
    system.collector = collector
    # H2: encrypt secret fields at rest (already-encrypted values aren't re-wrapped).
    system.collector_config = crypto.encrypt_config(_parse_json(collector_config))
    system.enabled = enabled == "on"
    system.updated_at = utcnow()
    session.add(system)
    session.commit()
    # Propagate this agent's tags (and any rename) to the devices it discovered.
    scanner.propagate_agent_to_devices(old_name, name, new_tags)
    return RedirectResponse(f"/systems/{system_id}", status_code=303)


@app.post("/systems/{system_id}/delete")
def delete_system(system_id: int, session: Session = Depends(get_session),
                  _: None = Depends(verify_csrf)):
    system = session.get(System, system_id)
    if system is None:
        return RedirectResponse("/", status_code=303)
    # Remove dependent rows first (SQLite has no cascade enabled here).
    scan_ids = [s.id for s in session.exec(select(Scan).where(Scan.system_id == system_id)).all()]
    for sid in scan_ids:
        for p in session.exec(select(Package).where(Package.scan_id == sid)).all():
            session.delete(p)
        for v in session.exec(select(Vulnerability).where(Vulnerability.scan_id == sid)).all():
            session.delete(v)
    for ch in session.exec(select(ComponentChange).where(ComponentChange.system_id == system_id)).all():
        session.delete(ch)
    for cmd in session.exec(select(AgentCommand).where(AgentCommand.system_id == system_id)).all():
        session.delete(cmd)
    for s in session.exec(select(Scan).where(Scan.system_id == system_id)).all():
        session.delete(s)
    session.delete(system)
    session.commit()
    return RedirectResponse("/", status_code=303)


@app.post("/systems/{system_id}/snooze")
def snooze_update(system_id: int, component: str = Form(...), days: int = Form(30),
                  _: None = Depends(verify_csrf)):
    scanner.snooze_component(system_id, component, days)
    return RedirectResponse(f"/systems/{system_id}", status_code=303)


@app.post("/systems/{system_id}/unsnooze")
def unsnooze_update(system_id: int, component: str = Form(...),
                    _: None = Depends(verify_csrf)):
    scanner.unsnooze_component(system_id, component)
    return RedirectResponse(f"/systems/{system_id}", status_code=303)


@app.post("/systems/{system_id}/scan")
def trigger_scan(system_id: int, background: BackgroundTasks,
                 _: None = Depends(verify_csrf)):
    background.add_task(scanner.run_scan, system_id)
    return RedirectResponse(f"/systems/{system_id}", status_code=303)


@app.post("/scan-all")
def trigger_scan_all(background: BackgroundTasks, _: None = Depends(verify_csrf)):
    background.add_task(scanner.run_all_enabled)
    return RedirectResponse("/", status_code=303)


@app.post("/systems/{system_id}/command")
def enqueue_command(
    system_id: int,
    cmd_type: str = Form("rescan"),
    minutes: int = Form(0),
    ports: str = Form(""),
    targets: str = Form(""),
    session: Session = Depends(get_session),
    _: None = Depends(verify_csrf),
):
    """Queue a control command; a push-mode client picks it up on its next POST.

    Supports set_interval (polling frequency) and set_config (hand the agent a
    port-scan preset/list and/or the subnets/targets to scan — central config,
    delivered to the agent; not a secret).
    """
    payload = None
    if cmd_type == "set_interval":
        payload = {"minutes": minutes}
    elif cmd_type == "set_config":
        cfg: dict = {}
        if ports:
            # ports may be a preset name ("top100") or a comma list of ints.
            if "," in ports or ports.strip().isdigit():
                cfg["ports"] = [int(p) for p in ports.replace(" ", "").split(",")
                                if p.strip().isdigit()]
            else:
                cfg["ports"] = ports.strip()
        if targets:
            # comma/space/newline separated CIDRs or hosts.
            cfg["targets"] = [t.strip() for t in re.split(r"[,\s]+", targets) if t.strip()]
        if cfg:
            payload = {"config": cfg}
            # Persist centrally so the server is the source of truth for this
            # system's scan config (shown in the UI, re-delivered on re-enroll).
            # Merge into the stored config; not a secret, stored in clear.
            system = session.get(System, system_id)
            if system is not None:
                merged = dict(system.collector_config or {})
                merged.update(cfg)
                system.collector_config = merged
                session.add(system)
                session.commit()
    scanner.enqueue_command(system_id, cmd_type, payload)
    return RedirectResponse(f"/systems/{system_id}", status_code=303)


# ---- read-only JSON API --------------------------------------------------

@app.get("/api/systems")
def api_systems(session: Session = Depends(get_session)):
    systems = session.exec(select(System)).all()
    out = []
    for s in systems:
        last = scanner.latest_scan(session, s.id) if s.id else None
        out.append(
            {
                "id": s.id,
                "name": s.name,
                "kind": s.kind.value,
                "hostname": s.hostname,
                "collector": s.collector,
                "last_scan": last.started_at.isoformat() if last else None,
                "vulnerabilities": len(_severity_counts(session, last.id)) if last else 0,
            }
        )
    return JSONResponse(out)


@app.get("/api/systems/{system_id}")
def api_system(system_id: int, session: Session = Depends(get_session)):
    system = session.get(System, system_id)
    if system is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    last = scanner.latest_scan(session, system_id)
    packages = (
        session.exec(select(Package).where(Package.scan_id == last.id)).all() if last else []
    )
    vulns = (
        session.exec(select(Vulnerability).where(Vulnerability.scan_id == last.id)).all()
        if last
        else []
    )
    return JSONResponse(
        {
            "system": {
                "id": system.id,
                "name": system.name,
                "kind": system.kind.value,
                "hostname": system.hostname,
                "web_url": system.web_url,
                "access_notes": system.access_notes,
                "collector": system.collector,
            },
            "last_scan": (
                {
                    "id": last.id,
                    "started_at": last.started_at.isoformat(),
                    "status": last.status.value,
                    "summary": last.summary,
                }
                if last
                else None
            ),
            "packages": [
                {"name": p.name, "version": p.version, "type": p.type, "source": p.source}
                for p in packages
            ],
            "vulnerabilities": [
                {
                    "cve": v.cve_id,
                    "severity": v.severity.value,
                    "package": v.package_name,
                    "installed": v.installed_version,
                    "fixed": v.fixed_version,
                }
                for v in vulns
            ],
        }
    )
