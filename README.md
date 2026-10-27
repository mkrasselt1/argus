# Argus

Ein **read-only Security- & Asset-Management-Dashboard** für selbst gehostete
Systeme (Linux, Windows, Synology NAS, Router, Docker-Hosts …).

Das Tool **steuert nichts** auf den überwachten Systemen – es liest nur aus und
dokumentiert:

- **Welche Systeme** existieren und **wie du sie erreichst** (Host, Web-UI, Zugangsnotizen).
- **Welche Software/Versionen/Dienste** laufen (Windows, Linux, Docker) – inkl.
  verfügbarer Updates und **Betriebssystem-End-of-Life**.
- **Bestandteile von Docker-Containern** (SBOM: OS-Pakete + App-Dependencies) und **CVEs**.
- **Geräte im Netzwerk** (auch portlose IoT/ESP32 via ARP) inkl. Shelly/Tasmota/…-
  Firmware – als eigene, gruppierbare Systeme.
- **Verlauf/Diff** aller Scans, **Update-Snooze**, Login, und **Push-Agenten** mit
  **Zero-Knowledge-Zugangsdaten** (der Server kennt Modul-Secrets nie im Klartext).

## Architektur

```
Argus-Server (FastAPI + SQLModel/SQLite, Web-UI mit Login + JSON-API)
  ├─ Scanner-Service → Collector (pro System, nur lesend):
  │     windows  installierte Programme/Dienste/Updates + Windows-/OS-EOL
  │     ssh_linux Pakete & OS über SSH (+ Jump-Host, + Distro-EOL)
  │     docker    Container/Images → SBOM + CVEs (trivy/syft/metadata)
  │     network_discovery  TCP-Sweep + ARP + Geräte-Module (Shelly, Tasmota, …)
  │     relay     Scan über einen Edge-Agenten im Zielnetz ausführen lassen
  │     manual    von Hand gepflegte Systeme
  ├─ Push/Ingest  Agenten pushen (Client→Server); Command-Channel in der Antwort
  ├─ Enrollment   Join-Token, Pro-Client-Secret, Freigeben/Sperren, Install-Skripte
  ├─ Credentials  Zero-Knowledge (auf Agent-Key versiegelt, Server kann nicht lesen)
  ├─ SystemSummary  denormalisierter Rollup → schnelles Dashboard bei vielen Geräten
  └─ Scheduler    periodischer Scan + tägliches Scan-Pruning (Retention)

Agent (pip-Paket vom Server):  argus-agent join | run | set-cred
```

- Neue Systemtypen = ein Collector in [`app/collectors/`](app/collectors/)
  (`register()` → `CollectResult`).
- Neue Gerätetypen = ein Modul in `app/collectors/network_discovery.py`
  (`DEVICE_MODULES`), read-only, server-aktivierbar.

Vertiefung: [ARCHITECTURE.md](ARCHITECTURE.md) (Produktiv/Skalierung/Krypto),
[ROADMAP.md](ROADMAP.md). **Wartung:** siehe [CLAUDE.md](CLAUDE.md) (README nach
Features aktualisieren; Breaking-Changes für Agenten im Commit markieren).

## Docker-Analyse (neue Anforderung)

Der `docker`-Collector verbindet sich **read-only** mit einem Docker-Daemon
(lokaler Socket oder remote via `ssh://`/`tcp://`) und zerlegt Container/Images:

| Vorhanden auf dem Host | Ergebnis |
|---|---|
| `trivy` | volle SBOM **und** CVEs *(empfohlen, im Image enthalten)* |
| `syft` | volle SBOM (ohne CVEs) |
| keins | Metadaten-Ebene: Tags, Digest, Größe, Layer, Entrypoint, Ports, Env-Keys, Labels |

Collector-Konfig (JSON):
```json
{ "base_url": "ssh://user@dockerhost", "targets": "running" }
```
`targets`: `"running"` (Standard), `"all"`, oder Liste konkreter Image-Refs.

## Entfernte Netze erreichen (Gateway / Relay)

Oft kommt das Dashboard von außen **nicht** an die Zielgeräte – aber an **einen**
Edge-Knoten (z.B. einen Kundenproduktionsserver per VPN), der die restlichen
Geräte im internen Netz sieht. Dafür gibt es zwei Wege:

**1. Relay-Agent (empfangen & weitergeben, verkettbar)**

Auf dem Edge-Knoten läuft Argus im *Agent-Modus* (nur ein gesetztes
`SECSCAN_AGENT_TOKEN`). Er nimmt token-geschützte Collect-Aufträge entgegen,
führt den Collector **lokal im Zielnetz** aus und gibt das Ergebnis zurück:

```
Dashboard --relay--> Edge-Agent --(docker/ssh_linux)--> internes Gerät
Dashboard --relay--> Edge-Agent --relay--> tieferer Jump --ssh_linux--> Gerät
```

System im Dashboard mit Collector `relay`:
```json
{
  "agent_url": "https://edge.kunde-a:8080",
  "token": "<SECSCAN_AGENT_TOKEN des Edge-Knotens>",
  "collector": "docker",
  "config": { "targets": "all" },
  "label": "Kunde-A Prod"
}
```
Der `relay`-Endpoint (`POST /agent/collect`) ist read-only und nur aktiv, wenn
ein Token gesetzt ist; ohne gültiges Token → 401, ohne Token-Config → 404.

**2. SSH-Jump (agentenlos)**

Ist auf dem Gateway kein Agent installiert, tunnelt `ssh_linux` über einen
Jump-Host (mehrstufig möglich):
```json
{ "host": "10.0.0.5", "username": "admin", "key_filename": "/data/keys/id",
  "via": { "host": "edge.kunde-a", "username": "ops", "key_filename": "/data/keys/edge" } }
```

## Datenfluss: Pull vs. Push

Argus unterstützt beide Richtungen — **Push ist der sichere Standard**:

**Push (Client → Server, empfohlen):** Der Client läuft auf dem Zielsystem,
scannt sich selbst **read-only** und schickt das Ergebnis per **ausgehendem
HTTPS-POST** an `/ingest`. Der Server braucht **keinen Weg zum Client** — es
bleibt kein Port/Pfad zum Client offen. Steuerbefehle (z.B. „jetzt neu scannen",
Intervall ändern) gibt der Server in der **Antwort auf den Push** zurück; der
Client führt sie beim nächsten Poll aus. Stündlich reicht.

```bash
# auf dem Zielsystem:
python -m app.push --server https://argus.example.com --token <INGEST_TOKEN> \
    --system "Dieser PC" --kind windows --collector windows --interval 60
```
Server-seitig aktivieren: `SECSCAN_INGEST_TOKEN=<geheim>` setzen.

**Pull/Relay (Server → Agent):** Der Server ruft einen Edge-Agenten
(`/agent/collect`), der tiefer ins Netz reicht. Gut für isolierte Kundennetze,
die der Server nur über **einen** erreichbaren Knoten sieht. Siehe oben
„Entfernte Netze erreichen".

## Push-Agenten & Enrollment

Agenten werden mit **einem Befehl** eingerichtet. Im Dashboard unter
**Agenten → Join-Token erzeugen** gibt es den fertigen Ein-Zeilen-Installer:

```bash
# Linux/NAS/Pi:
curl -fsSL https://argus.example/install.sh | sh -s -- --join <join-token>
# Windows (als Admin):
iwr -useb https://argus.example/install.ps1 | iex; Install-ArgusAgent -Join '<join-token>'
```

Der Installer holt den Agenten als pip-Paket vom Server (`/dist/argus-agent.tar.gz`,
immer passend zur Server-Version), meldet ihn an und registriert einen Dienst.

**Agent aktualisieren** (Anmeldung bleibt erhalten, kein neuer Agenten-Eintrag) —
nach jedem Server-Update, wenn der Agent „Agent-Update verfügbar“ loggt:

```bash
# Linux: Installer ohne --join (pip-Upgrade + Dienst-Neustart)
curl -fsSL https://argus.example/install.sh | sh
# Windows (als Admin):
iwr -useb https://argus.example/install.ps1 | iex; Update-ArgusAgent
```

Alle Update-/Diagnose-Befehle stehen fertig zum Kopieren im Dashboard unter
**Agenten → Agenten aktualisieren & prüfen**. Die Agenten-Liste zeigt je Agent die
gemeldete **Version** und markiert veraltete mit „Update“ (Agenten melden ihre
Version ab 1.1.10 beim Push mit).

`Update-ArgusAgent` nutzt das vorhandene venv (braucht also kein Python im PATH).
Nur ein Neu-Aufbau sucht ein System-Python: PATH → `py`-Launcher →
`C:\Program Files\Python3*`. Gezielt wählen bzw. venv mit anderem Python neu bauen:
`Update-ArgusAgent -Python "C:\Program Files\Python314\python.exe"`.

Ein erneutes Ausführen **mit** Join-Token meldet den Agenten neu an — das legt einen
**neuen** Eintrag an, der ggf. erst freigegeben werden muss (bis dahin 403 auf
`/ingest`).

**Agenten löschen:** Dashboard → Agenten → *Löschen*. Entfernt den Agenten-Eintrag
(seine Zugangsdaten werden ungültig) und die an seinen Schlüssel versiegelten
Credentials; das System und seine Scans bleiben erhalten. *Sperren* blockiert nur.

**Scheduling (selbstheilend):**
- **Linux (systemd):** Dauer-Loop `argus-agent run` mit `Restart=always` — stirbt
  der Prozess, startet systemd ihn neu.
- **Windows (Scheduled Task):** Herzschlag-Modell. Der Task feuert alle **15 min**
  (plus bei Systemstart) `argus-agent run --once`; der **Agent selbst** prüft, ob
  sein (zentral setzbares) Intervall abgelaufen ist — sonst beendet er sich ohne
  Push. Mit *StartWhenAvailable* (holt nach Standby/Ruhezustand nach) und Neustart
  bei Fehler. So lebt die Taktung in der Agent-Config statt in der Task-Definition,
  und der Agent ist gegen Absturz/Standby/Reboot selbstheilend. Der Task läuft als
  SYSTEM und bekommt den Config-Pfad direkt per `run --once --config <pfad>`
  übergeben (robust, unabhängig von Umgebungsvariablen-Propagation).
  Fälligkeit wird ab *Start* des letzten Pushs gemessen, mit halbem Herzschlag
  (7,5 min) Toleranz — sonst driftet ein 60-min-Intervall durch die Sammeldauer
  auf 75 min. Der Startup-Trigger wartet 2 min aufs Netz.
  - **Log:** `%ProgramData%\argus-agent\agent.log` (rotierend, auch bei
    Linux-Agenten neben der `agent.json`) — der SYSTEM-Task hat keine Konsole.
  - **Installer** bricht bei Fehlern ab (kein Python / Microsoft-Store-Python,
    `pip install` oder `join` fehlgeschlagen, exe fehlt), statt einen Task auf eine
    nicht vorhandene exe zu registrieren (Ereignis „Fehlerwert 2147942402“ =
    0x80070002 = Datei nicht gefunden). Während der Neuinstallation ist der Task
    deaktiviert; danach prüft der Installer den ersten Lauf als SYSTEM.
  - **Diagnose:** `iwr -useb https://argus.example/install.ps1 | iex; Test-ArgusAgent`
    zeigt Task-Aktion (exe vorhanden?), letztes Ergebnis und Log-Ende.
  - `agent.json` wird atomar geschrieben (Abbruch mitten im Lauf zerstört die
    Anmeldung nicht). Python am besten „für alle Benutzer“ installieren.
  - **403 auf `/ingest`** = Agent nicht freigegeben/gesperrt (Dashboard → Agenten);
    der Agent loggt den Grund.
  - Ein Agent ist nach dem ersten Push fest an **sein** System gebunden; spätere
    Pushes landen immer dort, egal welchen Namen die `agent.json` mitschickt. Ein
    Umbenennen des Systems im Dashboard sperrt den Agenten daher nicht mehr aus.
  - Systeme, die ein Agent pusht, scannt der Server **nicht** selbst (geplanter
    Scan überspringt sie); „Scan“ im Dashboard schickt stattdessen einen
    `rescan`-Befehl, den der Agent beim nächsten Herzschlag (≤ 15 min) ausführt
    (nicht fällige Herzschläge fragen dafür kurz `POST /agent/poll`).
  - Den Task im Aufgabenplaner manuell starten pusht nur, wenn das Intervall um ist.
    **Sofort pushen:** `argus-agent.exe run --once --force --config <agent.json>`
    (fertig zum Kopieren im Dashboard unter Agenten).
**Netzwerk-Scan vor Ort:** Jeder Agent kann zusätzlich sein lokales Netz scannen.
Sobald auf der System-Seite **Subnetze** gesetzt sind (z. B. `192.168.178.0/24`),
führt auch ein Host-Agent (z. B. `windows`) nach seinem Inventar den
`network_discovery`-Sweep aus und schickt beides in **einem** Push; gefundene
Geräte erscheinen wie gewohnt. Ein fehlschlagender Sweep kostet das Host-Inventar
nicht (Status in der Scan-Zusammenfassung unter `net_scan`).

Der Server kann über die Poll-Antwort steuern (rescan, Intervall, Portliste,
zu scannende **Subnetze/Hosts** (`targets`, zentral auf der System-Seite setzbar),
Collector-Config) und meldet Agent-Updates. Die zentral gesetzte Config wird im
Server gespeichert (kein Geheimnis) und beim nächsten Poll an den Agenten
ausgeliefert. Agenten sind einzeln **freigeb-/
sperrbar**; jeder hat ein eigenes, widerrufbares Secret.

## Geräte-Module & entdeckte Geräte

Der `network_discovery`-Collector findet per **TCP-Sweep + ARP** auch portlose
Geräte und identifiziert sie über **read-only Module** (server-aktivierbar via
`config["modules"]`): `shelly`, `tasmota`, `toshiba`, `homeassistant`,
`octoprint`, `smartwb`, `warp`, `dahua`, `supermicro`, `tplink` — inkl. Firmware
und (wo das Gerät es gecacht meldet) „Update verfügbar".

**Identifizierte Geräte werden eigene Systeme** (Wiedererkennung per MAC, Gruppe =
Agent, „Entdeckt über …"), benannt nach ihrem Geräte-Namen, mit eigener
Firmware-/Versions-Historie. Sie **erben die Tags des Agenten** (Kunde/Standort).

## Modul-Zugangsdaten (Zero-Knowledge)

Für Module hinter Login (HA, OctoPrint …): Secrets werden **auf den
öffentlichen Schlüssel des Ziel-Agenten verschlüsselt** — der **Server kann sie
nie lesen**. Nur der Agent öffnet sie zur Laufzeit im RAM (sein privater Key ist
passphrase-geschützt; die Passphrase liefert der Server erst zur Laufzeit —
Split-Knowledge). Zwei Eingabewege (beide zero-knowledge):

- **vor Ort:** `argus-agent set-cred --module homeassistant --secret <TOKEN>`
- **zentral im Browser:** Formular auf der Agenten-Seite (verschlüsselt per
  WebCrypto/@noble im Browser, sendet nur den Blob).

Details/Bedrohungsmodell: [ARCHITECTURE.md](ARCHITECTURE.md).

## Login / Konfiguration

Setze `SECSCAN_ADMIN_PASSWORD`, dann verlangt die Web-UI ein Login
(`ingest`/`enroll`/`agent` bleiben token-geschützt). Wichtigste Env-Variablen:

| Variable | Zweck |
|---|---|
| `SECSCAN_ADMIN_PASSWORD` | UI-Login aktivieren |
| `SECSCAN_ALLOW_NO_AUTH` | Nur-Opt-out: offene UI ohne Passwort auf Nicht-Loopback-Host erlauben (gefährlich) |
| `SECSCAN_SECRET_KEY` | Session-Cookie-Secret |
| `SECSCAN_SECURE_COOKIES` | Session-Cookie als `Secure` markieren (Standard 1; nur für lokales HTTP auf 0) |
| `SECSCAN_INGEST_TOKEN` | Shared-Token für Push (optional, pro-Client-Auth bevorzugt) |
| `SECSCAN_CRYPTO_KEY` | Fernet-Key für serverseitige Verschlüsselung (sonst abgeleitet; Warnung im Log) |
| `SECSCAN_AGENT_TOKEN` | Agent/Relay-Modus aktivieren (`/agent/collect`) |
| `SECSCAN_AGENT_ALLOWED_COLLECTORS` | Erlaubte Collectors für `/agent/collect` (Default ohne `relay`) |
| `SECSCAN_PUBLIC_URL` | Öffentliche Basis-URL für Install-Skripte/Join-Token (statt Host-Header) |
| `SECSCAN_SCAN_INTERVAL_MINUTES` | periodischer Komplett-Scan (0 = aus) |
| `SECSCAN_SCAN_RETENTION` | Scans pro System behalten (0 = unbegrenzt) |
| `SECSCAN_DATABASE_URL` | DB (Standard SQLite; Postgres für Produktiv) |
| `SECSCAN_RELOAD` | Dev: Auto-Reload bei Code-Änderung |

### Härtung & Sicherheitsverhalten

- **Start-Schutz:** Ohne `SECSCAN_ADMIN_PASSWORD` **und** Bind auf einen
  Nicht-Loopback-Host (Default `0.0.0.0`) **startet der Server nicht** — er würde
  sonst eine offene Admin-UI ins Netz stellen. Abhilfe: Passwort setzen,
  `SECSCAN_HOST=127.0.0.1`, oder bewusst `SECSCAN_ALLOW_NO_AUTH=1`.
- **CSRF:** Alle zustandsändernden UI-Formulare tragen ein Per-Session-CSRF-Token
  (verstecktes Feld, serverseitig geprüft). Maschinen-Endpunkte (`/ingest`,
  `/enroll`, `/agent/collect`, `/credentials/upload`) nutzen Token-/Client-Auth
  statt Cookies und sind ausgenommen. Session-Cookie: `Secure` + `SameSite=Lax`,
  global `Referrer-Policy: no-referrer`. `POST /logout`.
- **Agent↔System-Bindung:** Ein pro-Client-authentifizierter Agent wird beim
  ersten Push fest an **ein** System gebunden; spätere Pushes auf ein anderes
  System werden mit **403** abgelehnt (kein Fremd-Auto-Register).
- **TLS-Pinning (Agent):** Trägt der Join-Token einen `fingerprint` (sha256:…),
  pinnt der Agent das Server-Leaf-Zertifikat bei **jedem** Join und Push.
- **Secrets at rest:** Geheime Felder der `collector_config` (`password`, `token`,
  `secret`, …) werden verschlüsselt gespeichert und nur im RAM kurz vor dem
  Collector-Lauf entschlüsselt.
- **SSH:** Host-Key wird standardmäßig **verifiziert** (RejectPolicy); `"host_key_policy":"auto"`
  (+ optional `"known_hosts"`) ist bewusster Opt-out.
- **Rate-Limiting:** `/login` (10/5 min + Lockout) und `/enroll` (20/min) pro IP;
  `/ingest` begrenzt Paket-/Vuln-Anzahl und Body-Größe.
- **`/data` just works:** Der Container-Entrypoint legt `/data` an und übernimmt
  die Rechte für den `argus`-Nutzer, bevor er die Privilegien ablegt — ein
  Host-Bind-Mount mit beliebigem Owner (z.B. in Plesk) führt nicht mehr zu
  `sqlite3.OperationalError: unable to open database file`.

## Lokal starten

```bash
pip install -e .
python -m app            # Server starten (http://localhost:8080)
SECSCAN_RELOAD=1 python -m app   # Dev: lädt sich bei Code-Änderungen selbst neu
```

Hinweis: Immer nur **eine** Instanz pro Port. Mit `SECSCAN_RELOAD=1` reicht ein
einziger Start — Änderungen am Quellcode übernimmt der Server automatisch.

## Als Container deployen (version-sicher)

```bash
APP_VERSION=$(git rev-parse --short HEAD) docker compose up -d --build
```

- DB liegt im Volume `secscan-data` → übersteht Redeploys.
- Der rohe Docker-Socket wird **standardmäßig NICHT** eingehängt (in
  `docker-compose.yml` auskommentiert). Ein `/var/run/docker.sock`-Mount gibt dem
  Container faktisch **Root auf dem Host** (auch `:ro`). Der `docker`-Collector
  gehört auf einen **dedizierten Edge-Agenten** neben den Docker-Host oder hinter
  einen **read-only docker-socket-proxy** — nicht auf den zentralen Server.
- `SCHEMA_REVISION` (in [`app/__init__.py`](app/__init__.py)) + `schema_meta`-Tabelle
  verhindern, dass ein älteres Image gegen eine neuere DB startet.

## Edge-Agent deployen

Dasselbe Image, nur als Agent konfiguriert (Scheduler aus, Token gesetzt). Auf
dem Kundenserver:

```yaml
services:
  secscan-agent:
    image: argus:${APP_VERSION:-dev}
    restart: unless-stopped
    ports: ["8080:8080"]
    environment:
      SECSCAN_AGENT_TOKEN: "<starkes-geheimnis>"
      SECSCAN_SCAN_INTERVAL_MINUTES: "0"   # Agent scannt nur auf Anfrage
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
```
TLS/Transport über den bestehenden VPN-Tunnel oder einen Reverse-Proxy
absichern; das Token niemals ins Image backen.

## Image veröffentlichen (Docker Hub / GHCR)

**Manuell** (Multi-Arch für amd64 + ARM/Pi):
```bash
docker login
docker buildx build --platform linux/amd64,linux/arm64 \
  -t <user>/argus:v1 -t <user>/argus:latest --build-arg APP_VERSION=v1 --push .
```

**Automatisch per CI**: [.github/workflows/docker-publish.yml](.github/workflows/docker-publish.yml)
baut und pusht **nur** bei einem Git-Tag `v*` — ein Build je Release setzt
`vX.Y.Z`, `vX.Y` und `latest` (amd64 + arm64). Pushes auf `main` ohne Tag bauen
nicht, `latest` ist also immer ein echtes Release. Ein Release neu bauen: Actions →
*Run workflow* → bei „Use workflow from“ den Tag wählen. Repo-Secrets setzen:
`DOCKERHUB_USERNAME` und `DOCKERHUB_TOKEN`. (GHCR-Variante ist im Workflow auskommentiert.)

## Deployment in Plesk (Docker-Erweiterung)

Plesks Docker läuft **image-basiert** — ein veröffentlichtes Image ist hier der
einfachste Weg:

1. Plesk → **Docker** → Image `<user>/argus:latest` suchen und **Run**.
2. **Umgebungsvariablen** setzen: `SECSCAN_ADMIN_PASSWORD`, `SECSCAN_SECRET_KEY`,
   `SECSCAN_INGEST_TOKEN`, optional `SECSCAN_CRYPTO_KEY`.
3. **Volume** mappen: Host-Verzeichnis → `/data` (Persistenz).
4. **Port** mappen (z.B. 8080) oder direkt eine **Domain** zuweisen —
   Plesk setzt dann den Reverse-Proxy **inkl. Let's-Encrypt-TLS** davor (löst die
   HTTPS-Anforderung elegant).

Hinweis: Der Docker-Socket-Mount (für den `docker`-Collector) wird auf dem
**zentralen Server meist nicht gebraucht** — Container-Scans laufen auf den
Agenten/Edge-Knoten. Der Plesk-Server braucht also nur Volume + Port/Domain + Env.

## Container-Upgrade

Container werden nicht im Betrieb aktualisiert, sondern durch einen aus einem
neuen Image **ersetzt** — die Daten bleiben im Volume erhalten:

```bash
git pull
APP_VERSION=$(git rev-parse --short HEAD) docker compose up -d --build
```

- Das Volume `secscan-data` überlebt den Containertausch (DB bleibt).
- Beim Start **migriert die App die DB automatisch** (neue Tabellen/Spalten),
  der `SCHEMA_REVISION`-Guard verhindert ein zu altes Image gegen eine neuere DB.
- Rollback: altes Image-Tag wieder starten (nur solange die Schema-Revision passt).

## Tests

```bash
pip install -e ".[dev]"
pytest -q
```

## Sicherheitsprinzipien

- Keine schreibenden Aktionen auf Zielsystemen – Collectors führen nur
  Lese-/Inventar-Kommandos aus.
- Container läuft `read_only` mit `no-new-privileges`.
- Zugangsdaten gehören in die `collector_config` bzw. gemountete Key-Dateien,
  nicht ins Image.
