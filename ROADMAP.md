# Argus — Roadmap / TODO

Stand: 2026-10-22. Geordnet nach Thema, nicht strikt nach Priorität.

## Offene konkrete Features (nahe)

- [ ] **Auth** vor der Web-UI (Login/Session), bevor es produktiv läuft.
- [ ] **Synology-Collector** (DSM-API, read-only: DSM-Version, Pakete, Updates).
- [ ] **Agent-Code-Auslieferung**: Server stellt neue Agent-Version bereit
      (Bundle/pip/git), damit `--update-mode auto` echten Code ziehen kann.
      Version-Check (Server meldet `server_version`) + Modus manual/auto ist da.
- [ ] **Globale Netzwerk-Ansicht**: über alle Agenten entdeckte Geräte
      aggregiert (aktuell pro System-Seite unter „Im Netzwerk gefunden").
- [ ] Port-Set konfigurierbar pro Scan ist vorhanden (`ports`-Liste); optional
      Presets (Top-100 / Full-Range) anbieten.

## Plattformen

- [ ] **Android**: Geräte-Inventar (installierte Apps + Versionen, Patch-Level,
      Android-Version/EOL). Optionen prüfen: ADB über USB/WLAN (read-only
      `pm list packages -3`, `dumpsys`), oder ein companion-App-Push an /ingest.
- [ ] **macOS-Collector** (optional): `system_profiler`, Homebrew-Outdated, OS-EOL.

## Optionale Agent-Module (server-aktivierbar)

**Umgesetzt (erste Version):** Modul-Registry im `network_discovery`-Collector.
Jedes Modul ist ein read-only `DeviceInfo`-Abfrager (Produkt, Version + `details`-
Dict: Modell, Zustand, MAC, Uptime …) mit Metadaten (typische Ports, needs_auth).
Der Server aktiviert pro Agent eine Teilmenge via `config["modules"]` (Standard:
alle) — gesetzt beim Anlegen/Bearbeiten oder live per `set_config`-Command.
Vorhandene Module: `shelly` (Gen1/Gen2), `tasmota`, `toshiba` (Drucker),
`homeassistant`, `octoprint`, `smartwb`, `warp` (Wallbox).

Offen:
- [ ] Mehr Module: `immich` (`/server-info/version`), `proxmox` (pve API),
      `printer_snmp`/`printer_ipp`, Router-APIs (Fritzbox TR-064), `jellyfin`/`plex`.
- [ ] Module, die **Credentials** brauchen (HA-Token, OctoPrint-API-Key), über die
      Envelope-Verschlüsselung versorgen (siehe unten) — dann auch Version/Details
      hinter Auth lesbar.
- [ ] Modul-Metadaten in der UI anzeigen + pro Agent an-/abhaken (statt JSON).

## Client/Server-Authentifizierung & Enrollment (Sicherheitskern)

Heute: **ein** gemeinsames `SECSCAN_INGEST_TOKEN` für alle Push-Clients. Schwächen:
ein geleaktes Token kompromittiert alle; kein Freigeben/Sperren einzelner Clients;
der Client prüft die Server-Identität nicht. Ziel: **gegenseitige** Authentifizierung
mit Anlern-Flow — „neuen Client am Server anlernen" und „Server-Signatur im Client
hinterlegen".

Design (geplant):
- [ ] **Pro-Client-Credentials via Enrollment**: neuer `Client`-Datensatz
      (client_id, token_hash, system_name, status pending|approved|revoked,
      created_at, last_seen). Endpoint `POST /enroll` nimmt ein kurzlebiges
      Enrollment-Token + gewünschten Systemnamen (+ optional Client-Public-Key)
      und legt den Client **pending** an, gibt client_id + client_secret **einmalig** zurück.
- [ ] **Admin-Freigabe in der UI**: Liste anstehender Clients, „freigeben"/„sperren".
      Bis freigegeben werden Pushes abgelehnt (oder nur gepuffert).
- [ ] **/ingest** akzeptiert Pro-Client-Auth (`X-Client-Id` + `X-Client-Token`),
      prüft status=approved; `revoked` ⇒ sofort abgelehnt. Shared-Token bleibt für
      einfache Setups optional.
- [ ] **Server-Identität pinnen**: Server veröffentlicht TLS-Cert-/Signatur-Fingerprint;
      Client speichert erwarteten Fingerprint (`--server-fingerprint`) und verifiziert
      ihn bei jeder Verbindung (TOFU oder vorab verteilt) ⇒ schützt vor Rogue-/MitM-Server.
- [ ] Alternativ echte mTLS: Server-CA signiert Client-Zertifikate beim Enrollment;
      beide prüfen Zertifikate. (Mehr Aufwand, höchste Sicherheit.)
- [ ] Transport generell HTTPS; Enrollment-Token und client_secret nie ins Image.

## Zugangsdaten / Envelope-Verschlüsselung (Sicherheitskern)

Zugangsdaten für die optionalen Module liegen **verschlüsselt auf dem Client**
(at rest) und sind dort allein **nutzlos** — der Entschlüsselungs-Schlüssel wird
**nur vom Server** in dessen Poll-Antwort mitgeliefert, wenn ein Modul laufen
soll. So steht auf dem Client nie ein brauchbares Klartext-Geheimnis.

Design-Skizze:
- [ ] Client speichert Secrets als `enc(secret, data_key)`; `data_key` kennt nur
      der Server. Server liefert `data_key` (oder entsiegelt pro Lauf) über die
      Command-Antwort, zeitlich begrenzt, nur im RAM des Clients.
- [ ] Alternativ asymmetrisch: Client hält Public-Key-verschlüsselte Secrets,
      Server hält Private-Key und liefert pro Lauf ein entschlüsseltes
      Einmal-Token / den benötigten Key.
- [ ] Transport weiterhin strikt **Client→Server (Push)**; der Key reist nur in
      der Antwort auf einen Client-initiierten Request. Kein Inbound zum Client.
- [ ] Audit: jede Key-Auslieferung protokollieren (wann, welches Modul, welches
      System).

## Erledigt (zur Orientierung)

- [x] Collectors: docker (SBOM+CVE via trivy/syft), ssh_linux (+Jump, +OS-EOL),
      windows (Programme/MSI, winget+choco, Dienste, Windows-Update, OS-EOL),
      network_discovery (Multi-Subnetz), manual, relay (Pull über Edge-Agent).
- [x] Push/Ingest-Modell (Client→Server) + Command-Channel über Poll-Antwort.
- [x] OS-End-of-Life-Erkennung (Windows + Linux) via endoflife.date.
- [x] Update-Befehl pro Programm (winget/choco), Major/Minor-Klassifizierung.
- [x] Auto-Reload des Servers bei Code-Änderungen (SECSCAN_RELOAD=1).
- [x] Revisionssichere Scan-Historie, Schema-Versionsschutz.
- [x] Komponenten-Tabelle: Filtern/Sortieren/Ausblenden (localStorage pro System).
- [x] Änderungs-/Update-Historie (`ComponentChange`, erkennt „Update durchgeführt").
- [x] Systeme: Gruppen, Tags, Umbenennen/Bearbeiten/Löschen, IP-Anzeige.
- [x] „Im Netzwerk gefunden"-Ansicht pro Discovery-Agent (Geräte + Dienste).
- [x] Poll-Intervall per Server-Befehl steuerbar (set_interval, z.B. beim Debuggen).
- [x] Agent-Selbst-Update-Check (Server meldet Version; Modus manual[default]/auto).
