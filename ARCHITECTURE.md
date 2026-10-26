# Argus — Architektur-Neubewertung (Produktiv, Multi-Netzwerk, ~hunderte Geräte)

Stand: 2026-10-23. Bewertung für den Produktiv-Einsatz als zentrale Plattform,
die mehrere Netzwerke/Kunden mit mehreren hundert Geräten überwacht.

## 1. Topologie

```
                 (HTTPS, nur ausgehend vom Client)
Agenten  ──push──►  Argus-Server (zentral, hinter Reverse-Proxy/TLS)
  │                      │
  ├─ pro Kunde/Standort  ├─ DB (Scans, Geräte, Clients, Credentials[Chiffre])
  │  1 Scan-Agent (/24)  ├─ UI (Auth) + JSON-API
  └─ pro Host 1 Agent    └─ Scheduler (Retention/Prune)
```

- **Client-initiiert (Push)**: kein offener Port zu Agenten. Firewall-freundlich,
  NAT-tauglich, sicher. Bleibt so.
- **Server zentral** deployen (Docker hinter Caddy/Traefik/nginx mit TLS).
- **1 Scan-Agent je L2-Netz** (ARP ist L2-lokal) + Host-Agenten für Windows/Linux.

## 2. Credential-Sicherheit (zero-knowledge, asymmetrisch)

Ziel: Der **Server kennt die Modul-Zugangsdaten nie im Klartext**; Mandanten
sind kryptografisch getrennt; eine gestohlene Agent-Platte ist nutzlos.

**Schlüssel-Modell (Split-Knowledge):**
1. Beim Enrollment erzeugt der Agent ein **Schlüsselpaar** (X25519).
   Der **private Key verlässt den Agenten nie**.
2. Der private Key wird **mit einer Passphrase verschlüsselt** at-rest gespeichert
   (scrypt → AES-GCM). Die **Passphrase hält nur der Server** (pro Client).
3. Credentials werden **auf den Public Key des Agenten** verschlüsselt
   (sealed box). Gespeichert als **Chiffretext** — am Server (zentral) und/oder
   lokal am Agenten. Der Server kann sie **nicht** entschlüsseln.
4. **Zur Laufzeit**: der authentifizierte Agent erhält in der Push-Antwort
   (a) seine **Passphrase** und (b) die **Credential-Chiffretexte**.
   Er entschlüsselt den privaten Key im **RAM**, damit die Credentials, nutzt
   sie für den Scan — und verwirft sie. Nichts Brauchbares bleibt auf Platte.

**Bedrohungen:**
- Gestohlene Agent-Platte: verschl. privater Key, **keine Passphrase** → nutzlos.
- Kompromittierter Server: Passphrase + Chiffre, **kein privater Key** → nutzlos.
- Kompromittierter Agent (laufend): nur **seine eigenen** (= seines Mandanten)
  Credentials; andere Agenten sind durch deren eigene Keys getrennt.
- Enrollment-MITM: durch **Server-Fingerprint-Pinning** im Join-Token abgesichert.

**Eingabe der Credentials (beide zero-knowledge):**
- **Vor Ort (CLI)**: `argus-agent set-cred --module homeassistant --secret …`
  verschlüsselt lokal auf den eigenen Public Key; Chiffre optional zum Server
  synchronisiert (nur Inventar/Backup, unlesbar).
- **Zentral (Browser, E2E)**: Browser holt den Public Key des Ziel-Agenten,
  verschlüsselt per WebCrypto, sendet nur Chiffre. Server bleibt zero-knowledge.

**Migration:** das aktuelle symmetrische v1 (Server kennt Klartext) wird durch
dieses Modell ersetzt; bestehende Credentials einmalig neu erfassen.

**Caveats / Grenzen des Bedrohungsmodells (ehrlich benannt):**
- Die Zusage „der Server sieht den Klartext nie" gilt gegen einen
  **honest-but-curious** Server und **Platten-Diebstahl** — **nicht** gegen einen
  **bösartigen Server**, der die an den Agenten gelieferten Kommandos/Module
  kontrolliert: er könnte einen Agenten dazu bringen, ein Secret zu öffnen und
  das Ergebnis zweckzuentfremden. Fingerprint-Pinning sichert nur die
  Server-*Identität*, nicht dessen Gutartigkeit. Server-Integrität (Zugriff,
  Image, Reverse-Proxy) bleibt also sicherheitsrelevant.
- `Client.key_passphrase` wird **per Design im Klartext** in der Server-DB
  gehalten (Split-Knowledge: Passphrase am Server, verschlüsselter Private Key am
  Agenten). Wer die Server-DB **und** die Agent-Platte erbeutet, kann Credentials
  öffnen; einer allein genügt nicht.
- Secret-Felder der `collector_config` werden at-rest mit dem Fernet-Schlüssel
  (`SECSCAN_CRYPTO_KEY`, sonst abgeleitet) verschlüsselt. Das schützt gegen
  DB-/Platten-Diebstahl, nicht gegen einen Angreifer mit laufendem Server-Prozess
  (der den Schlüssel besitzt). Für `ssh_linux` etc. sind Key-Dateien gegenüber
  Passwörtern zu bevorzugen.

## 3. Skalierung auf hunderte Geräte

**Aktuelle Engpässe (zu beheben vor Produktiv):**
- **Dashboard N+1**: pro System eigene Queries (latest_scan, packages, snoozes).
  Bei hunderten Systemen → hunderte Queries/Seitenaufruf. **Fix:** denormalisierte
  `SystemSummary` (packages, updates, severity, last_scan) pro Scan aktualisiert;
  Dashboard liest **eine** Tabelle. Alternativ Batch-Queries.
- **Ingest-Materialisierung**: aktuell `commit()` pro entdecktem Gerät
  (hunderte Commits/Push). **Fix:** eine Transaktion/Batch pro Push.
- **Scan-Historie wächst unbegrenzt**: **Retention** (z.B. letzte N Scans oder
  X Tage je System) + geplanter Prune-Job. Sonst DB-Wachstum ungebremst.

**Datenbank:**
- SQLite ist für **einen** Server bis ~niedrige Tausende Systeme mit Retention
  praktikabel, aber Single-Writer (Ingest-Spitzen serialisieren).
- **Empfehlung Produktiv: PostgreSQL** (via `SECSCAN_DATABASE_URL`). Nötig für
  parallele Ingest-Last, HA/Backups, und wenn mehrere Worker laufen.
- WAL-Modus + `busy_timeout` falls bei SQLite bleibend.

**App-Server:**
- Mehrere uvicorn-Worker hinter dem Proxy (dann Scheduler nur in **einem**
  Worker starten, sonst doppelte Jobs → Lock/Leader-Election oder separater
  Scheduler-Prozess).
- Ingest ist CPU-leicht; Materialisierung/Diff ist der teuerste Teil → batchen.

## 4. Mandanten-Trennung (Multi-Kunde)

- Logisch heute über **group/tags** (Agent-Tags vererben auf Geräte).
- Produktiv sauberer: **Tenant**-Konzept (Agent↔Tenant, Systeme↔Tenant),
  UI-Scoping je Tenant, Rollen (Admin/Viewer). Credential-Crypto ist durch die
  per-Agent-Keys bereits mandantensicher.
- **Auth** aktuell: ein Admin-Passwort. Produktiv: Benutzer/Rollen + ggf. SSO.

## 5. Betrieb

- **Backups**: DB-Volume + (bei Postgres) pg_dump. Credential-Chiffre ist ohne
  Agent-Keys wertlos → Backup unkritischer.
- **Secrets**: `SECSCAN_ADMIN_PASSWORD`, `SECSCAN_SECRET_KEY`, Ingest-/Enrollment-
  Token, DB-Passwort über Secret-Store/ENV, nie im Image.
- **Updates**: Server per Image-Tag versioniert; Agenten melden Version, Update
  via Install-Skript/Paket (lean Agent-Paket als Ziel: nur nötige Deps).
- **Monitoring**: `/healthz`, Scan-Fehlerquote, Ingest-Latenz, DB-Größe.

## 6. Umsetzungsreihenfolge (Vorschlag)

1. **Credential-Crypto v2** (asymmetrisch, Split-Knowledge) — ersetzt v1.
   Agent-Keypair + Passphrase-Auslieferung + per-Agent-Verschlüsselung + CLI.
2. **Skalierungs-Fixes**: `SystemSummary` (Dashboard-N+1), Ingest-Batching,
   Scan-Retention/Prune-Job.
3. **PostgreSQL**-Option + Multi-Worker + Scheduler-Leader.
4. **Browser-E2E-Credential-Eingabe** (WebCrypto).
5. **Tenant/Rollen** + Server-Fingerprint-Pinning.
