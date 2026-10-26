# Argus — Projekt-Hinweise für Claude

Read-only Security-/Asset-Management-Plattform. Server (FastAPI + SQLModel) +
Push-Agenten. Details: [README.md](README.md), [ARCHITECTURE.md](ARCHITECTURE.md),
[ROADMAP.md](ROADMAP.md).

## Wartungsregeln (verbindlich)

### 1. README nach jedem Feature aktualisieren
Nach **jedem neuen Feature oder jeder relevanten Änderung** die
[README.md](README.md) mitpflegen (und bei Architektur-/Sicherheits-Änderungen
auch [ARCHITECTURE.md](ARCHITECTURE.md) bzw. [ROADMAP.md](ROADMAP.md)).
Nicht als „später"-Aufgabe — im selben Arbeitsschritt wie das Feature.
Mindestens prüfen: Architektur-Diagramm, Config/Env-Variablen, Collector-/Modul-
Liste, Deploy-/Upgrade-Schritte.

### 2. Commit-Nachricht: Breaking Changes für Agenten markieren
Vor jedem Commit prüfen, ob die Änderung **laufende Agenten bricht** (ein neuer
Server wäre inkompatibel mit noch nicht aktualisierten Agenten). Falls ja, die
Commit-Nachricht mit einer deutlichen Zeile kennzeichnen:

```
BREAKING (agents): <was bricht> — Agenten müssen aktualisiert werden
```

**Agenten-relevant sind Änderungen an:**
- dem Ingest-/Enroll-Vertrag (`POST /ingest`, `POST /enroll`, deren Request/Response-Felder),
- `app/agent.py`, `app/push.py` (Client-Logik),
- der Credential-Krypto (`app/services/crypto.py` seal/unseal/Key-Format, `enrollment` pubkey/passphrase-Protokoll, `/credentials/upload`),
- dem Command-Channel (neue/veränderte Command-Typen in der Poll-Antwort),
- dem `DeviceInfo`-/Modul-Vertrag, der über den Server ausgeliefert wird.

Reine **Server-interne** Änderungen (DB-Schema wird per `app/db._add_missing_columns`
auto-migriert; UI; Dashboard; neue Module ohne Protokolländerung) sind i.d.R.
**nicht** agenten-brechend — dann keine BREAKING-Markierung nötig.

Faustregel: Würde ein Agent mit der **vorherigen** Version nach diesem Deploy
noch fehlerfrei pushen/anlernen/Credentials öffnen? Wenn nein → BREAKING (agents).

## Schema-Versionierung
`SCHEMA_REVISION` in [app/__init__.py](app/__init__.py) bei Modelländerungen
hochzählen. Neue Tabellen/Spalten werden additiv migriert
([app/db.py](app/db.py) `_add_missing_columns`). Breaking-DB-Änderungen (Spalte
entfernen/umtypen) brauchen echte Migration.
