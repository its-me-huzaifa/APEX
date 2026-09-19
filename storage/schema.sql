-- APEX prototype SQLite schema.
-- Phase 0: schema only. Populated starting Phase 2 (recon) and Phase 3+ (attacks/findings).

CREATE TABLE IF NOT EXISTS assessments (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name     TEXT NOT NULL,
    started_at      TEXT NOT NULL,
    finished_at     TEXT,
    status          TEXT NOT NULL DEFAULT 'pending',   -- pending | running | completed | error
    target_profile  TEXT                                -- JSON blob from recon
);

CREATE TABLE IF NOT EXISTS attacks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id   INTEGER NOT NULL REFERENCES assessments(id),
    attack_type     TEXT NOT NULL,      -- e.g. direct_injection, indirect_injection
    payload         TEXT NOT NULL,
    response        TEXT,
    classification  TEXT,               -- SAFE | PARTIAL_SUCCESS | SUCCESS | ERROR
    classified_why  TEXT,
    timestamp       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id   INTEGER NOT NULL REFERENCES assessments(id),
    attack_id       INTEGER REFERENCES attacks(id),
    title           TEXT NOT NULL,
    attack_type     TEXT NOT NULL,
    severity        TEXT NOT NULL,      -- INFO | LOW | MEDIUM | HIGH | CRITICAL
    description     TEXT,
    evidence        TEXT,
    payload         TEXT,
    target          TEXT NOT NULL,
    classification  TEXT NOT NULL,
    recommendation  TEXT,
    timestamp       TEXT NOT NULL
);
