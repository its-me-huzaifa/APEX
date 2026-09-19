-- APEX prototype SQLite schema.
-- Phase 0: apex/attacks/findings tables. Phase 1 added VICTIM's own tables
-- below (employees, sent_emails) - VICTIM's modules also create these
-- lazily with IF NOT EXISTS, so this file is the documented single source
-- of truth even though it isn't strictly required at import time.

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

-- VICTIM's own tables (Phase 1) --------------------------------------------

CREATE TABLE IF NOT EXISTS employees (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    department  TEXT NOT NULL,
    title       TEXT NOT NULL,
    salary      INTEGER NOT NULL,
    email       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sent_emails (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient   TEXT NOT NULL,
    subject     TEXT NOT NULL,
    body        TEXT NOT NULL,
    timestamp   TEXT NOT NULL
);
