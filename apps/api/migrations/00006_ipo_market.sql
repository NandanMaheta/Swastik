-- +goose Up
-- IPO market data (feature 009): append-only GMP history and subscription snapshots.
-- Expand-only: two new tables, their indexes and two triggers using forbid_mutation() (00001).
-- Instants come from the app clock.

CREATE TABLE ipo_gmp_entries (
    id                uuid PRIMARY KEY DEFAULT uuidv7(),
    org_id            uuid NOT NULL REFERENCES orgs (id),
    ipo_id            uuid NOT NULL REFERENCES ipos (id),
    gmp_paise         bigint NOT NULL CHECK (gmp_paise BETWEEN -1000000000 AND 1000000000),
    note              text CHECK (char_length(btrim(note)) BETWEEN 1 AND 200),
    corrects_entry_id uuid UNIQUE,
    source            text NOT NULL DEFAULT 'manual'
        CHECK (source = 'manual' OR source ~ '^import:[a-z0-9_]{1,32}$'),
    actor_kind        text NOT NULL CHECK (actor_kind IN ('admin', 'system')),
    actor_id          uuid,
    idempotency_key   text CHECK (char_length(idempotency_key) BETWEEN 8 AND 200),
    request_hash      text CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    recorded_at       timestamptz NOT NULL,

    CONSTRAINT ipo_gmp_entries_ipo_id_uq UNIQUE (ipo_id, id),
    CONSTRAINT ipo_gmp_entries_no_self_correction CHECK (corrects_entry_id <> id),
    CONSTRAINT ipo_gmp_entries_corrects_fk FOREIGN KEY (ipo_id, corrects_entry_id)
        REFERENCES ipo_gmp_entries (ipo_id, id),
    CONSTRAINT ipo_gmp_entries_actor CHECK ((actor_kind = 'admin') = (actor_id IS NOT NULL)),
    CONSTRAINT ipo_gmp_entries_idem_pair CHECK ((idempotency_key IS NULL) = (request_hash IS NULL))
);

CREATE INDEX ipo_gmp_entries_ipo_idx ON ipo_gmp_entries (org_id, ipo_id, recorded_at DESC, id DESC);
CREATE UNIQUE INDEX ipo_gmp_entries_idem_uq ON ipo_gmp_entries (org_id, ipo_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

CREATE TRIGGER ipo_gmp_entries_append_only BEFORE UPDATE OR DELETE ON ipo_gmp_entries
    FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

CREATE TABLE ipo_subscription_snapshots (
    id              uuid PRIMARY KEY DEFAULT uuidv7(),
    org_id          uuid NOT NULL REFERENCES orgs (id),
    ipo_id          uuid NOT NULL REFERENCES ipos (id),
    as_of           timestamptz NOT NULL,
    total_x100      integer NOT NULL CHECK (total_x100 BETWEEN 0 AND 10000000),
    qib_x100        integer CHECK (qib_x100 BETWEEN 0 AND 10000000),
    nii_x100        integer CHECK (nii_x100 BETWEEN 0 AND 10000000),
    bnii_x100       integer CHECK (bnii_x100 BETWEEN 0 AND 10000000),
    snii_x100       integer CHECK (snii_x100 BETWEEN 0 AND 10000000),
    retail_x100     integer CHECK (retail_x100 BETWEEN 0 AND 10000000),
    employee_x100   integer CHECK (employee_x100 BETWEEN 0 AND 10000000),
    source          text NOT NULL DEFAULT 'manual'
        CHECK (source = 'manual' OR source ~ '^import:[a-z0-9_]{1,32}$'),
    actor_kind      text NOT NULL CHECK (actor_kind IN ('admin', 'system')),
    actor_id        uuid,
    idempotency_key text CHECK (char_length(idempotency_key) BETWEEN 8 AND 200),
    request_hash    text CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    recorded_at     timestamptz NOT NULL,

    CONSTRAINT ipo_subscription_actor CHECK ((actor_kind = 'admin') = (actor_id IS NOT NULL)),
    CONSTRAINT ipo_subscription_idem_pair CHECK ((idempotency_key IS NULL) = (request_hash IS NULL))
);

CREATE INDEX ipo_subscription_ipo_idx
    ON ipo_subscription_snapshots (org_id, ipo_id, as_of DESC, recorded_at DESC, id DESC);
CREATE UNIQUE INDEX ipo_subscription_idem_uq ON ipo_subscription_snapshots (org_id, ipo_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

CREATE TRIGGER ipo_subscription_append_only BEFORE UPDATE OR DELETE ON ipo_subscription_snapshots
    FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

-- +goose Down
DROP TABLE ipo_subscription_snapshots;
DROP TABLE ipo_gmp_entries;
