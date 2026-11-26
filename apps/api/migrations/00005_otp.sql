-- +goose Up
-- OTP delivery (feature 004). Expand-only: five new operational tables (mutable; every business
-- event is in the append-only audit_log) and one additive outbox column with its erase trigger.
-- Instants come from the app clock; the now() defaults are only a safety net.

CREATE TABLE otp_verifications (
    id                     uuid PRIMARY KEY DEFAULT uuidv7(),
    org_id                 uuid NOT NULL REFERENCES orgs (id),
    user_id                uuid REFERENCES users (id),
    purpose                text NOT NULL CHECK (purpose IN ('signup', 'change_email', 'change_mobile', 'password_reset')),
    handle_hash            bytea NOT NULL CHECK (octet_length(handle_hash) = 32),
    email                  text CHECK (email = lower(btrim(email)) AND char_length(email) BETWEEN 3 AND 254 AND position('@' IN email) > 1),
    mobile                 text CHECK (mobile ~ '^\+91[6-9][0-9]{9}$'),
    email_done_at          timestamptz,
    mobile_done_at         timestamptz,
    reset_token_hash       bytea CHECK (octet_length(reset_token_hash) = 32),
    reset_token_expires_at timestamptz,
    finished_at            timestamptz,
    cancelled_at           timestamptz,
    cancel_reason          text CHECK (cancel_reason IN ('cancelled', 'superseded')),
    created_at             timestamptz NOT NULL DEFAULT now(),
    expires_at             timestamptz NOT NULL,
    updated_at             timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT otp_verifications_handle_uq UNIQUE (handle_hash),
    CONSTRAINT otp_verifications_targets_ck CHECK (
        CASE purpose
            WHEN 'signup'         THEN user_id IS NOT NULL AND email IS NOT NULL AND mobile IS NOT NULL
            WHEN 'change_email'   THEN user_id IS NOT NULL AND email IS NOT NULL AND mobile IS NULL
            WHEN 'change_mobile'  THEN user_id IS NOT NULL AND mobile IS NOT NULL AND email IS NULL
            WHEN 'password_reset' THEN mobile IS NULL AND (user_id IS NULL) = (email IS NULL)
        END),
    CONSTRAINT otp_verifications_reset_only_ck CHECK (
        (reset_token_hash IS NULL) = (reset_token_expires_at IS NULL)
        AND (purpose = 'password_reset' OR reset_token_hash IS NULL)),
    CONSTRAINT otp_verifications_done_ck CHECK (
        (email_done_at IS NULL OR email IS NOT NULL) AND (mobile_done_at IS NULL OR mobile IS NOT NULL)),
    CONSTRAINT otp_verifications_cancel_ck CHECK (
        (cancelled_at IS NULL) = (cancel_reason IS NULL) AND NOT (cancelled_at IS NOT NULL AND finished_at IS NOT NULL)),
    CONSTRAINT otp_verifications_expiry_ck CHECK (expires_at > created_at)
);

-- One live flow per user and purpose; Start supersedes the previous one in the same transaction.
CREATE UNIQUE INDEX otp_verifications_open_uq ON otp_verifications (user_id, purpose)
    WHERE user_id IS NOT NULL AND cancelled_at IS NULL AND finished_at IS NULL;
CREATE INDEX otp_verifications_expires_idx ON otp_verifications (expires_at);

CREATE TABLE otp_email_codes (
    id              uuid PRIMARY KEY DEFAULT uuidv7(),
    org_id          uuid NOT NULL REFERENCES orgs (id),
    verification_id uuid NOT NULL REFERENCES otp_verifications (id) ON DELETE CASCADE,
    code_digest     bytea NOT NULL CHECK (octet_length(code_digest) = 32),
    issued_at       timestamptz NOT NULL,
    expires_at      timestamptz NOT NULL,
    wrong_attempts  smallint NOT NULL DEFAULT 0 CHECK (wrong_attempts BETWEEN 0 AND 5),
    outbox_key      text,
    ended_at        timestamptz,
    end_reason      text CHECK (end_reason IN ('used', 'superseded', 'used_up', 'cancelled')),

    CONSTRAINT otp_email_codes_expiry_ck CHECK (expires_at > issued_at),
    CONSTRAINT otp_email_codes_end_ck CHECK ((ended_at IS NULL) = (end_reason IS NULL))
);

CREATE UNIQUE INDEX otp_email_codes_live_uq ON otp_email_codes (verification_id) WHERE ended_at IS NULL;

CREATE TABLE otp_used_proofs (
    fingerprint     bytea PRIMARY KEY CHECK (octet_length(fingerprint) = 32),
    org_id          uuid NOT NULL REFERENCES orgs (id),
    verification_id uuid NOT NULL REFERENCES otp_verifications (id) ON DELETE CASCADE,
    used_at         timestamptz NOT NULL
);

CREATE INDEX otp_used_proofs_used_idx ON otp_used_proofs (used_at);
CREATE INDEX otp_used_proofs_verification_idx ON otp_used_proofs (verification_id);
CREATE INDEX otp_email_codes_verification_idx ON otp_email_codes (verification_id);

-- Durable send/check limits. No FK to users: unknown identifiers need rows too (D-07).
CREATE TABLE otp_limits (
    org_id     uuid NOT NULL REFERENCES orgs (id),
    scope      text NOT NULL CHECK (scope IN ('send_contact', 'send_user', 'send_ip', 'check_ip')),
    subject    bytea NOT NULL CHECK (octet_length(subject) = 32),
    events     timestamptz[] NOT NULL DEFAULT '{}' CHECK (cardinality(events) <= 60),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, scope, subject)
);

CREATE INDEX otp_limits_updated_idx ON otp_limits (updated_at);

-- Daily counters, no identifiers (FR-017).
CREATE TABLE otp_daily_counts (
    org_id uuid NOT NULL REFERENCES orgs (id),
    day    date NOT NULL,
    metric text NOT NULL CHECK (metric IN ('email_sent', 'email_failed', 'limit_refused', 'proof_accepted', 'proof_refused')),
    count  integer NOT NULL DEFAULT 0 CHECK (count >= 0),
    PRIMARY KEY (org_id, day, metric)
);

-- Outbox: a payload that carries a secret (an OTP code, sealed) is erased on every terminal
-- status (ADR 0003 Amendment 2). The trigger covers relay, withdraw, expiry and admin cancel.
ALTER TABLE outbox_messages ADD COLUMN sensitive_payload boolean NOT NULL DEFAULT false;

-- +goose StatementBegin
CREATE FUNCTION outbox_erase_sensitive_payload() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.sensitive_payload AND NEW.status IN ('sent', 'dead', 'withdrawn', 'expired') THEN
        NEW.payload = '{}'::jsonb;
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER outbox_erase_sensitive_payload
    BEFORE INSERT OR UPDATE OF status ON outbox_messages
    FOR EACH ROW EXECUTE FUNCTION outbox_erase_sensitive_payload();

ALTER TABLE outbox_messages ADD CONSTRAINT outbox_messages_sensitive_erased_ck
    CHECK (NOT sensitive_payload OR status IN ('pending', 'sending') OR payload = '{}'::jsonb);

-- +goose Down
ALTER TABLE outbox_messages DROP CONSTRAINT outbox_messages_sensitive_erased_ck;
DROP TRIGGER outbox_erase_sensitive_payload ON outbox_messages;
DROP FUNCTION outbox_erase_sensitive_payload();
ALTER TABLE outbox_messages DROP COLUMN sensitive_payload;
DROP TABLE otp_daily_counts;
DROP TABLE otp_limits;
DROP TABLE otp_used_proofs;
DROP TABLE otp_email_codes;
DROP TABLE otp_verifications;
