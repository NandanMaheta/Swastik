# Non-secret settings. project_number, cloudflare_* ids, access_emails and sentry_dsn come from the
# infra GitHub environment (TF_VAR_*), never from this file.

# 003 auth is merged: the API refuses to start in staging/production without these keys.
# Create them first with `secrets.sh <env> --with-auth`.
auth_keys_enabled = true
jwt_active_kid    = "k1"
pii_active_key_id = "1"
