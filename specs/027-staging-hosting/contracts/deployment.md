# Deployment contract (027): names of everything

`<env>` is `staging` or `production`. Project `swastik-4fcc9`, region `asia-south1`. Values are never written here or anywhere in the repo.

## Google Cloud

| Kind | Name | Created by |
|---|---|---|
| Tofu state bucket | `swastik-4fcc9-tofu-state` (versioned, uniform access, public access prevented); prefixes `shared/`, `staging/`, `production/` | bootstrap.sh |
| Workload identity pool / provider | `github` / `swastik-repo` (issuer `https://token.actions.githubusercontent.com`) | bootstrap.sh |
| Tofu SA | `tofu@swastik-4fcc9.iam.gserviceaccount.com`, impersonable only from GitHub environment `infra`. Rights (bootstrap.sh): project roles `run.admin`, `artifactregistry.admin`, `cloudscheduler.admin`, `iam.serviceAccountAdmin`, `serviceusage.serviceUsageAdmin`; custom role `tofuActAs` (only `iam.serviceAccounts.actAs`) conditioned to SAs named `api-*` and `tick-*`; `storage.objectAdmin` on the state bucket; `secretmanager.admin` on each secret only (granted by secrets.sh). No `projectIamAdmin`, pool admin, project-wide `serviceAccountUser` or project-wide `secretmanager.admin`. | bootstrap.sh, secrets.sh |
| Deployer SA | `deploy-<env>@…`, impersonable only from GitHub environment `<env>`; `run.developer` on its service, `iam.serviceAccountUser` on its runtime SA, `artifactregistry.writer` on the repo | tofu |
| Runtime SA | `api-<env>@…`; `secretAccessor` on its own secrets only | tofu |
| Tick caller SA | `tick-<env>@…`; no other rights | tofu |
| Artifact Registry | `asia-south1-docker.pkg.dev/swastik-4fcc9/swastik`, image `api`, keep newest 10 | tofu (shared) |
| Cloud Run service | `swastik-api-<env>` | tofu (config), deploy.yml (image, traffic) |
| Cloud Scheduler job | `swastik-tick-<env>` | tofu |

## Secret Manager (values added only by `infra/bootstrap/secrets.sh <env>`)

| Secret | Env var in the API | Needed from |
|---|---|---|
| `database-url-<env>` | `DATABASE_URL` (login `swastik_app`) | now |
| `jwt-signing-keys-<env>` | `JWT_SIGNING_KEYS` | 003 (`auth_keys_enabled = true`) |
| `pii-encryption-keys-<env>` | `PII_ENCRYPTION_KEYS` | 003 |
| `blind-index-key-<env>` | `BLIND_INDEX_KEY` | 003 |
| `proxy-shared-secrets-<env>` | `PROXY_SHARED_SECRETS` (API) and the Worker secret binding `PROXY_KEY` | 003 |

Formats written by `secrets.sh <env> --with-auth` (random 32 bytes each, standard base64, three distinct values; never printed): `JWT_SIGNING_KEYS=k1:<b64>`, `PII_ENCRYPTION_KEYS=1:<b64>`, `BLIND_INDEX_KEY=<b64>`, `PROXY_SHARED_SECRETS=<b64>`. Without `--with-auth` only `database-url-<env>` is created. Existing secrets are never recreated or given a new version unless `--rotate` is passed (new version, key ids from `ROTATE_JWT_KID`, default `k2`, and `ROTATE_PII_KEY_ID`, default `2`).

The Worker sets `X-Swastik-Client-IP` from `CF-Connecting-IP` and `X-Swastik-Proxy-Key` from `PROXY_KEY`, and removes incoming copies of both headers. Tofu reads `proxy-shared-secrets-<env>` to set the Worker binding, so that one value is also in the (private, versioned) state bucket.

## API settings set by tofu (`infra/tofu/envs/<env>/terraform.tfvars`, not secret)

`APP_ENV=<env>`, `TICK_AUTH=oidc`, `TICK_AUDIENCE=https://<api-host>/internal/tick`, `TICK_SERVICE_ACCOUNT=tick-<env>@swastik-4fcc9.iam.gserviceaccount.com`, `WEB_ORIGINS=https://<admin-host>,https://<app-host>`, `TRUSTED_PROXY_HOPS=1`, `JWT_ACTIVE_KID`, `PII_ACTIVE_KEY_ID` (003), `SENTRY_DSN`, `SENTRY_ENVIRONMENT=<env>` (if Q1 yes; the API falls back to `APP_ENV`). Tofu env variables `auth_keys_enabled`, `jwt_active_kid`, `pii_active_key_id` are set per environment when 003 arrives; production Cloud Run has `deletion_protection = true`; Access uses a one-time-PIN identity provider.

## Cloudflare (zone `swastikapp.co.in`)

| Kind | staging | production |
|---|---|---|
| API host (Worker route) | `api-staging.swastikapp.co.in` → Worker `swastik-api-proxy-staging` | `api.swastikapp.co.in` → `swastik-api-proxy-production` |
| Admin (Pages + Access) | `admin-staging.swastikapp.co.in`, project `swastik-admin-staging` | `admin.swastikapp.co.in`, `swastik-admin-production` |
| Client web app (Pages) | `app-staging.swastikapp.co.in`, project `swastik-app-staging` | `app.swastikapp.co.in`, `swastik-app-production` |
| R2 bucket | — | `swastik-backups` (lifecycle: delete after 30 days) |

Existing records (Resend on `mail.`) are not managed by tofu.

## GitHub environments

| Environment | Protection | Variables | Secrets |
|---|---|---|---|
| `staging` | branch `stage` only | `GCP_PROJECT_ID`, `GCP_WIF_PROVIDER`, `GCP_DEPLOY_SA`, `CLOUD_RUN_SERVICE`, `API_BASE_URL`, `ADMIN_PAGES_PROJECT`, `CLIENT_PAGES_PROJECT`, `CLOUDFLARE_ACCOUNT_ID` | `MIGRATE_DATABASE_URL` (Supabase `postgres` login, session pooler), `CLOUDFLARE_PAGES_TOKEN` |
| `production` | owner reviewer; `main` + tags `v*` | same names, production values | same names, production values |
| `infra` | owner reviewer; `stage`, `main` | `GCP_PROJECT_ID`, `GCP_WIF_PROVIDER`, `GCP_TOFU_SA`, `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_ZONE_ID`, `ACCESS_ALLOWED_EMAILS` (comma separated), `SENTRY_DSN` | `CLOUDFLARE_TOFU_TOKEN` |
| `backups` | branch `stage` only (scheduled runs) | `BACKUP_AGE_RECIPIENT` (public age key; the dump is encrypted to it before upload, the private key stays with the owner) | `BACKUP_DATABASE_URL` (login `swastik_backup`, production), `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, `R2_ENDPOINT` |

Removed from GitHub variables (now in tofu): `APP_ENV`, `TICK_AUDIENCE`, `TICK_SERVICE_ACCOUNT`.

## Cloudflare tokens (owner creates, least privilege)

- `CLOUDFLARE_TOFU_TOKEN`: Zone DNS Edit (`swastikapp.co.in`), Zone Workers Routes Edit, Account Workers Scripts Edit, Account Cloudflare Pages Edit, Account Access: Apps and Policies Edit, Account Workers R2 Storage Edit.
- `CLOUDFLARE_PAGES_TOKEN`: Account Cloudflare Pages Edit only.
- R2 key: Object Read & Write on bucket `swastik-backups` only.

## Supabase logins (per project; created by `infra/supabase/roles.sql`, passwords set with `\password`)

`postgres` (migrations), `swastik_app` (API), `swastik_backup` (read-only, production backups). Pooler user format `<login>.<project-ref>`; staging ref `hddzoasgsdtvdzauxfbo`, production `dxymdmefbgztygbxqcbb`.
