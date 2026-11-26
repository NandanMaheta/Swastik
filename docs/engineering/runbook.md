# Hosting runbook (staging and production)

Names: [contracts/deployment.md](../../specs/027-staging-hosting/contracts/deployment.md). Agents never run any of this against the cloud; the owner does steps 1–5 once, then everything runs from GitHub.

## First-time setup (staging first, production later with the same steps)

1. **Google Cloud Shell** (signed in as the owner, project `swastik-4fcc9`):
   - `bash infra/bootstrap/bootstrap.sh --dry-run` to read what it will do, then without `--dry-run`. It turns on the needed APIs, creates the state bucket, the `github` identity pool, and the `tofu` SA.
   - Billing → Budgets: create a budget of ₹100 with alerts at 1 % (₹1), 50 % and 100 %.
2. **Secrets**: `bash infra/bootstrap/secrets.sh staging`. It asks for the Supabase session-pooler URL for `swastik_app` (hidden input) and creates that secret plus the proxy key (`proxy-shared-secrets-<env>`). The proxy key is also sent to the Cloudflare Worker with wrangler (set `CLOUDFLARE_API_TOKEN` first); the Worker only exists after the first Infra apply (step 6), so **run `secrets.sh` a second time after that apply**: it re-sends the stored key without creating a new version (`--push-proxy` forces it). Once feature 003 is deployed, run it again with `--with-auth` (creates the JWT, PII and blind-index keys itself; existing secrets are left alone). To rotate: `--rotate` appends a new JWT/PII key to the ring, then set `jwt_active_kid` / `pii_active_key_id` in tfvars via the Infra workflow and remove old keys only after sessions/data are migrated; `--rotate-blind-index` needs a reindex. Nothing is printed.
3. **Supabase** (staging project, then production; run `roles.sql` after every migration batch that adds tables so grants stay complete):
   - Settings → API → switch off the Data API.
   - Cloud Shell: `psql "<postgres session-pooler URL>" -f infra/supabase/roles.sql`, then `\password swastik_app` (and `\password swastik_backup` on production).
4. **Cloudflare**: turn on Zero Trust (free plan) and enable the One-time PIN login method, otherwise the admin Access application cannot apply; note the zone id and set it as the `CLOUDFLARE_ZONE_ID` variable of the `infra` environment; add a payment method (needed to turn on R2; stays on the free tier); create the two tokens and the R2 key from the contract.
5. **Backups**: run `age-keygen -o backup.key` on your own machine, keep `backup.key` safe offline, and set the printed public key (`age1...`) as the `BACKUP_AGE_RECIPIENT` variable of the `backups` environment. Restoring needs `age -d -i backup.key`.
   5b. **GitHub** → Settings → Environments: create `infra` and `backups`, set protections, add the variables and secrets from the contract.
6. Actions → **Infra** → run for `shared`, then `staging`; approve. Then merge any PR into `stage` and open `https://api-staging.swastikapp.co.in/healthz`, `https://admin-staging.swastikapp.co.in` (asks for your email PIN) and `https://app-staging.swastikapp.co.in`.
7. UptimeRobot (free): one HTTPS monitor per environment on `/healthz`, every 5 minutes, alerts to your email.

## Rollback (under 5 minutes)

- **API**: Cloud Console → Cloud Run → `swastik-api-<env>` → Revisions → "Manage traffic" → 100 % to the previous revision. Or re-run the Deploy workflow for the previous tag.
- **Admin / client web**: Cloudflare → Pages → project → Deployments → previous one → "Rollback to this deployment".
- **Database**: migrations are never undone automatically. They are backward compatible, so the old API version runs on the new schema; a fix goes forward in a new migration.

## Restoring a backup

1. Download the dump and its `.counts` file from R2 `swastik-backups`.
2. Restore into a new, empty database first (`bash infra/backup/drill.sh --restore-only <dump> <target-url>`), check the counts.
3. Only then restore into production (owner, `postgres` login, with the Cloud Run service scaled to 0 instances during the restore), and scale it back.

## Key rotation

Follow 003's quickstart; secret names carry the environment suffix. Add a new secret version with `gcloud secrets versions add`, then change the active id in tfvars through an infra PR.

## Checks that run without cloud access

`bash scripts/check-deploy-workflow.sh --pages --infra --nightly`, `bash infra/bootstrap/test.sh`, `node --test infra/cloudflare/api-proxy/worker.test.js`, `bash infra/backup/drill_test.sh` and the tofu tests in `infra/tofu/tests` (see `.github/workflows/infra.yml`). The Postgres image used for backups (`DRILL_PG_IMAGE`, default `postgres:17-alpine`) must match the Supabase major (17, ADR 0010); change it in `infra/backup/drill.sh` and `nightly.yml` when Supabase moves.
