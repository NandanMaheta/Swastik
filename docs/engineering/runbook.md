# Hosting runbook (staging and production)

Names: [contracts/deployment.md](../../specs/027-staging-hosting/contracts/deployment.md). Agents never run any of this against the cloud; the owner does steps 1–5 once, then everything runs from GitHub.

## First-time setup (staging first, production later with the same steps)

1. **Google Cloud Shell** (signed in as the owner, project `swastik-4fcc9`):
   - `bash infra/bootstrap/bootstrap.sh --dry-run` to read what it will do, then without `--dry-run`. It turns on the needed APIs, creates the state bucket, the `github` identity pool, and the `tofu` SA.
   - Billing → Budgets: create a budget of ₹100 with alerts at 1 % (₹1), 50 % and 100 %.
2. **Secrets**: `bash infra/bootstrap/secrets.sh staging`. It asks for the Supabase session-pooler URL for `swastik_app` (hidden input) and creates the auth keys itself. Nothing is printed.
3. **Supabase** (staging project, then production; run `roles.sql` after every migration batch that adds tables so grants stay complete):
   - Settings → API → switch off the Data API.
   - Cloud Shell: `psql "<postgres session-pooler URL>" -f infra/supabase/roles.sql`, then `\password swastik_app` (and `\password swastik_backup` on production).
4. **Cloudflare**: note the zone id and set it as the `CLOUDFLARE_ZONE_ID` variable of the `infra` environment; add a payment method (needed to turn on R2; stays on the free tier); create the two tokens and the R2 key from the contract.
5. **GitHub** → Settings → Environments: create `infra` and `backups`, set protections, add the variables and secrets from the contract.
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

`bash scripts/check-deploy-workflow.sh --pages --infra --nightly`, `bash infra/bootstrap/test.sh`, `node --test infra/cloudflare/api-proxy/worker.test.js`, `bash infra/backup/drill_test.sh` and the tofu tests in `infra/tofu/tests` (see `.github/workflows/infra.yml`). The Postgres image used for backups (`DRILL_PG_IMAGE`, default `postgres:18-alpine`) must match the Supabase major; confirm it once and change it in `infra/backup/drill.sh` and `nightly.yml` if different.
