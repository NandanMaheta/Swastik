# Handover

Read this first in every new conductor session (with `CLAUDE.md` and `docs/engineering/delivery-pipeline.md`). Keep it short and current: update it whenever a feature merges or a decision is made.

_Last updated: 2026-11-26_

## Owner and setup

- Owner: Nandan Maheta. Repo: `NandanMaheta/Swastik`. Default branch `stage` (staging), `main` = production. Branch protection and the `staging` / `production` environments are configured.
- Accounts ready:
  - domain `swastikapp.co.in` (Cloudflare, Active; email via Resend on `mail.swastikapp.co.in`)
  - Google Cloud project `swastik-4fcc9`
  - Supabase staging `hddzoasgsdtvdzauxfbo` and prod `dxymdmefbgztygbxqcbb` (Mumbai)
  - Firebase (Blaze, phone auth, India-only SMS, Android app `com.nandanmaheta.swastik`)
  - Expo `nandy99`
  - Sentry project `swastik-api`
- Secrets are added only when a feature needs them. Never ask for secret values in chat; give the exact GitHub/Secret Manager names.

## Decisions to remember

- Product renamed from Divya to Swastik. The GitHub API needs the repo attached as `NandanMaheta/Swastik`.
- Owner prefers: plain, non-AI-sounding docs and README; short replies; the accounts and status tables only when asked.
- Libraries approved:
  - 002: go-oidc v3, uuid, rapid
  - 003: go-jose v4, pquerna/otp, x/crypto, x/term, x/text
  - 027: sentry-go
- Owner decisions (2026-11-15):
  - JWT leeway 5 s on `iat`/`nbf` only; `exp` strict.
  - Cloudflare Worker sends a shared proxy key; the API trusts the client IP only with it (`PROXY_SHARED_SECRETS`, `TRUSTED_PROXY_HOPS=1`).
  - One GCP project for staging and production; about ₹15/month for Secret Manager is accepted.
  - ADR 0008 (in-transaction module signals) accepted.
- Pipeline v2 (risk tiers, briefs, slices, batched passes) applies to all work from 2026-11-14.

## Feature status

| Feature                | State                                                                                            |
| ---------------------- | ------------------------------------------------------------------------------------------------ |
| 001 Platform           | done                                                                                             |
| 002 Scheduler + outbox | done (PR #9)                                                                                     |
| 003 Auth core          | done (PR #10)                                                                                    |
| 008 IPO catalogue      | done (PR #12)                                                                                    |
| 027 Staging hosting    | done (PR #11); owner is following `docs/engineering/staging-setup-guide.md` to make staging live |
| Others                 | not started; see `docs/product/modules.md`                                                       |

Small follow-ups:

- 008: the generated TS client still lists Huma's optional `$schema` field. Also add tests for the OverrideStatus warnings and for concurrent same-key creates with different bodies.
- 027: if the first Infra apply fails on `actAs`, bind the two exact service accounts (see `specs/027-staging-hosting/security.md`). Confirm the Supabase Postgres major version, because backups use `postgres:18-alpine`.

## Next steps

1. Owner: finish the staging setup guide. Then create the first admin with `swastik admin create`.
2. Next features, which can run in parallel: 004 OTP delivery (Tier A, unblocks 005 registration and 024 client auth) and 009 GMP and expected profit (Tier B).
3. Then 005, 006 and 012 (clients, family accounts, apply tasks), and the admin shell (022) once 005 is done.
