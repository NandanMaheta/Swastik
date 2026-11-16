# 027 security review summary

Scope: hosting, identity, secrets, edge proxy, backups. Findings came from the review and the 003 security review; each is fixed or listed as accepted risk.

## Fixed

| Area | Finding | Fix |
|---|---|---|
| Tofu SA rights | Too broad (project IAM admin, pool admin, project-wide `serviceAccountUser`, `secretmanager.admin`) | bootstrap.sh grants only `run.admin`, `artifactregistry.admin`, `cloudscheduler.admin`, `iam.serviceAccountAdmin`, `serviceusage.serviceUsageAdmin`, custom `tofuActAs`, state bucket `objectAdmin`; secrets: custom `tofuSecretMeta` (get/getIamPolicy/setIamPolicy, no `versions.access`) bound per secret |
| Secret values | Values could enter tofu state | Tofu never reads versions; Worker `PROXY_KEY` pushed by `secrets.sh` through wrangler (stdin), `keep_bindings` stops tofu wiping it; lifecycle test forbids `secret_version` and `PROXY_KEY` in `.tf` |
| Key formats and rotation | Wrong formats, replace-on-rotate | 003 formats; create-if-absent; `--rotate` appends to the ring and refuses an existing id; blind-index rotation only with `--rotate-blind-index` (reindex); values never printed |
| Client IP trust | Spoofable client address behind the proxy | Worker sets `X-Swastik-Client-IP` from `CF-Connecting-IP` and `X-Swastik-Proxy-Key` from `PROXY_KEY`, strips incoming copies, answers 500 (no forward) without the key; `TRUSTED_PROXY_HOPS=1` |
| Admin access | Access app had no identity provider | One-time-PIN IdP in `allowed_idps` (owner enables Zero Trust OTP) |
| Production safety | Stray apply could delete the API | `deletion_protection = true` in production |
| CI supply chain | Mutable action tags, one job holding GCP and Cloudflare credentials | Third-party actions pinned to commit SHAs; Pages build/deploy in its own job without GCP auth; deploy by image digest; temporary `c-<sha>` tag removed with `if: always()` once created |
| Infra changes | Plan and apply in one step | Plan job publishes the plan; apply job needs owner approval on `infra`; plan artifact kept 1 day |
| Backups | Plaintext dumps in R2; counts from a different moment than the dump | Encrypted with `age` to `BACKUP_AGE_RECIPIENT` before upload; dump and counts share one exported snapshot |
| Database logins | App could rewrite audit and migration tables; backup could run functions | roles.sql: no UPDATE/DELETE on `audit_log` and `goose_db_version` (re-locked each run), no PUBLIC/backup EXECUTE, `service_role` revoked |
| Error reporting | Personal values in Sentry text | `beforeSend` scrubs email, mobile, PAN, JWT, bearer tokens in message, exceptions, breadcrumbs |
| Cache headers | Immutable assets also got no-cache | `! Cache-Control` detach on `/assets/*` and `/_expo/static/*` |

## Accepted residual risks

1. **actAs condition is not a hard limit.** `iam.serviceAccountAdmin` lets the tofu SA edit SA IAM policies, so a compromised tofu SA could grant itself actAs elsewhere. Mitigation: only the `infra` environment (owner approval, `stage`/`main`) can impersonate it. The condition still blocks accidents and unrelated service accounts.
2. **`run.app` is directly reachable** (ADR 0003: public invoker). `/internal/tick` is protected by OIDC in the app; the API trusts a client IP only when the request carries the proxy key, so a direct call cannot forge its address. Rate limits keyed on the IP therefore apply per real address only via the proxy.
3. **Cookie prefix `__Secure-` vs `__Host-`** is decided in feature 003 (cookie name and attributes), not here.
4. **Proxy key lives in Cloudflare and Secret Manager**, never in tofu state or logs. It is a shared secret, rotated with `--rotate-proxy` (old and new accepted by the API ring during the change).
5. **`tofuSecretMeta` includes `setIamPolicy`** on secrets, so the tofu SA could grant itself read access; same containment as item 1.

## IAM condition format (verified or not)

`bootstrap.sh` conditions `tofuActAs` on `resource.name`. Google documents service account resource names in conditions as `projects/<project>/serviceAccounts/<email>`, but this could not be confirmed offline here. The expression therefore uses `resource.name.contains('/serviceAccounts/api-') || ...contains('/serviceAccounts/tick-')`, which holds for `projects/<id>`, `projects/-` and `projects/_` spellings. If the first Infra apply reports a missing `iam.serviceAccounts.actAs`, the name is in unique-id form: replace the condition with the two exact SA resource names after they exist, via `gcloud projects add-iam-policy-binding` (owner step), and note it in the runbook.
