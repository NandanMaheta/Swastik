# Staging setup guide (one time)

This guide makes staging live: `api-staging`, `admin-staging` and `app-staging` on `swastikapp.co.in`. Production uses the same steps later, with `production` in place of `staging`. Each step is done by you; agents never touch the cloud.

**Before you start**

- Merge PR #11 (027) into `stage`. Deploys stay switched off until the very last step, so merging first is safe. The **Infra** workflow can only be started once it is on `stage`.
- Allow about 1.5 hours. Do the parts in order: later steps use names and values from earlier ones.
- Rules for secret values (passwords, tokens, keys):
  - Paste them only into the Google Cloud Shell prompts, the GitHub secret fields or the Cloudflare and Supabase pages named below.
  - Never paste them into chat, a file, or an issue.
- Keep a private note of the **non-secret** values you collect, such as IDs and URLs. The table at the end shows where each one goes.

---

## Part 1: Supabase staging (about 10 min)

Project: **staging** (ref `hddzoasgsdtvdzauxfbo`).

1. **Postgres version.** Nothing to do: Supabase runs Postgres 17 and Swastik is built for 17 (ADR 0010). Upgrading to the 17.12 minor release (Project Settings → Infrastructure) is optional.
2. **Switch off the Data API.** Go to Integrations → Data API (or Project Settings → Data API) and turn off **Enable Data API**. If the project is paused, Restore it first. The app talks to Postgres directly, so nothing else should be reachable.
3. **Get the two connection strings.** Click **Connect** at the top of the project, then **Session pooler**, and copy the URI. It looks like `postgresql://postgres.hddzoasgsdtvdzauxfbo:[YOUR-PASSWORD]@aws-…pooler.supabase.com:5432/postgres`.
   - **Migration URL:** that URI with your database password in place of `[YOUR-PASSWORD]`. If you don't know the password, reset it under Project Settings → Database → Reset database password. This becomes the GitHub secret `MIGRATE_DATABASE_URL` in Part 5.
   - **App URL:** the same URI with the user `postgres.hddzoasgsdtvdzauxfbo` replaced by `swastik_app.hddzoasgsdtvdzauxfbo`, and the password you create in Part 2, step 4. You'll paste it once into `secrets.sh`.

## Part 2: Google Cloud (about 20 min)

Project `swastik-4fcc9`. Open **Cloud Shell**: the `>_` icon at the top right of console.cloud.google.com.

1. **Get the code into Cloud Shell.** The repository is private, so first create a read-only token on GitHub:
   - Go to Settings → Developer settings → Fine-grained tokens → **Generate new token**.
   - Name it `cloud-shell-read`, set it to expire in 7 days, and set Repository access to **Only select repositories → Swastik**.
   - Under Permissions, set **Contents: Read-only**. Generate it and copy it.
   - In Cloud Shell, run:

     ```bash
     git clone https://github.com/NandanMaheta/Swastik.git && cd Swastik
     ```
   - When asked, the username is `NandanMaheta` and the password is the token. Delete the token on GitHub when setup is done.
2. **Pick the project.**

   ```bash
   gcloud config set project swastik-4fcc9
   ```
3. **Bootstrap.** First read what the script will do, then run it for real:

   ```bash
   bash infra/bootstrap/bootstrap.sh --dry-run
   ```

   ```bash
   bash infra/bootstrap/bootstrap.sh
   ```

   It turns on the needed APIs and creates:
   - the state bucket `swastik-4fcc9-tofu-state`;
   - the GitHub sign-in pool;
   - the `tofu` service account.

   The last line prints two values, **GCP_WIF_PROVIDER** and **GCP_TOFU_SA**. Note both for Part 5.
4. **Database roles.** Run this, pasting the migration URL from Part 1 between the quotes:

   ```bash
   psql "<the migration URL from Part 1>" -f infra/supabase/roles.sql
   ```

   Then open a psql session the same way:

   ```bash
   psql "<the migration URL from Part 1>"
   ```

   At the `postgres=>` prompt, type `\password swastik_app`, choose a strong password (it is hidden as you type), then `\q`. Put this password into the app URL from Part 1.
5. **Budget alert.** Go to Billing → Budgets & alerts → **Create budget**. Name it `swastik`, choose project `swastik-4fcc9`, set the amount to ₹100, and add alert thresholds at 1 %, 50 % and 100 %. Any spend at all then emails you.

Leave Cloud Shell open. You'll come back to it in Part 3 and Part 6.

## Part 3: Cloudflare (about 20 min)

Use dash.cloudflare.com, account with zone `swastikapp.co.in`.

1. **IDs.** Open `swastikapp.co.in` → Overview. In the right-hand column under **API**, note the **Zone ID** and the **Account ID**.
2. **Zero Trust and one-time PIN.** This is the login screen in front of the admin panel.
   - Go to **Zero Trust** in the left menu. On first use, pick a team name (for example `swastik`) and the **Free** plan.
   - Then go to Zero Trust → Settings → Authentication → Login methods → **Add new** → **One-time PIN** → Save.
3. **Payment method for R2.** Backups are stored in R2. Go to **R2** in the left menu, add a card when asked, and switch R2 on. It stays on the free tier (10 GB), and the ₹100 budget in Part 2 does not cover Cloudflare.
4. **Token for OpenTofu.** Go to My Profile (top right) → API Tokens → **Create Token** → **Create Custom Token**. Name it `swastik-tofu` and add these permissions:
   - Zone → DNS → Edit
   - Zone → Workers Routes → Edit
   - Account → Workers Scripts → Edit
   - Account → Cloudflare Pages → Edit
   - Account → Access: Apps and Policies → Edit
   - Account → Workers R2 Storage → Edit

   For Zone Resources, choose Include → Specific zone → `swastikapp.co.in`. Create it and copy it: this is **CLOUDFLARE_TOFU_TOKEN**.
5. **Token for website deploys.** Create one more custom token, `swastik-pages`, with only Account → Cloudflare Pages → Edit. This is **CLOUDFLARE_PAGES_TOKEN**.
6. **Secrets for staging.** Back in Cloud Shell (inside `Swastik`), run:

   ```bash
   read -rsp "Cloudflare tofu token: " CLOUDFLARE_API_TOKEN && export CLOUDFLARE_API_TOKEN && echo
   ```

   ```bash
   bash infra/bootstrap/secrets.sh staging --with-auth
   ```

   When asked, paste the **app URL** (the one with `swastik_app`). The script creates every key itself: the database URL, the login and encryption keys, and the proxy key. Nothing is printed. A warning that the Worker doesn't exist yet is expected; Part 6 fixes it.

## Part 4: Sentry (2 min)

In Sentry, go to Settings → Projects → `swastik-api` → Client Keys (DSN) and copy the DSN. This is **SENTRY_DSN**. It isn't secret, so it goes in a variable.

## Part 5: GitHub settings (about 20 min)

Everything is in github.com/NandanMaheta/Swastik → **Settings**.

1. **Environments.** Go to Settings → Environments.
   - **`infra`:** create it. Under Required reviewers add yourself. Under Deployment branches choose **Selected branches and tags**, then add `stage` and `main`.
   - **`staging`:** it already exists. Under Deployment branches, choose **Selected branches** and add `stage`.
   - **`production`:** leave it as it is for now.
2. **Variables and secrets of `infra`.** Open the environment and add these.

   | Variable                | Value                                         |
   | ----------------------- | --------------------------------------------- |
   | `GCP_PROJECT_ID`        | `swastik-4fcc9`                               |
   | `GCP_WIF_PROVIDER`      | from bootstrap (Part 2, step 3)               |
   | `GCP_TOFU_SA`           | from bootstrap (Part 2, step 3)               |
   | `CLOUDFLARE_ACCOUNT_ID` | Part 3, step 1                                |
   | `CLOUDFLARE_ZONE_ID`    | Part 3, step 1                                |
   | `ACCESS_ALLOWED_EMAILS` | your email (comma-separated if more than one) |
   | `SENTRY_DSN`            | Part 4                                        |

   | Secret                  | Value          |
   | ----------------------- | -------------- |
   | `CLOUDFLARE_TOFU_TOKEN` | Part 3, step 4 |

3. **Variables and secrets of `staging`.**

   | Variable                | Value                                                  |
   | ----------------------- | ------------------------------------------------------ |
   | `GCP_PROJECT_ID`        | `swastik-4fcc9`                                        |
   | `GCP_WIF_PROVIDER`      | same as for infra                                      |
   | `GCP_DEPLOY_SA`         | `deploy-staging@swastik-4fcc9.iam.gserviceaccount.com` |
   | `CLOUD_RUN_SERVICE`     | `swastik-api-staging`                                  |
   | `API_BASE_URL`          | `https://api-staging.swastikapp.co.in`                 |
   | `ADMIN_PAGES_PROJECT`   | `swastik-admin-staging`                                |
   | `CLIENT_PAGES_PROJECT`  | `swastik-app-staging`                                  |
   | `CLOUDFLARE_ACCOUNT_ID` | Part 3, step 1                                         |

   | Secret                   | Value                                               |
   | ------------------------ | --------------------------------------------------- |
   | `MIGRATE_DATABASE_URL`   | the migration URL from Part 1 (the `postgres` user) |
   | `CLOUDFLARE_PAGES_TOKEN` | Part 3, step 5                                      |

   Remove the old variables `APP_ENV`, `TICK_AUDIENCE` and `TICK_SERVICE_ACCOUNT` if they exist. OpenTofu sets those now.
4. **Don't set the repository-level `GCP_PROJECT_ID` yet.** It is the switch that turns on deploys, so it comes in Part 7.

## Part 6: Create the cloud resources (about 15 min)

1. Go to GitHub → **Actions** → **Infra** → **Run workflow**, with branch `stage` and target **`shared`**.
   - The **plan** job asks for your approval. Approve it and read the plan in the run's summary.
   - Then the **apply** job asks for your approval. Approve it.
   - This creates the image registry and the R2 backup bucket.
2. Do the same again with target **`staging`**. This creates:
   - the Cloud Run service and its service accounts;
   - the scheduler (every 5 minutes);
   - DNS, the Worker and the two Pages projects;
   - the Access login on the admin site.
3. **Send the proxy key to the Worker**, now that the Worker exists. In Cloud Shell, run:

   ```bash
   bash infra/bootstrap/secrets.sh staging --with-auth
   ```

   It changes no secrets. It only pushes the stored proxy key to the Worker. `CLOUDFLARE_API_TOKEN` must still be set from Part 3; if Cloud Shell was closed, run the `read -rsp` line again first.

## Part 7: Switch on deploys and check (about 10 min)

1. Go to Settings → Secrets and variables → Actions → **Variables** tab → **Repository variables** → New: `GCP_PROJECT_ID` = `swastik-4fcc9`. Deploys and nightly jobs now run.
2. Go to Actions → **Deploy** → **Run workflow** on `stage`, or merge any small PR into `stage`. Watch it: migrations, a new revision, the readiness check, the traffic switch, the health check, then Pages.
3. Check these three addresses in a browser:
   - `https://api-staging.swastikapp.co.in/healthz` shows `ok`.
   - `https://admin-staging.swastikapp.co.in` asks for your email, then a PIN sent to it, then shows the admin app.
   - `https://app-staging.swastikapp.co.in` shows the client web app.
4. **Uptime alert.** Create a free account at uptimerobot.com. Add an HTTPS monitor on `https://api-staging.swastikapp.co.in/healthz`, checking every 5 minutes, with alerts to your email.
5. Tell me it's done, with the Postgres version from Part 1. I'll then create your first admin account with you (`swastik admin create`), and mark staging as live in the handover.

## Part 8: Sign-up codes by email and SMS (feature 004, about 15 min)

Do this once feature 004 is deployed. Until then the API answers that sign-up verification is not available, which is safe.

1. **Resend.** In resend.com, check that the domain `mail.swastikapp.co.in` shows as verified, then create an API key (Sending access) and keep the tab open for the next step. The free plan sends 100 emails a day.
2. **Firebase.** In the Firebase console for project `swastik-4fcc9`, go to Authentication → Sign-in method and make sure **Phone** is on. Under Settings → SMS region policy, allow **India** only. Add a couple of test phone numbers for staging.
3. **Secrets.** In Cloud Shell (inside `Swastik`, with `CLOUDFLARE_API_TOKEN` still set if you want the Worker check to run), run:

   ```bash
   bash infra/bootstrap/secrets.sh staging --with-otp
   ```

   Paste the **app URL** when asked, then paste the **Resend key** at the second prompt. Both stay hidden and nothing is printed. The script creates the other key (the one that protects the codes) itself and leaves everything that already exists alone.
4. **Switch it on.** I will open a small change that sets `otp_enabled = true` for staging. Merge it, then run Actions → **Infra** → target **`staging`** and approve.
5. **Try it on a real phone** (Android and iPhone home-screen app) once the client app screens exist, and tell me how long the email and the SMS took.

## If something fails

- Copy the **name of the failed step** and the **red error lines** from the Actions log, or the Cloud Shell output, and send them to me. Error text never contains secret values. If you think it might, remove the value first.
- Re-running any script or workflow is safe: everything is written to create things only when they're missing.

## Where each value goes (no secrets in this table)

| Value                              | Where from          | Goes to                             |
| ---------------------------------- | ------------------- | ----------------------------------- |
| WIF provider, tofu SA              | bootstrap output    | `infra` vars                        |
| Zone ID, Account ID                | Cloudflare overview | `infra` and `staging` vars          |
| Sentry DSN                         | Sentry client keys  | `infra` var                         |
| Your email                         | you                 | `infra` var `ACCESS_ALLOWED_EMAILS` |
| Resend API key                     | Resend dashboard    | `secrets.sh --with-otp` prompt only |
| Deploy SA, service and Pages names | this guide          | `staging` vars                      |
