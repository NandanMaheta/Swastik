# ADR 0009: Hosting topology and infrastructure ownership

- Status: Accepted (2026-11-15, feature 027; owner approved spec and plan, including Sentry and the Secret Manager cost)

## Context

The constitution fixes the hosting stack (Cloud Run in Mumbai, Supabase Postgres, Cloudflare Pages/Access/R2) and a ₹0 target. Open points were: how environments are separated, who changes cloud configuration, how the API gets an address on `swastikapp.co.in` (003 needs the admin and API on one registrable domain), and how the database login is limited.

## Decision

- One GCP project (`swastik-4fcc9`) for staging and production, separated by name suffix and per-environment service accounts with resource-level IAM only.
- OpenTofu owns all cloud configuration (state in GCS). CI deploys only images and static sites. Tofu applies run in a GitHub environment that needs owner approval. GitHub authenticates with Workload Identity Federation only.
- Secret values are created by an owner-run script straight into Secret Manager; tofu references them by name and never stores values.
- The API's public address is a Cloudflare Worker route that forwards to the `run.app` URL (Cloud Run domain mappings are not offered in asia-south1; a load balancer is not ₹0). The Worker blocks `/internal/*`; Cloud Scheduler calls the `run.app` URL directly.
- The API connects to Supabase through the session pooler as a role with row rights only; migrations use the owner role from CI before the new revision gets traffic.

## Consequences

Adding configuration for a feature is an infra PR plus an owner-approved apply. A second GCP project for production can be introduced later by pointing the production root at it. Requests through the proxy add a few milliseconds. If the product outgrows free tiers, the same modules move to a load balancer or a VM by changing tofu, not app code.

Sentry (`sentry-go`, confined to `internal/platform/observe`) reports ERROR logs; an empty `SENTRY_DSN` turns it off. Operations are in `docs/engineering/runbook.md`.
