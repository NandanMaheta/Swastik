# Quickstart: validate 004 OTP delivery

Prerequisites: Docker (for `dbtest`), Go 1.27, pnpm. Run from the worktree root.

1. Schema and queries: `cd apps/api && sqlc generate && sqlc vet && go test -race ./internal/otp/schema/... ./internal/outbox/...` — outbox erase trigger, expiry and `DeliverNow` tests pass (data-model §6).
2. Module: `cd apps/api && go test -race ./internal/otp/... ./internal/platform/email/... ./internal/platform/firebaseauth/...` — US1–US6 scenarios with the fake clock, fake mailer and minted Firebase tokens.
3. Contract: `cd apps/api && go test -race ./cmd/swastik/...` then `pnpm --filter @swastik/api-client generate && pnpm turbo run typecheck test --filter @swastik/domain --filter @swastik/api-client`.
4. Lint boundaries: `make lint-go && bash scripts/check-lint-boundaries.sh`.
5. Infra: `bash infra/bootstrap/test.sh` and `cd infra/tofu && tofu test` (module `env`).
6. Golden: `cd apps/api && go test -race -run 'GS_0' ./...`.
7. Staging (owner, after G-SECRETS): register a test client through 005 once it exists, or call `POST /v1/password-reset/start` for an active test client; the code email arrives within 60 s, also at 23:00 IST; a Firebase test number proves the mobile; the outbox row shows `payload = {}` after sending. Record the real-device SMS test (Jio, Airtel, Vi; Android and iPhone PWA) in `docs/engineering/runbook.md`.
