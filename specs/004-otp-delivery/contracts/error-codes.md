# Error codes: 004 OTP delivery

Stable problem codes (RFC 9457 `code`), added to `packages/domain/src/otp-error-codes.ts` (FR-016) with calm English wording; Gujarati/Hindi come with 024. Adding a code is non-breaking. Details never contain a contact, code, handle, token or proof (D-08, FR-009). Go: `internal/otp/errors.go` (sentinels + `ProblemFor`).

| Code | HTTP | Go sentinel | Audit reason | Wording (domain) |
|---|---|---|---|---|
| `otp.verification_invalid` | 404 | `ErrNotFound` | none | "This verification is not valid. Please start again." |
| `otp.verification_expired` | 410 | `ErrVerificationExpired` | `expired` | "This verification has expired. Please start again." |
| `otp.nothing_to_send` | 409 | `ErrNothingToSend` | none | "There is nothing to send for this step." (email already done, or a mobile-only flow) |
| `otp.cooldown` | 429 | `*RetryError{Reason: cooldown}` | `cooldown` | "Please wait {seconds} seconds before asking for a new code." |
| `otp.rate_limited` | 429 | `*RetryError{Reason: rate_limited}` | `rate_limited` | "Too many codes were requested. Please try again in {minutes} minutes." |
| `otp.code_wrong` | 422 | `ErrCodeWrong` | `wrong_code` | "That code is not correct. Please check it and try again." |
| `otp.code_expired` | 422 | `ErrCodeExpired` | `expired` | "That code has expired. Ask for a new one." (also superseded or already used) |
| `otp.code_used_up` | 422 | `ErrCodeUsedUp` | `used_up` | "Too many wrong tries. Ask for a new code." |
| `otp.email_first` | 409 | `ErrEmailFirst` | none | "Please verify your email first." (D-05) |
| `otp.proof_invalid` | 422 | `ErrProofInvalid` | `invalid_proof` | "We could not confirm your mobile number. Please try again." |
| `otp.proof_stale` | 422 | `ErrProofStale` | `stale_proof` | "That confirmation is too old. Please request a new SMS code." |
| `otp.proof_replayed` | 422 | `ErrProofReplayed` | `replayed_proof` | "That confirmation was already used. Please request a new SMS code." |
| `otp.number_mismatch` | 422 | `ErrNumberMismatch` | `number_mismatch` | "The number you confirmed is different from the one on your account." |
| `otp.contact_unavailable` | 409 | `ErrContactUnavailable` | `contact_unavailable` | "This email or mobile number cannot be used. Please choose another." (003 D-18) |
| `otp.reset_token_invalid` | 422 | `ErrResetTokenInvalid` | none | "This reset link has expired or was already used. Please start again." |
| `otp.not_configured` | 503 | `ErrNotConfigured` | none | "This step is not available right now. Please try again later." |

Reused: `auth.identifier_invalid` (reset start, malformed identifier only), `auth.password_*` policy codes and `auth.busy` (reset complete, through `auth.ProblemFor`), `rate_limited` (in-memory per-IP burst limiter), `validation_failed`.

Go-only (service callers 005/007, never HTTP): `ErrNotAllowed` (Start on a user whose status does not allow the purpose, e.g. sign-up for a `pending_approval` client), `ErrInvalidInput`.

`RetryError` carries `RetryAfter time.Duration`; `ProblemFor` rounds up to whole seconds and uses `httpx.ProblemRetry` (sets `Retry-After` and `retry_after_seconds`). The `{seconds}`/`{minutes}` placeholders are filled by `otpErrorMessage(code, {retryAfterSeconds})`.

Audit reason `invalid_proof` is added to the spec's FR-010 list for Firebase tokens that fail signature, project or provider checks (no new behaviour; it names an existing refusal).
