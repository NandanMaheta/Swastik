# Go contracts: 004 OTP delivery

Signatures the compile skeleton (S01) creates. Bodies are the slices' work. Names are binding for tests.

## 1. `internal/otp` (new module)

```go
type Purpose string
const (
    PurposeSignup        Purpose = "signup"         // email code + Firebase mobile proof (BR-CLI-04)
    PurposeChangeEmail   Purpose = "change_email"   // code to the NEW email (BR-CLI-05)
    PurposeChangeMobile  Purpose = "change_mobile"  // Firebase proof of the NEW mobile
    PurposePasswordReset Purpose = "password_reset" // code to the account email (D-06)
)

// Policy numbers (spec D-01..D-04, FR-001); tests reference these, never literals.
const (
    CodeTTL = 10 * time.Minute; MaxWrongAttempts = 5; ResendCooldown = 60 * time.Second
    VerificationTTL = 24 * time.Hour; ProofMaxAge = 5 * time.Minute; ProofClockLeeway = 30 * time.Second
    ResetTokenTTL = 10 * time.Minute
    TopicEmailCode = "otp.email_code"; TopicContactNotice = "otp.contact_notice"
    HousekeepingKind = "otp.housekeeping"
)

type Deps struct {
    Tx       db.TxRunner
    Now      clock.Func
    Accounts Accounts               // *auth.Service
    Outbox   Outbox                 // *outbox.Service
    Keyring  *crypto.Keyring        // PII ring: seals outbox payloads (FR-013)
    Digests  crypto.BlindIndexer    // OTP_HMAC_KEY: codes, limits, proof fingerprints (D-08)
    Proofs   firebaseauth.Verifier  // nil or Disabled() => ErrNotConfigured on mobile proofs
    Mailer   email.Mailer           // used by the outbox Sender
    Log      *slog.Logger
    Wait     func(ctx context.Context, until time.Time) // response floor; nil = real timer (tests pass a no-op)
}
func New(d Deps) (*Service, error)

// Accounts is the subset of auth.Accounts otp needs (satisfied by *auth.Service).
type Accounts interface {
    GetUser(ctx context.Context, id uuid.UUID) (auth.UserView, error)
    FindUser(ctx context.Context, identifier string) (auth.UserView, error)   // new in auth (section 5)
    DefaultOrg(ctx context.Context) (uuid.UUID, error)                       // new in auth (section 5)
    MarkEmailVerified(ctx context.Context, id uuid.UUID, by audit.Actor) (auth.Status, error)
    MarkMobileVerified(ctx context.Context, id uuid.UUID, by audit.Actor) (auth.Status, error)
    ResetPassword(ctx context.Context, id uuid.UUID, newPassword string, by audit.Actor) error
}

// Outbox is the subset of *outbox.Service otp needs.
type Outbox interface {
    Add(ctx context.Context, m outbox.Message) (bool, error)
    Withdraw(ctx context.Context, org uuid.UUID, topic, key string) (int, error)
    WithdrawSubject(ctx context.Context, org uuid.UUID, subject string) (int, error)
    DeliverNow(ctx context.Context, org uuid.UUID, topic, key string) (bool, error)
}

// --- in-process capability for 005 / 007 (join the caller's transaction when there is one) ---
type StartInput struct {
    OrgID, UserID uuid.UUID
    Purpose       Purpose   // signup | change_email | change_mobile (password_reset only via StartReset)
    NewContact    string    // change_* only; normalised with auth.NormalizeEmail/NormalizeMobile
    IP            string    // httpx.ClientIP of the request that caused the start (D-03 per-address limit)
}
type Started struct { ID uuid.UUID; Handle string; ExpiresAt time.Time }
func (s *Service) Start(ctx context.Context, in StartInput, by audit.Actor) (Started, error)
    // signup: user must be a pending_verification client (else ErrNotAllowed); targets = account email+mobile.
    // Supersedes the user's open flow of the same purpose. Queues the first email code (signup, change_email),
    // subject to D-03 limits (*RetryError). Returns ErrInvalidInput for a bad contact.
func (s *Service) Deliver(ctx context.Context, id uuid.UUID) error  // after commit: DeliverNow the live code email; no-op if none; must not run in a tx
func (s *Service) Get(ctx context.Context, id uuid.UUID) (View, error)   // View carries the readable targets for 007 (in-process only)
func (s *Service) Cancel(ctx context.Context, id uuid.UUID, by audit.Actor) error  // ends live code, withdraws its email
type ContactNotice struct { OrgID, UserID uuid.UUID; OldEmail string; Changed string /* "email" | "mobile" */ }
func (s *Service) NotifyOldContact(ctx context.Context, n ContactNotice, by audit.Actor) error // FR-014; respects quiet hours
func (s *Service) DailyCounts(ctx context.Context, org uuid.UUID, day istdate.Date) (DailyCounts, error) // FR-017

// --- handle-keyed operations behind HTTP ---
type Caller struct { IP string; UserID *uuid.UUID } // UserID set on /v1/me/* (must own the handle and purpose change_*)
func (s *Service) Status(ctx context.Context, c Caller, handle string) (View, error)
func (s *Service) Resend(ctx context.Context, c Caller, handle string) (ResendResult, error)
func (s *Service) VerifyEmail(ctx context.Context, c Caller, handle, code string) (VerifyEmailResult, error)
func (s *Service) VerifyMobile(ctx context.Context, c Caller, handle, idToken string) (View, error)
func (s *Service) StartReset(ctx context.Context, ip, identifier string) (ResetStarted, error)
func (s *Service) CompleteReset(ctx context.Context, ip, handle, resetToken, newPassword string) error

// Pure helpers (unit/property tests)
func GenerateCode(r io.Reader) (string, error)                       // 6 digits, uniform (rejection sampling)
func ApplyLimits(in LimitInput, now time.Time) LimitDecision          // data-model section 4
func MaskEmail(e string) string; func MaskMobile(m string) string
func HousekeepingNext(now time.Time) time.Time                        // next 03:15 IST

func Register(api huma.API, svc *Service, cfg HandlerConfig)          // HandlerConfig as auth's (hops, proxy secrets, limiter)
func RegisterJobs(r JobRegistrar, s *Service)
func (s *Service) Sender() outbox.Sender                              // registered for both topics, maxAttempts 3
```

## 2. Outbox Sender for `otp.*` (implements `outbox.Sender`)

- Payload (JSON, ≤ 8192 bytes): `{"v":1,"box":"<base64 Keyring.Seal(plain, aad)>"}`; `aad = topic + "|" + dedupe_key`. Plain JSON: `{"to":"<email>","code":"123456","purpose":"signup","expires_at":"…"}` (notice: no `code`, adds `"changed":"email|mobile"`). Messages are added with `SensitivePayload: true`; code emails also with `ExemptFromQuietHours: true` (FR-012) and `ExpiresAt = code expiry` (FR-011). Dedupe `otp:code:<code_id>` / `otp:notice:<uuidv7>`; subject `otp:<verification_id>`.
- `Send(ctx, e)`: open the box (failure ⇒ error, no detail); if `now ≥ expires_at` return nil without sending (outbox marks sent ⇒ payload erased; counted as neither sent nor failed); render the English template; `Mailer.Send(ctx, email.Mail{To, Subject, Text, IdempotencyKey: e.DedupeKey})`; on success count `email_sent`, on error `email_failed`, and return the error (retry until expiry). Never logs `to`, body, code or payload.
- Templates: subject "Your Swastik code: 123456"; body says the purpose, "expires in 10 minutes", "never share it", "ignore if you did not ask". Notice: "Your email/mobile on Swastik is being changed. If this was not you, contact the operator." No code, no new contact.

## 3. `internal/platform/email` (new, stdlib only)

```go
type Mail struct { To, Subject, Text string; IdempotencyKey string }
type Mailer interface { Send(ctx context.Context, m Mail) error }
var ErrRejected = errors.New("email: rejected")       // 4xx other than 429: permanent for this content
var ErrUnavailable = errors.New("email: unavailable") // 429, 5xx, network, timeout
func NewResend(apiKey, from string, opts ...ResendOption) Mailer  // POST https://api.resend.com/emails, Bearer key, Idempotency-Key header, 5 s timeout
func WithBaseURL(u string) ResendOption; func WithHTTPClient(c *http.Client) ResendOption
func Discard() Mailer                                  // local/ci without RESEND_API_KEY; sends nothing
```
Errors carry the status code only (no body echo, no recipient).

## 4. `internal/platform/firebaseauth` (new; go-oidc v3, already approved)

```go
type Proof struct { Subject, PhoneNumber, SignInProvider string; AuthTime, IssuedAt time.Time }
type Verifier interface { Verify(ctx context.Context, rawIDToken string) (Proof, error) }
var ErrInvalid = errors.New("firebaseauth: invalid token")
var ErrDisabled = errors.New("firebaseauth: not configured") // otp maps it to ErrNotConfigured
func New(ctx context.Context, projectID string, now func() time.Time, opts ...Option) Verifier // "" => Disabled()
func Disabled() Verifier                       // always returns ErrDisabled
func WithJWKSURL(u string) Option; func WithHTTPClient(c *http.Client) Option
```
Checks: RS256; `kid` in `https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com` (go-oidc `RemoteKeySet` caches/rotates); `iss = https://securetoken.google.com/<projectID>`; `aud = projectID`; `exp > now`; `sub` non-empty; `iat ≤ now + 30 s`. Claims read: `auth_time`, `phone_number`, `firebase.sign_in_provider`. otp then requires provider `phone`, `now − auth_time < 5 min` (and `auth_time ≤ now + 30 s`), `auth.NormalizeMobile(phone_number) == target`, unused fingerprint.

## 5. Changes to existing packages (additive)

- `outbox`: `Message.SensitivePayload bool`; `func (s *Service) DeliverNow(ctx, org uuid.UUID, topic, key string) (sent bool, err error)` (claims that one pending, available, unexpired message with the fenced claim, sends, marks; returns false if absent, claimed elsewhere or failed — a failure is recorded as a normal failed attempt; refuses to run in a tx). Admin retry of a sensitive message ⇒ `ErrConflict`. Expiry/claim changes per data-model section 6.
- `auth`: `func (s *Service) FindUser(ctx, identifier string) (UserView, error)` (normalises; `ErrInvalidIdentifier`, `ErrUserNotFound`) and `func (s *Service) DefaultOrg(ctx) (uuid.UUID, error)`; both added to `auth.Accounts`. No schema change.
- `platform/httpx`: `ErrorModel.RetryAfterSeconds int \`json:"retry_after_seconds,omitempty"\``; `func ProblemRetry(status int, code, detail string, after time.Duration) error` (implements `huma.HeadersError`, sets `Retry-After`).
- `platform/config`: `type OTPConfig struct { Enabled bool; Digests crypto.BlindIndexer; ResendAPIKey, EmailFrom, FirebaseProjectID, FirebaseJWKSURL string }` on `Config.OTP`, with `LogValue` hiding secrets. Staging/production: all of `RESEND_API_KEY`, `OTP_HMAC_KEY`, `OTP_EMAIL_FROM`, `FIREBASE_PROJECT_ID` or none (none ⇒ `Enabled=false`, operations answer `otp.not_configured`, warning at boot; partial ⇒ boot error); `FIREBASE_JWKS_URL` refused there. Local/ci: ephemeral HMAC key, `email.Discard()` without a key, Firebase disabled without a project id.
