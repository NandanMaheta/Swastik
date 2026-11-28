# Feature Specification: 004 OTP delivery (email OTP, mobile verification, rate limits)

**Feature Branch**: `feat/004-otp-delivery` · **Created**: 2026-11-26 · **Status**: Approved by owner 2026-11-26 · **Tier**: A (auth, PII)
**Module**: M1 Auth, row 004 in `docs/product/modules.md`; depends on 003; consumed by 005 (registration), 007 (contact changes), 024 (client auth screens)
**Rules**: BR-CLI-04, BR-CLI-05 (`docs/product/business-rules.md`). **Golden scenarios**: none affected (no money); GS-01…04 must keep passing.
**Sources**: `research.md` (this folder), ADR 0004, ADR 0007, product blueprint "Sign up / Forgot password / Change email or mobile" rows and "OTP delivery at ₹0", `specs/003-auth-core/spec.md` (D-02, D-09, D-13, FR-050…055, FR-091), `specs/002-scheduler-tick/spec.md` (FR-031 quiet hours).

## Questions for the owner (answer before the plan)

1. **Should OTP and password-reset emails ignore quiet hours (21:30–08:00 IST)?** 002's clarification lists overdue reminders (019) as the only planned exemption, so adding one is your call. **Recommend yes**: the person asked for the code a moment ago and it expires in 10 minutes, so holding it until 08:00 makes it useless. This spec assumes yes (FR-012).
2. **How should the readable code be held between "issued" and "sent"?** The email needs the plain code, so a copy waits in the outgoing-message queue until it is sent. **Recommend**: encrypt that copy with the existing PII key ring and erase it once the message is sent, withdrawn or expired. This needs a small change to 002's message queue (security-sensitive, so you approve it). The weaker alternative keeps it readable until 002's normal cleanup. This spec assumes the recommendation (FR-013).
3. **Do we need a second SMS provider in case Firebase fails?** **Recommend not now.** Run a real delivery test on staging (Jio, Airtel, Vi; Android and iPhone home-screen app) before 024 depends on it, and add an Indian DLT-registered provider (for example MSG91) as a separate feature only if that test fails. Adding one later means a new vendor and per-SMS cost. It would also let 007 send the BR-CLI-05 notice to an old mobile number by SMS, which 004 cannot do.

## Clarifications

### Session 2026-11-26 (settled from sources, no owner input needed)

- Q: How do pending registrants act on a verification when they cannot sign in? → A: Through the opaque verification handle returned to the app; change verifications also need the owner's session (003 D-09 blocks sign-in until `active`).
- Q: What does operations need to see? → A: Daily counts of code emails sent, failed and refused by limits, and mobile proofs accepted/refused, for the ops digest (automation blueprint, "Free-tier surprises": digest tracks email/SMS counts).


| ID | Decision | Source |
|----|----------|--------|
| D-01 | Email code: 6 digits, valid 10 minutes, single use; issuing a newer code for the same verification cancels the older one. | Blueprint "Sign up" (6 digits, 10 min); research §4 |
| D-02 | 5 wrong entries end a code; the person must ask for a new one. Resend waits 60 s after the previous send. | Research §4 (OWASP range 5–10) |
| D-03 | Send limits per contact: 5 per hour and 10 per IST day; per user: 10 per IST day across all contacts; per network address: 20 send requests and 60 check requests per hour. Limits hold across all server instances. | Research §4, §5, §8 (shared 100/day email budget) |
| D-04 | Mobile is proved with Firebase phone sign-in on the device; the server accepts the proof only if it was issued for our Firebase project, by phone sign-in, within the last 5 minutes, has never been used before, and its number equals the number being verified. Firebase never becomes a sign-in session. | ADR 0004; research §2 |
| D-05 | At sign-up the mobile step is accepted only after the email step succeeded (protects SMS cost). 003 still accepts either order at its own level. | Blueprint "Sign up" order; research §3 |
| D-06 | Forgot password: the person enters email or mobile; the code always goes to the account's email, never by SMS. Only `active` clients can reset; anyone else gets the same reply and no email. Admins are excluded (TOTP accounts, 003 D-22). A reset ends all sessions (003 D-13). | Blueprint "Forgot password" and "Use SMS only at sign-up and when a mobile number changes"; 003 US-7, D-13, D-22 |
| D-07 | Replies to "send", "resend" and "start reset" look the same, with comparable timing, whether or not the account or contact exists; limits apply to unknown identifiers in the same way. | 003 D-09; research §4 (OWASP) |
| D-08 | Codes are stored only as a keyed digest tied to the verification and purpose; codes, contacts and Firebase proofs never appear in logs, audit, errors or responses. | ADR 0007 point 3; 003 FR-091; constitution VI |
| D-09 | 004 marks contacts verified (003 FR-051) only for sign-up. For contact changes it only reports "new contact proved"; 007 runs the approval and replaces the contact (003 FR-055). | BR-CLI-05; 003 D-01 |

## User Scenarios & Testing

### User Story 1 - Verify email with a code at sign-up (Priority: P1)
A new client who has just registered (005) gets a 6-digit code by email, enters it, and their email is marked verified.
**Why P1**: BR-CLI-04 blocks every client until email is verified. **Independent test**: create a pending user through 003, start a sign-up verification, read the queued email in a fake sender, verify the code.
**Acceptance Scenarios**:
1. **Given** a `pending_verification` client and a new sign-up verification, **When** it starts, **Then** exactly one email with a 6-digit code is queued to that client's email, and an "OTP issued" audit entry is written without the email or the code (BR-CLI-04).
2. **Given** a code issued at 10:00:00, **When** the correct code is entered at 10:09:59, **Then** the email is marked verified; **When** entered at 10:10:00, **Then** it is rejected as expired and nothing changes (D-01).
3. **Given** a verified code, **When** it is entered again (also two entries at the same moment), **Then** exactly one succeeds and the other is rejected (single use).
4. **Given** a code, **When** 5 wrong codes are entered, **Then** the 5th reply says the code is used up, and the correct code entered afterwards is rejected (D-02).
5. **Given** the email is verified and the mobile is verified later, **Then** the client moves to `pending_approval` and still cannot sign in until the admin approves (003 D-02, BR-CLI-04).

### User Story 2 - Resend a code with a cooldown (Priority: P1)
A client who did not get the email asks for a new code.
**Independent test**: fake clock; request resends at 59 s, 60 s, and past the hourly limit.
**Acceptance Scenarios**:
1. **Given** a code sent at 10:00:00, **When** a resend is asked at 10:00:59, **Then** it is refused with "wait 1 s"; **at 10:01:00**, **Then** a new code is queued, the old code stops working, and the old email is withdrawn if not yet sent (D-01, D-02).
2. **Given** 5 sends to one contact in the last hour, **When** a 6th is asked, **Then** it is refused with the time the next send is allowed, and no email is queued (D-03).
3. **Given** 20 send requests from one network address in an hour across different identifiers, **When** a 21st arrives, **Then** it is refused, whatever the identifier (D-03).
4. **Given** a resend at 23:00 IST, **Then** the email is sent at once, not at 08:00 (owner question 1, assumed yes).

### User Story 3 - Verify the mobile number via Firebase (Priority: P1)
After the email step, the client proves their mobile with the SMS code Firebase sends to their phone; the app passes Firebase's proof to us.
**Independent test**: signed test proofs from a fake key set; real Firebase test numbers in staging.
**Acceptance Scenarios**:
1. **Given** a sign-up verification with email verified and a fresh proof for the same number, **When** submitted, **Then** the mobile is marked verified and a "mobile verified" audit entry is written without the number (BR-CLI-04, D-04).
2. **Given** the email is not yet verified, **When** a proof is submitted, **Then** it is refused and nothing changes (D-05).
3. **Given** a proof for +91 98123 45679 and a registered +91 98123 45678, **Then** it is refused as "different number"; the reply does not echo either number (D-04, D-08).
4. **Given** a proof signed in 6 minutes ago, or for another Firebase project, or not from phone sign-in, or already used once, **Then** it is refused (D-04).
5. **Given** an Android app proof and an iPhone home-screen app proof for the right number, **Then** both are accepted the same way.

### User Story 4 - Forgot password (Priority: P2)
A client who forgot their password enters email or mobile, gets a code by email, and sets a new password.
**Acceptance Scenarios**:
1. **Given** an `active` client, **When** they start a reset with their mobile number, **Then** a code is queued to their email; after the right code they may set one new password within 10 minutes, all their sessions end, any lock clears (D-06, 003 D-13).
2. **Given** an unknown identifier, a `pending_approval` or `disabled` client, or an admin, **When** a reset is started, **Then** the reply looks the same as case 1 and no email is sent, and no audit entry names the identifier (D-06, D-07).
3. **Given** a reset already completed, **When** the same code or permission is used again, **Then** it is refused.

### User Story 5 - Prove a new contact for a change (Priority: P2)
A signed-in client changing email or mobile (007) proves they control the new contact; 007 then sends it for approval.
**Acceptance Scenarios**:
1. **Given** 007 starts a change-email verification for a new address, **Then** the code goes to the new address only and the account keeps its old email until 007 applies the approved change (BR-CLI-05, D-09).
2. **Given** a change-mobile verification, **When** a valid proof for the new number arrives with the same client's session, **Then** the verification is "proved" and the account's mobile is unchanged; with another client's session it is refused.
3. **Given** the new contact already belongs to another user, **When** proof succeeds, **Then** it is refused as "contact unavailable" without saying whose it is (003 D-18).

### User Story 6 - Audit and abuse visibility for the admin (Priority: P3)
**Acceptance Scenarios**:
1. **Given** any issue, resend, verify, failure, throttle, reset or cancel on a known user, **Then** one audit entry records the user, purpose, outcome, reason code and the network address (as 003's sign-in audit does), and no contact, code or proof (D-08).

### Edge Cases
- **Time windows**: code expiry, resend cooldown, Firebase 5-minute freshness and hourly/daily windows are tested at the exact boundary (inclusive start, exclusive end); daily limits reset at 00:00 IST.
- **Email delayed**: a code email that is still unsent when the code expires is never sent; a failed send is retried until expiry, then dropped; the client can resend.
- **Shared email budget**: if the provider refuses for its daily cap, the send fails quietly for the client ("try again later") and is counted for the ops digest.
- **Corrections**: a mistyped email or mobile at sign-up cannot be fixed here; 005 cancels the verification and starts a new one with the corrected contact. A contact already verified stays verified.
- **Approvals pending**: verifying never approves anyone; a client in `pending_approval` who starts a new sign-up verification is refused.
- **iPhone vs Android**: the server treats proofs from both identically; iPhone home-screen app Firebase behaviour is a spike before 024 (research §2).
- **Abandoned flows**: a verification lives 24 hours; after that every action on it is refused and 005/007 start a new one.

## Requirements

### Functional Requirements
- **FR-001** (BR-CLI-04, BR-CLI-05): Offer verification purposes: sign-up email, sign-up mobile, change email, change mobile, password reset. Each verification belongs to one user and one target contact and expires 24 hours after start.
- **FR-002**: Issue 6-digit uniformly random email codes valid 10 minutes, single use, cancelled by a newer code (D-01).
- **FR-003**: End a code after 5 wrong entries (D-02).
- **FR-004**: Enforce the resend cooldown and the per-contact, per-user and per-address limits of D-03, durable across server instances, including for unknown identifiers.
- **FR-005** (BR-CLI-04): Accept a mobile proof only under D-04 and, at sign-up, only after email (D-05); store a fingerprint of each used proof so it works once.
- **FR-006** (BR-CLI-04): On sign-up success, mark the contact verified through 003 FR-051 in the same step.
- **FR-007** (BR-CLI-05): On change success, mark the verification "proved" and leave the account unchanged; refuse if the contact belongs to another user.
- **FR-008**: Password reset per D-06, granting one new-password action valid 10 minutes, applied through 003 FR-053.
- **FR-009**: Keep replies and timing uniform per D-07; typed identifiers never appear in replies.
- **FR-010**: Audit every event in US-6 with stable reason codes (`wrong_code`, `expired`, `used_up`, `cooldown`, `rate_limited`, `number_mismatch`, `stale_proof`, `replayed_proof`, `contact_unavailable`); nothing for unmatched identifiers (003 FR-091).
- **FR-011**: Queue each code email in the same commit as the code; send through 002's outgoing-message relay via the email provider (Resend); the queued message expires with the code; a newer code withdraws the older message.
- **FR-012**: Code and reset emails ignore quiet hours (owner question 1).
- **FR-013**: Never store a code readably at rest beyond the queued message, which is encrypted and erased on send, withdrawal or expiry (owner question 2).
- **FR-014**: Offer an "old contact notice" email (no code) for 007 (BR-CLI-05).
- **FR-015**: Purge expired codes, proofs and verifications daily, keeping audit entries.
- **FR-016**: Error codes for every refusal are shared with the client apps (`packages/domain`) with calm wording ("Please wait 40 seconds", "That code has expired").
- **FR-017**: Expose daily counts of code emails sent, failed and limit-refused, and mobile proofs accepted/refused, to the ops digest (no identifiers).

### Capabilities offered to other features (contract level; shapes belong in the plan's `contracts/`)
- **Service (in-process, for 005/007)**: start verification (user, purpose, target contact) returning an opaque handle and queuing the first code for email purposes; read status (per contact: pending, proved/verified, expired; next resend time; masked contact); cancel; send old-contact notice.
- **HTTP (client app, 024)**: read verification status; resend email code; verify email code; verify mobile with a Firebase proof; start password reset (public; always returns a handle); complete password reset with the one-time permission and a new password. Sign-up and reset operations are public and keyed by the handle; change operations also require the owner's signed-in session.

### Key Entities
- **Verification**: user, purpose, target contact, state per contact, created/expires, cancelled.
- **Email code**: verification, keyed digest, issued/expires, wrong-entry count, used.
- **Used mobile proof**: fingerprint, verification, used at.
- **Limit counter**: key (contact, user or address), window, count.

## Success Criteria
- **SC-001**: Every time rule (10-minute code, 60 s cooldown, 5-minute proof freshness, hourly/daily limits, 24-hour verification) passes fake-clock tests at the boundary ±1 s with no real waiting.
- **SC-002**: In staging, 95% of code emails reach the inbox within 60 s of the request, including requests made in quiet hours.
- **SC-003**: Zero contacts, codes or proofs in audit, logs, errors or replies across the full test suite (automated scan, as 003).
- **SC-004**: Known and unknown identifiers get identical reply shapes and statuses; median timing differs by less than 10% (same bound as 003 SC-003).
- **SC-005**: One network address can trigger at most 20 emails per hour; normal use by ~100 clients stays under 30 emails per day (provider free cap 100/day).
- **SC-006**: A client completes both sign-up verifications in under 3 minutes on Android and on the iPhone home-screen app (UAT).

## Assumptions
- 003 is merged: users, statuses, FR-051/053/055, durable throttle records, audit and PII key ring exist. 002's relay supports per-message quiet-hours exemption, expiry and withdrawal.
- Domain `mail.swastikapp.co.in` is verified on Resend; Firebase project `swastik-4fcc9` is on the Blaze plan with SMS limited to India and test numbers for staging/CI (research §3).
- 005 decides how an abandoned registrant resumes; 007 decides how long a proved change waits for approval.
- **New configuration names (no values)**: secrets `RESEND_API_KEY`, `OTP_HMAC_KEY`; settings `OTP_EMAIL_FROM`, `FIREBASE_PROJECT_ID`, `FIREBASE_JWKS_URL` (test override only); reuses `PII_ENCRYPTION_KEYS`. Feature 027's `infra/bootstrap/secrets.sh` and the OpenTofu Secret Manager/Cloud Run definitions must add them; the owner creates the values.
- No new server dependencies are expected (research §6); client Firebase packages are 024's owner-approved additions.

## Out of Scope
- Registration form, approval queue and welcome message (005); contact-change requests, approval and the old-mobile notice channel (007); all screens (024, 022).
- SMS sent by us, SMS fallback provider, WhatsApp, voice codes; OTP as a sign-in factor or passwordless login; admin password reset.
- Automated IPO applying, SME IPOs, any money or ledger behaviour.
- Firebase console settings (App Check, reCAPTCHA, region policy) beyond recording them in the runbook.
