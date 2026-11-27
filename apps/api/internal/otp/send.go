package otp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/outbox"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/crypto"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/db"
)

// sealedPayload is the whole outbox payload of an otp message: the content is one AES-GCM box
// (FR-013). The box is erased with the message when it is sent, withdrawn, expired or dead.
type sealedPayload struct {
	V   int    `json:"v"`
	Box string `json:"box"`
}

// mailContent is what is sealed: the recipient, and for a code its value, purpose and expiry.
type mailContent struct {
	To        string `json:"to"`
	Code      string `json:"code,omitempty"`
	Purpose   string `json:"purpose,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Changed   string `json:"changed,omitempty"`
}

// aad binds a box to its message, so a box copied to another row does not open.
func aad(topic, key string) []byte { return []byte(topic + "|" + key) }

func (s *Service) seal(topic, key string, c mailContent) (sealedPayload, error) {
	plain, err := json.Marshal(c)
	if err != nil {
		return sealedPayload{}, fmt.Errorf("otp: encode message: %w", err)
	}
	box, err := s.d.Keyring.Seal(plain, aad(topic, key))
	if err != nil {
		return sealedPayload{}, fmt.Errorf("otp: seal message: %w", err)
	}
	return sealedPayload{V: 1, Box: base64.StdEncoding.EncodeToString(box)}, nil
}

// open reads a sealed payload. Failures carry no detail: never the payload, key or content.
func (s *Service) open(env outbox.Envelope) (mailContent, error) {
	errUnreadable := errors.New("otp: message is not readable")
	var p sealedPayload
	if err := json.Unmarshal(env.Payload, &p); err != nil || p.V != 1 || p.Box == "" {
		return mailContent{}, errUnreadable
	}
	box, err := base64.StdEncoding.DecodeString(p.Box)
	if err != nil {
		return mailContent{}, errUnreadable
	}
	plain, err := s.d.Keyring.Open(box, aad(env.Topic, env.DedupeKey))
	if err != nil {
		return mailContent{}, errUnreadable
	}
	var c mailContent
	if err := json.Unmarshal(plain, &c); err != nil {
		return mailContent{}, errUnreadable
	}
	return c, nil
}

// issueCode ends the verification's live code (withdrawing its unsent email) and issues a new one.
// A real code (to set) is also queued to the outbox in the same transaction; a decoy (to empty)
// stores a digest of a value nobody receives, so verify behaves alike (D-07).
func (s *Service) issueCode(ctx context.Context, ver VerificationRow, to string, user uuid.UUID) (CodeRow, error) {
	if err := s.endLiveCode(ctx, ver, EndSuperseded); err != nil {
		return CodeRow{}, err
	}
	now := s.now()
	id, err := uuid.NewV7()
	if err != nil {
		return CodeRow{}, fmt.Errorf("otp: code id: %w", err)
	}
	nc := NewCode{ID: id, OrgID: ver.OrgID, VerificationID: ver.ID, IssuedAt: now, ExpiresAt: now.Add(CodeTTL)}
	if to == "" {
		nc.Digest, err = s.decoyDigest(ver, id)
		if err != nil {
			return CodeRow{}, err
		}
		return s.st.InsertCode(ctx, nc)
	}
	code, err := GenerateCode(randomReader())
	if err != nil {
		return CodeRow{}, err
	}
	nc.Digest = CodeDigest(s.d.Digests, ver.Purpose, ver.ID, id, code)
	nc.OutboxKey = "otp:code:" + id.String()
	row, err := s.st.InsertCode(ctx, nc)
	if err != nil {
		return CodeRow{}, err
	}
	box, err := s.seal(TopicEmailCode, nc.OutboxKey, mailContent{
		To: to, Code: code, Purpose: string(ver.Purpose), ExpiresAt: nc.ExpiresAt.UTC().Format(time.RFC3339Nano)})
	if err != nil {
		return CodeRow{}, err
	}
	expires := nc.ExpiresAt
	_, err = s.d.Outbox.Add(ctx, outbox.Message{
		OrgID: ver.OrgID, Topic: TopicEmailCode, Recipient: outbox.Recipient{Kind: "client", ID: &user},
		Subject: "otp:" + ver.ID.String(), DedupeKey: nc.OutboxKey, Payload: box,
		ExemptFromQuietHours: true, ExpiresAt: &expires, SensitivePayload: true,
	})
	if err != nil {
		return CodeRow{}, fmt.Errorf("otp: queue code: %w", err)
	}
	return row, nil
}

// decoyDigest is the digest of a random value that is not a 6-digit code, so no entry matches.
func (s *Service) decoyDigest(ver VerificationRow, codeID uuid.UUID) ([]byte, error) {
	nobody, _, err := crypto.NewToken("decoy_")
	if err != nil {
		return nil, fmt.Errorf("otp: decoy: %w", err)
	}
	return CodeDigest(s.d.Digests, ver.Purpose, ver.ID, codeID, nobody), nil
}

// Deliver sends the live code email of a verification right away (outbox.DeliverNow). Call it
// after the transaction commits; it is a no-op when there is no live code and must not run in a
// transaction.
func (s *Service) Deliver(ctx context.Context, id uuid.UUID) error {
	if _, err := db.MustTx(ctx); err == nil {
		return errors.New("otp: Deliver must not run inside a transaction")
	}
	org, err := s.orgID(ctx)
	if err != nil {
		return err
	}
	code, err := s.st.GetLiveCode(ctx, org, id)
	if errors.Is(err, ErrNoLiveCode) {
		return nil
	}
	if err != nil {
		return err
	}
	return s.deliverKey(ctx, org, code.OutboxKey)
}

// deliverKey hands one queued code message to DeliverNow. A failed send is recorded by the outbox
// as an attempt (the tick relay retries until the code expires); it is not an error here.
func (s *Service) deliverKey(ctx context.Context, org uuid.UUID, key string) error {
	if key == "" {
		return nil
	}
	if _, err := s.d.Outbox.DeliverNow(ctx, org, TopicEmailCode, key); err != nil {
		return fmt.Errorf("otp: deliver code: %w", err)
	}
	return nil
}

// Resend issues a new code for the verification behind handle (cooldown and limits apply). A
// public caller is answered no earlier than the response floor, whatever the outcome (I-3).
func (s *Service) Resend(ctx context.Context, c Caller, handle string) (res ResendResult, err error) {
	start := s.now()
	if c.UserID == nil {
		defer func() { s.wait(ctx, start.Add(responseFloor)) }()
	}
	org, err := s.orgID(ctx)
	if err != nil {
		return ResendResult{}, err
	}
	var outcome error
	var key string
	err = s.d.Tx.InTx(ctx, func(ctx context.Context) error {
		ver, err := s.lockFlow(ctx, org, c, handle)
		if err != nil {
			return settle(&outcome, err)
		}
		// A reset flow without a user is a decoy: it sends nothing but answers like a real one.
		decoy := ver.Purpose == PurposePasswordReset && ver.UserID == uuid.Nil
		if ver.FinishedAt != nil || ver.EmailDoneAt != nil || (ver.Email == "" && !decoy) {
			outcome = ErrNothingToSend
			return nil
		}
		now := s.now()
		keys := []LimitKey{s.limitKey(ScopeSendContact, ver.Email), s.limitKey(ScopeSendIP, c.IP)}
		if decoy {
			keys[0] = s.limitKey(ScopeSendContact, "decoy:"+ver.ID.String())
		} else {
			keys = append(keys, s.limitKey(ScopeSendUser, ver.UserID.String()))
		}
		refusal, err := s.applyLimits(ctx, org, keys, now)
		if err != nil {
			return err
		}
		if refusal != nil {
			outcome = refusal
			return s.refused(ctx, org, ver.UserID, ver.ID, ver.Purpose, c.IP, refusal, clientActor(ver.UserID))
		}
		to := ver.Email
		code, err := s.issueCode(ctx, ver, to, ver.UserID)
		if err != nil {
			return err
		}
		if err := s.record(ctx, org, clientActor(ver.UserID), ver.UserID, "otp.code.issued", auditAfter{
			VerificationID: ver.ID.String(), Purpose: string(ver.Purpose), Outcome: "issued", IP: c.IP}); err != nil {
			return err
		}
		key = code.OutboxKey
		res = ResendResult{NextResendAt: now.Add(ResendCooldown), CodeExpiresAt: code.ExpiresAt}
		return nil
	})
	if err != nil {
		return ResendResult{}, err
	}
	if outcome != nil {
		return ResendResult{}, outcome
	}
	if err := s.deliverKey(ctx, org, key); err != nil {
		s.log.WarnContext(ctx, "otp: delivering a code failed; the relay will retry", "err", err)
	}
	return res, nil
}

// lockFlow locks the verification behind handle for a caller: absent, another user's, a flow of a
// kind the caller cannot reach and a cancelled one all read as ErrNotFound; an expired one is
// ErrVerificationExpired.
func (s *Service) lockFlow(ctx context.Context, org uuid.UUID, c Caller, handle string) (VerificationRow, error) {
	ver, err := s.st.LockVerificationByHandle(ctx, org, crypto.Digest(handle))
	if err != nil {
		return VerificationRow{}, err
	}
	if !visibleTo(c, ver) || ver.CancelledAt != nil {
		return VerificationRow{}, ErrNotFound
	}
	if !s.now().Before(ver.ExpiresAt) {
		return VerificationRow{}, ErrVerificationExpired
	}
	return ver, nil
}
