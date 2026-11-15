package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/authz"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/crypto"
)

// errInvalidChallenge is every challenge verification failure; it never names the cause.
var errInvalidChallenge = errors.New("auth: invalid challenge token")

// BearerVerifier verifies access tokens (scheme "bearer") against the session lookup of P-02.
// It only reads: a request never extends a session (D-06).
func (s *Service) BearerVerifier() authz.Verifier { return bearerVerifier{s} }

// ChallengeVerifier verifies interim MFA challenge tokens (scheme "mfaChallenge"). It does not
// consume the challenge; completing the second factor does.
func (s *Service) ChallengeVerifier() authz.Verifier { return challengeVerifier{s} }

type bearerVerifier struct{ s *Service }

func (v bearerVerifier) Verify(ctx context.Context, token string) (authz.Principal, error) {
	claims, err := v.s.tokens.Verify(token)
	if err != nil {
		return authz.Principal{}, err
	}
	sp, err := v.s.store.GetSessionPrincipal(ctx, claims.SessionID)
	if err != nil {
		return authz.Principal{}, fmt.Errorf("auth: session lookup: %w", err)
	}
	if !sp.Live(v.s.now()) || sp.UserID != claims.UserID || sp.OrgID != claims.OrgID || sp.Role != claims.Role {
		return authz.Principal{}, ErrInvalidToken
	}
	return authz.Principal{UserID: sp.UserID, OrgID: sp.OrgID, SessionID: sp.SessionID, Role: authz.Role(sp.Role)}, nil
}

type challengeVerifier struct{ s *Service }

func (v challengeVerifier) Verify(ctx context.Context, token string) (authz.Principal, error) {
	if token == "" || len(token) > maxTokenLength {
		return authz.Principal{}, errInvalidChallenge
	}
	ch, err := v.s.store.FindChallengeByHash(ctx, crypto.Digest(token))
	if err != nil {
		return authz.Principal{}, fmt.Errorf("%w: %w", errInvalidChallenge, err)
	}
	if ch.ConsumedAt != nil || !v.s.now().Before(ch.ExpiresAt) {
		return authz.Principal{}, errInvalidChallenge
	}
	u, err := v.s.store.GetUser(ctx, ch.UserID)
	if err != nil {
		return authz.Principal{}, fmt.Errorf("%w: %w", errInvalidChallenge, err)
	}
	if u.Role != roleAdmin || u.Status != StatusActive {
		return authz.Principal{}, errInvalidChallenge
	}
	return authz.Principal{UserID: u.ID, OrgID: ch.OrgID, SessionID: uuid.Nil, Role: authz.RoleAdmin}, nil
}
