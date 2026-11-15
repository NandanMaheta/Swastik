package auth

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/authz"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/crypto"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/httpx"
)

// Wire types of the admin second factor.

// MfaVerifyRequest completes a sign-in: exactly one of code and recovery_code.
type MfaVerifyRequest struct {
	Code         string `json:"code,omitempty" pattern:"^[0-9]{6}$"`
	RecoveryCode string `json:"recovery_code,omitempty" minLength:"16" maxLength:"24"`
}

// TotpCodeRequest carries one authenticator code.
type TotpCodeRequest struct {
	Code string `json:"code" pattern:"^[0-9]{6}$"`
}

// TotpSecret is a new authenticator secret, shown once.
type TotpSecret struct {
	Secret     string `json:"secret" doc:"Base32, shown once."`
	OTPAuthURI string `json:"otpauth_uri" doc:"otpauth://totp/Swastik:<email>?secret=...&issuer=Swastik&algorithm=SHA1&digits=6&period=30"`
}

// EnrolmentResponse is a completed enrolment.
type EnrolmentResponse struct {
	Session       SessionResponse `json:"session"`
	RecoveryCodes []string        `json:"recovery_codes" minItems:"10" maxItems:"10" doc:"Shown once."`
}

// RecoveryCodes is a new set of recovery codes.
type RecoveryCodes struct {
	RecoveryCodes []string `json:"recovery_codes" minItems:"10" maxItems:"10"`
}

// ReauthWithCode re-authenticates with the password and a current TOTP code.
type ReauthWithCode struct {
	Password string `json:"password" minLength:"1" maxLength:"1024" format:"password"`
	Code     string `json:"code" pattern:"^[0-9]{6}$"`
}

// ReauthWithCodeOrRecovery re-authenticates with the password and exactly one of a TOTP code and a
// recovery code.
type ReauthWithCodeOrRecovery struct {
	Password     string `json:"password" minLength:"1" maxLength:"1024" format:"password"`
	Code         string `json:"code,omitempty" pattern:"^[0-9]{6}$"`
	RecoveryCode string `json:"recovery_code,omitempty" minLength:"16" maxLength:"24"`
}

type (
	mfaVerifyInput struct {
		Origin string `header:"Origin" doc:"Required for web requests: must equal an allowed admin panel origin."`
		CSRF   string `header:"X-Swastik-CSRF" doc:"Required for web requests: must be 1."`
		Body   MfaVerifyRequest
	}
	enrolmentConfirmInput struct {
		Origin string `header:"Origin" doc:"Required for web requests: must equal an allowed admin panel origin."`
		CSRF   string `header:"X-Swastik-CSRF" doc:"Required for web requests: must be 1."`
		Body   TotpCodeRequest
	}
	enrolmentConfirmOutput struct {
		SetCookie string `header:"Set-Cookie"`
		Body      EnrolmentResponse
	}
	totpSecretOutput  struct{ Body TotpSecret }
	recoveryInput     struct{ Body ReauthWithCode }
	recoveryOutput    struct{ Body RecoveryCodes }
	replaceStartInput struct{ Body ReauthWithCodeOrRecovery }
	replaceConfirmIn  struct{ Body TotpCodeRequest }
)

func (h *handlers) registerMFA(api huma.API) {
	limited := huma.Middlewares{h.ingress(true)}
	huma.Register(api, huma.Operation{
		OperationID: "auth-mfa-verify", Method: http.MethodPost, Path: "/v1/auth/mfa/verify", Tags: []string{"Auth"},
		Summary: "Complete an admin sign-in with a TOTP or recovery code", Security: authz.ChallengeOnly(), Middlewares: limited,
	}, h.mfaVerify)
	huma.Register(api, huma.Operation{
		OperationID: "auth-mfa-enrolment-start", Method: http.MethodPost, Path: "/v1/auth/mfa/enrolment", Tags: []string{"Auth"},
		Summary: "Start enrolling an authenticator", Security: authz.ChallengeOnly(), Middlewares: limited,
	}, h.enrolmentStart)
	huma.Register(api, huma.Operation{
		OperationID: "auth-mfa-enrolment-confirm", Method: http.MethodPost, Path: "/v1/auth/mfa/enrolment/confirm", Tags: []string{"Auth"},
		Summary: "Confirm the authenticator and open the admin session", Security: authz.ChallengeOnly(), Middlewares: limited,
	}, h.enrolmentConfirm)
	huma.Register(api, huma.Operation{
		OperationID: "auth-recovery-codes-regenerate", Method: http.MethodPost, Path: "/v1/auth/mfa/recovery-codes", Tags: []string{"Auth"},
		Summary: "Replace the recovery codes", Security: authz.Require(authz.RoleAdmin),
		Middlewares: huma.Middlewares{h.ingress(false)},
	}, h.regenerateRecoveryCodes)
	huma.Register(api, huma.Operation{
		OperationID: "auth-authenticator-replace-start", Method: http.MethodPost, Path: "/v1/auth/mfa/authenticator", Tags: []string{"Auth"},
		Summary: "Start replacing the authenticator", Security: authz.Require(authz.RoleAdmin),
		Middlewares: huma.Middlewares{h.ingress(false)},
	}, h.replaceStart)
	huma.Register(api, huma.Operation{
		OperationID: "auth-authenticator-replace-confirm", Method: http.MethodPost, Path: "/v1/auth/mfa/authenticator/confirm", Tags: []string{"Auth"},
		Summary: "Confirm the new authenticator", Security: authz.Require(authz.RoleAdmin), DefaultStatus: http.StatusNoContent,
		Middlewares: huma.Middlewares{h.ingress(false)},
	}, h.replaceConfirm)
}

// challengeIsWeb reports whether the challenge was issued to a web sign-in, whose completion sets
// the refresh cookie and so needs the CSRF defences.
func (h *handlers) challengeIsWeb(ctx context.Context) bool {
	ch, err := h.svc.store.FindChallengeByHash(ctx, crypto.Digest(tokenOf(ctx)))
	return err == nil && ch.ClientType == ClientTypeWeb
}

func exactlyOne(a, b string) error {
	if (a == "") == (b == "") {
		return httpx.Problem(http.StatusUnprocessableEntity, "validation_failed", "Provide exactly one of code and recovery_code.")
	}
	return nil
}

func (h *handlers) mfaVerify(ctx context.Context, in *mfaVerifyInput) (*sessionOutput, error) {
	if err := h.ready(); err != nil {
		return nil, err
	}
	if err := exactlyOne(in.Body.Code, in.Body.RecoveryCode); err != nil {
		return nil, err
	}
	web := h.challengeIsWeb(ctx)
	if web {
		if err := h.checkBrowserRequest(in.Origin, in.CSRF); err != nil {
			return nil, err
		}
	}
	s, err := h.svc.VerifyMFA(ctx, MFAVerifyInput{
		ChallengeToken: tokenOf(ctx), Code: in.Body.Code, RecoveryCode: in.Body.RecoveryCode, IP: ipOf(ctx),
	})
	if err != nil {
		return nil, h.fail(ctx, err)
	}
	return &sessionOutput{SetCookie: h.cookieFor(s, web), Body: toSessionResponse(s, web)}, nil
}

func (h *handlers) enrolmentStart(ctx context.Context, _ *struct{}) (*totpSecretOutput, error) {
	if err := h.ready(); err != nil {
		return nil, err
	}
	e, err := h.svc.StartEnrolment(ctx, tokenOf(ctx))
	if err != nil {
		return nil, h.fail(ctx, err)
	}
	return &totpSecretOutput{Body: TotpSecret(e)}, nil
}

func (h *handlers) enrolmentConfirm(ctx context.Context, in *enrolmentConfirmInput) (*enrolmentConfirmOutput, error) {
	if err := h.ready(); err != nil {
		return nil, err
	}
	web := h.challengeIsWeb(ctx)
	if web {
		if err := h.checkBrowserRequest(in.Origin, in.CSRF); err != nil {
			return nil, err
		}
	}
	res, err := h.svc.ConfirmEnrolment(ctx, EnrolmentConfirmInput{ChallengeToken: tokenOf(ctx), Code: in.Body.Code, IP: ipOf(ctx)})
	if err != nil {
		return nil, h.fail(ctx, err)
	}
	return &enrolmentConfirmOutput{
		SetCookie: h.cookieFor(res.Session, web),
		Body:      EnrolmentResponse{Session: toSessionResponse(res.Session, web), RecoveryCodes: res.RecoveryCodes},
	}, nil
}

func (h *handlers) regenerateRecoveryCodes(ctx context.Context, in *recoveryInput) (*recoveryOutput, error) {
	if err := h.ready(); err != nil {
		return nil, err
	}
	codes, err := h.svc.RegenerateRecoveryCodes(ctx, h.principal(ctx), in.Body.Password, in.Body.Code)
	if err != nil {
		return nil, h.fail(ctx, err)
	}
	return &recoveryOutput{Body: RecoveryCodes{RecoveryCodes: codes}}, nil
}

func (h *handlers) replaceStart(ctx context.Context, in *replaceStartInput) (*totpSecretOutput, error) {
	if err := h.ready(); err != nil {
		return nil, err
	}
	if err := exactlyOne(in.Body.Code, in.Body.RecoveryCode); err != nil {
		return nil, err
	}
	e, err := h.svc.StartAuthenticatorReplace(ctx, h.principal(ctx), Reauth{
		Password: in.Body.Password, Code: in.Body.Code, RecoveryCode: in.Body.RecoveryCode,
	})
	if err != nil {
		return nil, h.fail(ctx, err)
	}
	return &totpSecretOutput{Body: TotpSecret(e)}, nil
}

func (h *handlers) replaceConfirm(ctx context.Context, in *replaceConfirmIn) (*struct{}, error) {
	if err := h.ready(); err != nil {
		return nil, err
	}
	if err := h.svc.ConfirmAuthenticatorReplace(ctx, h.principal(ctx), in.Body.Code); err != nil {
		return nil, h.fail(ctx, err)
	}
	return &struct{}{}, nil
}
