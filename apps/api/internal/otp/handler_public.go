package otp

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/authz"
)

type (
	handleIn      struct{ Body HandleRequest }
	verifyEmailIn struct{ Body VerifyEmailRequest }
	verifyMobileI struct{ Body VerifyMobileRequest }
	resetStartIn  struct{ Body ResetStartRequest }
	resetEndIn    struct{ Body ResetCompleteRequest }

	statusOut      struct{ Body VerificationStatus }
	resendOut      struct{ Body ResendResponse }
	verifyEmailOut struct{ Body VerifyEmailResponse }
	resetStartOut  struct{ Body ResetStartedResponse }
	noBodyOut      struct{}
)

// idempotencyExempt marks credential-like operations (plan Complexity Tracking): replaying a
// stored response would mean storing a code or reset token readably, and a retry is harmless
// because codes are single use and sends are cooldown-guarded.
var idempotencyExempt = map[string]any{"idempotency": "exempt"}

func (h *handlers) registerPublic(api huma.API) {
	mw := huma.Middlewares{h.ingress}
	op := func(id, path, summary string, status int, errs map[string]*huma.Response) huma.Operation {
		return huma.Operation{
			OperationID: id, Method: http.MethodPost, Path: path, Tags: []string{tagVerification}, Summary: summary,
			Security: authz.Public(), Middlewares: mw, DefaultStatus: status, Metadata: idempotencyExempt, Responses: errs,
		}
	}
	huma.Register(api, op("verification-status", "/v1/verifications/status",
		"Read a sign-up or password-reset verification by its handle", http.StatusOK,
		problems(api, false, 404, 429)), h.status(false))
	huma.Register(api, op("verification-resend", "/v1/verifications/resend",
		"Send a new email code (cooldown and limits apply)", http.StatusAccepted,
		problems(api, true, 404, 409, 410, 429)), h.resend(false))
	huma.Register(api, op("verification-verify-email", "/v1/verifications/verify-email",
		"Check the 6-digit email code; a password reset returns a one-time reset token", http.StatusOK,
		problems(api, true, 404, 410, 422, 429)), h.verifyEmail(false))
	huma.Register(api, op("verification-verify-mobile", "/v1/verifications/verify-mobile",
		"Prove the sign-up mobile with a Firebase phone sign-in ID token", http.StatusOK,
		problems(api, true, 404, 409, 410, 422, 429, 503)), h.verifyMobile(false))
	huma.Register(api, op("password-reset-start", "/v1/password-reset/start",
		"Start a password reset by email or mobile; always 202 with a handle", http.StatusAccepted,
		problems(api, true, 422, 429)), h.resetStart)
	huma.Register(api, op("password-reset-complete", "/v1/password-reset/complete",
		"Set a new password with the one-time reset token; ends all sessions", http.StatusNoContent,
		problems(api, true, 422, 429, 503)), h.resetComplete)
}

// caller is who calls: the address, and for /v1/me/* the signed-in owner.
func caller(ctx context.Context, me bool) Caller {
	c := Caller{IP: ipOf(ctx)}
	if me {
		id := authz.MustPrincipal(ctx).UserID
		c.UserID = &id
	}
	return c
}

func (h *handlers) status(me bool) func(context.Context, *handleIn) (*statusOut, error) {
	return func(ctx context.Context, in *handleIn) (*statusOut, error) {
		if err := h.ready(); err != nil {
			return nil, err
		}
		v, err := h.svc.Status(ctx, caller(ctx, me), in.Body.Handle)
		if err != nil {
			return nil, h.fail(ctx, err)
		}
		return &statusOut{Body: statusOf(v)}, nil
	}
}

func (h *handlers) resend(me bool) func(context.Context, *handleIn) (*resendOut, error) {
	return func(ctx context.Context, in *handleIn) (*resendOut, error) {
		if err := h.ready(); err != nil {
			return nil, err
		}
		r, err := h.svc.Resend(ctx, caller(ctx, me), in.Body.Handle)
		if err != nil {
			return nil, h.fail(ctx, err)
		}
		return &resendOut{Body: ResendResponse{NextResendAt: r.NextResendAt.UTC(), CodeExpiresAt: r.CodeExpiresAt.UTC()}}, nil
	}
}

func (h *handlers) verifyEmail(me bool) func(context.Context, *verifyEmailIn) (*verifyEmailOut, error) {
	return func(ctx context.Context, in *verifyEmailIn) (*verifyEmailOut, error) {
		if err := h.ready(); err != nil {
			return nil, err
		}
		r, err := h.svc.VerifyEmail(ctx, caller(ctx, me), in.Body.Handle, in.Body.Code)
		if err != nil {
			return nil, h.fail(ctx, err)
		}
		out := VerifyEmailResponse{Verification: statusOf(r.Verification), ResetToken: r.ResetToken}
		if r.ResetTokenExpiresAt != nil {
			t := r.ResetTokenExpiresAt.UTC()
			out.ResetTokenExpiresAt = &t
		}
		return &verifyEmailOut{Body: out}, nil
	}
}

func (h *handlers) verifyMobile(me bool) func(context.Context, *verifyMobileI) (*statusOut, error) {
	return func(ctx context.Context, in *verifyMobileI) (*statusOut, error) {
		if err := h.ready(); err != nil {
			return nil, err
		}
		v, err := h.svc.VerifyMobile(ctx, caller(ctx, me), in.Body.Handle, in.Body.FirebaseIDToken)
		if err != nil {
			return nil, h.fail(ctx, err)
		}
		return &statusOut{Body: statusOf(v)}, nil
	}
}

func (h *handlers) resetStart(ctx context.Context, in *resetStartIn) (*resetStartOut, error) {
	if err := h.ready(); err != nil {
		return nil, err
	}
	r, err := h.svc.StartReset(ctx, ipOf(ctx), in.Body.Identifier)
	if err != nil {
		return nil, h.fail(ctx, err)
	}
	return &resetStartOut{Body: ResetStartedResponse{Handle: r.Handle, ExpiresAt: r.ExpiresAt.UTC(), NextResendAt: r.NextResendAt.UTC()}}, nil
}

func (h *handlers) resetComplete(ctx context.Context, in *resetEndIn) (*noBodyOut, error) {
	if err := h.ready(); err != nil {
		return nil, err
	}
	if err := h.svc.CompleteReset(ctx, ipOf(ctx), in.Body.Handle, in.Body.ResetToken, in.Body.NewPassword); err != nil {
		return nil, h.fail(ctx, err)
	}
	return &noBodyOut{}, nil
}
