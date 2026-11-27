package otp

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/authz"
)

// registerMe mounts the four operations of a signed-in client for their contact changes (007).
// Another user's handle reads exactly like an unknown one (404 otp.verification_invalid).
func (h *handlers) registerMe(api huma.API) {
	op := func(id, path, summary string, status int, errs map[string]*huma.Response) huma.Operation {
		return huma.Operation{
			OperationID: id, Method: http.MethodPost, Path: path, Tags: []string{tagVerification}, Summary: summary,
			Security: authz.Require(authz.RoleClient), Middlewares: huma.Middlewares{h.ingress},
			DefaultStatus: status, Metadata: idempotencyExempt, Responses: errs,
		}
	}
	huma.Register(api, op("my-verification-status", "/v1/me/verifications/status",
		"Read one of my contact-change verifications", http.StatusOK,
		problems(api, false, 404, 429)), h.status(true))
	huma.Register(api, op("my-verification-resend", "/v1/me/verifications/resend",
		"Send a new code to my new email", http.StatusAccepted,
		problems(api, true, 404, 409, 410, 429)), h.resend(true))
	huma.Register(api, op("my-verification-verify-email", "/v1/me/verifications/verify-email",
		"Prove my new email; the account is unchanged until the approved change is applied", http.StatusOK,
		problems(api, true, 404, 409, 410, 422, 429)), h.verifyEmail(true))
	huma.Register(api, op("my-verification-verify-mobile", "/v1/me/verifications/verify-mobile",
		"Prove my new mobile with a Firebase ID token", http.StatusOK,
		problems(api, true, 404, 409, 410, 422, 429, 503)), h.verifyMobile(true))
}
