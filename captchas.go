package captcha

import (
	"context"
	"net/http"
)

type captcha int8

const (
	ReCaptcha captcha = iota
	HCaptcha
	Turnstile
)

// contextKey is a private type for context keys defined by this package,
// so they can never collide with keys set by other packages.
type contextKey string

const (
	// MiddlewareCtxKey is the context key under which Middleware stores the *Response.
	MiddlewareCtxKey contextKey = "captcha-response"
	// MiddlewareErrKey is the context key under which Middleware stores a verification error.
	MiddlewareErrKey contextKey = "captcha-error"
)

// New creates a new captcha instance.
// publicKey is only used by hCaptcha; pass "" for other providers.
// It returns nil for an unknown provider.
//
//goland:noinspection GoUnusedExportedFunction
func New(provider captcha, privateKey, publicKey string) Provider {

	switch provider {
	case ReCaptcha:
		return &reCaptchaClient{baseClient: baseClient{endpoint: recaptchaEndpoint}, privateKey: privateKey}
	case HCaptcha:
		return &hcaptchaClient{baseClient: baseClient{endpoint: hcaptchaEndpoint}, privateKey: privateKey, publicKey: publicKey}
	case Turnstile:
		return &turnstileClient{baseClient: baseClient{endpoint: turnstileEndpoint}, privateKey: privateKey}
	default:
		return nil
	}
}

type Provider interface {
	// CheckRequest verifies the captcha token found in the request's form data,
	// using the request's context and client IP.
	CheckRequest(r *http.Request) (resp *Response, err error)
	// CheckPost verifies a captcha token. ip is optional and may be empty.
	CheckPost(post string, ip string) (resp *Response, err error)
	// CheckPostWithContext is CheckPost with a context for cancellation/deadlines.
	CheckPostWithContext(ctx context.Context, post string, ip string) (resp *Response, err error)
	// SetClient replaces the default HTTP client (which has a 10 second timeout).
	SetClient(client *http.Client)
	// sealed prevents implementations outside this package, so methods can be
	// added to Provider without it being a breaking change.
	sealed()
}

type Response struct {
	Time     string
	HostName string
	Errors   []error
	Success  bool
	Score    float32 // reCAPTCHA v3, hCaptcha Enterprise
	Action   string  // reCAPTCHA v3, Turnstile
}

// Middleware verifies the captcha token on every request. On failure the
// *Response is stored in the context under MiddlewareCtxKey and errorHandler
// is called instead of next. On success the *Response is also stored under
// MiddlewareCtxKey and next is called.
//
// Note that Middleware is fail-open: if verification itself errors (e.g. the
// provider is unreachable) the request is passed to next with the error stored
// under MiddlewareErrKey, so handlers can decide how to treat it.
//
//goland:noinspection GoUnusedExportedFunction
func Middleware(provider Provider, errorHandler http.HandlerFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			resp, err := provider.CheckRequest(r)
			if err != nil {
				r = r.WithContext(context.WithValue(r.Context(), MiddlewareErrKey, err))
				next.ServeHTTP(w, r)
				return
			}

			r = r.WithContext(context.WithValue(r.Context(), MiddlewareCtxKey, resp))

			if !resp.Success {
				errorHandler(w, r)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
