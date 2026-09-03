# captcha-go

[![Go Reference](https://pkg.go.dev/badge/github.com/Jleagle/captcha-go.svg)](https://pkg.go.dev/github.com/Jleagle/captcha-go)

- Choice of reCAPTCHA, hCaptcha or Cloudflare Turnstile
- Middleware helper
- No dependencies

## Usage

```go
provider := captcha.New(captcha.ReCaptcha, "secret-key", "") // public key only needed for hCaptcha

// Verify a token directly
resp, err := provider.CheckPost(token, clientIP)
if err != nil {
    // the verification request itself failed
}
if resp.Success {
    // human
}

// Or verify straight from an incoming request (reads the provider's form field and client IP)
resp, err = provider.CheckRequest(r)
```

### Middleware

```go
handler := captcha.Middleware(provider, func(w http.ResponseWriter, r *http.Request) {
    resp := r.Context().Value(captcha.MiddlewareCtxKey).(*captcha.Response)
    http.Error(w, fmt.Sprintf("captcha failed: %v", resp.Errors), http.StatusForbidden)
})(next)
```

On success the `*captcha.Response` is available to `next` under `captcha.MiddlewareCtxKey`.
If verification itself errors (e.g. the provider is unreachable), the middleware is
fail-open: `next` is called with the error stored under `captcha.MiddlewareErrKey`.
