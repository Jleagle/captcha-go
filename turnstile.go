package captcha

import (
	"context"
	"errors"
	"net/http"
	"net/url"
)

const turnstileEndpoint = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

var (
	ErrTurnstileMissingSecret   = errors.New("the secret parameter was not passed")
	ErrTurnstileInvalidSecret   = errors.New("the secret parameter was invalid or did not exist")
	ErrTurnstileMissingResponse = errors.New("the response parameter (token) was not passed")
	ErrTurnstileInvalidResponse = errors.New("the response parameter (token) is invalid or has expired")
	ErrTurnstileBadRequest      = errors.New("the request was rejected because it was malformed")
	ErrTurnstileTimeout         = errors.New("the response parameter (token) has already been validated before")
	ErrTurnstileInternalError   = errors.New("an internal error happened while validating the response")
)

var turnstileErrorMap = map[string]error{
	"missing-input-secret":   ErrTurnstileMissingSecret,
	"invalid-input-secret":   ErrTurnstileInvalidSecret,
	"missing-input-response": ErrTurnstileMissingResponse,
	"invalid-input-response": ErrTurnstileInvalidResponse,
	"bad-request":            ErrTurnstileBadRequest,
	"timeout-or-duplicate":   ErrTurnstileTimeout,
	"internal-error":         ErrTurnstileInternalError,
}

type turnstileClient struct {
	baseClient
	privateKey string
}

func (c *turnstileClient) CheckRequest(r *http.Request) (*Response, error) {

	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	return c.CheckPostWithContext(r.Context(), r.PostForm.Get("cf-turnstile-response"), stripPort(r.RemoteAddr))
}

func (c *turnstileClient) CheckPost(post string, ip string) (*Response, error) {
	return c.CheckPostWithContext(context.Background(), post, ip)
}

func (c *turnstileClient) CheckPostWithContext(ctx context.Context, post string, ip string) (*Response, error) {

	form := url.Values{}
	form.Add("secret", c.privateKey)
	form.Add("response", post)
	form.Add("remoteip", ip)

	return c.verify(ctx, form, turnstileErrorMap)
}
