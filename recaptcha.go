package captcha

import (
	"context"
	"errors"
	"net/http"
	"net/url"
)

const recaptchaEndpoint = "https://www.google.com/recaptcha/api/siteverify"

var (
	ErrRecaptchaMissingSecret   = errors.New("secret is missing")
	ErrRecaptchaInvalidSecret   = errors.New("secret is invalid")
	ErrRecaptchaMissingResponse = errors.New("response is missing")
	ErrRecaptchaInvalidResponse = errors.New("response is invalid")
	ErrRecaptchaBadRequest      = errors.New("request is invalid")
	ErrRecaptchaTimeout         = errors.New("request timed out")
)

var recaptchaErrorMap = map[string]error{
	"missing-input-secret":   ErrRecaptchaMissingSecret,
	"invalid-input-secret":   ErrRecaptchaInvalidSecret,
	"missing-input-response": ErrRecaptchaMissingResponse,
	"invalid-input-response": ErrRecaptchaInvalidResponse,
	"bad-request":            ErrRecaptchaBadRequest,
	"timeout-or-duplicate":   ErrRecaptchaTimeout,
}

type reCaptchaClient struct {
	baseClient
	privateKey string
}

func (c *reCaptchaClient) CheckRequest(r *http.Request) (*Response, error) {

	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	return c.CheckPostWithContext(r.Context(), r.PostForm.Get("g-recaptcha-response"), stripPort(r.RemoteAddr))
}

func (c *reCaptchaClient) CheckPost(post string, ip string) (*Response, error) {
	return c.CheckPostWithContext(context.Background(), post, ip)
}

func (c *reCaptchaClient) CheckPostWithContext(ctx context.Context, post string, ip string) (*Response, error) {

	form := url.Values{}
	form.Add("secret", c.privateKey)
	form.Add("response", post)
	form.Add("remoteip", ip)

	return c.verify(ctx, form, recaptchaErrorMap)
}
