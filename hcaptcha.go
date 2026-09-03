package captcha

import (
	"context"
	"errors"
	"net/http"
	"net/url"
)

const hcaptchaEndpoint = "https://hcaptcha.com/siteverify"

var (
	ErrHCaptchaMissingInputSecret           = errors.New("your secret key is missing")
	ErrHCaptchaInvalidInputSecret           = errors.New("your secret key is invalid or malformed")
	ErrHCaptchaMissingInputResponse         = errors.New("the response parameter (verification token) is missing")
	ErrHCaptchaInvalidInputResponse         = errors.New("the response parameter (verification token) is invalid or malformed")
	ErrHCaptchaBadRequest                   = errors.New("the request is invalid or malformed")
	ErrHCaptchaInvalidOrAlreadySeenResponse = errors.New("the response parameter has already been checked, or has another issue")
	ErrHCaptchaNotUsingDummyPasscode        = errors.New("you have used a testing sitekey but have not used its matching secret")
	ErrHCaptchaSitekeySecretMismatch        = errors.New("the sitekey is not registered with the provided secret")
)

var hcaptchaErrorMap = map[string]error{
	"missing-input-secret":             ErrHCaptchaMissingInputSecret,
	"invalid-input-secret":             ErrHCaptchaInvalidInputSecret,
	"missing-input-response":           ErrHCaptchaMissingInputResponse,
	"invalid-input-response":           ErrHCaptchaInvalidInputResponse,
	"bad-request":                      ErrHCaptchaBadRequest,
	"invalid-or-already-seen-response": ErrHCaptchaInvalidOrAlreadySeenResponse,
	"not-using-dummy-passcode":         ErrHCaptchaNotUsingDummyPasscode,
	"sitekey-secret-mismatch":          ErrHCaptchaSitekeySecretMismatch,
}

type hcaptchaClient struct {
	baseClient
	privateKey string
	publicKey  string
}

func (c *hcaptchaClient) CheckRequest(r *http.Request) (*Response, error) {

	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	return c.CheckPostWithContext(r.Context(), r.PostForm.Get("h-captcha-response"), stripPort(r.RemoteAddr))
}

func (c *hcaptchaClient) CheckPost(post string, ip string) (*Response, error) {
	return c.CheckPostWithContext(context.Background(), post, ip)
}

func (c *hcaptchaClient) CheckPostWithContext(ctx context.Context, post string, ip string) (*Response, error) {

	form := url.Values{}
	form.Add("sitekey", c.publicKey)
	form.Add("secret", c.privateKey)
	form.Add("response", post)
	form.Add("remoteip", ip)

	return c.verify(ctx, form, hcaptchaErrorMap)
}
