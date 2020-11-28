package captcha

import (
	"context"
	"net/http"
	"time"
)

type captcha int8

const (
	ReCaptcha captcha = iota
	HCaptcha

	MiddlewareCtxKey = "captcha-response"
	MiddlewareErrKey = "captcha-error"
)

// publicKey is just used by hCaptcha
//goland:noinspection GoUnusedExportedFunction
func New(provider captcha, privateKey, publicKey string) Provider {

	var c Provider
	switch provider {
	case ReCaptcha:
		c = &reCaptchaClient{}
	case HCaptcha:
		c = &hcaptchaClient{}
	default:
		return nil
	}

	c.setKeys(publicKey, privateKey)

	return c
}

type Provider interface {
	checkRequest(r *http.Request) (resp *Response, err error)
	checkPost(post string, ip string) (resp *Response, err error)
	setClient(client *http.Client)
	setKeys(private, public string)
}

type Response struct {
	Time     time.Time
	HostName string
	Errors   []error
	Success  bool
	Credit   bool
}

//goland:noinspection GoUnusedExportedFunction
func Middleware(provider Provider, errorHandler http.HandlerFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			resp, err := provider.checkRequest(r)
			if err != nil {
				r = r.WithContext(context.WithValue(r.Context(), MiddlewareErrKey, err))
				next.ServeHTTP(w, r)
				return
			}

			if !resp.Success {
				r = r.WithContext(context.WithValue(r.Context(), MiddlewareCtxKey, resp))
				errorHandler(w, r)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
