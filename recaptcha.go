package captcha

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
)

var (
	ErrRecaptchaMissingSecret   = errors.New("secret is missing")
	ErrRecaptchaInvalidSecret   = errors.New("secret is invalid")
	ErrRecaptchaMissingResponse = errors.New("response is missing")
	ErrRecaptchaInvalidResponse = errors.New("response is invalid")
	ErrRecaptchaBadRequest      = errors.New("request is invalid")
	ErrRecaptchaTimeout         = errors.New("request timed out")
)

type reCaptchaClient struct {
	client     *http.Client
	privateKey string
}

func (c reCaptchaClient) CheckRequest(r *http.Request) (*Response, error) {

	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	return c.CheckPost(r.PostForm.Get("g-recaptcha-response"), r.RemoteAddr)
}

func (c reCaptchaClient) CheckPost(post string, ip string) (ret *Response, err error) {

	// Build request
	form := url.Values{}
	form.Add("secret", c.privateKey)
	form.Add("response", post)
	form.Add("remoteip", ip)

	req, err := http.NewRequest("POST", "https://www.google.com/recaptcha/api/siteverify", bytes.NewBufferString(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")

	// Make request
	if c.client == nil {
		c.client = http.DefaultClient
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	//goland:noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	// Read response
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var recaptchaResponse recaptchaResponse
	err = json.Unmarshal(b, &recaptchaResponse)
	if err != nil {
		return nil, err
	}

	// Build new response
	ret = &Response{
		Time:     recaptchaResponse.ChallengeTS,
		HostName: recaptchaResponse.Hostname,
		Success:  recaptchaResponse.Success,
	}

	if len(recaptchaResponse.ErrorCodes) > 0 {

		var errorMap = map[string]error{
			"missing-input-secret":   ErrRecaptchaMissingSecret,
			"invalid-input-secret":   ErrRecaptchaInvalidSecret,
			"missing-input-response": ErrRecaptchaMissingResponse,
			"invalid-input-response": ErrRecaptchaInvalidResponse,
			"bad-request":            ErrRecaptchaBadRequest,
			"timeout-or-duplicate":   ErrRecaptchaTimeout,
		}

		for _, errorCode := range recaptchaResponse.ErrorCodes {
			if err, ok := errorMap[errorCode]; ok {
				ret.Errors = append(ret.Errors, err)
			} else {
				ret.Errors = append(ret.Errors, errors.New(errorCode))
			}
		}
	}

	return ret, nil
}

func (c *reCaptchaClient) SetClient(client *http.Client) {
	c.client = client
}

//goland:noinspection GoUnusedParameter
func (c *reCaptchaClient) setKeys(private, public string) {
	c.privateKey = private
}

type recaptchaResponse struct {
	Success     bool     `json:"success"`
	ChallengeTS string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	ErrorCodes  []string `json:"error-codes"`
}
