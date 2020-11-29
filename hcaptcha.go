package captcha

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

var (
	ErrHCaptchaMissingInputSecret           = errors.New("your secret key is missing")
	ErrHCaptchaInvalidInputSecret           = errors.New("your secret key is invalid or malformed")
	ErrHCaptchaMissingInputResponse         = errors.New("the response parameter (verification token) is missing")
	ErrHCaptchaInvalidInputResponse         = errors.New("the response parameter (verification token) is invalid or malformed")
	ErrHCaptchaBadRequest                   = errors.New("the request is invalid or malformed")
	ErrHCaptchaInvalidOrAlreadySeenResponse = errors.New("the response parameter has already been checked, or has another issue")
	ErrHCaptchaSitekeySecretMismatch        = errors.New("the sitekey is not registered with the provided secret")
)

type hcaptchaClient struct {
	client     *http.Client
	privateKey string
	publicKey  string
}

func (c hcaptchaClient) CheckRequest(r *http.Request) (resp *Response, err error) {

	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	return c.CheckPost(r.PostForm.Get("h-captcha-response"), r.RemoteAddr)
}

func (c hcaptchaClient) CheckPost(post string, ip string) (ret *Response, err error) {

	// Build request
	form := url.Values{}
	form.Add("sitekey", c.publicKey)
	form.Add("secret", c.privateKey)
	form.Add("response", post)
	form.Add("remoteip", ip)

	req, err := http.NewRequest("POST", "https://hcaptcha.com/siteverify", bytes.NewBufferString(form.Encode()))
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
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var hcaptchaResponse hcaptchaResponse
	err = json.Unmarshal(b, &hcaptchaResponse)
	if err != nil {
		return nil, err
	}

	// Build new response
	ret = &Response{
		Time:     hcaptchaResponse.ChallengeTS,
		HostName: hcaptchaResponse.Hostname,
		Success:  hcaptchaResponse.Success,
	}

	if len(hcaptchaResponse.ErrorCodes) > 0 {

		var errorMap = map[string]error{
			"missing-input-secret":             ErrHCaptchaMissingInputSecret,
			"invalid-input-secret":             ErrHCaptchaInvalidInputSecret,
			"missing-input-response":           ErrHCaptchaMissingInputResponse,
			"invalid-input-response":           ErrHCaptchaInvalidInputResponse,
			"bad-request":                      ErrHCaptchaBadRequest,
			"invalid-or-already-seen-response": ErrHCaptchaInvalidOrAlreadySeenResponse,
			"sitekey-secret-mismatch":          ErrHCaptchaSitekeySecretMismatch,
		}

		for _, errorCode := range hcaptchaResponse.ErrorCodes {
			if err, ok := errorMap[errorCode]; ok {
				ret.Errors = append(ret.Errors, err)
			} else {
				ret.Errors = append(ret.Errors, errors.New(errorCode))
			}
		}
	}

	return ret, nil
}

func (c *hcaptchaClient) SetClient(client *http.Client) {
	c.client = client
}

func (c *hcaptchaClient) setKeys(private, public string) {
	c.privateKey = private
	c.publicKey = public
}

type hcaptchaResponse struct {
	Success     bool      `json:"success"`      // is the passcode valid, and does it meet security criteria you specified, e.g. sitekey?
	ChallengeTS time.Time `json:"challenge_ts"` // timestamp of the captcha (ISO format yyyy-MM-dd'T'HH:mm:ssZZ)
	Hostname    string    `json:"hostname"`     // the hostname of the site where the captcha was solved
	Credit      bool      `json:"credit"`       // optional: whether the response will be credited
	ErrorCodes  []string  `json:"error-codes"`  // optional: any error codes
	Score       float64   `json:"score"`        // ENTERPRISE feature: a score denoting malicious activity.
	Reason      []string  `json:"score_reason"` // ENTERPRISE feature: reason(s) for score. See BotStop.com for details.
}
