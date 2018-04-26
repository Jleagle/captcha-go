package recaptcha

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"errors"
	"net/http"
	"net/url"
	"time"
)

const (
	endpoint = "https://www.google.com/recaptcha/api/siteverify"
	response = "g-recaptcha-response"
)

var secret string

// User errors
var ErrNotChecked = errors.New("captcha not checked")

// Internal errors
var (
	ErrMissingSecret   = errors.New("secret is missing")
	ErrInvalidSecret   = errors.New("secret is invalid")
	ErrMissingResponse = errors.New("response is missing")
	ErrInvalidResponse = errors.New("response is invalid")
	ErrBadRequest      = errors.New("request is invalid")
	ErrInvalidIP       = errors.New("ip is invalid")
)

func SetSecret(key string) {
	secret = key
}

func Check(response string, ip string) error {

	// Validation
	if secret == "" {
		return ErrMissingSecret
	}

	if response == "" {
		return ErrMissingResponse
	}

	//if ip != "" && net.ParseIP(ip) == nil {
	//	return ErrInvalidIP // Does not currently work for IPs such as [::1]:64833
	//}

	// Build request
	form := url.Values{}
	form.Add("secret", secret)
	form.Add("response", response)
	form.Add("remoteip", ip)

	req, err := http.NewRequest("POST", endpoint, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")

	// Make request
	client := &http.Client{Timeout: time.Second * 5}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Read into bytes
	responseBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Unmarshal
	var responseStruct recaptchaResponse
	err = json.Unmarshal(responseBytes, &responseStruct)
	if err != nil {
		return err
	}

	// Check for errors
	if len(responseStruct.ErrorCodes) > 0 {

		var errorMap = map[string]error{
			"missing-input-secret":   ErrMissingSecret,
			"invalid-input-secret":   ErrInvalidSecret,
			"missing-input-response": ErrMissingResponse,
			"invalid-input-response": ErrInvalidResponse,
			"bad-request":            ErrBadRequest,
		}

		return errorMap[responseStruct.ErrorCodes[0]]
	}

	//
	if !responseStruct.Success {
		return ErrNotChecked
	}

	return nil
}

type recaptchaResponse struct {
	Success     bool      `json:"success"`
	ChallengeTS time.Time `json:"challenge_ts"`
	Hostname    string    `json:"hostname"`
	ErrorCodes  []string  `json:"error-codes"`
}

func CheckFromRequest(r *http.Request) error {

	// Form validation
	if err := r.ParseForm(); err != nil {
		return err
	}

	// Get response
	recaptchaResponse := r.PostForm.Get(response)
	if recaptchaResponse == "" {
		return ErrNotChecked
	}

	//
	return Check(recaptchaResponse, r.RemoteAddr)
}
