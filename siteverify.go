package captcha

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// defaultClient is used when no client has been set with SetClient.
// http.DefaultClient has no timeout, so a slow provider could hang requests forever.
var defaultClient = &http.Client{Timeout: 10 * time.Second}

// baseClient holds the behaviour shared by every siteverify-style provider.
type baseClient struct {
	client   *http.Client
	endpoint string
}

func (c *baseClient) SetClient(client *http.Client) {
	c.client = client
}

func (c *baseClient) sealed() {}

func (c *baseClient) httpClient() *http.Client {
	if c.client != nil {
		return c.client
	}
	return defaultClient
}

// siteverifyResponse is the superset of the JSON returned by reCAPTCHA,
// hCaptcha and Turnstile - they all share the same siteverify protocol.
type siteverifyResponse struct {
	Success     bool     `json:"success"`
	ChallengeTS string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	ErrorCodes  []string `json:"error-codes"`
	Score       float64  `json:"score"`  // reCAPTCHA v3, hCaptcha Enterprise
	Action      string   `json:"action"` // reCAPTCHA v3, Turnstile
}

func (c *baseClient) verify(ctx context.Context, form url.Values, errorMap map[string]error) (*Response, error) {

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}

	//goland:noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("captcha: unexpected status %d from %s", resp.StatusCode, c.endpoint)
	}

	var sv siteverifyResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&sv); err != nil {
		return nil, fmt.Errorf("captcha: decoding response: %w", err)
	}

	ret := &Response{
		Time:     sv.ChallengeTS,
		HostName: sv.Hostname,
		Success:  sv.Success,
		Score:    float32(sv.Score),
		Action:   sv.Action,
	}

	for _, errorCode := range sv.ErrorCodes {
		if err, ok := errorMap[errorCode]; ok {
			ret.Errors = append(ret.Errors, err)
		} else {
			ret.Errors = append(ret.Errors, errors.New(errorCode))
		}
	}

	return ret, nil
}

// stripPort removes the port from an http.Request RemoteAddr ("ip:port"),
// as the siteverify APIs expect a bare IP address.
func stripPort(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}
