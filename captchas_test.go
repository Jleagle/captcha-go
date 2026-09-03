package captcha

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// verifyServer fakes a siteverify endpoint, capturing the form it receives.
func verifyServer(t *testing.T, body string, gotForm *url.Values) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("content type = %q", ct)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		*gotForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
}

// setEndpoint points a Provider at a test server.
func setEndpoint(t *testing.T, p Provider, endpoint string) {
	t.Helper()
	switch c := p.(type) {
	case *reCaptchaClient:
		c.endpoint = endpoint
	case *hcaptchaClient:
		c.endpoint = endpoint
	case *turnstileClient:
		c.endpoint = endpoint
	default:
		t.Fatalf("unknown provider type %T", p)
	}
}

func TestNew(t *testing.T) {
	if _, ok := New(ReCaptcha, "priv", "").(*reCaptchaClient); !ok {
		t.Error("New(ReCaptcha) did not return a reCaptchaClient")
	}
	if _, ok := New(HCaptcha, "priv", "pub").(*hcaptchaClient); !ok {
		t.Error("New(HCaptcha) did not return an hcaptchaClient")
	}
	if _, ok := New(Turnstile, "priv", "").(*turnstileClient); !ok {
		t.Error("New(Turnstile) did not return a turnstileClient")
	}
	if p := New(captcha(99), "priv", ""); p != nil {
		t.Error("New with unknown provider should return nil")
	}
}

func TestCheckPost(t *testing.T) {

	for _, tc := range []struct {
		name      string
		provider  captcha
		body      string
		wantForm  map[string]string
		wantScore float32
	}{
		{
			name:      "recaptcha",
			provider:  ReCaptcha,
			body:      `{"success": true, "challenge_ts": "2026-01-01T00:00:00Z", "hostname": "example.com", "score": 0.9, "action": "login"}`,
			wantForm:  map[string]string{"secret": "priv", "response": "token", "remoteip": "1.2.3.4"},
			wantScore: 0.9,
		},
		{
			name:      "hcaptcha",
			provider:  HCaptcha,
			body:      `{"success": true, "challenge_ts": "2026-01-01T00:00:00Z", "hostname": "example.com", "score": 0.5}`,
			wantForm:  map[string]string{"secret": "priv", "sitekey": "pub", "response": "token", "remoteip": "1.2.3.4"},
			wantScore: 0.5,
		},
		{
			name:      "turnstile",
			provider:  Turnstile,
			body:      `{"success": true, "challenge_ts": "2026-01-01T00:00:00Z", "hostname": "example.com", "action": "login"}`,
			wantForm:  map[string]string{"secret": "priv", "response": "token", "remoteip": "1.2.3.4"},
			wantScore: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {

			var gotForm url.Values
			server := verifyServer(t, tc.body, &gotForm)
			defer server.Close()

			p := New(tc.provider, "priv", "pub")
			setEndpoint(t, p, server.URL)

			resp, err := p.CheckPost("token", "1.2.3.4")
			if err != nil {
				t.Fatal(err)
			}

			for key, want := range tc.wantForm {
				if got := gotForm.Get(key); got != want {
					t.Errorf("form[%s] = %q, want %q", key, got, want)
				}
			}
			if !resp.Success {
				t.Error("Success = false, want true")
			}
			if resp.HostName != "example.com" {
				t.Errorf("HostName = %q", resp.HostName)
			}
			if resp.Time != "2026-01-01T00:00:00Z" {
				t.Errorf("Time = %q", resp.Time)
			}
			if resp.Score != tc.wantScore {
				t.Errorf("Score = %v, want %v", resp.Score, tc.wantScore)
			}
		})
	}
}

func TestCheckPostErrorCodes(t *testing.T) {

	var gotForm url.Values
	server := verifyServer(t, `{"success": false, "error-codes": ["invalid-input-secret", "some-new-code"]}`, &gotForm)
	defer server.Close()

	p := New(ReCaptcha, "priv", "")
	setEndpoint(t, p, server.URL)

	resp, err := p.CheckPost("token", "")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Success {
		t.Error("Success = true, want false")
	}
	if len(resp.Errors) != 2 {
		t.Fatalf("Errors = %v, want 2 entries", resp.Errors)
	}
	if !errors.Is(resp.Errors[0], ErrRecaptchaInvalidSecret) {
		t.Errorf("Errors[0] = %v, want ErrRecaptchaInvalidSecret", resp.Errors[0])
	}
	if resp.Errors[1].Error() != "some-new-code" {
		t.Errorf("Errors[1] = %v, want some-new-code", resp.Errors[1])
	}
}

func TestCheckPostBadStatus(t *testing.T) {

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()

	p := New(ReCaptcha, "priv", "")
	setEndpoint(t, p, server.URL)

	if _, err := p.CheckPost("token", ""); err == nil {
		t.Error("expected an error for a non-200 status")
	}
}

func TestCheckRequestStripsPort(t *testing.T) {

	for _, tc := range []struct {
		provider  captcha
		formField string
	}{
		{ReCaptcha, "g-recaptcha-response"},
		{HCaptcha, "h-captcha-response"},
		{Turnstile, "cf-turnstile-response"},
	} {
		var gotForm url.Values
		server := verifyServer(t, `{"success": true}`, &gotForm)

		p := New(tc.provider, "priv", "pub")
		setEndpoint(t, p, server.URL)

		form := url.Values{tc.formField: {"token"}}
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.RemoteAddr = "1.2.3.4:56789"

		resp, err := p.CheckRequest(r)
		if err != nil {
			t.Fatal(err)
		}
		if !resp.Success {
			t.Error("Success = false, want true")
		}
		if got := gotForm.Get("remoteip"); got != "1.2.3.4" {
			t.Errorf("%s: remoteip = %q, want port stripped", tc.formField, got)
		}
		if got := gotForm.Get("response"); got != "token" {
			t.Errorf("%s: response = %q, want token", tc.formField, got)
		}

		server.Close()
	}
}

func TestMiddleware(t *testing.T) {

	newRequest := func() *http.Request {
		form := url.Values{"g-recaptcha-response": {"token"}}
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return r
	}

	t.Run("success calls next with response in context", func(t *testing.T) {

		var gotForm url.Values
		server := verifyServer(t, `{"success": true}`, &gotForm)
		defer server.Close()

		p := New(ReCaptcha, "priv", "")
		setEndpoint(t, p, server.URL)

		var nextCalled, errorCalled bool
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			if _, ok := r.Context().Value(MiddlewareCtxKey).(*Response); !ok {
				t.Error("response missing from context on success")
			}
		})
		errorHandler := func(w http.ResponseWriter, r *http.Request) { errorCalled = true }

		Middleware(p, errorHandler)(next).ServeHTTP(httptest.NewRecorder(), newRequest())

		if !nextCalled || errorCalled {
			t.Errorf("nextCalled = %v, errorCalled = %v", nextCalled, errorCalled)
		}
	})

	t.Run("failure calls errorHandler with response in context", func(t *testing.T) {

		var gotForm url.Values
		server := verifyServer(t, `{"success": false}`, &gotForm)
		defer server.Close()

		p := New(ReCaptcha, "priv", "")
		setEndpoint(t, p, server.URL)

		var nextCalled, errorCalled bool
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { nextCalled = true })
		errorHandler := func(w http.ResponseWriter, r *http.Request) {
			errorCalled = true
			if _, ok := r.Context().Value(MiddlewareCtxKey).(*Response); !ok {
				t.Error("response missing from context on failure")
			}
		}

		Middleware(p, errorHandler)(next).ServeHTTP(httptest.NewRecorder(), newRequest())

		if nextCalled || !errorCalled {
			t.Errorf("nextCalled = %v, errorCalled = %v", nextCalled, errorCalled)
		}
	})

	t.Run("verification error calls next with error in context", func(t *testing.T) {

		p := New(ReCaptcha, "priv", "")
		setEndpoint(t, p, "http://127.0.0.1:1") // nothing listening

		var nextCalled bool
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			if _, ok := r.Context().Value(MiddlewareErrKey).(error); !ok {
				t.Error("error missing from context")
			}
		})
		errorHandler := func(w http.ResponseWriter, r *http.Request) { t.Error("errorHandler should not be called") }

		Middleware(p, errorHandler)(next).ServeHTTP(httptest.NewRecorder(), newRequest())

		if !nextCalled {
			t.Error("next was not called")
		}
	})
}

func TestStripPort(t *testing.T) {
	for input, want := range map[string]string{
		"1.2.3.4:56789":     "1.2.3.4",
		"1.2.3.4":           "1.2.3.4",
		"[2001:db8::1]:443": "2001:db8::1",
		"":                  "",
	} {
		if got := stripPort(input); got != want {
			t.Errorf("stripPort(%q) = %q, want %q", input, got, want)
		}
	}
}
