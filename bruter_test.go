package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/valyala/fasthttp"
)

// fakeWP serves the minimum WordPress login surface tryLogin needs.
func fakeWP(t *testing.T, goodPass string) *httptest.Server {
	t.Helper()
	const loginPage = `<html><form method="post" action="/wp-login.php">
<input name="log"><input name="pwd"><input name="wp-submit"></form></html>`

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/wp-login.php" && r.Method == http.MethodGet:
			http.SetCookie(w, &http.Cookie{Name: "wordpress_test_cookie", Value: "x"})
			fmt.Fprint(w, loginPage)
		case r.URL.Path == "/wp-login.php" && r.Method == http.MethodPost:
			if r.FormValue("pwd") == goodPass {
				http.SetCookie(w, &http.Cookie{Name: "wordpress_logged_in_abc123", Value: "secret"})
				http.Redirect(w, r, "/wp-admin/", http.StatusFound)
				return
			}
			fmt.Fprint(w, loginPage)
		case r.URL.Path == "/wp-admin/":
			fmt.Fprint(w, `<html><body class="wp-admin"><div id="wpbody-content">
<div id="adminmenu"></div></body></html>`)
		default:
			http.NotFound(w, r)
		}
	}))
}

func withTimeout(t *testing.T, seconds int) {
	t.Helper()
	old := *timeoutSec
	*timeoutSec = seconds
	httpClient = newHTTPClient()
	t.Cleanup(func() { *timeoutSec = old })
}

func TestTryLoginSuccessViaAuthCookie(t *testing.T) {
	srv := fakeWP(t, "s3cret")
	defer srv.Close()
	withTimeout(t, 5)

	j := &SiteJob{Site: srv.URL, quit: make(chan struct{})}
	outcome, detail := tryLogin(j, "admin", "s3cret")
	if outcome != outSuccess {
		t.Fatalf("want outSuccess, got %v (%s)", outcome, detail)
	}
}

func TestTryLoginFailure(t *testing.T) {
	srv := fakeWP(t, "s3cret")
	defer srv.Close()
	withTimeout(t, 5)

	j := &SiteJob{Site: srv.URL, quit: make(chan struct{})}
	outcome, detail := tryLogin(j, "admin", "wrong")
	if outcome != outFail {
		t.Fatalf("want outFail, got %v (%s)", outcome, detail)
	}
}

func TestHasAuthCookie(t *testing.T) {
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	if hasAuthCookie(resp) {
		t.Fatal("empty response must not look authenticated")
	}

	resp.Header.Set("Set-Cookie", "wordpress_test_cookie=WP+Cookie+check")
	if hasAuthCookie(resp) {
		t.Fatal("test cookie must not look authenticated")
	}

	resp.Header.Set("Set-Cookie", "wordpress_logged_in_abc=user%7C123")
	if !hasAuthCookie(resp) {
		t.Fatal("logged-in cookie not detected")
	}
}

func TestSwapScheme(t *testing.T) {
	cases := map[string]string{
		"https://example.com": "http://example.com",
		"http://example.com":  "https://example.com",
		"example.com":         "",
	}
	for in, want := range cases {
		if got := swapScheme(in); got != want {
			t.Errorf("swapScheme(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCheckpointRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "progress.txt")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	old := progressOut
	progressOut = f

	markDone("https://a.example", "verified_success")
	markDone("https://b.example", "network_error")
	markDone("https://c.example", "")
	f.Close()
	progressOut = old

	// A legacy row written by an older version has no status column.
	if err := os.WriteFile(path, append([]byte("https://legacy.example\n"), mustRead(t, path)...), 0o600); err != nil {
		t.Fatal(err)
	}

	got := loadProgress(path)
	if got["https://a.example"] != "verified_success" {
		t.Errorf("status not preserved: %q", got["https://a.example"])
	}
	if got["https://c.example"] != "done" {
		t.Errorf("empty status should fold to done, got %q", got["https://c.example"])
	}
	if got["https://legacy.example"] != "done" {
		t.Errorf("legacy row should count as done, got %q", got["https://legacy.example"])
	}

	cases := map[string]bool{
		"verified_success": false,
		"not_wordpress":    false,
		"done":             false,
		"network_error":    true,
		"slow":             true,
		"rate_limited":     true,
		"waf_cloudflare":   true,
	}
	for status, want := range cases {
		if got := retryableStatus(status); got != want {
			t.Errorf("retryableStatus(%q) = %v, want %v", status, got, want)
		}
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestQuickCheckSchemeFallback points an https:// URL at a plain-HTTP server:
// the TLS handshake fails, so only the http:// fallback can succeed.
func TestQuickCheckSchemeFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><form method="post" action="/wp-login.php">
<input name="log"><input name="pwd"></form></html>`)
	}))
	defer srv.Close()
	withTimeout(t, 3)

	busted := "https://" + strings.TrimPrefix(srv.URL, "http://")
	got, reason, _ := quickCheckRetry(busted)
	if reason != "" {
		t.Fatalf("expected scheme fallback to succeed, got skip reason %q", reason)
	}
	if want := "http://" + strings.TrimPrefix(srv.URL, "http://"); got != want {
		t.Errorf("fallback URL = %q, want %q", got, want)
	}
}

// TestEnumerateUsersNoRace fails under -race if wg.Wait returns before the
// enumeration goroutines stop appending.
func TestEnumerateUsersNoRace(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/wp-json/wp/v2/users":
			fmt.Fprint(w, `[{"slug":"alice"},{"slug":"bob"}]`)
		case "/index.php":
			fmt.Fprint(w, `[{"slug":"carol"}]`)
		default:
			http.Redirect(w, r, "/author/dave/", http.StatusFound)
		}
	}))
	defer srv.Close()
	withTimeout(t, 5)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := enumerateUsers(srv.URL); len(got) == 0 {
				t.Error("expected at least one user")
			}
		}()
	}
	wg.Wait()
}

// A themed login page that links to "Dashboard" must not be mistaken for an
// authenticated page when the password is wrong.
func TestNoFalsePositiveOnDashboardLoginPage(t *testing.T) {
	const loginPage = `<html><body><p><a href="/wp-admin/">Go to Dashboard</a></p>
<form method="post" action="/wp-login.php">
<input name="log"><input name="pwd"><input name="wp-submit"></form></body></html>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, loginPage) // always 200 login page, never sets a cookie
	}))
	defer srv.Close()
	withTimeout(t, 5)

	j := &SiteJob{Site: srv.URL, quit: make(chan struct{})}
	if outcome, _ := tryLogin(j, "admin", "admin"); outcome != outFail {
		t.Fatalf("login page with a Dashboard link must not verify, got %v", outcome)
	}
}

// Some plugins answer a successful login with a 200 dashboard instead of a
// redirect and without a core cookie.
func TestDirect200AdminPage(t *testing.T) {
	const adminPage = `<html><body><div id="wpadminbar"></div>
<div id="adminmenu"></div><div id="wpbody-content">hi</div></body></html>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			fmt.Fprint(w, adminPage)
			return
		}
		fmt.Fprint(w, `<html><form method="post"><input name="log"><input name="pwd"></form></html>`)
	}))
	defer srv.Close()
	withTimeout(t, 5)

	j := &SiteJob{Site: srv.URL, quit: make(chan struct{})}
	if outcome, _ := tryLogin(j, "admin", "right"); outcome != outSuccess {
		t.Fatalf("direct 200 admin page must verify, got %v", outcome)
	}
}

func TestReadWordsKeepsLeadingHashWords(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/words.txt"
	// Leading-# words are skipped by the comment rule, but whitespace is split.
	os.WriteFile(path, []byte("one\ntwo three\n\n# comment\n"), 0o600)
	got, err := readWords(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[2] != "three" {
		t.Fatalf("unexpected words: %v", got)
	}
}

// A success must win over a transient stop reason recorded concurrently by
// other in-flight attempts, otherwise a cracked site is re-queued on resume.
func TestOutcomePrefersSuccess(t *testing.T) {
	j := &SiteJob{quit: make(chan struct{})}
	j.cracked.Store(true)
	j.stop("network_error")
	if got := j.outcome(); got != "verified_success" {
		t.Fatalf("outcome = %q, want verified_success", got)
	}
}

// One attempt must be one POST, carrying the session cookie collected during
// the pre-flight check.
func TestAttemptReusesSessionWithSingleRequest(t *testing.T) {
	var mu sync.Mutex
	var requests, posts int
	var seenCookie string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		if r.Method == http.MethodPost {
			posts++
			seenCookie = r.Header.Get("Cookie")
			http.SetCookie(w, &http.Cookie{Name: "wordpress_logged_in_x", Value: "1", Path: "/"})
			http.Redirect(w, r, "/wp-admin/", http.StatusFound)
			return
		}
		fmt.Fprint(w, `<html><form method="post"><input name="log"><input name="pwd"></form></html>`)
	}))
	defer srv.Close()
	withTimeout(t, 5)

	j := &SiteJob{Site: srv.URL, Cookies: "PHPSESSID=abc", quit: make(chan struct{})}
	if outcome, _ := tryLogin(j, "admin", "x"); outcome != outSuccess {
		t.Fatalf("want success, got %v", outcome)
	}
	mu.Lock()
	defer mu.Unlock()
	if posts != 1 {
		t.Errorf("attempt made %d POSTs, want 1", posts)
	}
	if requests > 2 { // one POST plus at most one verification GET
		t.Errorf("attempt made %d requests, want <= 2", requests)
	}
	if !strings.Contains(seenCookie, "PHPSESSID=abc") {
		t.Errorf("session cookie not forwarded: %q", seenCookie)
	}
}
