package exec

import (
	"fmt"
	"log"
	"os/exec"
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	validIP        = regexp.MustCompile(`^[0-9a-fA-F.:]+$`)
	validUID       = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	validTimestamp = regexp.MustCompile(`^[0-9]+$`)
	validRule      = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	validUnixUser  = regexp.MustCompile(`^[a-z_][a-z0-9_-]*$`)
)

// Run executes an action template with variable substitution.
// If executeAs is non-empty, the command runs as that system user by setting
// the process UID/GID directly (requires root, no sudo needed).
func Run(template string, vars map[string]string, executeAs string) error {
	if err := validateVars(vars); err != nil {
		return fmt.Errorf("variable validation: %w", err)
	}

	cmdStr := substituteVars(template, vars)
	cmd := exec.Command("sh", "-c", cmdStr)

	if executeAs != "" {
		if !validUnixUser.MatchString(executeAs) {
			return fmt.Errorf("invalid execute_as user: %q", executeAs)
		}
		cred, err := lookupCredential(executeAs)
		if err != nil {
			return fmt.Errorf("lookup user %q: %w", executeAs, err)
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: cred,
		}
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("action failed: %w (output: %s)", err, string(out))
	}
	return nil
}

// Schedule executes an action after a delay.
func Schedule(delay time.Duration, template string, vars map[string]string, executeAs string) {
	go func() {
		time.Sleep(delay)
		if err := Run(template, vars, executeAs); err != nil {
			log.Printf("[UNDO ERROR] %v", err)
		} else {
			log.Printf("[UNDO] executed: rule=%s uid=%s ip=%s", vars["rule"], vars["uid"], vars["ip"])
		}
	}()
}

// lookupCredential resolves a username to syscall.Credential (UID + GID + supplementary groups).
func lookupCredential(username string) (*syscall.Credential, error) {
	u, err := user.Lookup(username)
	if err != nil {
		return nil, err
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("parse uid: %w", err)
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("parse gid: %w", err)
	}

	// Resolve supplementary groups (docker, storage, etc.)
	groupIDs, err := u.GroupIds()
	if err != nil {
		return nil, fmt.Errorf("lookup groups: %w", err)
	}
	var groups []uint32
	for _, g := range groupIDs {
		id, err := strconv.ParseUint(g, 10, 32)
		if err != nil {
			continue
		}
		groups = append(groups, uint32(id))
	}

	return &syscall.Credential{
		Uid:    uint32(uid),
		Gid:    uint32(gid),
		Groups: groups,
	}, nil
}

func validateVars(vars map[string]string) error {
	if ip, ok := vars["ip"]; ok && !validIP.MatchString(ip) {
		return fmt.Errorf("invalid ip: %q", ip)
	}
	if uid, ok := vars["uid"]; ok && !validUID.MatchString(uid) {
		return fmt.Errorf("invalid uid: %q", uid)
	}
	if ts, ok := vars["timestamp"]; ok && !validTimestamp.MatchString(ts) {
		return fmt.Errorf("invalid timestamp: %q", ts)
	}
	if rule, ok := vars["rule"]; ok && !validRule.MatchString(rule) {
		return fmt.Errorf("invalid rule: %q", rule)
	}
	return nil
}

func substituteVars(template string, vars map[string]string) string {
	result := template
	for k, v := range vars {
		result = strings.ReplaceAll(result, "{"+k+"}", v)
	}
	return result
}
