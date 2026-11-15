// Smoke test for workload identity (JWT) sessions: run by
// scripts/workload-check.sh against a real cofferakd, not mocked.
//
// Usage: COFFERAK_SOCKET=... COFFERAK_JWT_DIR=... COFFERAK_JWT_EXPIRES_IN=<seconds>
// COFFERAK_REVOKE_CMD=<shell command> go run ./examples/smoke_jwt <allowed-prefix> <denied-path>
package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	cofferak "github.com/arkrwn/cofferak/sdk/go/cofferak"
)

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", args...)
	os.Exit(1)
}

func check(err error, what string) {
	if err != nil {
		fail("%s: %v", what, err)
	}
}

func isDenied(err error) bool {
	var d cofferak.DeniedError
	return errors.As(err, &d)
}

func mustDenied(err error, what string) {
	if !isDenied(err) {
		fail("%s: expected DeniedError, got %v", what, err)
	}
}

func env(name string) string {
	v := os.Getenv(name)
	if v == "" {
		fail("%s must be set", name)
	}
	return v
}

func main() {
	if len(os.Args) != 3 {
		fail("usage: smoke_jwt <allowed-prefix> <denied-path>")
	}
	prefix, denied := os.Args[1], os.Args[2]
	socket := env("COFFERAK_SOCKET")
	dir := env("COFFERAK_JWT_DIR")
	expiresIn, err := strconv.Atoi(env("COFFERAK_JWT_EXPIRES_IN"))
	check(err, "COFFERAK_JWT_EXPIRES_IN")
	revokeCmd := env("COFFERAK_REVOKE_CMD")
	client := cofferak.Connect(socket)

	// a. a good token
	s, err := client.SessionJWTFile(filepath.Join(dir, "good.jwt"))
	check(err, "open with good.jwt")
	if s.Service() != "app1" {
		fail("Service() = %q, want app1", s.Service())
	}
	value := make([]byte, 256)
	for i := range value {
		value[i] = byte(i)
	}
	path := prefix + "/jwt"
	check(s.Set(path, value), "set")
	got, err := s.Get(path)
	check(err, "get")
	if !bytes.Equal(got, value) {
		fail("binary value did not round-trip")
	}
	many, err := s.GetMany([]string{path, prefix + "/missing"})
	check(err, "getmany")
	if len(many) != 1 || !bytes.Equal(many[path], value) {
		fail("GetMany returned %d entries", len(many))
	}
	all, err := s.GetAll(prefix)
	check(err, "getall")
	if !bytes.Equal(all[path], value) {
		fail("GetAll did not return the value")
	}
	listed, err := s.List(prefix)
	check(err, "list")
	found := false
	for _, p := range listed {
		found = found || p == path
	}
	if !found {
		fail("List did not contain %s: %v", path, listed)
	}
	_, err = s.Get(denied)
	mustDenied(err, "get of the denied path")
	_, err = s.GetMany([]string{path, denied})
	mustDenied(err, "getmany with the denied path")
	check(s.Ping(), "ping")
	check(s.Close(), "close")

	// b. bad tokens
	for _, name := range []string{"wrong-aud", "unbound", "expired", "wrong-key"} {
		bad, err := client.SessionJWTFile(filepath.Join(dir, name+".jwt"))
		if err == nil {
			bad.Close()
		}
		mustDenied(err, "open with "+name+".jwt")
	}

	// c. reconnect with a fresh token file after the old one expired
	current := filepath.Join(dir, "current.jwt")
	s, err = client.SessionJWTFile(current)
	check(err, "open with current.jwt")
	opened := time.Now()
	_, err = s.Get(path)
	check(err, "get with current.jwt")
	long, err := os.ReadFile(filepath.Join(dir, "long.jwt"))
	check(err, "read long.jwt")
	tmp := filepath.Join(dir, "current.jwt.tmp")
	check(os.WriteFile(tmp, long, 0o600), "write temp token file")
	check(os.Rename(tmp, current), "replace current.jwt")
	time.Sleep(time.Until(opened.Add(time.Duration(expiresIn)*time.Second + 1500*time.Millisecond)))
	got, err = s.Get(path)
	check(err, "get after the token expired (reconnect)")
	if !bytes.Equal(got, value) {
		fail("value after reconnect differs")
	}
	check(s.Close(), "close")

	// e. a provider closure (runs before the revocation, which removes the binding)
	calls := 0
	s, err = client.SessionJWT(func() (string, error) {
		calls++
		b, err := os.ReadFile(filepath.Join(dir, "good.jwt"))
		return string(bytes.TrimSpace(b)), err
	})
	check(err, "open with a provider")
	got, err = s.Get(path)
	check(err, "get with a provider")
	if !bytes.Equal(got, value) || calls != 1 {
		fail("provider session: value ok=%v, provider calls=%d", bytes.Equal(got, value), calls)
	}
	check(s.Close(), "close")

	// d. revocation
	s, err = client.SessionJWTFile(filepath.Join(dir, "good.jwt"))
	check(err, "open before revocation")
	_, err = s.Get(path)
	check(err, "get before revocation")
	if out, err := exec.Command("sh", "-c", revokeCmd).CombinedOutput(); err != nil {
		fail("revoke command: %v: %s", err, out)
	}
	_, err = s.Get(path)
	mustDenied(err, "get after revocation")
	s.Close()

	fmt.Println("go SDK JWT smoke test passed")
}
