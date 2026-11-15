// Package sessioncheck holds the session (protocol version 2) checks
// shared by the smoke and smoke_tls examples, so both transports prove the
// same behaviour against a real cofferakd.
package sessioncheck

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"time"

	cofferak "github.com/arkrwn/cofferak/sdk/go/cofferak"
)

// Run exercises a session end to end and returns the first failure.
func Run(client *cofferak.Client, token, allowedPath, deniedPath string) error {
	base := allowedPath + "-session"
	a, b := base+"/A", base+"/B"
	binary := make([]byte, 256)
	for i := range binary {
		binary[i] = byte(i)
	}

	s, err := client.Session(token)
	if err != nil {
		return fmt.Errorf("opening a session: %w", err)
	}
	defer s.Close()
	if s.Service() == "" {
		return errors.New("the session must report its service id")
	}
	if err := s.Ping(); err != nil {
		return fmt.Errorf("ping: %w", err)
	}
	if err := s.Set(a, []byte("alpha")); err != nil {
		return fmt.Errorf("set: %w", err)
	}
	if err := s.Set(b, binary); err != nil {
		return fmt.Errorf("set binary: %w", err)
	}
	got, err := s.Get(b)
	if err != nil || !bytes.Equal(got, binary) {
		return fmt.Errorf("binary value must round-trip: %v", err)
	}

	check := func(values map[string][]byte, err error, what string) error {
		if err != nil {
			return fmt.Errorf("%s: %w", what, err)
		}
		if len(values) != 2 || !bytes.Equal(values[a], []byte("alpha")) || !bytes.Equal(values[b], binary) {
			return fmt.Errorf("%s returned the wrong values (%d entries)", what, len(values))
		}
		return nil
	}
	values, err := s.GetMany([]string{a, b, base + "/MISSING"})
	if err := check(values, err, "GetMany"); err != nil {
		return err
	}
	values, err = s.GetAll(base)
	if err := check(values, err, "GetAll"); err != nil {
		return err
	}
	listed, err := s.List(base)
	sort.Strings(listed)
	if err != nil || len(listed) != 2 || listed[0] != a || listed[1] != b {
		return fmt.Errorf("list returned %v: %v", listed, err)
	}

	var denied cofferak.DeniedError
	if _, err := s.Get(deniedPath); !errors.As(err, &denied) {
		return fmt.Errorf("expected DeniedError from Get in a session, got %v", err)
	}
	if _, err := s.GetMany([]string{deniedPath}); !errors.As(err, &denied) {
		return fmt.Errorf("expected DeniedError from GetMany in a session, got %v", err)
	}

	// With $COFFERAK_SMOKE_IDLE_SECS the daemon closes idle sessions
	// after that many seconds: wait it out, the next call must reconnect.
	if raw := os.Getenv("COFFERAK_SMOKE_IDLE_SECS"); raw != "" {
		secs, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return fmt.Errorf("COFFERAK_SMOKE_IDLE_SECS: %w", err)
		}
		time.Sleep(time.Duration((secs + 1) * float64(time.Second)))
	}
	if got, err := s.Get(a); err != nil || !bytes.Equal(got, []byte("alpha")) {
		return fmt.Errorf("session must reconnect after the daemon closed it: %v", err)
	}
	// A closed session reconnects when used again.
	s.Close()
	if err := s.Rm(a); err != nil {
		return fmt.Errorf("rm: %w", err)
	}
	if err := s.Rm(b); err != nil {
		return fmt.Errorf("rm: %w", err)
	}
	var notFound cofferak.NotFoundError
	if _, err := s.Get(a); !errors.As(err, &notFound) {
		return fmt.Errorf("expected NotFoundError after rm, got %v", err)
	}

	if _, err := client.Session("0000000000000000000000000000000000000000000000000000000000000000"); !errors.As(err, &denied) {
		return fmt.Errorf("expected DeniedError for an unknown token, got %v", err)
	}
	return nil
}
