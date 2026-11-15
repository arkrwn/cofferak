package cofferak

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// maxBatchPaths mirrors cofferakd's protocol::MAX_BATCH_PATHS: the most
// paths one GetMany request may carry. Session.GetMany splits longer lists.
const maxBatchPaths = 256

// Session is an authenticated connection to cofferakd (protocol version
// 2). One connection carries every call, so over TLS the handshake is
// paid once instead of once per secret. If the daemon closes the
// connection (it does after an idle period), the next call reconnects and
// authenticates again without the caller noticing.
//
// A Session is safe for use by several goroutines, calls run one at a
// time.
type Session struct {
	client *Client
	// source gives the authentication method and credential for every
	// (re)connect: the static token, or a fresh JWT from the provider.
	source func() (method, credential string, err error)

	mu      sync.Mutex
	conn    net.Conn
	reader  *bufio.Reader
	service string
}

// Session opens a session: it authenticates once with token, then any
// number of calls run on one connection. Close it when done. It returns
// DeniedError if the token is not accepted and ProtocolError if the
// daemon is too old for sessions.
func (c *Client) Session(token string) (*Session, error) {
	return c.openSession(func() (string, string, error) { return "token", token, nil })
}

// SessionJWT opens a session for a workload identity: it authenticates
// with the JWT that provider returns. The provider is called on every
// connect and reconnect, so it can hand out a fresh token after the old
// one expired (the daemon closes the connection of an expired workload
// token, the next call reconnects with a new one). Everything else works
// as for Session. It returns DeniedError if the daemon does not accept the
// JWT; an error from provider is returned wrapped, never as DeniedError.
// The JWT is never included in an error message.
func (c *Client) SessionJWT(provider func() (string, error)) (*Session, error) {
	if provider == nil {
		return nil, errors.New("cofferak: SessionJWT needs a provider")
	}
	return c.openSession(func() (string, string, error) {
		jwt, err := provider()
		if err != nil {
			return "", "", fmt.Errorf("obtaining the JWT: %w", err)
		}
		if jwt == "" {
			return "", "", errors.New("obtaining the JWT: the provider returned an empty token")
		}
		return "jwt", jwt, nil
	})
}

// SessionJWTFile is SessionJWT with the JWT read from the file at path
// (surrounding whitespace and newlines are trimmed). The file is read again
// on every connect and reconnect, so a token that something else rotates
// in place, like a Kubernetes projected service account token, is picked up.
func (c *Client) SessionJWTFile(path string) (*Session, error) {
	return c.SessionJWT(func() (string, error) {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("reading the JWT file: %w", err)
		}
		return strings.TrimSpace(string(data)), nil
	})
}

func (c *Client) openSession(source func() (string, string, error)) (*Session, error) {
	s := &Session{client: c, source: source}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.connect(); err != nil {
		return nil, err
	}
	return s, nil
}

// Service is the service id the daemon knows this session's credential
// (token or JWT) as.
func (s *Session) Service() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.service
}

// Close closes the connection. The session reconnects if used again.
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.drop()
}

func (s *Session) drop() error {
	if s.conn == nil {
		return nil
	}
	err := s.conn.Close()
	s.conn, s.reader = nil, nil
	return err
}

func (s *Session) connect() error {
	s.drop()
	method, credential, err := s.source()
	if err != nil {
		return err
	}
	conn, err := s.client.dial()
	if err != nil {
		return err
	}
	s.conn, s.reader = conn, bufio.NewReader(conn)

	fail := func(err error) error {
		s.drop()
		return err
	}
	raw, err := s.roundtrip(map[string]any{"Hello": map[string]int{"version": 2}})
	if err != nil {
		return fail(err)
	}
	var hello struct {
		Hello *struct {
			Version int `json:"version"`
		}
	}
	if json.Unmarshal(raw, &hello) != nil || hello.Hello == nil {
		return fail(ProtocolError{Message: "this cofferakd does not support sessions (protocol version 2), upgrade it or use the per-call Client methods"})
	}

	raw, err = s.roundtrip(map[string]any{"Auth": map[string]string{"method": method, "credential": credential}})
	if err != nil {
		return fail(err)
	}
	service, err := classify(raw, func(key string, payload json.RawMessage) (any, error) {
		if key != "Authed" {
			return nil, ProtocolError{Message: "unexpected response key to Auth: " + key}
		}
		var authed struct {
			Service string `json:"service"`
		}
		if err := json.Unmarshal(payload, &authed); err != nil {
			return nil, ProtocolError{Message: "Authed payload was not an object: " + err.Error()}
		}
		return authed.Service, nil
	})
	if err != nil {
		return fail(err)
	}
	name, ok := service.(string)
	if !ok {
		return fail(ProtocolError{Message: "unexpected response to Auth"})
	}
	s.service = name
	return nil
}

// roundtrip sends one request line and reads one response line, never
// buffering more than maxLineBytes of a response.
func (s *Session) roundtrip(request any) (json.RawMessage, error) {
	if err := s.conn.SetDeadline(time.Now().Add(ioTimeout)); err != nil {
		return nil, err
	}
	body, err := json.Marshal(request)
	if err != nil {
		return nil, ProtocolError{Message: "failed to encode request: " + err.Error()}
	}
	if _, err := s.conn.Write(append(body, '\n')); err != nil {
		return nil, fmt.Errorf("writing request: %w", err)
	}
	var line []byte
	for {
		part, err := s.reader.ReadSlice('\n')
		if len(line)+len(part) > maxLineBytes {
			return nil, ProtocolError{Message: "response line exceeded the maximum allowed size"}
		}
		line = append(line, part...)
		if err == nil {
			return json.RawMessage(line), nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return nil, fmt.Errorf("reading response: %w", err)
		}
	}
}

// call sends one request. If the connection is gone it reconnects and
// sends the request again once, unless retry is false (a request that
// must not be repeated), where the connection error is returned.
func (s *Session) call(request any, retry bool) (json.RawMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		if err := s.connect(); err != nil {
			return nil, err
		}
	}
	raw, err := s.roundtrip(request)
	if err == nil {
		return raw, nil
	}
	var protocolErr ProtocolError
	if errors.As(err, &protocolErr) || !retry {
		s.drop()
		return nil, err
	}
	if err := s.connect(); err != nil {
		return nil, err
	}
	raw, err = s.roundtrip(request)
	if err != nil {
		s.drop()
	}
	return raw, err
}

func decodeValue(payload json.RawMessage) ([]byte, error) {
	var encoded string
	if err := json.Unmarshal(payload, &encoded); err != nil {
		return nil, ProtocolError{Message: "value was not a base64 string: " + err.Error()}
	}
	value, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, ProtocolError{Message: "value was not valid base64: " + err.Error()}
	}
	return value, nil
}

// Get reads a secret's value.
func (s *Session) Get(path string) ([]byte, error) {
	raw, err := s.call(map[string]any{"Get": map[string]string{"path": path}}, true)
	if err != nil {
		return nil, err
	}
	value, err := classify(raw, func(key string, payload json.RawMessage) (any, error) {
		if key != "Value" {
			return nil, ProtocolError{Message: "unexpected response key to Get: " + key}
		}
		return decodeValue(payload)
	})
	if err != nil {
		return nil, err
	}
	bytes, ok := value.([]byte)
	if !ok {
		return nil, ProtocolError{Message: "unexpected response to Get"}
	}
	return bytes, nil
}

// GetMany reads several secrets in one round trip. It returns the values
// of the paths that exist, a path with no value is left out. It returns
// DeniedError if any path is outside what the token may read.
func (s *Session) GetMany(paths []string) (map[string][]byte, error) {
	out := make(map[string][]byte, len(paths))
	for start := 0; start < len(paths); start += maxBatchPaths {
		end := min(start+maxBatchPaths, len(paths))
		raw, err := s.call(map[string]any{"GetMany": map[string][]string{"paths": paths[start:end]}}, true)
		if err != nil {
			return nil, err
		}
		items, err := classify(raw, func(key string, payload json.RawMessage) (any, error) {
			if key != "Values" {
				return nil, ProtocolError{Message: "unexpected response key to GetMany: " + key}
			}
			var items []struct {
				Path  string          `json:"path"`
				Value json.RawMessage `json:"value"`
				Error string          `json:"error"`
			}
			if err := json.Unmarshal(payload, &items); err != nil {
				return nil, ProtocolError{Message: "Values payload was not a list: " + err.Error()}
			}
			for _, item := range items {
				switch item.Error {
				case "":
					value, err := decodeValue(item.Value)
					if err != nil {
						return nil, err
					}
					out[item.Path] = value
				case "not_found":
				case "denied":
					return nil, DeniedError{}
				default:
					return nil, RemoteError{Message: "could not read " + item.Path}
				}
			}
			return true, nil
		})
		if err != nil {
			return nil, err
		}
		if items == nil {
			return nil, ProtocolError{Message: "unexpected response to GetMany"}
		}
	}
	return out, nil
}

// GetAll reads every secret under prefix.
func (s *Session) GetAll(prefix string) (map[string][]byte, error) {
	paths, err := s.List(prefix)
	if err != nil {
		return nil, err
	}
	return s.GetMany(paths)
}

func expectOk(raw json.RawMessage, what string) error {
	_, err := classify(raw, func(key string, _ json.RawMessage) (any, error) {
		return nil, ProtocolError{Message: "unexpected response key to " + what + ": " + key}
	})
	return err
}

// Set writes a secret's value. Requires a read-write token.
func (s *Session) Set(path string, value []byte) error {
	encoded := base64.StdEncoding.EncodeToString(value)
	raw, err := s.call(map[string]any{"Set": map[string]string{"path": path, "value": encoded}}, true)
	if err != nil {
		return err
	}
	return expectOk(raw, "Set")
}

// Rm removes a secret. Requires a read-write token.
func (s *Session) Rm(path string) error {
	// Not repeated on a lost connection: a second try after a removal
	// that did go through would wrongly report "not found".
	raw, err := s.call(map[string]any{"Rm": map[string]string{"path": path}}, false)
	if err != nil {
		return err
	}
	return expectOk(raw, "Rm")
}

// List lists secret paths under prefix.
func (s *Session) List(prefix string) ([]string, error) {
	raw, err := s.call(map[string]any{"List": map[string]string{"prefix": prefix}}, true)
	if err != nil {
		return nil, err
	}
	value, err := classify(raw, func(key string, payload json.RawMessage) (any, error) {
		if key != "Listed" {
			return nil, ProtocolError{Message: "unexpected response key to List: " + key}
		}
		var paths []string
		if err := json.Unmarshal(payload, &paths); err != nil {
			return nil, ProtocolError{Message: "Listed payload was not a string array: " + err.Error()}
		}
		return paths, nil
	})
	if err != nil {
		return nil, err
	}
	paths, ok := value.([]string)
	if !ok {
		return nil, ProtocolError{Message: "unexpected response to List"}
	}
	return paths, nil
}

// Ping checks that the daemon answers on this session.
func (s *Session) Ping() error {
	raw, err := s.call("Ping", true)
	if err != nil {
		return err
	}
	return expectOk(raw, "Ping")
}
