package main

// MCP *client* side: the gateway connects to real MCP servers over stdio (spawned processes such
// as the official filesystem / fetch servers) or Streamable HTTP (remote servers such as GitHub's).

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const upstreamProtocolVersion = "2025-06-18"

type jsonrpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonrpcError   `json:"error,omitempty"`
}

type jsonrpcError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *jsonrpcError) Error() string { return fmt.Sprintf("upstream error %d: %s", e.Code, e.Message) }

// upstreamTool is one tool as the upstream server described it (kept raw for faithful pass-through).
type upstreamTool struct {
	Name string
	Raw  map[string]any
}

type Upstream interface {
	Config() UpstreamConfig
	Start(ctx context.Context) error
	Tools() []upstreamTool
	// Call runs tools/call and returns the raw "result" object, or a *jsonrpcError.
	Call(ctx context.Context, tool string, args json.RawMessage) (json.RawMessage, error)
	Close()
}

func newUpstream(cfg UpstreamConfig) (Upstream, error) {
	switch cfg.Transport {
	case "stdio", "":
		if cfg.Command == "" {
			return nil, fmt.Errorf("upstream %s: stdio transport needs a command", cfg.Name)
		}
		return &stdioUpstream{cfg: cfg}, nil
	case "http", "streamable-http":
		if cfg.URL == "" {
			return nil, fmt.Errorf("upstream %s: http transport needs a url", cfg.Name)
		}
		return &httpUpstream{cfg: cfg, client: &http.Client{Timeout: 150 * time.Second}}, nil
	}
	return nil, fmt.Errorf("upstream %s: unknown transport %q", cfg.Name, cfg.Transport)
}

// rpcCaller is the minimal request primitive both transports implement.
type rpcCaller interface {
	request(ctx context.Context, method string, params any) (json.RawMessage, error)
	notify(method string, params any) error
}

// handshake runs initialize → notifications/initialized → tools/list (all pages).
func handshake(ctx context.Context, c rpcCaller) ([]upstreamTool, error) {
	_, err := c.request(ctx, "initialize", map[string]any{
		"protocolVersion": upstreamProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "agent-identity-gateway", "version": gatewayVersion},
	})
	if err != nil {
		return nil, fmt.Errorf("initialize: %w", err)
	}
	if err := c.notify("notifications/initialized", map[string]any{}); err != nil {
		return nil, fmt.Errorf("initialized notification: %w", err)
	}
	var tools []upstreamTool
	cursor := ""
	for page := 0; page < 20; page++ {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		raw, err := c.request(ctx, "tools/list", params)
		if err != nil {
			return nil, fmt.Errorf("tools/list: %w", err)
		}
		var res struct {
			Tools      []map[string]any `json:"tools"`
			NextCursor string           `json:"nextCursor"`
		}
		if err := json.Unmarshal(raw, &res); err != nil {
			return nil, fmt.Errorf("tools/list decode: %w", err)
		}
		for _, t := range res.Tools {
			name, _ := t["name"].(string)
			if name != "" {
				tools = append(tools, upstreamTool{Name: name, Raw: t})
			}
		}
		if res.NextCursor == "" {
			break
		}
		cursor = res.NextCursor
	}
	return tools, nil
}

// ---------------------------------------------------------------------------------------------
// stdio
// ---------------------------------------------------------------------------------------------

type stdioUpstream struct {
	cfg UpstreamConfig

	mu    sync.Mutex // guards proc + tools
	proc  *stdioProc
	tools []upstreamTool
}

// stdioProc is one running instance of the upstream server. Each restart gets a fresh one, so a
// dying old process can never fail requests that belong to its replacement.
type stdioProc struct {
	name    string
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	writeMu sync.Mutex
	alive   atomic.Bool

	pendingMu sync.Mutex
	pending   map[int64]chan jsonrpcMessage
	nextID    atomic.Int64
}

func (u *stdioUpstream) Config() UpstreamConfig { return u.cfg }

func (u *stdioUpstream) Tools() []upstreamTool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.tools
}

func (u *stdioUpstream) Start(ctx context.Context) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	_, err := u.startLocked(ctx)
	return err
}

func (u *stdioUpstream) startLocked(ctx context.Context) (*stdioProc, error) {
	u.stopLocked()
	cmd := exec.Command(u.cfg.Command, u.cfg.Args...)
	cmd.Dir = u.cfg.Dir
	cmd.Env = baseUpstreamEnv()
	for k, v := range u.cfg.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	setProcessGroup(cmd)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", u.cfg.Command, err)
	}
	p := &stdioProc{name: u.cfg.Name, cmd: cmd, stdin: stdin, pending: make(map[int64]chan jsonrpcMessage)}
	p.alive.Store(true)

	go func() { // upstream logs → our stderr, prefixed
		sc := bufio.NewScanner(stderr)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			fmt.Fprintf(os.Stderr, "  [%s] %s\n", u.cfg.Name, sc.Text())
		}
	}()
	go p.readLoop(stdout)

	tools, err := handshake(ctx, p)
	if err != nil {
		p.kill()
		return nil, err
	}
	u.proc, u.tools = p, tools
	return p, nil
}

func (p *stdioProc) readLoop(stdout io.Reader) {
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var msg jsonrpcMessage
		if err := json.Unmarshal(line, &msg); err != nil {
			continue // not JSON-RPC (some servers print banners)
		}
		switch {
		case msg.Method != "" && len(msg.ID) > 0:
			// Server → client request (ping, roots/list, sampling…). We expose no client capabilities.
			reply := jsonrpcMessage{JSONRPC: "2.0", ID: msg.ID}
			if msg.Method == "ping" {
				reply.Result = json.RawMessage(`{}`)
			} else {
				reply.Error = &jsonrpcError{Code: -32601, Message: "gateway does not support " + msg.Method}
			}
			_ = p.write(reply)
		case msg.Method != "":
			// notification (logging, progress, list_changed) — ignored in this prototype
		default:
			var id int64
			if json.Unmarshal(msg.ID, &id) == nil {
				p.pendingMu.Lock()
				ch := p.pending[id]
				delete(p.pending, id)
				p.pendingMu.Unlock()
				if ch != nil {
					ch <- msg
				}
			}
		}
	}
	_ = p.cmd.Wait()
	p.alive.Store(false)
	p.pendingMu.Lock()
	for id, ch := range p.pending {
		close(ch)
		delete(p.pending, id)
	}
	p.pendingMu.Unlock()
}

func (p *stdioProc) write(msg jsonrpcMessage) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	_, err = p.stdin.Write(append(b, '\n'))
	return err
}

func (p *stdioProc) request(ctx context.Context, method string, params any) (json.RawMessage, error) {
	if !p.alive.Load() {
		return nil, fmt.Errorf("upstream %s is not running", p.name)
	}
	id := p.nextID.Add(1)
	raw, _ := json.Marshal(params)
	ch := make(chan jsonrpcMessage, 1)
	p.pendingMu.Lock()
	p.pending[id] = ch
	p.pendingMu.Unlock()
	idRaw, _ := json.Marshal(id)
	if err := p.write(jsonrpcMessage{JSONRPC: "2.0", ID: idRaw, Method: method, Params: raw}); err != nil {
		return nil, err
	}
	select {
	case msg, ok := <-ch:
		if !ok {
			return nil, fmt.Errorf("upstream %s exited", p.name)
		}
		if msg.Error != nil {
			return nil, msg.Error
		}
		return msg.Result, nil
	case <-ctx.Done():
		p.pendingMu.Lock()
		delete(p.pending, id)
		p.pendingMu.Unlock()
		return nil, fmt.Errorf("upstream %s: %w", p.name, ctx.Err())
	}
}

func (p *stdioProc) notify(method string, params any) error {
	raw, _ := json.Marshal(params)
	return p.write(jsonrpcMessage{JSONRPC: "2.0", Method: method, Params: raw})
}

func (p *stdioProc) kill() {
	_ = p.stdin.Close()
	killProcessGroup(p.cmd)
}

func (u *stdioUpstream) Call(ctx context.Context, tool string, args json.RawMessage) (json.RawMessage, error) {
	u.mu.Lock()
	p := u.proc
	if p == nil || !p.alive.Load() { // crashed since last call: restart once
		var err error
		if p, err = u.startLocked(ctx); err != nil {
			u.mu.Unlock()
			return nil, fmt.Errorf("upstream %s is down and failed to restart: %w", u.cfg.Name, err)
		}
	}
	u.mu.Unlock()
	if len(args) == 0 {
		args = json.RawMessage(`{}`)
	}
	return p.request(ctx, "tools/call", map[string]any{"name": tool, "arguments": args})
}

func (u *stdioUpstream) stopLocked() {
	if u.proc != nil {
		u.proc.kill()
	}
	u.proc = nil
}

func (u *stdioUpstream) Close() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.stopLocked()
}

// ---------------------------------------------------------------------------------------------
// Streamable HTTP
// ---------------------------------------------------------------------------------------------

type httpUpstream struct {
	cfg    UpstreamConfig
	client *http.Client

	mu        sync.Mutex
	sessionID string
	protocol  string
	tools     []upstreamTool
	nextID    atomic.Int64
}

func (u *httpUpstream) Config() UpstreamConfig { return u.cfg }

func (u *httpUpstream) Tools() []upstreamTool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.tools
}

func (u *httpUpstream) Start(ctx context.Context) error {
	u.mu.Lock()
	u.sessionID, u.protocol = "", ""
	u.mu.Unlock()
	tools, err := handshake(ctx, u)
	if err != nil {
		return err
	}
	u.mu.Lock()
	u.tools = tools
	u.protocol = upstreamProtocolVersion
	u.mu.Unlock()
	return nil
}

func (u *httpUpstream) post(ctx context.Context, msg jsonrpcMessage) (*http.Response, error) {
	b, _ := json.Marshal(msg)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.cfg.URL, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range u.cfg.Headers {
		req.Header.Set(k, v)
	}
	u.mu.Lock()
	if u.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", u.sessionID)
	}
	if u.protocol != "" {
		req.Header.Set("MCP-Protocol-Version", u.protocol)
	}
	u.mu.Unlock()
	return u.client.Do(req)
}

func (u *httpUpstream) request(ctx context.Context, method string, params any) (json.RawMessage, error) {
	id := u.nextID.Add(1)
	idRaw, _ := json.Marshal(id)
	p, _ := json.Marshal(params)
	resp, err := u.post(ctx, jsonrpcMessage{JSONRPC: "2.0", ID: idRaw, Method: method, Params: p})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" && method == "initialize" {
		u.mu.Lock()
		u.sessionID = sid
		u.mu.Unlock()
	}
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("upstream %s: HTTP %d %s", u.cfg.Name, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var msg *jsonrpcMessage
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		msg, err = readSSEResponse(resp.Body, idRaw)
	} else {
		var m jsonrpcMessage
		err = json.NewDecoder(resp.Body).Decode(&m)
		msg = &m
	}
	if err != nil {
		return nil, fmt.Errorf("upstream %s: %w", u.cfg.Name, err)
	}
	if msg.Error != nil {
		return nil, msg.Error
	}
	return msg.Result, nil
}

// readSSEResponse reads an SSE stream until the JSON-RPC response with the given id arrives.
func readSSEResponse(r io.Reader, id json.RawMessage) (*jsonrpcMessage, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	var data strings.Builder
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "data:") {
			data.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
			continue
		}
		if line == "" && data.Len() > 0 {
			var m jsonrpcMessage
			if json.Unmarshal([]byte(data.String()), &m) == nil && m.Method == "" && bytes.Equal(bytes.TrimSpace(m.ID), id) {
				return &m, nil
			}
			data.Reset()
		}
	}
	if data.Len() > 0 {
		var m jsonrpcMessage
		if json.Unmarshal([]byte(data.String()), &m) == nil && bytes.Equal(bytes.TrimSpace(m.ID), id) {
			return &m, nil
		}
	}
	return nil, errors.New("stream ended without a response")
}

func (u *httpUpstream) notify(method string, params any) error {
	p, _ := json.Marshal(params)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := u.post(ctx, jsonrpcMessage{JSONRPC: "2.0", Method: method, Params: p})
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (u *httpUpstream) Call(ctx context.Context, tool string, args json.RawMessage) (json.RawMessage, error) {
	if len(args) == 0 {
		args = json.RawMessage(`{}`)
	}
	params := map[string]any{"name": tool, "arguments": args}
	res, err := u.request(ctx, "tools/call", params)
	if err != nil && strings.Contains(err.Error(), "HTTP 404") { // session expired upstream: re-initialise once
		if serr := u.Start(ctx); serr == nil {
			return u.request(ctx, "tools/call", params)
		}
	}
	return res, err
}

func (u *httpUpstream) Close() {}

// baseUpstreamEnv is the environment every stdio upstream gets: what runtimes need to start
// (PATH, HOME, locale, temp dirs, Node/npm/uv/Go settings), never the gateway's own secrets
// (GATEWAY_SHARED_SECRET, DATABASE_URL, tokens). An upstream that needs a secret names it in its
// config "env" block, e.g. {"GITHUB_TOKEN": "${GITHUB_TOKEN}"}.
func baseUpstreamEnv() []string {
	keep := []string{"PATH", "HOME", "USER", "LOGNAME", "SHELL", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TERM",
		"TMPDIR", "TMP", "TEMP", "SYSTEMROOT", "APPDATA", "LOCALAPPDATA", "USERPROFILE", "COMSPEC", "PATHEXT"}
	prefixes := []string{"NODE_", "NPM_CONFIG_", "npm_config_", "UV_", "XDG_", "GO", "PYTHON"}
	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		ok := false
		for _, x := range keep {
			if strings.EqualFold(k, x) {
				ok = true
				break
			}
		}
		for _, p := range prefixes {
			if !ok && strings.HasPrefix(k, p) {
				ok = true
			}
		}
		if ok {
			env = append(env, kv)
		}
	}
	return env
}
