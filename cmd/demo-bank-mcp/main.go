// Command demo-bank-mcp is a small but real, stateful core-banking MCP server (stdio) used as an
// upstream behind the Agent Identity Gateway. Balances, payees and payments persist to a JSON file,
// so what an agent does through the gateway is visible afterwards.
//
// It has NO security of its own on purpose: everything it exposes is protected only by the gateway.
// Never expose it directly to an agent.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/buildathon2026/agent-identity-backend/internal/persist"
)

type Account struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	IFSC       string `json:"ifsc"`
	BalanceINR int64  `json:"balance_inr"`
}

type Payee struct {
	Name    string `json:"name"`
	Account string `json:"account"`
	IFSC    string `json:"ifsc"`
}

type Txn struct {
	Ref       string `json:"ref"`
	AccountID string `json:"account_id"`
	Time      string `json:"time"`
	Narration string `json:"narration"`
	AmountINR int64  `json:"amount_inr"` // negative = debit
	Initiator string `json:"initiator"`
}

type State struct {
	Accounts     []*Account `json:"accounts"`
	Payees       []*Payee   `json:"payees"`
	Transactions []*Txn     `json:"transactions"`
}

var (
	mu        sync.Mutex
	state     State
	statePath string
)

func seed() State {
	now := time.Now()
	day := func(d int) string { return now.AddDate(0, 0, -d).Format(time.RFC3339) }
	return State{
		Accounts: []*Account{
			{ID: "ACC-OPS-001", Name: "Acme India Operations (Current)", IFSC: "HDFC0000123", BalanceINR: 4820000},
			{ID: "ACC-PAY-002", Name: "Acme India Payroll", IFSC: "HDFC0000123", BalanceINR: 12650000},
		},
		Payees: []*Payee{
			{Name: "CloudInfra India Pvt Ltd", Account: "50200011223344", IFSC: "ICIC0001122"},
			{Name: "Tata Steel Ltd", Account: "00112233445566", IFSC: "SBIN0000456"},
			{Name: "Mumbai Office Facilities LLP", Account: "77889900112233", IFSC: "UTIB0000789"},
		},
		Transactions: []*Txn{
			{Ref: "UTR26Q3A0001", AccountID: "ACC-OPS-001", Time: day(9), Narration: "NEFT CloudInfra India — INV-2026-Q3-0141", AmountINR: -182000, Initiator: "user:finance-ops"},
			{Ref: "UTR26Q3A0002", AccountID: "ACC-OPS-001", Time: day(6), Narration: "RTGS Tata Steel — INV-2026-Q3-0152", AmountINR: -1200000, Initiator: "user:finance-ops"},
			{Ref: "UTR26Q3A0003", AccountID: "ACC-OPS-001", Time: day(3), Narration: "Customer receipt — Globex Retail", AmountINR: 2450000, Initiator: "system"},
			{Ref: "UTR26Q3A0004", AccountID: "ACC-PAY-002", Time: day(1), Narration: "Salary run — October", AmountINR: -9800000, Initiator: "user:payroll"},
		},
	}
}

// db is set when BANK_DATABASE_URL is configured: balances and payments then live in Postgres
// (row kind "bank_state") and survive redeploys. Otherwise they live in a local JSON file.
var db *persist.Postgres

func load() {
	var raw []byte
	var err error
	if db != nil {
		var found bool
		raw, found, err = db.Get(context.Background(), "bank_state", "default")
		if err == nil && !found {
			err = os.ErrNotExist
		}
	} else {
		raw, err = os.ReadFile(statePath)
	}
	if err == nil && json.Unmarshal(raw, &state) == nil && len(state.Accounts) > 0 {
		return
	}
	state = seed()
	save()
}

func save() {
	raw, _ := json.MarshalIndent(state, "", "  ")
	if db != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := db.Put(ctx, "bank_state", "default", raw); err != nil {
			fmt.Fprintf(os.Stderr, "demo-bank-mcp: save: %v\n", err)
		}
		return
	}
	_ = os.MkdirAll(filepath.Dir(statePath), 0o755)
	_ = os.WriteFile(statePath, raw, 0o644)
}

func ref() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return "UTR" + strings.ToUpper(hex.EncodeToString(b))
}

func findAccount(id string) *Account {
	for _, a := range state.Accounts {
		if strings.EqualFold(a.ID, id) {
			return a
		}
	}
	return nil
}

func findPayee(name string) (*Payee, int) {
	for i, p := range state.Payees {
		if strings.EqualFold(p.Name, name) {
			return p, i
		}
	}
	return nil, -1
}

func inr(rupees int64) string {
	neg := rupees < 0
	if neg {
		rupees = -rupees
	}
	s := fmt.Sprintf("%d", rupees)
	// Indian digit grouping: last 3, then groups of 2.
	if len(s) > 3 {
		head, tail := s[:len(s)-3], s[len(s)-3:]
		var parts []string
		for len(head) > 2 {
			parts = append([]string{head[len(head)-2:]}, parts...)
			head = head[:len(head)-2]
		}
		if head != "" {
			parts = append([]string{head}, parts...)
		}
		s = strings.Join(parts, ",") + "," + tail
	}
	if neg {
		return "-₹" + s
	}
	return "₹" + s
}

// ---------------------------------------------------------------------------------------------

type tool struct {
	Name, Description string
	Schema            map[string]any
	ReadOnly          bool
	Destructive       bool
	Run               func(args map[string]any) (string, error)
}

func obj(props map[string]any, required ...string) map[string]any {
	m := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		m["required"] = required
	}
	return m
}

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }

var tools = []tool{
	{
		Name: "list_accounts", Description: "List the company's bank accounts with current balances.", ReadOnly: true,
		Schema: obj(map[string]any{}),
		Run: func(map[string]any) (string, error) {
			var sb strings.Builder
			for _, a := range state.Accounts {
				fmt.Fprintf(&sb, "%s  %-34s  IFSC %s  balance %s\n", a.ID, a.Name, a.IFSC, inr(a.BalanceINR))
			}
			return sb.String(), nil
		},
	},
	{
		Name: "get_transactions", Description: "Recent transactions for one account, newest first.", ReadOnly: true,
		Schema: obj(map[string]any{"account_id": str("Account ID, e.g. ACC-OPS-001"), "limit": map[string]any{"type": "integer", "description": "Max rows (default 20)"}}, "account_id"),
		Run: func(a map[string]any) (string, error) {
			id, _ := a["account_id"].(string)
			if findAccount(id) == nil {
				return "", fmt.Errorf("unknown account %q", id)
			}
			limit := 20
			if l, ok := a["limit"].(float64); ok && l > 0 {
				limit = int(l)
			}
			var rows []*Txn
			for _, t := range state.Transactions {
				if strings.EqualFold(t.AccountID, id) {
					rows = append(rows, t)
				}
			}
			sort.Slice(rows, func(i, j int) bool { return rows[i].Time > rows[j].Time })
			if len(rows) > limit {
				rows = rows[:limit]
			}
			var sb strings.Builder
			for _, t := range rows {
				fmt.Fprintf(&sb, "%s  %s  %-12s  %s  (by %s)\n", t.Time[:10], t.Ref, inr(t.AmountINR), t.Narration, t.Initiator)
			}
			if sb.Len() == 0 {
				return "No transactions.", nil
			}
			return sb.String(), nil
		},
	},
	{
		Name: "list_payees", Description: "List approved payees (beneficiaries).", ReadOnly: true,
		Schema: obj(map[string]any{}),
		Run: func(map[string]any) (string, error) {
			var sb strings.Builder
			for _, p := range state.Payees {
				fmt.Fprintf(&sb, "%s — A/c %s, IFSC %s\n", p.Name, p.Account, p.IFSC)
			}
			return sb.String(), nil
		},
	},
	{
		Name: "initiate_payment", Description: "Send money by NEFT/RTGS from a company account to an approved payee.",
		Schema: obj(map[string]any{
			"from_account": str("Source account ID, e.g. ACC-OPS-001"),
			"payee":        str("Exact payee name from list_payees"),
			"amount_inr":   map[string]any{"type": "number", "description": "Amount in rupees"},
			"note":         str("Narration / invoice reference"),
		}, "from_account", "payee", "amount_inr"),
		Run: func(a map[string]any) (string, error) {
			from, _ := a["from_account"].(string)
			payee, _ := a["payee"].(string)
			amt, _ := a["amount_inr"].(float64)
			note, _ := a["note"].(string)
			acc := findAccount(from)
			if acc == nil {
				return "", fmt.Errorf("unknown account %q", from)
			}
			p, _ := findPayee(payee)
			if p == nil {
				return "", fmt.Errorf("%q is not an approved payee", payee)
			}
			if amt <= 0 || int64(amt) > acc.BalanceINR {
				return "", fmt.Errorf("invalid amount or insufficient balance")
			}
			rail := "NEFT"
			if amt >= 200000 {
				rail = "RTGS"
			}
			t := &Txn{Ref: ref(), AccountID: acc.ID, Time: time.Now().Format(time.RFC3339), Narration: fmt.Sprintf("%s %s — %s", rail, p.Name, note), AmountINR: -int64(amt), Initiator: "agent via gateway"}
			acc.BalanceINR -= int64(amt)
			state.Transactions = append(state.Transactions, t)
			save()
			return fmt.Sprintf("Payment sent. %s %s to %s. Reference %s. New balance %s.", rail, inr(int64(amt)), p.Name, t.Ref, inr(acc.BalanceINR)), nil
		},
	},
	{
		Name: "export_statement", Description: "Send an account statement (JSON) to an external URL, e.g. an accounting system webhook.",
		Schema: obj(map[string]any{"account_id": str("Account ID"), "destination_url": str("https URL to POST the statement to")}, "account_id", "destination_url"),
		Run: func(a map[string]any) (string, error) {
			id, _ := a["account_id"].(string)
			dest, _ := a["destination_url"].(string)
			acc := findAccount(id)
			if acc == nil {
				return "", fmt.Errorf("unknown account %q", id)
			}
			if !strings.HasPrefix(dest, "https://") {
				dest = "https://" + strings.TrimPrefix(dest, "http://")
			}
			var rows []*Txn
			for _, t := range state.Transactions {
				if t.AccountID == acc.ID {
					rows = append(rows, t)
				}
			}
			body, _ := json.Marshal(map[string]any{"account": acc, "transactions": rows, "exported_at": time.Now().Format(time.RFC3339)})
			hc := &http.Client{Timeout: 8 * time.Second}
			resp, err := hc.Post(dest, "application/json", bytes.NewReader(body))
			if err != nil {
				return "", fmt.Errorf("export failed: %v", err)
			}
			resp.Body.Close()
			return fmt.Sprintf("Statement for %s (%d transactions, %d bytes) POSTed to %s — HTTP %d.", acc.ID, len(rows), len(body), dest, resp.StatusCode), nil
		},
	},
	{
		Name: "delete_payee", Description: "Remove a payee from the approved list.", Destructive: true,
		Schema: obj(map[string]any{"payee": str("Exact payee name")}, "payee"),
		Run: func(a map[string]any) (string, error) {
			name, _ := a["payee"].(string)
			_, i := findPayee(name)
			if i < 0 {
				return "", fmt.Errorf("no payee %q", name)
			}
			state.Payees = append(state.Payees[:i], state.Payees[i+1:]...)
			save()
			return "Payee " + name + " deleted.", nil
		},
	},
}

// ---------------------------------------------------------------------------------------------

type msg struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   any             `json:"error,omitempty"`
}

func reply(out *json.Encoder, id json.RawMessage, result any, err any) {
	_ = out.Encode(msg{JSONRPC: "2.0", ID: id, Result: result, Error: err})
}

func main() {
	flag.StringVar(&statePath, "state", "demo-data/bank_state.json", "where balances and payments are stored")
	flag.Parse()
	if url := os.Getenv("BANK_DATABASE_URL"); url != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		pg, err := persist.OpenPostgres(ctx, url)
		cancel()
		if err != nil {
			fmt.Fprintf(os.Stderr, "demo-bank-mcp: %v\n", err)
			os.Exit(1)
		}
		db = pg
		statePath = "postgres"
	}
	load()

	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 16<<20)
	out := json.NewEncoder(os.Stdout)
	fmt.Fprintf(os.Stderr, "demo-bank-mcp ready (state: %s)\n", statePath)

	for in.Scan() {
		var m msg
		if json.Unmarshal(in.Bytes(), &m) != nil || len(m.ID) == 0 {
			continue // ignore notifications
		}
		switch m.Method {
		case "initialize":
			var p struct {
				ProtocolVersion string `json:"protocolVersion"`
			}
			_ = json.Unmarshal(m.Params, &p)
			if p.ProtocolVersion == "" {
				p.ProtocolVersion = "2025-06-18"
			}
			reply(out, m.ID, map[string]any{
				"protocolVersion": p.ProtocolVersion,
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "demo-bank", "version": "1.0.0"},
			}, nil)
		case "ping":
			reply(out, m.ID, map[string]any{}, nil)
		case "tools/list":
			var list []map[string]any
			for _, t := range tools {
				list = append(list, map[string]any{
					"name": t.Name, "description": t.Description, "inputSchema": t.Schema,
					"annotations": map[string]any{"readOnlyHint": t.ReadOnly, "destructiveHint": t.Destructive},
				})
			}
			reply(out, m.ID, map[string]any{"tools": list}, nil)
		case "tools/call":
			var p struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			}
			_ = json.Unmarshal(m.Params, &p)
			var found *tool
			for i := range tools {
				if tools[i].Name == p.Name {
					found = &tools[i]
				}
			}
			if found == nil {
				reply(out, m.ID, nil, map[string]any{"code": -32602, "message": "unknown tool " + p.Name})
				continue
			}
			mu.Lock()
			text, err := found.Run(p.Arguments)
			mu.Unlock()
			isErr := err != nil
			if isErr {
				text = err.Error()
			}
			reply(out, m.ID, map[string]any{"content": []map[string]any{{"type": "text", "text": text}}, "isError": isErr}, nil)
		default:
			reply(out, m.ID, nil, map[string]any{"code": -32601, "message": "method not found"})
		}
	}
}
