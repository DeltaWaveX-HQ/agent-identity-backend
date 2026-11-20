package main

// The gateway derives what a tool call *does* from the call itself (tool name, MCP annotations,
// arguments, tenant config). The agent never gets to label its own actions.

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

type Classification struct {
	Action    string   `json:"action"`
	Hosts     []string `json:"hosts,omitempty"`
	AmountINR int      `json:"amount_inr,omitempty"`
	Bulk      bool     `json:"bulk,omitempty"`
	Basis     string   `json:"basis"` // why we chose this action (config | annotation | name | default)
}

var (
	deleteWords  = words("delete remove rm drop destroy purge truncate wipe erase revoke")
	paymentWords = words("pay payment payments transfer remit payout disburse neft rtgs imps upi wire")
	exportWords  = words("export upload send post email mail share publish webhook sync push")
	writeWords   = words("write create update edit move rename set add insert put patch append mkdir make save modify replace commit merge approve")
	readWords    = words("read get list search find fetch query describe show view head tail tree info stat lookup retrieve download browse count check")
	bulkWords    = words("all dump bulk everything full")
	urlRe        = regexp.MustCompile(`https?://[^\s"'<>]+`)
)

func words(s string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(s) {
		m[w] = true
	}
	return m
}

// nameTokens splits read_file / readFile / read-file into ["read","file"].
func nameTokens(name string) []string {
	var out []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, strings.ToLower(cur.String()))
			cur.Reset()
		}
	}
	prevLower := false
	for _, r := range name {
		switch {
		case !unicode.IsLetter(r) && !unicode.IsDigit(r):
			flush()
			prevLower = false
		case unicode.IsUpper(r) && prevLower:
			flush()
			cur.WriteRune(r)
			prevLower = false
		default:
			cur.WriteRune(r)
			prevLower = unicode.IsLower(r)
		}
	}
	flush()
	return out
}

func anyToken(tokens []string, set map[string]bool) bool {
	for _, t := range tokens {
		if set[t] {
			return true
		}
	}
	return false
}

func classifyCall(toolName string, annotations map[string]any, policy ToolPolicy, args map[string]any) Classification {
	c := Classification{}
	tokens := nameTokens(toolName)

	switch {
	case policy.Action != "":
		c.Action, c.Basis = policy.Action, "config"
	case anyToken(tokens, deleteWords):
		c.Action, c.Basis = "delete", "name"
	case anyToken(tokens, paymentWords):
		c.Action, c.Basis = "payment_transfer", "name"
	case anyToken(tokens, exportWords):
		c.Action, c.Basis = "export", "name"
	case annotations["readOnlyHint"] == true:
		c.Action, c.Basis = "read", "annotation"
	case anyToken(tokens, writeWords):
		c.Action, c.Basis = "write", "name"
	case anyToken(tokens, readWords):
		c.Action, c.Basis = "read", "name"
	default:
		// Unknown verbs are treated as changes: safer to ask than to assume read-only.
		c.Action, c.Basis = "write", "default"
	}

	// Destinations: configured URL arguments, otherwise any URL found anywhere in the arguments.
	seen := map[string]bool{}
	addHost := func(raw string) {
		u, err := url.Parse(strings.TrimRight(raw, ".,;)"))
		if err != nil || u.Hostname() == "" {
			return
		}
		h := strings.ToLower(u.Hostname())
		if !seen[h] {
			seen[h] = true
			c.Hosts = append(c.Hosts, h)
		}
	}
	if len(policy.URLArgs) > 0 {
		for _, k := range policy.URLArgs {
			if s, ok := args[k].(string); ok {
				if !strings.Contains(s, "://") {
					s = "https://" + s
				}
				addHost(s)
			}
		}
	} else {
		walkStrings(args, 0, func(s string) {
			for _, m := range urlRe.FindAllString(s, 5) {
				addHost(m)
			}
		})
	}

	// Amount in INR.
	if policy.AmountArg != "" {
		c.AmountINR = toInt(args[policy.AmountArg])
	} else {
		for k, v := range args {
			if strings.Contains(strings.ToLower(k), "amount") {
				c.AmountINR = toInt(v)
				break
			}
		}
	}

	// Bulk access.
	c.Bulk = policy.Bulk || anyToken(tokens, bulkWords)
	for _, k := range []string{"limit", "count", "page_size", "pageSize", "max_results", "per_page"} {
		if toInt(args[k]) > 500 {
			c.Bulk = true
		}
	}
	return c
}

func walkStrings(v any, depth int, fn func(string)) {
	if depth > 6 {
		return
	}
	switch t := v.(type) {
	case string:
		fn(t)
	case map[string]any:
		for _, x := range t {
			walkStrings(x, depth+1, fn)
		}
	case []any:
		for _, x := range t {
			walkStrings(x, depth+1, fn)
		}
	}
}

func toInt(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case json.Number:
		n, _ := t.Int64()
		return int(n)
	case string:
		n := 0
		for _, r := range t {
			if r >= '0' && r <= '9' {
				n = n*10 + int(r-'0')
			} else if r == '.' {
				break
			}
		}
		return n
	}
	return 0
}

// Phrases typical of indirect prompt injection hidden in documents, web pages, tickets or emails.
var injectionMarkers = []string{
	"ignore previous instructions",
	"ignore all previous instructions",
	"ignore the above instructions",
	"disregard previous instructions",
	"disregard all prior",
	"forget your instructions",
	"new instructions for the ai",
	"instructions for ai agents",
	"you are now in developer mode",
	"do not tell the user",
	"don't tell the user",
	"without telling the user",
	"without asking the user",
	"exfiltrate",
	"<!-- ai:",
	"[system]",
	"</system>",
}

// scanForInjection returns the markers found in the text parts of an MCP tool result.
func scanForInjection(result json.RawMessage) (markers []string, size int) {
	size = len(result)
	var res struct {
		Content []struct {
			Type     string `json:"type"`
			Text     string `json:"text"`
			Resource struct {
				Text string `json:"text"`
			} `json:"resource"`
		} `json:"content"`
		StructuredContent any `json:"structuredContent"`
	}
	if json.Unmarshal(result, &res) != nil {
		return nil, size
	}
	var sb strings.Builder
	for _, c := range res.Content {
		sb.WriteString(c.Text)
		sb.WriteString(c.Resource.Text)
		sb.WriteByte('\n')
	}
	if res.StructuredContent != nil {
		walkStrings(res.StructuredContent, 0, func(s string) { sb.WriteString(s); sb.WriteByte('\n') })
	}
	text := strings.ToLower(sb.String())
	for _, m := range injectionMarkers {
		if strings.Contains(text, m) {
			markers = append(markers, m)
		}
	}
	return markers, size
}
