package store

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// Hook keys let a client-side adapter (e.g. Claude Code's PreToolUse hook) tell a hosted gateway
// which sub-agent is about to call a tool. A key belongs to one user; the gateway accepts a
// notice only for MCP sessions of that same user. Only a SHA-256 hash of the key is stored.

type HookKey struct {
	UserID    string `json:"user_id"`
	Prefix    string `json:"prefix"` // first characters, shown in the console
	CreatedAt int64  `json:"created_at"`
}

func hookHash(key string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(key)))
	return hex.EncodeToString(sum[:])
}

// IssueHookKey creates a new key for the user and revokes any previous one. The key is returned once.
func (ds *DataStore) IssueHookKey(userID string) (string, *HookKey) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	if ds.hookKeys == nil {
		ds.hookKeys = map[string]*HookKey{}
	}
	for h, k := range ds.hookKeys {
		if k.UserID == userID {
			delete(ds.hookKeys, h)
		}
	}
	key := "ahk_" + randomToken(24)
	hk := &HookKey{UserID: userID, Prefix: key[:10], CreatedAt: time.Now().Unix()}
	ds.hookKeys[hookHash(key)] = hk
	return key, hk
}

// HookKeyFor returns the user's current key metadata (never the key itself).
func (ds *DataStore) HookKeyFor(userID string) (*HookKey, bool) {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	for _, k := range ds.hookKeys {
		if k.UserID == userID {
			c := *k
			return &c, true
		}
	}
	return nil, false
}

// HookKeyUser resolves a presented key to its user.
func (ds *DataStore) HookKeyUser(key string) (*User, bool) {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	k, ok := ds.hookKeys[hookHash(key)]
	if !ok {
		return nil, false
	}
	for _, u := range ds.state.Users {
		if u.ID == k.UserID {
			c := *u
			c.Password = ""
			return &c, true
		}
	}
	return nil, false
}
