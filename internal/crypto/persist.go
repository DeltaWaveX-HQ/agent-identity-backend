package crypto

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"time"

	"github.com/buildathon2026/agent-identity-backend/internal/persist"
)

// KeyStore persists the token-signing keys (encrypted with APP_SECRET), so tokens issued before
// a restart or redeploy still verify afterwards.
type KeyStore struct {
	km     *KeyManager
	sealer *persist.Sealer
}

func NewKeyStore(km *KeyManager, sealer *persist.Sealer) *KeyStore {
	return &KeyStore{km: km, sealer: sealer}
}

type storedKey struct {
	Kid       string `json:"kid"`
	Sealed    string `json:"sealed_private_key"` // AES-GCM(SEC1 DER) — never the plain key
	RotatedAt int64  `json:"rotated_at,omitempty"`
}

func (ks *KeyStore) Kinds() []string { return []string{"signing_key"} }

func (ks *KeyStore) seal(k *ecdsa.PrivateKey, kid string, rotated int64) json.RawMessage {
	der, _ := x509.MarshalECPrivateKey(k)
	b, _ := json.Marshal(storedKey{Kid: kid, Sealed: ks.sealer.Seal(der), RotatedAt: rotated})
	return b
}

// Snapshot re-seals only when the key changes: the syncer compares hashes, and AES-GCM uses a
// fresh nonce each time, so cache the sealed form per kid.
func (ks *KeyStore) Snapshot() persist.Snapshot {
	ks.km.mu.RLock()
	defer ks.km.mu.RUnlock()
	if ks.km.sealedCache == nil {
		ks.km.sealedCache = map[string]json.RawMessage{}
	}
	get := func(k *ecdsa.PrivateKey, kid string) json.RawMessage {
		if v, ok := ks.km.sealedCache[kid]; ok {
			return v
		}
		v := ks.seal(k, kid, ks.km.rotatedAt.Unix())
		ks.km.sealedCache[kid] = v
		return v
	}
	return persist.Snapshot{"signing_key": {
		"active": get(ks.km.activeKey, ks.km.activeKid),
		"staged": get(ks.km.stagedKey, ks.km.stagedKid),
	}}
}

func (ks *KeyStore) Restore(l persist.Loaded) error {
	m := l["signing_key"]
	if len(m) == 0 {
		return nil // first boot: keep the freshly generated keys; they are saved on the next flush
	}
	load := func(slot string) (*ecdsa.PrivateKey, string, int64, error) {
		rawDoc, ok := m[slot]
		if !ok {
			return nil, "", 0, fmt.Errorf("signing key %q missing", slot)
		}
		var sk storedKey
		if err := json.Unmarshal(rawDoc, &sk); err != nil {
			return nil, "", 0, err
		}
		der, err := ks.sealer.Open(sk.Sealed)
		if err != nil {
			return nil, "", 0, fmt.Errorf("signing key %q: %w", slot, err)
		}
		k, err := x509.ParseECPrivateKey(der)
		return k, sk.Kid, sk.RotatedAt, err
	}
	a, akid, rot, err := load("active")
	if err != nil {
		return err
	}
	st, skid, _, err := load("staged")
	if err != nil {
		return err
	}
	ks.km.mu.Lock()
	defer ks.km.mu.Unlock()
	ks.km.activeKey, ks.km.activeKid = a, akid
	ks.km.stagedKey, ks.km.stagedKid = st, skid
	if rot > 0 {
		ks.km.rotatedAt = time.Unix(rot, 0).UTC()
		ks.km.nextRotate = ks.km.rotatedAt.Add(30 * 24 * time.Hour)
	}
	ks.km.sealedCache = map[string]json.RawMessage{akid: m["active"], skid: m["staged"]}
	return nil
}
