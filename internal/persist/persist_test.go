package persist

import (
	"context"
	"encoding/json"
	"testing"
)

type memBackend struct{ rows map[Key][]byte }

func (m *memBackend) LoadAll(context.Context) ([]Row, error) {
	var out []Row
	for k, v := range m.rows {
		out = append(out, Row{k.Kind, k.ID, v})
	}
	return out, nil
}
func (m *memBackend) Apply(_ context.Context, ups []Row, dels []Key) error {
	for _, r := range ups {
		m.rows[Key{r.Kind, r.ID}] = r.Doc
	}
	for _, k := range dels {
		delete(m.rows, k)
	}
	return nil
}
func (m *memBackend) Close() {}

type mapSource struct{ items map[string]string }

func (s *mapSource) Kinds() []string { return []string{"item"} }
func (s *mapSource) Snapshot() Snapshot {
	out := Snapshot{"item": {}}
	for k, v := range s.items {
		out["item"][k] = v
	}
	return out
}
func (s *mapSource) Restore(l Loaded) error {
	s.items = map[string]string{}
	for id, raw := range l["item"] {
		var v string
		_ = json.Unmarshal(raw, &v)
		s.items[id] = v
	}
	return nil
}

func TestSyncerRoundTripAndForeignKinds(t *testing.T) {
	ctx := context.Background()
	b := &memBackend{rows: map[Key][]byte{{"bank_state", "default"}: []byte(`{"x":1}`)}}
	src := &mapSource{items: map[string]string{}}
	s := NewSyncer(b, src)
	if _, err := s.Load(ctx); err != nil {
		t.Fatal(err)
	}
	src.items["a"], src.items["b"] = "1", "2"
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	delete(src.items, "a")
	src.items["b"] = "3"
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.rows[Key{"bank_state", "default"}]; !ok {
		t.Fatal("a row owned by another process was deleted")
	}
	if _, ok := b.rows[Key{"item", "a"}]; ok {
		t.Fatal("removed record still stored")
	}
	src2 := &mapSource{}
	if _, err := NewSyncer(b, src2).Load(ctx); err != nil {
		t.Fatal(err)
	}
	if src2.items["b"] != "3" || len(src2.items) != 1 {
		t.Fatalf("restore mismatch: %v", src2.items)
	}
}

func TestSealer(t *testing.T) {
	s, _ := NewSealer("secret")
	v := s.Seal([]byte("key"))
	got, err := s.Open(v)
	if err != nil || string(got) != "key" {
		t.Fatal(err)
	}
	other, _ := NewSealer("other")
	if _, err := other.Open(v); err == nil {
		t.Fatal("wrong secret decrypted")
	}
}
