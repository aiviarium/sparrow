package hub

import (
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/aiviarium/sparrow/go/admin"
	"github.com/aiviarium/sparrow/go/cbor"
	"github.com/aiviarium/sparrow/go/schema"
)

// facetKey identifies a hub facet ID (10.3): stable for the triple (node
// ID, facet name, major version). The hub's own facets use node "".
type facetKey struct {
	node, name, major string
}

// table is the hub's facet-ID table with the last definition of every ID
// and the last known facets of every node (10.3, 10.7), persisted in the
// data directory (hub-admin 2.4).
type table struct {
	store   *admin.Store
	nextID  uint64
	ids     map[facetKey]uint64
	history map[uint64]*schema.Facet // last definition, with the hub facet ID
	known   map[string][]uint64      // node -> hub facet IDs it last published
}

const fileTable = "hub.cbor"

func newTable(store *admin.Store) (*table, error) {
	t := &table{store: store, nextID: schema.FirstFreeFacetID, ids: map[facetKey]uint64{},
		history: map[uint64]*schema.Facet{}, known: map[string][]uint64{}}
	if store == nil {
		return t, nil
	}
	b, err := store.Read(fileTable)
	if errors.Is(err, os.ErrNotExist) {
		return t, nil
	}
	if err != nil {
		return nil, err
	}
	if err := t.decode(b); err != nil {
		return nil, fmt.Errorf("hub: %s: %w", fileTable, err)
	}
	return t, nil
}

// encoding: [nextID, [[node, name, major, id]...], [[id, facet]...], [[node, [id...]]...]]
func (t *table) encode() []byte {
	b := cbor.AppendArrayHead(nil, 4)
	b = cbor.AppendUint(b, t.nextID)
	keys := make([]facetKey, 0, len(t.ids))
	for k := range t.ids {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return t.ids[keys[i]] < t.ids[keys[j]] })
	b = cbor.AppendArrayHead(b, len(keys))
	for _, k := range keys {
		b = cbor.AppendArrayHead(b, 4)
		b = cbor.AppendText(b, k.node)
		b = cbor.AppendText(b, k.name)
		b = cbor.AppendText(b, k.major)
		b = cbor.AppendUint(b, t.ids[k])
	}
	hids := make([]uint64, 0, len(t.history))
	for id := range t.history {
		hids = append(hids, id)
	}
	sort.Slice(hids, func(i, j int) bool { return hids[i] < hids[j] })
	b = cbor.AppendArrayHead(b, len(hids))
	for _, id := range hids {
		fb, err := t.history[id].CanonicalBytes()
		if err != nil {
			panic(err)
		}
		b = cbor.AppendArrayHead(b, 2)
		b = cbor.AppendUint(b, id)
		b = cbor.AppendBytes(b, fb)
	}
	nodes := make([]string, 0, len(t.known))
	for n := range t.known {
		nodes = append(nodes, n)
	}
	sort.Strings(nodes)
	b = cbor.AppendArrayHead(b, len(nodes))
	for _, n := range nodes {
		b = cbor.AppendArrayHead(b, 2)
		b = cbor.AppendText(b, n)
		b = cbor.AppendArrayHead(b, len(t.known[n]))
		for _, id := range t.known[n] {
			b = cbor.AppendUint(b, id)
		}
	}
	return b
}

func (t *table) decode(b []byte) error {
	d := cbor.NewDecoder(b)
	fail := func(err error) error {
		if err != nil {
			return err
		}
		return nil
	}
	if n, err := d.ArrayHead(); err != nil || n != 4 {
		return errors.New("bad table")
	}
	var err error
	if t.nextID, err = d.Uint(); err != nil {
		return err
	}
	n, err := d.ArrayHead()
	if err != nil {
		return err
	}
	for i := 0; i < n; i++ {
		if _, err := d.ArrayHead(); err != nil {
			return err
		}
		var k facetKey
		if k.node, err = d.Text(); err != nil {
			return err
		}
		if k.name, err = d.Text(); err != nil {
			return err
		}
		if k.major, err = d.Text(); err != nil {
			return err
		}
		id, err := d.Uint()
		if err != nil {
			return err
		}
		t.ids[k] = id
	}
	if n, err = d.ArrayHead(); err != nil {
		return err
	}
	for i := 0; i < n; i++ {
		if _, err := d.ArrayHead(); err != nil {
			return err
		}
		id, err := d.Uint()
		if err != nil {
			return err
		}
		fb, err := d.Bytes()
		if err != nil {
			return err
		}
		f, err := schema.DecodeFacet(fb)
		if err != nil {
			return fail(err)
		}
		t.history[id] = f
	}
	if n, err = d.ArrayHead(); err != nil {
		return err
	}
	for i := 0; i < n; i++ {
		if _, err := d.ArrayHead(); err != nil {
			return err
		}
		node, err := d.Text()
		if err != nil {
			return err
		}
		k, err := d.ArrayHead()
		if err != nil {
			return err
		}
		ids := make([]uint64, 0, k)
		for j := 0; j < k; j++ {
			id, err := d.Uint()
			if err != nil {
				return err
			}
			ids = append(ids, id)
		}
		t.known[node] = ids
	}
	return nil
}

func (t *table) save() error {
	if t.store == nil {
		return nil
	}
	return t.store.Write(fileTable, t.encode())
}

// lookup returns the ID of a key, if allocated.
func (t *table) lookup(k facetKey) (uint64, bool) {
	id, ok := t.ids[k]
	return id, ok
}

// allocate returns the ID of a key, allocating a new one that was never
// handed out before.
func (t *table) allocate(k facetKey) uint64 {
	if id, ok := t.ids[k]; ok {
		return id
	}
	used := map[uint64]bool{}
	for _, x := range t.ids {
		used[x] = true
	}
	for used[t.nextID] {
		t.nextID++ // skip IDs pinned above the counter
	}
	id := t.nextID
	t.nextID++
	t.ids[k] = id
	return id
}

// fix pins a key to a given ID (the hub's own facets, configured IDs).
func (t *table) fix(k facetKey, id uint64) { t.ids[k] = id }

// retire forgets every ID of a removed node; the IDs are never handed out
// again because nextID only grows (10.3).
func (t *table) retire(node string) {
	for k, id := range t.ids {
		if k.node == node {
			delete(t.ids, k)
			delete(t.history, id)
		}
	}
	delete(t.known, node)
}
