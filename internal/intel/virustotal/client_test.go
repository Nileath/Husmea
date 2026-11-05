package virustotal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const report = `{"data":{"attributes":{"last_analysis_stats":{"malicious":42,"suspicious":1,"harmless":0,"undetected":20},
"meaningful_name":"evil.exe","popular_threat_classification":{"suggested_threat_label":"trojan.emotet/wacatac"}}}}`

func newTestClient(t *testing.T, h http.HandlerFunc) (*Client, *int32) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		if r.Header.Get("x-apikey") != "k" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	c := New("k", 6000)
	c.BaseURL = srv.URL + "/files/"
	c.CachePath = filepath.Join(t.TempDir(), "cache.json")
	c.cache = map[string]Result{}
	return c, &calls
}

func TestLookupFoundNotFoundAndCache(t *testing.T) {
	c, calls := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/aaa") {
			_, _ = w.Write([]byte(report))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	ctx := context.Background()
	r, err := c.Lookup(ctx, "aaa")
	if err != nil || !r.Found || r.Malicious != 42 || r.Label != "trojan.emotet/wacatac" || r.Name != "evil.exe" {
		t.Fatalf("Lookup = %+v %v", r, err)
	}
	r, err = c.Lookup(ctx, "bbb")
	if err != nil || r.Found {
		t.Fatalf("not found = %+v %v", r, err)
	}
	_, _ = c.Lookup(ctx, "aaa")
	if *calls != 2 {
		t.Errorf("cache not used, calls = %d", *calls)
	}
	if err := c.SaveCache(); err != nil {
		t.Fatal(err)
	}
	c2 := &Client{CachePath: c.CachePath, CacheTTL: time.Hour}
	c2.loadCache()
	if _, ok := c2.cached("aaa"); !ok {
		t.Error("persisted cache not loaded")
	}
}

func TestLookupUnauthorized(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {})
	c.Key = "wrong"
	if _, err := c.Lookup(context.Background(), "x"); err != ErrUnauthorized {
		t.Errorf("err = %v", err)
	}
}

func TestLookupRetriesOn429(t *testing.T) {
	var n int32
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(report))
	})
	c.Interval = time.Millisecond
	c.Backoff = 10 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r, err := c.Lookup(ctx, "aaa")
	if err != nil || r.Malicious != 42 {
		t.Errorf("retry = %+v %v", r, err)
	}
}
