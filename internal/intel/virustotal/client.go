// Package virustotal implements a minimal VirusTotal API v3 client for hash lookups.
// Only hashes are sent; file contents are never uploaded.
package virustotal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const baseURL = "https://www.virustotal.com/api/v3/files/"

type Result struct {
	SHA256     string    `json:"sha256"`
	Found      bool      `json:"found"`
	Malicious  int       `json:"malicious"`
	Suspicious int       `json:"suspicious"`
	Harmless   int       `json:"harmless"`
	Undetected int       `json:"undetected"`
	Name       string    `json:"name,omitempty"`
	Label      string    `json:"label,omitempty"`
	Checked    time.Time `json:"checked"`
}

func (r Result) Link() string { return "https://www.virustotal.com/gui/file/" + r.SHA256 }

type Client struct {
	Key       string
	HTTP      *http.Client
	BaseURL   string
	Interval  time.Duration // minimum time between requests (free API: 4/min)
	CachePath string
	CacheTTL  time.Duration
	Backoff   time.Duration // wait after HTTP 429 (quota exceeded)

	mu    sync.Mutex
	last  time.Time
	cache map[string]Result
}

func New(key string, perMinute int) *Client {
	if perMinute <= 0 {
		perMinute = 4
	}
	c := &Client{
		Key:      key,
		HTTP:     &http.Client{Timeout: 30 * time.Second},
		BaseURL:  baseURL,
		Interval: time.Minute / time.Duration(perMinute),
		CacheTTL: 7 * 24 * time.Hour,
		Backoff:  time.Minute,
	}
	if dir, err := os.UserCacheDir(); err == nil {
		c.CachePath = filepath.Join(dir, "husmea", "vt-cache.json")
	}
	c.loadCache()
	return c
}

func (c *Client) loadCache() {
	c.cache = map[string]Result{}
	if c.CachePath == "" {
		return
	}
	if b, err := os.ReadFile(c.CachePath); err == nil {
		_ = json.Unmarshal(b, &c.cache)
	}
}

func (c *Client) SaveCache() error {
	if c.CachePath == "" {
		return nil
	}
	c.mu.Lock()
	b, err := json.Marshal(c.cache)
	c.mu.Unlock()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.CachePath), 0o700); err != nil {
		return err
	}
	return os.WriteFile(c.CachePath, b, 0o600)
}

func (c *Client) cached(sha string) (Result, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.cache[sha]
	if ok && time.Since(r.Checked) < c.CacheTTL {
		return r, true
	}
	return Result{}, false
}

func (c *Client) wait(ctx context.Context) error {
	c.mu.Lock()
	next := c.last.Add(c.Interval)
	c.mu.Unlock()
	if d := time.Until(next); d > 0 {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
	c.mu.Lock()
	c.last = time.Now()
	c.mu.Unlock()
	return nil
}

var ErrUnauthorized = errors.New("API key de VirusTotal no válida")

// Lookup returns the VirusTotal verdict for a SHA-256 (cached for CacheTTL).
func (c *Client) Lookup(ctx context.Context, sha256 string) (Result, error) {
	if r, ok := c.cached(sha256); ok {
		return r, nil
	}
	for attempt := 0; attempt < 3; attempt++ {
		if err := c.wait(ctx); err != nil {
			return Result{}, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+sha256, nil)
		if err != nil {
			return Result{}, err
		}
		req.Header.Set("x-apikey", c.Key)
		req.Header.Set("Accept", "application/json")
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return Result{}, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusOK:
			r, err := ParseFileReport(body)
			if err != nil {
				return Result{}, err
			}
			r.SHA256, r.Found, r.Checked = sha256, true, time.Now()
			c.store(r)
			return r, nil
		case http.StatusNotFound:
			r := Result{SHA256: sha256, Checked: time.Now()}
			c.store(r)
			return r, nil
		case http.StatusUnauthorized, http.StatusForbidden:
			return Result{}, ErrUnauthorized
		case http.StatusTooManyRequests:
			// Quota exceeded: back off before retrying.
			c.mu.Lock()
			c.last = time.Now().Add(c.Backoff - c.Interval)
			c.mu.Unlock()
			continue
		default:
			return Result{}, fmt.Errorf("VirusTotal respondió %d", resp.StatusCode)
		}
	}
	return Result{}, errors.New("cuota de VirusTotal agotada")
}

func (c *Client) store(r Result) {
	c.mu.Lock()
	c.cache[r.SHA256] = r
	c.mu.Unlock()
}

// ParseFileReport extracts the relevant fields from a /files/{id} response.
func ParseFileReport(b []byte) (Result, error) {
	var doc struct {
		Data struct {
			Attributes struct {
				Stats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Harmless   int `json:"harmless"`
					Undetected int `json:"undetected"`
				} `json:"last_analysis_stats"`
				MeaningfulName string `json:"meaningful_name"`
				Threat         struct {
					Label string `json:"suggested_threat_label"`
				} `json:"popular_threat_classification"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return Result{}, fmt.Errorf("respuesta de VirusTotal no válida: %w", err)
	}
	a := doc.Data.Attributes
	return Result{
		Malicious:  a.Stats.Malicious,
		Suspicious: a.Stats.Suspicious,
		Harmless:   a.Stats.Harmless,
		Undetected: a.Stats.Undetected,
		Name:       a.MeaningfulName,
		Label:      a.Threat.Label,
	}, nil
}
