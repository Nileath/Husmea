package unixutil

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type User struct {
	Name  string
	UID   int
	GID   int
	Home  string
	Shell string
}

// LoginShell reports whether the user can log in interactively.
func (u User) LoginShell() bool {
	s := filepath.Base(u.Shell)
	return u.Shell != "" && s != "nologin" && s != "false" && s != "sync" && s != "halt" && s != "shutdown"
}

func ParsePasswd(r io.Reader) []User {
	var out []User
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		f := strings.Split(l, ":")
		if len(f) < 7 {
			continue
		}
		uid, err1 := strconv.Atoi(f[2])
		gid, err2 := strconv.Atoi(f[3])
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, User{Name: f[0], UID: uid, GID: gid, Home: f[5], Shell: f[6]})
	}
	return out
}

func Users() []User {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil
	}
	defer f.Close()
	return ParsePasswd(f)
}

// HomeDirs returns existing home directories of root and regular users (deduplicated).
func HomeDirs() []string {
	seen := map[string]bool{}
	var out []string
	add := func(h string) {
		if h == "" || h == "/" || seen[h] {
			return
		}
		if st, err := os.Stat(h); err == nil && st.IsDir() {
			seen[h] = true
			out = append(out, h)
		}
	}
	add("/root")
	for _, u := range Users() {
		if u.UID == 0 || (u.UID >= 1000 && u.UID < 60000) {
			add(u.Home)
		}
	}
	if h, err := os.UserHomeDir(); err == nil {
		add(h)
	}
	return out
}

// IsELF reports whether the file starts with the ELF magic.
func IsELF(p string) bool {
	b, _ := ReadHead(p, 4)
	return len(b) == 4 && b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F'
}

// HasShebang reports whether the file is a script starting with "#!".
func HasShebang(p string) bool {
	b, _ := ReadHead(p, 2)
	return len(b) == 2 && b[0] == '#' && b[1] == '!'
}

// ReadHead reads up to max bytes of a file.
func ReadHead(p string, max int64) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, max))
}

// ReadLines reads a text file (bounded) and returns its lines.
func ReadLines(p string) ([]string, error) {
	b, err := ReadHead(p, 1<<20)
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n"), nil
}

// ListFiles returns regular files directly inside dir (sorted by name).
func ListFiles(dir string) []string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if e.Type().IsRegular() || e.Type()&os.ModeSymlink != 0 {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out
}
