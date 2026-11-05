package unixutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParsePasswd(t *testing.T) {
	us := ParsePasswd(strings.NewReader("root:x:0:0:root:/root:/bin/bash\n# c\nbad\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\nbob:x:1000:1000:Bob:/home/bob:/bin/zsh\n"))
	if len(us) != 3 || us[2].Name != "bob" || us[2].UID != 1000 || !us[2].LoginShell() || us[1].LoginShell() {
		t.Errorf("ParsePasswd = %+v", us)
	}
}

func TestPackageDBParsers(t *testing.T) {
	db := &PackageDB{files: map[string]string{}}
	db.parseList(strings.NewReader("/.\n/usr\n/usr/bin/ls\n"), "coreutils")
	db.parsePacmanFiles(strings.NewReader("%FILES%\nusr/\nusr/bin/pacman\n\n%BACKUP%\netc/pacman.conf\n"), "pacman")
	db.parseApk(strings.NewReader("P:busybox\nF:bin\nR:busybox\n"))
	db.parseRpm(strings.NewReader("/usr/bin/rpm\trpm\n(contains no files)\n"))
	for p, want := range map[string]string{
		"/usr/bin/ls": "coreutils", "/bin/ls": "coreutils", "/usr/bin/pacman": "pacman",
		"/bin/busybox": "busybox", "/usr/bin/busybox": "busybox", "/usr/bin/rpm": "rpm", "/etc/pacman.conf": "",
	} {
		if got := db.Owner(p); got != want {
			t.Errorf("Owner(%s) = %q, want %q", p, got, want)
		}
	}
}

func TestOwnerFollowsSymlinks(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	link := filepath.Join(dir, "link")
	_ = os.WriteFile(real, []byte("x"), 0o600)
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlinks unsupported")
	}
	db := NewPackageDBForTest(map[string]string{real: "pkg"})
	if db.Owner(link) != "pkg" {
		t.Error("symlink not resolved")
	}
}

func TestFileTypes(t *testing.T) {
	dir := t.TempDir()
	elf := filepath.Join(dir, "a")
	sh := filepath.Join(dir, "b")
	_ = os.WriteFile(elf, []byte{0x7f, 'E', 'L', 'F', 2}, 0o700)
	_ = os.WriteFile(sh, []byte("#!/bin/sh\necho\n"), 0o700)
	if !IsELF(elf) || IsELF(sh) || !HasShebang(sh) || HasShebang(elf) {
		t.Error("file type detection wrong")
	}
}
