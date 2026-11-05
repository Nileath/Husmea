package hashes

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"husmea/internal/core"
)

func TestParseIOC(t *testing.T) {
	in := `# comment
44d88612fea8a8f36de82e1278abb02f,EICAR
3395856CE81F2B7382DEE72602F798B642F14140 eicar sha1
"emotet";275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
not-a-hash
abc
`
	m := ParseIOC(strings.NewReader(in))
	if len(m) != 3 || m["44d88612fea8a8f36de82e1278abb02f"] != "EICAR" ||
		m["3395856ce81f2b7382dee72602f798b642f14140"] != "eicar sha1" ||
		m["275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"] != "emotet" {
		t.Errorf("ParseIOC = %v", m)
	}
}

func TestRunMatchesArtifacts(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.bin")
	good := filepath.Join(dir, "good.bin")
	_ = os.WriteFile(bad, []byte("abc"), 0o600)
	_ = os.WriteFile(good, []byte("hello"), 0o600)
	ioc := filepath.Join(dir, "ioc.txt")
	_ = os.WriteFile(ioc, []byte("900150983cd24fb0d6963f7d28e17f72 test-md5\n"), 0o600)

	env := &core.Env{Ctx: context.Background(), Opts: &core.Options{IOCFile: ioc}, Artifacts: core.NewArtifacts()}
	env.Artifacts.Add(bad, "test")
	env.Artifacts.Add(good, "test")
	env.Artifacts.Add(filepath.Join(dir, "missing"), "test")

	fs, err := New().Run(env)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Path != bad || fs[0].Severity != core.Critical || !strings.Contains(fs[0].Title, "test-md5") {
		t.Errorf("findings = %+v", fs)
	}

	env.Opts.IOCFile = ""
	if _, err := New().Run(env); err == nil {
		t.Error("expected skip without IOC file")
	}
}
