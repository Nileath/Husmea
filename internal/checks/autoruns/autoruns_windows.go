//go:build windows

package autoruns

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"

	"husmea/internal/core"
	"husmea/internal/heuristics"
	"husmea/internal/winutil"
)

type check struct{}

func New() core.Check { return check{} }

func (check) Name() string { return Name }
func (check) Description() string {
	return "Persistencia: claves Run, carpeta Inicio, Winlogon, IFEO, AppInit_DLLs"
}
func (check) Phase() int { return core.PhaseCollect }

type hive struct {
	key  registry.Key
	path string // prefix inside the hive
	name string // printable
}

// userHives returns HKU\<SID> for every loaded interactive user profile.
func userHives() []hive {
	var out []hive
	k, err := registry.OpenKey(registry.USERS, "", registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return []hive{{registry.CURRENT_USER, "", "HKCU"}}
	}
	defer k.Close()
	names, _ := k.ReadSubKeyNames(-1)
	for _, n := range names {
		if strings.HasPrefix(n, "S-1-5-21-") && !strings.HasSuffix(n, "_Classes") {
			out = append(out, hive{registry.USERS, n + `\`, `HKU\` + n})
		}
	}
	if len(out) == 0 {
		out = append(out, hive{registry.CURRENT_USER, "", "HKCU"})
	}
	return out
}

func readValues(root registry.Key, path string) map[string]string {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, _ := k.ReadValueNames(-1)
	out := map[string]string{}
	for _, n := range names {
		if v, ok := winutil.RegValue(k, n); ok {
			out[n] = v
		}
	}
	return out
}

func readValue(root registry.Key, path, name string) (string, bool) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return "", false
	}
	defer k.Close()
	return winutil.RegValue(k, name)
}

func subKeys(root registry.Key, path string) []string {
	k, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer k.Close()
	n, _ := k.ReadSubKeyNames(-1)
	return n
}

var runPaths = []string{
	`Software\Microsoft\Windows\CurrentVersion\Run`,
	`Software\Microsoft\Windows\CurrentVersion\RunOnce`,
	`Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`,
	`Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`,
	`Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`,
}

func collect() []entry {
	var out []entry
	add := func(k kind, loc, name, cmd string) {
		out = append(out, entry{Kind: k, Location: loc, Name: name, Command: cmd})
	}
	hives := append([]hive{{registry.LOCAL_MACHINE, "", "HKLM"}}, userHives()...)

	for _, h := range hives {
		for _, p := range runPaths {
			for n, v := range readValues(h.key, h.path+p) {
				add(kindRun, h.name+`\`+p, n, v)
			}
		}
		for _, p := range []string{`Software\Microsoft\Command Processor`, `Software\Wow6432Node\Microsoft\Command Processor`} {
			if v, ok := readValue(h.key, h.path+p, "AutoRun"); ok && strings.TrimSpace(v) != "" {
				add(kindCmdAutoRun, h.name+`\`+p, "AutoRun", v)
			}
		}
		if h.key != registry.LOCAL_MACHINE {
			if v, ok := readValue(h.key, h.path+`Environment`, "UserInitMprLogonScript"); ok && v != "" {
				add(kindLogonScript, h.name+`\Environment`, "UserInitMprLogonScript", v)
			}
			wl := `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`
			if v, ok := readValue(h.key, h.path+wl, "Shell"); ok && v != "" {
				add(kindWinlogon, h.name+`\`+wl, "Shell", v)
			}
			win := `Software\Microsoft\Windows NT\CurrentVersion\Windows`
			for _, n := range []string{"Load", "Run"} {
				if v, ok := readValue(h.key, h.path+win, n); ok && strings.TrimSpace(v) != "" {
					add(kindRun, h.name+`\`+win, n, v)
				}
			}
		}
	}

	wl := `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
	for _, n := range []string{"Shell", "Userinit"} {
		if v, ok := readValue(registry.LOCAL_MACHINE, wl, n); ok {
			add(kindWinlogon, `HKLM\`+wl, n, v)
		}
	}
	for _, base := range []string{`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, `SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion`} {
		ifeo := base + `\Image File Execution Options`
		for _, sk := range subKeys(registry.LOCAL_MACHINE, ifeo) {
			if v, ok := readValue(registry.LOCAL_MACHINE, ifeo+`\`+sk, "Debugger"); ok && strings.TrimSpace(v) != "" {
				add(kindIFEO, `HKLM\`+ifeo+`\`+sk, sk, v)
			}
		}
		spe := base + `\SilentProcessExit`
		for _, sk := range subKeys(registry.LOCAL_MACHINE, spe) {
			if v, ok := readValue(registry.LOCAL_MACHINE, spe+`\`+sk, "MonitorProcess"); ok && strings.TrimSpace(v) != "" {
				add(kindSilentExit, `HKLM\`+spe+`\`+sk, sk, v)
			}
		}
		win := base + `\Windows`
		if dlls, ok := readValue(registry.LOCAL_MACHINE, win, "AppInit_DLLs"); ok && strings.TrimSpace(dlls) != "" {
			if load, _ := readValue(registry.LOCAL_MACHINE, win, "LoadAppInit_DLLs"); load == "1" {
				for _, d := range strings.FieldsFunc(dlls, func(r rune) bool { return r == ',' || r == ' ' }) {
					add(kindAppInit, `HKLM\`+win, "AppInit_DLLs", d)
				}
			}
		}
	}
	sm := `SYSTEM\CurrentControlSet\Control\Session Manager`
	if v, ok := readValue(registry.LOCAL_MACHINE, sm, "BootExecute"); ok {
		add(kindBootExecute, `HKLM\`+sm, "BootExecute", v)
	}

	out = append(out, startupFolders()...)
	return out
}

func startupFolders() []entry {
	dirs := map[string]bool{}
	if d := os.Getenv("ProgramData"); d != "" {
		dirs[filepath.Join(d, `Microsoft\Windows\Start Menu\Programs\StartUp`)] = true
	}
	if d := os.Getenv("APPDATA"); d != "" {
		dirs[filepath.Join(d, `Microsoft\Windows\Start Menu\Programs\Startup`)] = true
	}
	// Other users' folders (readable when running as administrator).
	usersRoot := filepath.Join(filepath.VolumeName(os.Getenv("SystemRoot"))+`\`, "Users")
	if ents, err := os.ReadDir(usersRoot); err == nil {
		for _, u := range ents {
			if u.IsDir() {
				dirs[filepath.Join(usersRoot, u.Name(), `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`)] = true
			}
		}
	}
	var out []entry
	seen := map[string]bool{}
	for d := range dirs {
		files, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, f := range files {
			if f.IsDir() || strings.EqualFold(f.Name(), "desktop.ini") {
				continue
			}
			full := filepath.Join(d, f.Name())
			if seen[strings.ToLower(full)] {
				continue
			}
			seen[strings.ToLower(full)] = true
			e := entry{Kind: kindStartupFolder, Location: d, Name: f.Name(), Command: `"` + full + `"`}
			if strings.EqualFold(filepath.Ext(full), ".lnk") {
				if b, err := os.ReadFile(full); err == nil {
					if sc, err := ParseLnk(b); err == nil {
						target := sc.Target
						if target == "" && sc.RelativePath != "" {
							target = filepath.Join(d, sc.RelativePath)
						}
						if target != "" {
							e.Command = strings.TrimSpace(`"` + target + `" ` + sc.Arguments)
						}
					}
				}
			}
			out = append(out, e)
		}
	}
	return out
}

func (check) Run(env *core.Env) ([]core.Finding, error) {
	entries := collect()
	var files []string
	refs := make([]winutil.CommandRef, len(entries))
	for i, e := range entries {
		if e.Kind == kindBootExecute {
			continue
		}
		refs[i] = winutil.ParseRegistryCommand(e.Command)
		for _, f := range refs[i].Files() {
			files = append(files, f)
			env.Artifacts.Add(f, "autorun:"+e.Name)
		}
		if e.Kind == kindStartupFolder {
			// The startup file itself (e.g. the .lnk or a dropped script) is also worth hashing.
			env.Artifacts.Add(filepath.Join(e.Location, e.Name), "carpeta-inicio")
		}
	}
	env.Sig.Prefetch(env.Ctx, files)
	var out []core.Finding
	for i, e := range entries {
		if e.Kind != kindBootExecute {
			e.Launch = refs[i].Launch(env.Ctx, env.Sig)
		} else {
			e.Launch = heuristics.Launch{}
		}
		if f := assess(e); f != nil {
			out = append(out, *f)
		}
	}
	if !env.IsAdmin {
		env.Logf("autoruns: sin privilegios de administrador solo se revisan los usuarios accesibles")
	}
	return out, nil
}
