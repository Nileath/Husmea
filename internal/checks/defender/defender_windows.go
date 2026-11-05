//go:build windows

package defender

import (
	"husmea/internal/core"
	"husmea/internal/winutil"
)

type check struct{}

func New() core.Check { return check{} }

func (check) Name() string { return Name }
func (check) Description() string {
	return "Estado de Microsoft Defender, exclusiones y detecciones recientes"
}
func (check) Phase() int { return core.PhaseCollect }

func (check) Run(env *core.Env) ([]core.Finding, error) {
	b, err := winutil.RunPowerShell(env.Ctx, script, nil)
	if err != nil {
		return nil, err
	}
	r, err := parseReport(b)
	if err != nil {
		return nil, err
	}
	return assess(r, env.IsAdmin), nil
}
