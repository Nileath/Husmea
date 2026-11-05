package autoruns

import (
	"encoding/binary"
	"errors"
	"strings"
	"unicode/utf16"
)

// Shortcut holds the interesting fields of a Windows .lnk file (MS-SHLLINK).
type Shortcut struct {
	Target       string
	Arguments    string
	WorkingDir   string
	RelativePath string
}

const (
	hasLinkTargetIDList = 1 << 0
	hasLinkInfo         = 1 << 1
	hasName             = 1 << 2
	hasRelativePath     = 1 << 3
	hasWorkingDir       = 1 << 4
	hasArguments        = 1 << 5
	hasIconLocation     = 1 << 6
	isUnicode           = 1 << 7
)

var errBadLnk = errors.New("lnk inválido")

func ParseLnk(b []byte) (*Shortcut, error) {
	if len(b) < 0x4C || binary.LittleEndian.Uint32(b[0:4]) != 0x4C {
		return nil, errBadLnk
	}
	flags := binary.LittleEndian.Uint32(b[0x14:0x18])
	off := 0x4C
	need := func(n int) bool { return off+n <= len(b) }

	if flags&hasLinkTargetIDList != 0 {
		if !need(2) {
			return nil, errBadLnk
		}
		off += 2 + int(binary.LittleEndian.Uint16(b[off:]))
	}
	sc := &Shortcut{}
	if flags&hasLinkInfo != 0 {
		if !need(4) {
			return nil, errBadLnk
		}
		start := off
		size := int(binary.LittleEndian.Uint32(b[off:]))
		if size < 0x1C || start+size > len(b) {
			return nil, errBadLnk
		}
		li := b[start : start+size]
		liFlags := binary.LittleEndian.Uint32(li[8:12])
		if liFlags&1 != 0 { // VolumeIDAndLocalBasePath
			lbp := int(binary.LittleEndian.Uint32(li[16:20]))
			headerSize := binary.LittleEndian.Uint32(li[4:8])
			if headerSize >= 0x24 && len(li) >= 0x24 {
				if u := int(binary.LittleEndian.Uint32(li[28:32])); u > 0 && u < len(li) {
					sc.Target = readUTF16Z(li[u:])
				}
			}
			if sc.Target == "" && lbp > 0 && lbp < len(li) {
				sc.Target = readANSIZ(li[lbp:])
			}
		}
		off = start + size
	}
	unicode := flags&isUnicode != 0
	readStr := func() (string, error) {
		if !need(2) {
			return "", errBadLnk
		}
		n := int(binary.LittleEndian.Uint16(b[off:]))
		off += 2
		if unicode {
			if !need(n * 2) {
				return "", errBadLnk
			}
			u := make([]uint16, n)
			for i := range u {
				u[i] = binary.LittleEndian.Uint16(b[off+i*2:])
			}
			off += n * 2
			return string(utf16.Decode(u)), nil
		}
		if !need(n) {
			return "", errBadLnk
		}
		s := string(b[off : off+n])
		off += n
		return s, nil
	}
	fields := []struct {
		flag uint32
		dst  *string
	}{
		{hasName, nil},
		{hasRelativePath, &sc.RelativePath},
		{hasWorkingDir, &sc.WorkingDir},
		{hasArguments, &sc.Arguments},
		{hasIconLocation, nil},
	}
	for _, f := range fields {
		if flags&f.flag == 0 {
			continue
		}
		s, err := readStr()
		if err != nil {
			return sc, nil // keep what we have; trailing data is optional
		}
		if f.dst != nil {
			*f.dst = s
		}
	}
	return sc, nil
}

func readANSIZ(b []byte) string {
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func readUTF16Z(b []byte) string {
	var u []uint16
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}
