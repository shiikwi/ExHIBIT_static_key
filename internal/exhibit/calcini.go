package exhibit

import (
	"bytes"
	"os"
	"strconv"
)

func CalcIniValue(iniPath string) (uint32, error) {
	raw, err := os.ReadFile(iniPath)
	if err != nil {
		return 0, err
	}

	values, err := ParseSettingSection(raw)
	if err != nil {
		return 0, err
	}

	keys := []string{
		"CLASS", "TITLE", "W_VIEW", "H_VIEW", "N_REG", "N_STRREG",
		"N_SYSREG", "N_LOCREG", "N_USAVE", "N_ASAVE", "N_QSAVE",
		"N_CG", "N_MESSAGE", "N_SCENE", "N_SOUND",
	}
	flags := FlagsValue(values)
	if flags&4 != 0 {
		keys = append(keys, "FLAGS", "GUID", "SVDATA")
	}

	var blob []byte
	for _, key := range keys {
		blob = append(blob, values[key]...)
	}

	var sums [4]byte
	for i, c := range blob {
		sums[i&3] += c
	}
	return uint32(sums[3])<<24 | uint32(sums[2])<<16 | uint32(sums[1])<<8 | uint32(sums[0]), nil
}

func FlagsValue(values map[string][]byte) int {
	flags, _ := strconv.Atoi(string(values["FLAGS"]))
	return flags
}

func ParseSettingSection(raw []byte) (map[string][]byte, error) {
	values := make(map[string][]byte)
	inSetting := false
	for _, line := range bytes.Split(raw, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		if line[0] == '[' {
			inSetting = bytes.Equal(bytes.ToLower(line), []byte("[setting]"))
			continue
		}
		if !inSetting || line[0] == ';' {
			continue
		}
		eq := bytes.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key := string(bytes.TrimSpace(line[:eq]))
		values[key] = bytes.TrimSpace(line[eq+1:])
	}
	return values, nil
}
