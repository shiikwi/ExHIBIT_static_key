package exhibit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"ExHIBITkeyfind/internal/pefile"
)

func Run(gamePath string) error {
	gameDir := filepath.Dir(gamePath)

	if !strings.EqualFold(filepath.Ext(gamePath), ".exe") {
		return fmt.Errorf("%s is not a game exe", filepath.Base(gamePath))
	}
	resident, err := pefile.Open(filepath.Join(gameDir, "resident.dll"))
	if err != nil {
		return err
	}
	exe, err := pefile.Open(gamePath)
	if err != nil {
		return err
	}

	keyDef, err := FindKeyDef(resident)
	if err != nil {
		return err
	}
	sample, err := LiteInitSampleDIB(exe)
	if err != nil {
		return err
	}
	iniValue, err := CalcIniValue(filepath.Join(gameDir, "ExHIBIT.ini"))
	if err != nil {
		return err
	}

	key := uint32(0)
	if sample != 0 {
		key = sample ^ iniValue
	}

	outDir := filepath.Join(gameDir, "keys")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	crypto := NewUxMemoryCrypto(key)
	if err := os.WriteFile(filepath.Join(outDir, "key.bin"), crypto.Table[:], 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "key.txt"), []byte(fmt.Sprintf("0x%08X", key)), 0o644); err != nil {
		return err
	}
	cryptoDef := NewUxMemoryCrypto(keyDef)
	if err := os.WriteFile(filepath.Join(outDir, "key_def.bin"), cryptoDef.Table[:], 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "key_def.txt"), []byte(fmt.Sprintf("0x%08X", keyDef)), 0o644); err != nil {
		return err
	}

	fmt.Printf("Generate keys in %s \n", outDir)
	return nil
}
