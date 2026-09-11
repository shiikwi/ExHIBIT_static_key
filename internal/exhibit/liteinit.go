package exhibit

import (
	"encoding/binary"
	"fmt"

	"ExHIBITkeyfind/internal/pefile"
)

const (
	liteInitExportName  = "?liteInit@RetouchSystem@@QAEXXZ"
	keyBitmapTypeID     = 2
	keyBitmapResourceID = 0x98
)

func FindKeyDef(resident *pefile.Image) (uint32, error) {
	rva, err := resident.FindExport(liteInitExportName)
	if err != nil {
		return 0, err
	}
	code, err := resident.ReadRVA(rva, 0x120)
	if err != nil {
		return 0, err
	}

	//mov     [esi+1868h], ebp
	zeroed := make(map[uint32]bool)
	for i := 0; i < len(code)-6; i++ {
		if code[i] == 0x89 && code[i+1]&0xC0 == 0x80 && code[i+1]&7 != 4 {
			disp := binary.LittleEndian.Uint32(code[i+2:])
			zeroed[disp] = true
		}
	}

	//mov     dword ptr [esi+186Ch], 0AE85A916h
	for i := 0; i < len(code)-10; i++ {
		if code[i] != 0xC7 || code[i+1]&0xC8 != 0x80 || code[i+1]&7 == 4 {
			continue
		}
		disp := binary.LittleEndian.Uint32(code[i+2:])
		imm := binary.LittleEndian.Uint32(code[i+6:])
		if zeroed[disp] && imm != 0 && imm != 0xFFFFFFFF {
			return imm, nil
		}
	}
	return 0, fmt.Errorf("keydef constant was not found in liteInit")
}

func LiteInitSampleDIB(exe *pefile.Image) (uint32, error) {
	data, err := exe.FindFirstResource(keyBitmapTypeID, keyBitmapResourceID)
	if err != nil {
		return 0, err
	}

	headerSize := binary.LittleEndian.Uint32(data)
	width := int32(binary.LittleEndian.Uint32(data[4:]))
	height := int32(binary.LittleEndian.Uint32(data[8:]))
	bpp := binary.LittleEndian.Uint16(data[14:])
	if bpp != 24 {
		return 0, fmt.Errorf("bitmap #0x98 is %d bpp, expect 24 bpp", bpp)
	}
	srcStride := (int(width)*3 + 3) &^ 3
	pixels := data[headerSize:]

	blue := func(col int, row int) byte {
		return pixels[row*srcStride+col*3]
	}

	A, C := int(width), int(height)
	p1 := (C-31)*A*4 + 0x7C
	p2 := (C-29)*A*4 + 0x7C
	p3 := ((C-31)*4+4)*A + 0x7C
	p4 := ((C-31)*4-4)*A + 0x7C

	var bits uint32
	stride := A * 16
	for round := 0; round < 8; round++ {
		for _, off := range []int{p4, p1, p3, p2} {
			addr := off + round*stride
			col := addr % (A * 4) / 4
			row := addr / (A * 4)
			bits = bits<<1 | uint32(blue(col, row)&1)
		}
	}
	return bits, nil
}
