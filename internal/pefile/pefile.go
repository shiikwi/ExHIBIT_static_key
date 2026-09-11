package pefile

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
)

type Section struct {
	Name    string
	VA      uint32
	Size    uint32
	Raw     uint32
	RawSize uint32
}

type Export struct {
	Name string
	RVA  uint32
}

type Image struct {
	Path        string
	Data        []byte
	ImageBase   uint64
	ResourceRVA uint32
	ExportDir   uint32
	Sections    []Section
}

func Open(path string) (*Image, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return New(path, data)
}

func New(path string, data []byte) (*Image, error) {
	pe := u32(data, 0x3c)
	if pe+24 > uint32(len(data)) || string(data[pe:pe+4]) != "PE\x00\x00" {
		return nil, fmt.Errorf("%s is not a PE file", path)
	}

	coff := pe + 4
	sectionCount := u16(data, coff+2)
	optionalSize := u16(data, coff+16)
	optional := coff + 20
	if optional+uint32(optionalSize) > uint32(len(data)) {
		return nil, fmt.Errorf("%s has a truncated optional header", path)
	}

	magic := u16(data, optional)
	var imageBase uint64
	var dataDir uint32
	switch magic {
	case 0x10b:
		imageBase = uint64(u32(data, optional+28))
		dataDir = optional + 96
	default:
		return nil, fmt.Errorf("%s has unsupported PE optional header magic 0x%x", path, magic)
	}

	sections := make([]Section, 0, sectionCount)
	sectionTable := optional + uint32(optionalSize)
	for i := uint16(0); i < sectionCount; i++ {
		off := sectionTable + uint32(i)*40
		name := string(data[off : off+8])
		if nul := strings.IndexByte(name, 0); nul >= 0 {
			name = name[:nul]
		}
		virtualSize := u32(data, off+8)
		rawSize := u32(data, off+16)
		size := virtualSize
		if rawSize > size {
			size = rawSize
		}
		sections = append(sections, Section{
			Name:    name,
			VA:      u32(data, off+12),
			Size:    size,
			RawSize: rawSize,
			Raw:     u32(data, off+20),
		})
	}

	return &Image{
		Path:        path,
		Data:        data,
		ImageBase:   imageBase,
		ResourceRVA: u32(data, dataDir+2*8),
		ExportDir:   u32(data, dataDir+0*8),
		Sections:    sections,
	}, nil
}

func (img *Image) RVAToOffset(rva uint32) (uint32, error) {
	for _, section := range img.Sections {
		if rva >= section.VA && rva < section.VA+section.Size {
			return section.Raw + (rva - section.VA), nil
		}
	}
	return 0, fmt.Errorf("RVA 0x%x is not mapped", rva)
}

func (img *Image) ReadRVA(rva uint32, size uint32) ([]byte, error) {
	off, err := img.RVAToOffset(rva)
	if err != nil {
		return nil, err
	}
	if uint64(off)+uint64(size) > uint64(len(img.Data)) {
		return nil, fmt.Errorf("RVA 0x%x size 0x%x exceeds %s", rva, size, img.Path)
	}
	return img.Data[off : off+size], nil
}

func (img *Image) Exports() ([]Export, error) {
	if img.ExportDir == 0 {
		return nil, fmt.Errorf("%s has no export table", img.Path)
	}
	dir, err := img.ReadRVA(img.ExportDir, 40)
	if err != nil {
		return nil, err
	}
	nameCount := u32(dir, 24)
	functionsRVA := u32(dir, 28)
	namesRVA := u32(dir, 32)
	ordinalsRVA := u32(dir, 36)
	functions, err := img.ReadRVA(functionsRVA, nameCount*4)
	if err != nil {
		return nil, err
	}
	names, err := img.ReadRVA(namesRVA, nameCount*4)
	if err != nil {
		return nil, err
	}
	ordinals, err := img.ReadRVA(ordinalsRVA, nameCount*2)
	if err != nil {
		return nil, err
	}

	exports := make([]Export, 0, nameCount)
	for i := uint32(0); i < nameCount; i++ {
		nameRVA := u32(names, i*4)
		nameData, err := img.ReadRVA(nameRVA, 64)
		if err != nil {
			continue
		}
		name := string(nameData)
		if nul := strings.IndexByte(name, 0); nul >= 0 {
			name = name[:nul]
		}
		exports = append(exports, Export{
			Name: name,
			RVA:  u32(functions, uint32(u16(ordinals, i*2))*4),
		})
	}
	return exports, nil
}

func (img *Image) FindExport(name string) (uint32, error) {
	exports, err := img.Exports()
	if err != nil {
		return 0, err
	}
	for _, export := range exports {
		if export.Name == name {
			return export.RVA, nil
		}
	}
	return 0, fmt.Errorf("export %s was not found in %s", name, img.Path)
}

func (img *Image) FindFirstResource(typ uint32, name uint32) ([]byte, error) {
	if img.ResourceRVA == 0 {
		return nil, fmt.Errorf("%s has no resource table", img.Path)
	}
	resourceOff, err := img.RVAToOffset(img.ResourceRVA)
	if err != nil {
		return nil, err
	}

	findDir := func(directoryRel uint32, want uint32) (uint32, error) {
		base := resourceOff + directoryRel
		count := uint32(u16(img.Data, base+12)) + uint32(u16(img.Data, base+14))
		for i := uint32(0); i < count; i++ {
			entry := base + 16 + i*8
			if u32(img.Data, entry) != want {
				continue
			}
			child := u32(img.Data, entry+4)
			if child&0x80000000 == 0 {
				return 0, fmt.Errorf("resource type %d name %d has an unexpected leaf entry", typ, name)
			}
			return child & 0x7fffffff, nil
		}
		return 0, fmt.Errorf("resource type %d name %d was not found in %s", typ, name, img.Path)
	}

	typeDir, err := findDir(0, typ)
	if err != nil {
		return nil, err
	}
	nameDir, err := findDir(typeDir, name)
	if err != nil {
		return nil, err
	}

	base := resourceOff + nameDir
	count := uint32(u16(img.Data, base+12)) + uint32(u16(img.Data, base+14))
	if count == 0 {
		return nil, fmt.Errorf("resource type %d name %d is empty in %s", typ, name, img.Path)
	}
	dataEntry := resourceOff + u32(img.Data, base+16+4)
	rva := u32(img.Data, dataEntry)
	size := u32(img.Data, dataEntry+4)
	data, err := img.ReadRVA(rva, size)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), data...), nil
}

func u16(data []byte, off uint32) uint16 {
	return binary.LittleEndian.Uint16(data[off:])
}

func u32(data []byte, off uint32) uint32 {
	return binary.LittleEndian.Uint32(data[off:])
}
