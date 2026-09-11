package exhibit

import "encoding/binary"

type UxMemoryCrypto struct {
	Key   uint32
	Table [1024]byte
}

func NewUxMemoryCrypto(key uint32) *UxMemoryCrypto {
	c := &UxMemoryCrypto{}
	c.MakeTable(key)
	return c
}

func (c *UxMemoryCrypto) MakeTable(key uint32) {
	if c.Key == key {
		return
	}
	r := NewUxStaticRandom(key)
	for i := 0; i < 256; i++ {
		binary.LittleEndian.PutUint32(c.Table[i*4:], r.Next())
	}
	c.Key = key
}

func (c *UxMemoryCrypto) DecodeScript(script []byte, key uint32) {
	c.MakeTable(key)
	n := min(len(script)/4, 0x3FF0)
	for i := 0; i < n; i++ {
		off := i * 4
		v := binary.LittleEndian.Uint32(script[off:])
		t := binary.LittleEndian.Uint32(c.Table[(i&0xFF)*4:])
		binary.LittleEndian.PutUint32(script[off:], v^t^key)
	}
}
