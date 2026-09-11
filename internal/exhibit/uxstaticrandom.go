package exhibit

const (
	mtN       = 624
	mtM       = 397
	mtMatrixA = 0x9908B0DF
	mtUpper   = 0x80000000
	mtLower   = 0x7FFFFFFF
)

type UxStaticRandom struct {
	mt    []uint32
	index int
}

func NewUxStaticRandom(seed uint32) *UxStaticRandom {
	r := &UxStaticRandom{}
	r.Seed(seed)
	return r
}

func (r *UxStaticRandom) Seed(value uint32) {
	s := value
	r.mt = make([]uint32, mtN)
	for i := 0; i < mtN; i++ {
		high := s & 0xFFFF0000
		s1 := s*69069 + 1
		s = s1*69069 + 1
		r.mt[i] = high | (s1 >> 16)
	}
	r.Genrand()
}

func (r *UxStaticRandom) Next() uint32 {
	if r.index >= mtN {
		r.Genrand()
	}
	value := r.mt[r.index]
	r.index++
	return value
}

func (r *UxStaticRandom) Genrand() {
	for kk := 0; kk < mtN-mtM; kk++ {
		y := (r.mt[kk] & mtUpper) | (r.mt[kk+1] & mtLower)
		r.mt[kk] = r.mt[kk+mtM] ^ (y >> 1) ^ mag01(y)
	}
	for kk := mtN - mtM; kk < mtN-1; kk++ {
		y := (r.mt[kk] & mtUpper) | (r.mt[kk+1] & mtLower)
		r.mt[kk] = r.mt[kk+mtM-mtN] ^ (y >> 1) ^ mag01(y)
	}
	y := (r.mt[mtN-1] & mtUpper) | (r.mt[0] & mtLower)
	r.mt[mtN-1] = r.mt[mtM-1] ^ (y >> 1) ^ mag01(y)

	for i := 0; i < mtN; i++ {
		r.mt[i] = temper(r.mt[i])
	}
	r.index = 0
}

func mag01(y uint32) uint32 {
	if y&1 != 0 {
		return mtMatrixA
	}
	return 0
}

func temper(y uint32) uint32 {
	y ^= y >> 11
	y ^= (y << 7) & 0x9D2C5680
	y ^= (y << 15) & 0xEFC60000
	y ^= y >> 18
	return y
}
