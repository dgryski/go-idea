// Package idea implements the IDEA cipher
// Derived from Public Domain code by Colin Plumb
package idea

import (
	"encoding/binary"
)

const IDEAKEYSIZE = 16
const IDEAROUNDS = 8
const IDEAKEYLEN = (6*IDEAROUNDS + 4)

func mulInv(x uint16) (ret uint16) {

	if x <= 1 {
		return x // 0 and 1 are self-inverse
	}
	t1 := uint16(0x10001 / uint32(x)) // Since x >= 2, this fits into 16 bits
	y := uint16(0x10001 % uint32(x))
	if y == 1 {
		return (1 - t1)
	}
	t0 := uint16(1)
	var q uint16
	for y != 1 {
		q = x / y
		x = x % y
		t0 += q * t1
		if x == 1 {
			return t0
		}
		q = y / x
		y = y % x
		t1 += q * t0
	}
	return uint16(1 - t1)
}

func mul(x, y uint16) (ret uint16) {

	t16 := y
	if t16 != 0 {

		if x != 0 {
			t32 := uint32(x) * uint32(t16)
			x = uint16(t32)
			t16 = uint16(t32 >> 16)

			if x < t16 {
				x = (x - t16) + 1
			} else {
				x = (x - t16)
			}
		} else {
			x = 1 - t16
		}
	} else {
		x = 1 - x
	}

	return x
}

/*
 * Expand a 128-bit user key to a working encryption key EK
 */

func ideaExpandKey(userKey []byte, EK []uint16) {
	var i, j int

	for j = 0; j < 8; j++ {
		EK[j] = (uint16(userKey[0]) << 8) + uint16(userKey[1])
		userKey = userKey[2:]
	}
	for i = 0; j < IDEAKEYLEN; j++ {
		i++
		EK[i+7] = EK[i&7]<<9 | EK[(i+1)&7]>>7
		EK = EK[i&8:]
		i &= 7
	}
}

func ideaInvertKey(EK []uint16, DK []uint16) {

	var t1, t2, t3 uint16
	var p [IDEAKEYLEN]uint16
	pidx := IDEAKEYLEN
	ekidx := 0

	t1 = mulInv(EK[ekidx])
	ekidx++
	t2 = -EK[ekidx]
	ekidx++
	t3 = -EK[ekidx]
	ekidx++
	pidx--
	p[pidx] = mulInv(EK[ekidx])
	ekidx++
	pidx--
	p[pidx] = t3
	pidx--
	p[pidx] = t2
	pidx--
	p[pidx] = t1

	for i := 0; i < IDEAROUNDS-1; i++ {
		t1 = EK[ekidx]
		ekidx++
		pidx--
		p[pidx] = EK[ekidx]
		ekidx++
		pidx--
		p[pidx] = t1

		t1 = mulInv(EK[ekidx])
		ekidx++
		t2 = -EK[ekidx]
		ekidx++
		t3 = -EK[ekidx]
		ekidx++
		pidx--
		p[pidx] = mulInv(EK[ekidx])
		ekidx++
		pidx--
		p[pidx] = t2
		pidx--
		p[pidx] = t3
		pidx--
		p[pidx] = t1
	}

	t1 = EK[ekidx]
	ekidx++
	pidx--
	p[pidx] = EK[ekidx]
	ekidx++
	pidx--
	p[pidx] = t1

	t1 = mulInv(EK[ekidx])
	ekidx++
	t2 = -EK[ekidx]
	ekidx++
	t3 = -EK[ekidx]
	ekidx++
	pidx--
	p[pidx] = mulInv(EK[ekidx])
	ekidx++
	pidx--
	p[pidx] = t3
	pidx--
	p[pidx] = t2
	pidx--
	p[pidx] = t1

	copy(DK, p[:])
}

func ideaCipher(inbuf, outbuf []byte, key []uint16) {

	var x1, x2, x3, x4, s2, s3 uint16

	x1 = binary.BigEndian.Uint16(inbuf[0:])
	x2 = binary.BigEndian.Uint16(inbuf[2:])
	x3 = binary.BigEndian.Uint16(inbuf[4:])
	x4 = binary.BigEndian.Uint16(inbuf[6:])

	for r := IDEAROUNDS; r > 0; r-- {

		x1 = mul(x1, key[0])
		key = key[1:]
		x2 += key[0]
		key = key[1:]
		x3 += key[0]
		key = key[1:]

		x4 = mul(x4, key[0])
		key = key[1:]

		s3 = x3
		x3 ^= x1
		x3 = mul(x3, key[0])
		key = key[1:]
		s2 = x2

		x2 ^= x4
		x2 += x3
		x2 = mul(x2, key[0])
		key = key[1:]
		x3 += x2

		x1 ^= x2
		x4 ^= x3

		x2 ^= s3
		x3 ^= s2

	}
	x1 = mul(x1, key[0])
	key = key[1:]

	x3 += key[0]
	key = key[1:]
	x2 += key[0]
	key = key[1:]
	x4 = mul(x4, key[0])

	binary.BigEndian.PutUint16(outbuf[0:], x1)
	binary.BigEndian.PutUint16(outbuf[2:], x3)
	binary.BigEndian.PutUint16(outbuf[4:], x2)
	binary.BigEndian.PutUint16(outbuf[6:], x4)

} /* ideaCipher */

func IdeaEncrypt(dst, src, key []byte) {
	ek := make([]uint16, IDEAKEYLEN)
	ideaExpandKey(key, ek)
	ideaCipher(src, dst, ek)
}

func IdeaDecrypt(dst, src, key []byte) {
	ek := make([]uint16, IDEAKEYLEN)
	dk := make([]uint16, IDEAKEYLEN)
	ideaExpandKey(key, ek)
	ideaInvertKey(ek, dk)
	ideaCipher(src, dst, dk)
}
