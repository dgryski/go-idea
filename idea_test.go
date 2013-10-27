package idea

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {

	var tests = []struct {
		key    string
		plain  string
		cipher string
	}{
		// From https://www.cosic.esat.kuleuven.be/nessie/testvectors/bc/idea/Idea-128-64.verified.test-vectors
		{
			"000102030405060708090A0B0C0D0E0F",
			"0011223344556677",
			"F526AB9A62C0D258",
		},
		{
			"2BD6459F82C5B300952C49104881FF48",
			"EA024714AD5C4D84",
			"C8FB51D3516627A8",
		},
		{
			"000102030405060708090A0B0C0D0E0F",
			"DB2D4A92AA68273F",
			"0011223344556677",
		},
		{
			"2BD6459F82C5B300952C49104881FF48",
			"F129A6601EF62A47",
			"EA024714AD5C4D84",
		},
	}

	for _, tt := range tests {
		k, _ := hex.DecodeString(tt.key)
		p, _ := hex.DecodeString(tt.plain)
		c, _ := hex.DecodeString(tt.cipher)

		var dst [8]byte

		cipher, _ := NewCipher(k)

		cipher.Encrypt(dst[:], p)

		if !bytes.Equal(dst[:], c) {
			t.Errorf("encrypt failed: got % 2x wanted % 2x\n", dst, c)
		}

		var plain [8]byte

		cipher.Decrypt(plain[:], dst[:])

		if !bytes.Equal(plain[:], p) {
			t.Errorf("decrypt failed: got % 2x wanted % 2x\n", plain, p)
		}
	}
}
