package openpgp

import (
	"testing"
)

func TestOpenPGP_EncryptSymmetric(t *testing.T) {

	options := &KeyOptions{
		CompressionLevel: 9,
		RSABits:          4096,
		Cipher:           "aes256",
		Compression:      "zlib",
		Hash:             "sha512",
	}
	openPGP := NewOpenPGP()
	output, err := openPGP.EncryptSymmetric(inputMessage, passphrase, options)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
