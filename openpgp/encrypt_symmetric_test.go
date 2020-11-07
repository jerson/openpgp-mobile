package openpgp

import (
	"testing"
)

func TestFastOpenPGP_EncryptSymmetric(t *testing.T) {

	options := &KeyOptions{
		CompressionLevel: 9,
		RSABits:          4096,
		Cipher:           "aes256",
		Compression:      "zlib",
		Hash:             "sha512",
	}
	openPGP := NewFastOpenPGP()
	output, err := openPGP.EncryptSymmetric(inputMessage, passphrase, nil, options)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
