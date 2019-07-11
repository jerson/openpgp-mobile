package openpgp

import (
	"testing"
)

func TestOpenPGP_Generate(t *testing.T) {

	options := &Options{
		Email:   "sample@sample.com",
		Name:    "Test",
		Comment: "sample",
		KeyOptions: &KeyOptions{
			CompressionLevel: 9,
			RSABits:          2048,
			Cipher:           "aes256",
			Compression:      "zlib",
			Hash:             "sha512",
		},
	}
	openPGP := NewOpenPGP()
	output, err := openPGP.Generate(options)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
