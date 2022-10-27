package openpgp

import (
	"testing"
)

func TestFastOpenPGP_Generate(t *testing.T) {

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
	openPGP := NewFastOpenPGP()
	output, err := openPGP.Generate(options)
	if err != nil {
		t.Fatal(err)
	}
	println(len(output.PrivateKey))
	println(len(output.PublicKey))
	t.Log("output:", output)
}

func TestFastOpenPGP_GenerateECC(t *testing.T) {

	options := &Options{
		Email:   "sample@sample.com",
		Name:    "Test",
		Comment: "sample",
		KeyOptions: &KeyOptions{
			CompressionLevel: 9,
			RSABits:          2048,
			Cipher:           "x25519",
			Compression:      "zlib",
			Hash:             "sha256",
		},
	}
	openPGP := NewFastOpenPGP()
	output, err := openPGP.Generate(options)
	if err != nil {
		t.Fatal(err)
	}
	println(len(output.PrivateKey))
	println(len(output.PublicKey))
	println(output.PrivateKey)
	println(output.PublicKey)
	t.Log("output:", output)
}

func TestFastOpenPGP_GenerateWithPassphrase(t *testing.T) {

	options := &Options{
		Email:      "sample@sample.com",
		Name:       "Test",
		Comment:    "sample",
		Passphrase: "test",
		KeyOptions: &KeyOptions{
			CompressionLevel: 9,
			RSABits:          2048,
			Cipher:           "aes256",
			Compression:      "zlib",
			Hash:             "sha512",
		},
	}
	openPGP := NewFastOpenPGP()
	output, err := openPGP.Generate(options)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
