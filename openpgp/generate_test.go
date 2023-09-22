package openpgp

import (
	"encoding/json"
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
	t.Log("output:", output)
}

func TestFastOpenPGP_Generate_ECDSA(t *testing.T) {

	options := &Options{
		Email:   "sample@sample.com",
		Name:    "Test",
		Comment: "sample",
		KeyOptions: &KeyOptions{
			CompressionLevel: 9,
			RSABits:          2048,
			Algorithm:        "ecdsa",
			Compression:      "zlib",
			Hash:             "sha256",
			Curve:            "p521",
		},
	}
	openPGP := NewFastOpenPGP()
	output, err := openPGP.Generate(options)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)

	metadata, err := openPGP.GetPublicKeyMetadata(output.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(metadata, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("metadata:", string(data))
}

func TestFastOpenPGP_Generate_EdDSA(t *testing.T) {

	options := &Options{
		Email:   "sample@sample.com",
		Name:    "Test",
		Comment: "sample",
		KeyOptions: &KeyOptions{
			CompressionLevel: 9,
			RSABits:          2048,
			Algorithm:        "eddsa",
			Compression:      "zlib",
			Hash:             "sha256",
		},
	}
	openPGP := NewFastOpenPGP()
	output, err := openPGP.Generate(options)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)

	metadata, err := openPGP.GetPublicKeyMetadata(output.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(metadata, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("metadata:", string(data))
}

func TestFastOpenPGP_Generate_rsa(t *testing.T) {

	options := &Options{
		Email: "sample@sample.com",
		Name:  "Test",
		KeyOptions: &KeyOptions{
			CompressionLevel: 9,
			RSABits:          2048,
			Cipher:           "rsa",
			Compression:      "zlib",
			Hash:             "sha256",
		},
	}
	openPGP := NewFastOpenPGP()
	output, err := openPGP.Generate(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("output:", output)
	metadata, err := openPGP.GetPublicKeyMetadata(output.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(metadata, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("metadata:", string(data))
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

func TestFastOpenPGP_GenerateEmpty(t *testing.T) {

	options := &Options{KeyOptions: &KeyOptions{}}
	openPGP := NewFastOpenPGP()
	output, err := openPGP.Generate(options)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
