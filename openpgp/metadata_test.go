package openpgp

import (
	"encoding/json"
	"testing"
)

func TestFastOpenPGP_GetPublicKeyMetadata(t *testing.T) {

	openPGP := NewFastOpenPGP()
	output, err := openPGP.GetPublicKeyMetadata(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.MarshalIndent(output, "", " ")
	t.Log(string(data))

}

func TestFastOpenPGP_GetPublicKeyMetadataWithPrivateKeyShouldWork(t *testing.T) {

	openPGP := NewFastOpenPGP()
	output, err := openPGP.GetPublicKeyMetadata(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.MarshalIndent(output, "", " ")
	t.Log(string(data))

}

func TestFastOpenPGP_GetPrivateKeyMetadata(t *testing.T) {

	openPGP := NewFastOpenPGP()
	output, err := openPGP.GetPrivateKeyMetadata(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.MarshalIndent(output, "", " ")
	t.Log(string(data))

}

func TestFastOpenPGP_GetPrivateKeyMetadataWithPublic(t *testing.T) {

	openPGP := NewFastOpenPGP()
	output, err := openPGP.GetPrivateKeyMetadata(publicKey)
	if err == nil {
		t.Fatal("must return error")
	}
	data, _ := json.MarshalIndent(output, "", " ")
	t.Log(string(data))

}

func TestFastOpenPGP_GetPrivateKeyMetadataAndGenerate(t *testing.T) {

	options := &Options{
		Email:      "sample@sample.com",
		Name:       "Test",
		Comment:    "sample",
		Passphrase: "test",
		KeyOptions: &KeyOptions{
			CompressionLevel: 9,
			RSABits:          2048,
			Cipher:           "aes256",
			Compression:      "none",
			Hash:             "sha512",
		},
	}
	openPGP := NewFastOpenPGP()

	keyPair, err := openPGP.Generate(options)
	if err != nil {
		t.Fatal(err)
	}

	output, err := openPGP.GetPrivateKeyMetadata(keyPair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.MarshalIndent(output, "", " ")
	t.Log(string(data))

}

func TestFastOpenPGP_GetPublicKeyMetadataAndGenerate(t *testing.T) {

	options := &Options{
		Email:      "sample@sample.com",
		Name:       "Test",
		Comment:    "sample",
		Passphrase: "test",
		KeyOptions: &KeyOptions{
			CompressionLevel: 9,
			RSABits:          2048,
			Cipher:           "aes256",
			Compression:      "none",
			Hash:             "sha512",
		},
	}
	openPGP := NewFastOpenPGP()

	keyPair, err := openPGP.Generate(options)
	if err != nil {
		t.Fatal(err)
	}

	output, err := openPGP.GetPublicKeyMetadata(keyPair.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.MarshalIndent(output, "", " ")
	t.Log(string(data))

}
