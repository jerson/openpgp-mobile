package openpgp

import (
	"os"
	"testing"
)

func TestFastOpenPGP_Sign(t *testing.T) {

	openPGP := NewFastOpenPGP()
	output, err := openPGP.Sign(inputMessage, publicKey, privateKey, passphrase, nil)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}

func TestFastOpenPGP_SignFile(t *testing.T) {
	input := createSampleFile("buenos dias")
	t.Log("input:", input)

	defer func() {
		_ = os.Remove(input)
	}()

	openPGP := NewFastOpenPGP()
	output, err := openPGP.SignFile(input, publicKey, privateKey, passphrase, nil)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}

func TestFastOpenPGP_SignVerifyAndGenerate(t *testing.T) {
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

	signed, err := openPGP.Sign(inputMessage, keyPair.PublicKey, keyPair.PrivateKey, passphrase, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("signed:", signed)

	ok, err := openPGP.Verify(signed, inputMessage, keyPair.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("verified:", ok)

}
