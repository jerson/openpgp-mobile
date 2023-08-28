package openpgp

import (
	"encoding/json"
	"testing"
)

func TestFastOpenPGP_ConvertPrivateKeyToPublicKey(t *testing.T) {

	openPGP := NewFastOpenPGP()
	output, err := openPGP.ConvertPrivateKeyToPublicKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}

func TestFastOpenPGP_ConvertPrivateKeyToPublicKeyAndEncrypt(t *testing.T) {

	openPGP := NewFastOpenPGP()
	publicKey, err := openPGP.ConvertPrivateKeyToPublicKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("publicKey:", publicKey)

	encrypted, err := openPGP.Encrypt(inputMessage, publicKey, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("encrypted:", encrypted)

	decrypted, err := openPGP.Decrypt(encrypted, privateKey, passphrase, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("decrypted:", decrypted)

	if decrypted != inputMessage {
		t.Fatal("not same message")
	}
}

func TestFastOpenPGP_ConvertPrivateKeyToPublicKeyAndSign(t *testing.T) {

	openPGP := NewFastOpenPGP()
	publicKey, err := openPGP.ConvertPrivateKeyToPublicKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("publicKey:", publicKey)

	signed, err := openPGP.Sign(inputMessage, privateKey, passphrase, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("signed:", signed)

	verified, err := openPGP.Verify(signed, inputMessage, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("verified:", verified)

	if !verified {
		t.Fatal("invalid signature")
	}
}

func TestFastOpenPGP_ConvertPrivateKeyToPublicKeyAndMetadata(t *testing.T) {

	openPGP := NewFastOpenPGP()
	publicKey, err := openPGP.ConvertPrivateKeyToPublicKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("publicKey:", publicKey)

	metadata, err := openPGP.GetPublicKeyMetadata(publicKey)
	if err != nil {
		t.Fatal(err)
	}

	data, _ := json.MarshalIndent(metadata, "", " ")
	t.Log(string(data))
}
func TestFastOpenPGP_ConvertPrivateKeyToPublicKeyAndGenerate(t *testing.T) {

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

	output, err := openPGP.ConvertPrivateKeyToPublicKey(keyPair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
	t.Log("expected:", keyPair.PublicKey)

	if output != keyPair.PublicKey {
		t.Fatal("not same public key")
	}
}
