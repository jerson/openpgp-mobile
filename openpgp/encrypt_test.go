package openpgp

import (
	"strings"
	"testing"
)

func TestFastOpenPGP_Encrypt(t *testing.T) {

	openPGP := NewFastOpenPGP()
	output, err := openPGP.Encrypt(inputMessage, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	outputDecrypted, err := openPGP.Decrypt(output, privateKey, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("output:", output, outputDecrypted)
}

func TestFastOpenPGP_SignEncrypt(t *testing.T) {

	openPGP := NewFastOpenPGP()
	signature, err := openPGP.Sign(inputMessage, publicKey, privateKey, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("signature:", signature)

	output, err := openPGP.Encrypt(signature, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("encrypted:", output)

	decrypted, err := openPGP.Decrypt(output, privateKey, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("decrypted:", decrypted)

	verified, err := openPGP.Verify(decrypted, inputMessage, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("verified:", verified)
}

func TestFastOpenPGP_EncryptMultipleKey(t *testing.T) {

	options := &Options{
		Email:      "sample@sample.com",
		Name:       "Test2",
		Comment:    "sample",
		Passphrase: passphrase,
		KeyOptions: &KeyOptions{
			CompressionLevel: 9,
			RSABits:          2048,
			Cipher:           "aes256",
			Compression:      "zlib",
			Hash:             "sha512",
		},
	}

	openPGP := NewFastOpenPGP()
	keyPair1, err := openPGP.Generate(options)
	if err != nil {
		t.Fatal(err)
	}
	keyPair2, err := openPGP.Generate(options)
	if err != nil {
		t.Fatal(err)
	}

	keys := []string{publicKey, keyPair1.PublicKey, keyPair2.PublicKey}
	keysString := strings.Join(keys, "\n")
	output, err := openPGP.Encrypt(inputMessage, keysString)
	if err != nil {
		t.Fatal(err)
	}
	output1, err := openPGP.Decrypt(output, privateKey, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("output1:", output1)
	output2, err := openPGP.Decrypt(output, keyPair2.PrivateKey, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("output2:", output2)
	output3, err := openPGP.Decrypt(output, keyPair1.PrivateKey, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("output3:", output3)

}
