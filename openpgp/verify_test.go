package openpgp

import (
	"encoding/base64"
	"testing"
)

func TestFastOpenPGP_Verify(t *testing.T) {

	openPGP := NewFastOpenPGP()
	output, err := openPGP.Verify(signed, inputMessage, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}

func TestFastOpenPGP_VerifyBytes(t *testing.T) {

	openPGP := NewFastOpenPGP()
	input := "hola"
	signature, err := openPGP.SignBytes([]byte(input), publicKey, privateKey, passphrase, nil)
	output, err := openPGP.VerifyBytes(base64.StdEncoding.EncodeToString(signature), []byte(input), publicKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
