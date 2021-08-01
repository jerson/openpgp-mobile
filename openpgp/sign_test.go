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
