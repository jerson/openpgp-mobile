package openpgp

import "testing"

func TestFastOpenPGP_Encrypt(t *testing.T) {

	openPGP := NewFastOpenPGP()
	output, err := openPGP.Encrypt(inputMessage, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
