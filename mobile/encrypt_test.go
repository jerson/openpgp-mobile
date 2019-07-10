package openpgp

import "testing"

func TestOpenPGP_Encrypt(t *testing.T) {

	openPGP := NewOpenPGP()
	output, err := openPGP.Encrypt(inputMessage, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
