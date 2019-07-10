package openpgp

import "testing"

func TestOpenPGP_Sign(t *testing.T) {

	openPGP := NewOpenPGP()
	output, err := openPGP.Sign(inputMessage, publicKey, privateKey, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
