package openpgp

import "testing"

func TestOpenPGP_Decrypt(t *testing.T) {

	openPGP := NewOpenPGP()
	output, err := openPGP.Decrypt(message, privateKey, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}

