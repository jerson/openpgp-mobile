package openpgp

import "testing"

func TestOpenPGP_DecryptSymmetric(t *testing.T) {

	openPGP := NewOpenPGP()
	output, err := openPGP.DecryptSymmetric(message, privateKey, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}

