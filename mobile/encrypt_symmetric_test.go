package openpgp

import "testing"

func TestOpenPGP_EncryptSymmetric(t *testing.T) {

	openPGP := NewOpenPGP()
	output, err := openPGP.EncryptSymmetric(message, passphrase, nil)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}

