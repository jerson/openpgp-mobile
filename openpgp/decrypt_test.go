package openpgp

import "testing"

func TestFastOpenPGP_Decrypt(t *testing.T) {

	openPGP := NewFastOpenPGP()
	output, err := openPGP.Decrypt(message, privateKey, passphrase, nil)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
