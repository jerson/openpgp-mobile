package openpgp

import "testing"

func TestFastOpenPGP_Sign(t *testing.T) {

	openPGP := NewFastOpenPGP()
	output, err := openPGP.Sign(inputMessage, publicKey, privateKey, passphrase,nil)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
