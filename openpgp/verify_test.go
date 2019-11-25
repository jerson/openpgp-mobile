package openpgp

import "testing"

func TestFastOpenPGP_Verify(t *testing.T) {

	openPGP := NewFastOpenPGP()
	output, err := openPGP.Verify(signed, inputMessage, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
