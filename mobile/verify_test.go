package openpgp

import "testing"

func TestOpenPGP_Verify(t *testing.T) {

	openPGP := NewOpenPGP()
	output, err := openPGP.Verify(signed, inputMessage, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
