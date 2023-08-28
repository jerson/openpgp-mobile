package openpgp

import (
	"testing"
)

var encoded = `-----BEGIN PGP MESSAGE-----
Version: openpgp-mobile

cmFuZG9tIHN0cmluZw==
-----END PGP MESSAGE-----`

func TestFastOpenPGP_ArmorEncode(t *testing.T) {

	openPGP := NewFastOpenPGP()
	output, err := openPGP.ArmorEncode([]byte("random string"))
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)

	if string(output) != string(encoded) {
		t.Fatal("not same input")
	}
}
