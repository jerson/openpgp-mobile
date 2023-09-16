package openpgp

import (
	"testing"
)

var encoded = `-----BEGIN PGP MESSAGE-----
Version: openpgp-mobile

cmFuZG9tIHN0cmluZw==
=zR7q
-----END PGP MESSAGE-----`

func TestFastOpenPGP_ArmorEncode(t *testing.T) {

	openPGP := NewFastOpenPGP()
	output, err := openPGP.ArmorEncode([]byte("random string"), messageType)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)

	if string(output) != string(encoded) {
		t.Fatal("not same input")
	}
}

func TestFastOpenPGP_DecodeEncode(t *testing.T) {

	openPGP := NewFastOpenPGP()
	output, err := openPGP.ArmorDecode(encoded)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)

	if output.Type != messageType {
		t.Fatal("not same type:", output.Type)
	}
	if string(output.Body) != "random string" {
		t.Fatal("not same input")
	}
}
