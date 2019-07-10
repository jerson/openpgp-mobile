package openpgp

import (
	"testing"
)

func TestOpenPGP_Generate(t *testing.T) {

	options := &Options{
		Email:      "sample@sample.com",
		Name:       "Test",
		Comment:    "sample",
		Passphrase: "sample",
		KeyOptions: &KeyOptions{
			CompressionLevel: 1,
			RSABits:          2048,
		},
	}
	openPGP := NewOpenPGP()
	output, err := openPGP.Generate(options)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
