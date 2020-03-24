package openpgp

import (
	"encoding/json"
	"testing"
)

func TestFastOpenPGP_GetPublicKeyMetadata(t *testing.T) {

	openPGP := NewFastOpenPGP()
	output, err := openPGP.GetPublicKeyMetadata(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.MarshalIndent(output, "", " ")
	t.Log(string(data))

	t.Log("output:", output)
}
