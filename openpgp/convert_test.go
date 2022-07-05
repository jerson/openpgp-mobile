package openpgp

import (
	"encoding/json"
	"testing"
)

func TestFastOpenPGP_ConvertPrivateKeyToPublicKey(t *testing.T) {

	openPGP := NewFastOpenPGP()
	output, err := openPGP.ConvertPrivateKeyToPublicKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.MarshalIndent(output, "", " ")
	t.Log(string(data))

	t.Log("output:", output)
}
