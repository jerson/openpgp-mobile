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

func TestFastOpenPGP_GetPublicKeyMetadataWithPrivateKeyShouldWork(t *testing.T) {

	openPGP := NewFastOpenPGP()
	output, err := openPGP.GetPublicKeyMetadata(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.MarshalIndent(output, "", " ")
	t.Log(string(data))

	t.Log("output:", output)
}

func TestFastOpenPGP_GetPrivateKeyMetadata(t *testing.T) {

	openPGP := NewFastOpenPGP()
	output, err := openPGP.GetPrivateKeyMetadata(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.MarshalIndent(output, "", " ")
	t.Log(string(data))

	t.Log("output:", output)
}

func TestFastOpenPGP_GetPrivateKeyMetadataWithPublic(t *testing.T) {

	openPGP := NewFastOpenPGP()
	output, err := openPGP.GetPrivateKeyMetadata(publicKey)
	if err == nil {
		t.Fatal("must return error")
	}

	t.Log("output:", output)
}
