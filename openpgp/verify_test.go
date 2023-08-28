package openpgp

import (
	"encoding/base64"
	"os"
	"testing"
)

func TestFastOpenPGP_VerifyData(t *testing.T) {
	openPGP := NewFastOpenPGP()
	signed, err := openPGP.SignData(inputMessage, privateKey, passphrase, nil)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("signed:", signed)

	output, err := openPGP.VerifyData(signed, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("verified:", output)
}

func TestFastOpenPGP_VerifyDataBytes(t *testing.T) {
	openPGP := NewFastOpenPGP()
	signed, err := openPGP.SignDataBytes([]byte(inputMessage), privateKey, passphrase, nil)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("signed:", signed)

	output, err := openPGP.VerifyDataBytes(signed, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("verified:", output)
}

func TestFastOpenPGP_VerifyDataBytesToString(t *testing.T) {
	openPGP := NewFastOpenPGP()
	signed, err := openPGP.SignDataBytesToString([]byte(inputMessage), privateKey, passphrase, nil)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("signed:", signed)

	output, err := openPGP.VerifyData(signed, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("verified:", output)
}

func TestFastOpenPGP_Verify(t *testing.T) {

	openPGP := NewFastOpenPGP()
	output, err := openPGP.Verify(signed, inputMessage, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}

func TestFastOpenPGP_VerifyBytes(t *testing.T) {

	openPGP := NewFastOpenPGP()
	input := "hola"
	signature, err := openPGP.SignBytes([]byte(input), privateKey, passphrase, nil)
	if err != nil {
		t.Fatal(err)
	}
	output, err := openPGP.VerifyBytes(base64.StdEncoding.EncodeToString(signature), []byte(input), publicKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}

func TestFastOpenPGP_VerifyFile(t *testing.T) {
	input := createSampleFile("buenos dias")
	t.Log("input:", input)

	defer func() {
		_ = os.Remove(input)
	}()

	openPGP := NewFastOpenPGP()
	output, err := openPGP.SignFile(input, privateKey, passphrase, nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := openPGP.VerifyFile(output, input, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !result {
		t.Fatal("invalid")
	}

	t.Log("output:", output)
}
