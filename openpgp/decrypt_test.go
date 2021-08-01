package openpgp

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

func TestFastOpenPGP_Decrypt(t *testing.T) {

	openPGP := NewFastOpenPGP()
	output, err := openPGP.Decrypt(message, privateKey, passphrase, nil)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}

func TestFastOpenPGP_DecryptFile(t *testing.T) {

	input := createSampleFile("buenos dias")
	output := fmt.Sprintf("%s.output", input)
	outputDecrypted := fmt.Sprintf("%s.output.decrypted", input)

	t.Log("input:", input)
	t.Log("output:", output)
	t.Log("outputDecrypted:", output)

	defer func() {
		_ = os.Remove(input)
		_ = os.Remove(output)
		_ = os.Remove(outputDecrypted)
	}()

	options := &KeyOptions{
		CompressionLevel: 9,
		RSABits:          4096,
		Cipher:           "aes256",
		Compression:      "zlib",
		Hash:             "sha512",
	}
	fileHints := &FileHints{
		IsBinary: false,
		FileName: "",
		ModTime:  "",
	}
	openPGP := NewFastOpenPGP()
	_, err := openPGP.EncryptFile(input, output, publicKey, nil, fileHints, options)
	if err != nil {
		t.Fatal(err)
	}
	result, err := openPGP.DecryptFile(output, outputDecrypted, privateKey, passphrase, options)
	if err != nil {
		t.Fatal(err)
	}

	inputData, err := ioutil.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	outputData, err := ioutil.ReadFile(outputDecrypted)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("inputData:", string(inputData))
	t.Log("outputData:", string(outputData))

	if string(inputData) != string(outputData) {
		t.Fatal("not same input")
	}

	t.Log("result:", result)
}
