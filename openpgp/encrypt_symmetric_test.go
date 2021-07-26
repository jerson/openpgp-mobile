package openpgp

import (
	"fmt"
	"os"
	"testing"
)

func TestFastOpenPGP_EncryptSymmetric(t *testing.T) {

	options := &KeyOptions{
		CompressionLevel: 9,
		RSABits:          4096,
		Cipher:           "aes256",
		Compression:      "zlib",
		Hash:             "sha512",
	}
	openPGP := NewFastOpenPGP()
	output, err := openPGP.EncryptSymmetric(inputMessage, passphrase, nil, options)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}

func TestFastOpenPGP_EncryptSymmetricFile(t *testing.T) {

	input := createSampleFile("buenos dias")
	output := fmt.Sprintf("%s.output", input)

	t.Log("input:", input)
	t.Log("output:", output)

	defer func() {
		_ = os.Remove(input)
		_ = os.Remove(output)
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
	result, err := openPGP.EncryptSymmetricFile(input, output, passphrase, fileHints, options)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("result:", result)
}
