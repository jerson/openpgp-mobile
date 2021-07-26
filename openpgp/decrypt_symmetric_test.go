package openpgp

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

var symmetricMessage = `-----BEGIN PGP MESSAGE-----
Provider: react-native-fast-openpgp

wy4ECQMKh9ZaS+L1qIdgUlcPFG2Fn8MojzLkB29LJhit6gvw+tZjsq0+vxasThfz
0uAB5N8A4hQS+WIkmcC80FhmWMHhG3XgL+D/4Ofgz+E9geAm5JmU5esNJpFMkJ8w
ex4dGwLgr+PbaxXCd0xq8OBU4MXgWuI7iYLg4BviHtHuHeD55GgMVGWn+237+idp
hFhABS/ig+ryWeEGIgA=
=RN2S
-----END PGP MESSAGE-----`

func TestFastOpenPGP_DecryptSymmetric(t *testing.T) {

	options := &KeyOptions{
		CompressionLevel: 9,
		RSABits:          4096,
		Cipher:           "aes256",
		Compression:      "zlib",
		Hash:             "sha512"}

	openPGP := NewFastOpenPGP()
	output, err := openPGP.DecryptSymmetric(symmetricMessage, passphrase, options)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}

func createSampleFile(content string) string {
	file, err := ioutil.TempFile("", "sample.txt")
	if err != nil {
		return ""
	}
	defer file.Close()

	_, err = file.WriteString(content)
	if err != nil {
		return ""
	}
	return file.Name()
}

func TestFastOpenPGP_DecryptSymmetricFile(t *testing.T) {

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
	_, err := openPGP.EncryptSymmetricFile(input, output, passphrase, fileHints, options)
	if err != nil {
		t.Fatal(err)
	}
	result, err := openPGP.DecryptSymmetricFile(output, outputDecrypted, passphrase, options)
	if err != nil {
		t.Fatal(err)
	}

	inputData, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	outputData, err := os.ReadFile(outputDecrypted)
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
