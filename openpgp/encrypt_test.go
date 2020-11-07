package openpgp

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(name string, data []byte) error {
	dir, _ := os.Getwd()
	path := filepath.Join(dir+"/testdata", name)
	return ioutil.WriteFile(path, data, 0777)
}
func readFile(name string) ([]byte, error) {
	dir, _ := os.Getwd()
	path := filepath.Join(dir+"/testdata", name)
	return ioutil.ReadFile(path)
}
func TestFastOpenPGP_EncryptFile(t *testing.T) {

	openPGP := NewFastOpenPGP()

	inputMessage, err := readFile("sample.zip")
	if err != nil {
		t.Fatal(err)
	}
	output, err := openPGP.EncryptBytes(inputMessage, publicKey,nil,nil,nil)
	if err != nil {
		t.Fatal(err)
	}
	outputFile := "sample.zip.gpg"
	err = writeFile(outputFile, output)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", outputFile)
}

func TestFastOpenPGP_Encrypt(t *testing.T) {

	openPGP := NewFastOpenPGP()
	output, err := openPGP.Encrypt(inputMessage, publicKey,nil,nil,nil)
	if err != nil {
		t.Fatal(err)
	}

	outputDecrypted, err := openPGP.Decrypt(output, privateKey, passphrase,nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("output:", output, outputDecrypted)
}

func TestFastOpenPGP_SignEncrypt(t *testing.T) {

	openPGP := NewFastOpenPGP()
	signature, err := openPGP.Sign(inputMessage, publicKey, privateKey, passphrase,nil)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("signature:", signature)

	output, err := openPGP.Encrypt(signature, publicKey,nil,nil,nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("encrypted:", output)

	decrypted, err := openPGP.Decrypt(output, privateKey, passphrase,nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("decrypted:", decrypted)

	verified, err := openPGP.Verify(decrypted, inputMessage, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("verified:", verified)
}

func TestFastOpenPGP_EncryptMultipleKey(t *testing.T) {

	options := &Options{
		Email:      "sample@sample.com",
		Name:       "Test2",
		Comment:    "sample",
		Passphrase: passphrase,
		KeyOptions: &KeyOptions{
			CompressionLevel: 9,
			RSABits:          2048,
			Cipher:           "aes256",
			Compression:      "zlib",
			Hash:             "sha512",
		},
	}

	openPGP := NewFastOpenPGP()
	keyPair1, err := openPGP.Generate(options)
	if err != nil {
		t.Fatal(err)
	}
	keyPair2, err := openPGP.Generate(options)
	if err != nil {
		t.Fatal(err)
	}

	keys := []string{publicKey, keyPair1.PublicKey, keyPair2.PublicKey}
	keysString := strings.Join(keys, "\n")
	output, err := openPGP.Encrypt(inputMessage, keysString,nil,nil,nil)
	if err != nil {
		t.Fatal(err)
	}
	output1, err := openPGP.Decrypt(output, privateKey, passphrase,nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("output1:", output1)
	output2, err := openPGP.Decrypt(output, keyPair2.PrivateKey, passphrase,nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("output2:", output2)
	output3, err := openPGP.Decrypt(output, keyPair1.PrivateKey, passphrase,nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("output3:", output3)

}
