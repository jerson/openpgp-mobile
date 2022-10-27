package openpgp

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(name string, data []byte) error {
	dir, _ := os.Getwd()
	path := filepath.Join(dir, "testdata", name)
	return ioutil.WriteFile(path, data, 0777)
}
func readFile(name string) ([]byte, error) {
	dir, _ := os.Getwd()
	path := filepath.Join(dir, "testdata", name)
	return ioutil.ReadFile(path)
}
func TestFastOpenPGP_EncryptBytesFile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped, only call when its necessary")
	}
	openPGP := NewFastOpenPGP()

	inputMessage, err := readFile("sample.zip")
	if err != nil {
		t.Fatal(err)
	}
	output, err := openPGP.EncryptBytes(inputMessage, publicKey, nil, &FileHints{IsBinary: true}, nil)
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

func TestFastOpenPGP_EncryptOptions(t *testing.T) {

	openPGP := NewFastOpenPGP()
	output, err := openPGP.Encrypt(privateKey+privateKey+privateKey, publicKey, nil, nil, &KeyOptions{
		Hash:             "sha512",
		Cipher:           "aes256",
		Compression:      "zlib",
		CompressionLevel: 9,
		RSABits:          4096,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = openPGP.Decrypt(output, privateKey, passphrase, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("output:", output)
}

func TestFastOpenPGP_EncryptOptionsECC(t *testing.T) {

	openPGP := NewFastOpenPGP()
	output, err := openPGP.EncryptBytes([]byte("Hello"), publicKeyECC, nil, nil, &KeyOptions{
		Hash:             "sha256",
		Compression:      "zlib",
		CompressionLevel: 9,
		RSABits:          4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	encodedString, _ := base64.StdEncoding.DecodeString("wV4Dvq15eT/QjtQSAQdAgP4X7BegCTvG78Vjqc89DBco+biNEjqIuBYrupGStjwwSzUCxgbuVOw1jxGxTbaylQAoFhQTwAqCi4rP0oldYmNwxZh//ZQw1wNbt/Rrs5hN0jYBArb9whokTUMFLRVemffxw4sxsn6RklleWxWBwL4S6UuH2AZd7DHx/84TCDuMBYS0nc8y47k=")
	data, err := openPGP.DecryptBytes(encodedString, privateKeyECC, passphrase, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("output base64:", base64.StdEncoding.EncodeToString(output))
	t.Log("data:", string(data))
	t.Log("output:", output)
}

func TestFastOpenPGP_Encrypt(t *testing.T) {

	openPGP := NewFastOpenPGP()
	encrypted, err := openPGP.Encrypt(inputMessage, publicKey, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	outputDecrypted, err := openPGP.Decrypt(encrypted, privateKey, passphrase, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("output:", encrypted, outputDecrypted)

	if inputMessage != outputDecrypted {
		t.Fatal("not same message")
	}
}

func TestFastOpenPGP_EncryptFile(t *testing.T) {

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
	result, err := openPGP.EncryptFile(input, output, publicKey, nil, fileHints, options)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("result:", result)
}

func TestFastOpenPGP_SignEncrypt(t *testing.T) {

	openPGP := NewFastOpenPGP()
	signature, err := openPGP.Sign(inputMessage, publicKey, privateKey, passphrase, nil)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("signature:", signature)

	output, err := openPGP.Encrypt(signature, publicKey, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("encrypted:", output)

	decrypted, err := openPGP.Decrypt(output, privateKey, passphrase, nil)
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
	output, err := openPGP.Encrypt(inputMessage, keysString, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	output1, err := openPGP.Decrypt(output, privateKey, passphrase, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("output1:", output1)
	output2, err := openPGP.Decrypt(output, keyPair2.PrivateKey, passphrase, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("output2:", output2)
	output3, err := openPGP.Decrypt(output, keyPair1.PrivateKey, passphrase, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("output3:", output3)

}
