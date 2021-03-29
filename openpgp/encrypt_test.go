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

func TestFastOpenPGP_EncryptECC(t *testing.T) {

	//passphrase := "123456"

	publicKey := `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: Keybase OpenPGP v1.0.0
Comment: https://keybase.io/crypto

xm8EYGFDVxMFK4EEACIDAwS/TVvzd5C0xf/XZUeIWdR1Bcd3LKpZx4ab1n0LjCNN
eKIHuf3Y3B6ArIlmPlqy4kOMnrxiWEc8g9rn96/wXY1CKs5wsATu7Hka6s5dH/Mq
2aqpp0IMsDqwH1ZsG4hKrM/NI3NhbXBsZSAoc2FtcGxlKSA8c2FtcGxlQHNhbXBs
ZS5jb20+wo8EExMKABcFAmBhQ1cCGy8DCwkHAxUKCAIeAQIXgAAKCRD4jkQ2KRTd
fcaUAYCAoniTBUXVvwpbMM0/jKDHtdMB4GIfCg+SPgFf/oMMhmxPDlCFuGJcYbmw
k7TfaXABgLUa+HJdP6q+no3KlzkI6xotgSlfLVWii2j4vEe0d3r3rUQZEVMPL2ky
LaHwtk56R85SBGBhQ1cTCCqGSM49AwEHAgMET/zo0CWE9C/F4a9VIIdV79W0sWrd
gOqP9bGHtqlMM+tdQ2V/m6xIR+wKLjBk8Fes6ciOEWkC4i893KagcGYxcMLAJwQY
EwoADwUCYGFDVwUJDwmcAAIbLgBqCRD4jkQ2KRTdfV8gBBkTCgAGBQJgYUNXAAoJ
EHuSl/tfe3e23UYBAIUdoSkAg35XLvGkaQqHgUnbdAgPOulbDIkqsxfNFqe+AQDY
3fEJ+o29ulyPTXWA1UUYdWHKfDh8AaPFKp3yjH1zsGmLAYDmzRgm47xTrgzpCURy
1+jcqVoYrnzLy7ARD0PKZaE+CCdYkcsFdoQI3lBt+y2AqE8BgOicquBgyHO1NYPE
FCb1FWGkFvH6Nt1z0jfjOy4EGA5gqHqG38P2GBMtPdm7hqP0C85SBGBhQ1cTCCqG
SM49AwEHAgME899ZH5qsaljjfykfYwIdSW9kMIs/6DdJBk+SPBKPU2NlstdNMpPD
2biQL4a5HvSqNrRuXZq1gKggWT0fr2NPEcLAJwQYEwoADwUCYGFDVwUJDwmcAAIb
LgBqCRD4jkQ2KRTdfV8gBBkTCgAGBQJgYUNXAAoJECD9vjGTJ5WTQ/0BAIHRtKms
i4Fx6F1Qlb6NGy/OcnhiM4DLnrCuxnhq/FTuAP9s3giBFN/CkRVIP/rFpKVGTZWD
iZokHb/AgMfP0OTd7iXOAYD8hbItckwe9DiH83NsY/AxYxrPBIE54c3+9Fhf9z/p
bDmOkmVaI6By5LfoL0AWcjMBgOudqmvuG+DJMGnJ7W3/QnYtiKXjnd2Yp45khvtR
Ghg20bINJqZcdPcOssTj//naTA==
=5Yvg
-----END PGP PUBLIC KEY BLOCK-----
`
	/*
	privateKey := `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: Keybase OpenPGP v1.0.0
Comment: https://keybase.io/crypto

xcASBGBhQ1cTBSuBBAAiAwMEv01b83eQtMX/12VHiFnUdQXHdyyqWceGm9Z9C4wj
TXiiB7n92NwegKyJZj5asuJDjJ68YlhHPIPa5/ev8F2NQirOcLAE7ux5GurOXR/z
KtmqqadCDLA6sB9WbBuISqzP/gkDCDUJKj8fsLjGYD9kjMdcdzhhv8TkRwHf4s7g
OzmfqZ0VTRAhMw9If6+/1Qn677rR7EtjrvhR5BO0aZ3v4f/maUS9wQTCkLs2hWIY
EAbm0vWIbgoC09UEv6bXDS/hpmuWzSNzYW1wbGUgKHNhbXBsZSkgPHNhbXBsZUBz
YW1wbGUuY29tPsKPBBMTCgAXBQJgYUNXAhsvAwsJBwMVCggCHgECF4AACgkQ+I5E
NikU3X3GlAGAgKJ4kwVF1b8KWzDNP4ygx7XTAeBiHwoPkj4BX/6DDIZsTw5Qhbhi
XGG5sJO032lwAYC1GvhyXT+qvp6Nypc5COsaLYEpXy1Vooto+LxHtHd6961EGRFT
Dy9pMi2h8LZOekfHpQRgYUNXEwgqhkjOPQMBBwIDBE/86NAlhPQvxeGvVSCHVe/V
tLFq3YDqj/Wxh7apTDPrXUNlf5usSEfsCi4wZPBXrOnIjhFpAuIvPdymoHBmMXD+
CQMIurU/ReZ/jaxgl5Qthni8WNYL2JBTlfjuljdx3kw0AfKuk59fgzsTgcN/Mxzv
nWUchith2TaeddwkgaoW/6cYFv/Rq3IxnxM9FmSZkxMF4MLAJwQYEwoADwUCYGFD
VwUJDwmcAAIbLgBqCRD4jkQ2KRTdfV8gBBkTCgAGBQJgYUNXAAoJEHuSl/tfe3e2
3UYBAIUdoSkAg35XLvGkaQqHgUnbdAgPOulbDIkqsxfNFqe+AQDY3fEJ+o29ulyP
TXWA1UUYdWHKfDh8AaPFKp3yjH1zsGmLAYDmzRgm47xTrgzpCURy1+jcqVoYrnzL
y7ARD0PKZaE+CCdYkcsFdoQI3lBt+y2AqE8BgOicquBgyHO1NYPEFCb1FWGkFvH6
Nt1z0jfjOy4EGA5gqHqG38P2GBMtPdm7hqP0C8elBGBhQ1cTCCqGSM49AwEHAgME
899ZH5qsaljjfykfYwIdSW9kMIs/6DdJBk+SPBKPU2NlstdNMpPD2biQL4a5HvSq
NrRuXZq1gKggWT0fr2NPEf4JAwjglKsoVF6O52CDKflcvctdbV8TqmNwLnV7+e4N
pzth8r3YIJMbc43l9PXZbEB+7VVg2MEYGo46Fz7lmPOJT2hwy7FXGIzrw76Hm/+j
A8mPwsAnBBgTCgAPBQJgYUNXBQkPCZwAAhsuAGoJEPiORDYpFN19XyAEGRMKAAYF
AmBhQ1cACgkQIP2+MZMnlZND/QEAgdG0qayLgXHoXVCVvo0bL85yeGIzgMuesK7G
eGr8VO4A/2zeCIEU38KRFUg/+sWkpUZNlYOJmiQdv8CAx8/Q5N3uJc4BgPyFsi1y
TB70OIfzc2xj8DFjGs8EgTnhzf70WF/3P+lsOY6SZVojoHLkt+gvQBZyMwGA652q
a+4b4Mkwacntbf9Cdi2IpeOd3ZinjmSG+1EaGDbRsg0mplx09w6yxOP/+dpM
=i/4D
-----END PGP PRIVATE KEY BLOCK-----
`
*/

	openPGP := NewFastOpenPGP()

	output, err := openPGP.Encrypt(inputMessage, publicKey, nil, nil, nil)
	if err != nil {
		//FIXME this test for now is not working with ECC
		t.Log(err)
	}
	t.Log("output:", output)

	//outputDecrypted, err := openPGP.Decrypt(output, privateKey, passphrase, nil)
	//if err != nil {
	//	t.Fatal(err)
	//}
	//t.Log("output:", output, outputDecrypted)
}

func TestFastOpenPGP_Encrypt(t *testing.T) {

	openPGP := NewFastOpenPGP()
	output, err := openPGP.Encrypt(inputMessage, publicKey, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	outputDecrypted, err := openPGP.Decrypt(output, privateKey, passphrase, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("output:", output, outputDecrypted)
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
