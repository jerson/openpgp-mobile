package openpgp

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

func TestFastOpenPGP_Decrypt(t *testing.T) {

	openPGP := NewFastOpenPGP()

	output, err := openPGP.Decrypt(message, privateKey, passphrase, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}

func TestFastOpenPGP_DecryptVerifyEntity(t *testing.T) {

	openPGP := NewFastOpenPGP()
	publicKey := `-----BEGIN PGP PUBLIC KEY BLOCK-----

xsBNBGZFFToBCADGr9nBnYiy73KzIfIGzmSOTsG4B1TnUkBfZovg8YuX3DW6
SDbL06NsEvXcFBC+VnQe1+DUX42LaQXWIFFcHQe6FrfGWTEY2AYl16BUIoQK
CJ0aOW7QNITWyFllOErqcaSrL4eEgoDUKUV6vQFW+lEZPYiDEVQB2/F32EAC
IihyI8PN11Ufu+0zXj2DnXPTN0CjSkKMJuroZ/DqGkQ6o4D9+/b9yfKRKtap
YsAWus0cG/LwLGBtXKYdYbZTdtXb/A9fBSNajBziu3PDJQKL+mTyPuxjclv2
Q5Yk2oIB2AjBK8XGHiwt5ICetvpgNXLAiml/rjQr/hZVzdPjtGCk9/aFABEB
AAHNFVNhbSA8c2FtQG9wZW5zb3J0LmlvPsLAigQQAQgAPgWCZkUVOgQLCQcI
CZDgEZ+mup4LZgMVCAoEFgACAQIZAQKbAwIeARYhBC8cy8/ZPTJTXuuxVuAR
n6a6ngtmAAAXxgf/YjduMfaNB842Kh55L9P+dPRWZlOOKw01GdvvLI5ew7+U
vHcXRZ5mb2rIx0ia7nzswPJVYumekm/o4dCl/RpT8jv1xsQB/5/celVJUT3v
X/lKgF7RRb4bBYxtYwOR2IGc+RP2sIuSnGt0cV0aR6f9rZEpsLYqtZLGZ358
9bSk2hQw4baTJDW5sn+m+Dz/7LS+kdfV5+1wkr4+4eYIVrqLSikARorvdSge
LM4zP9bNW0GBDDbSln0gVyT16xcuWQD+UCs+qxtfxubnT/On7Z9LB95La5Lr
7nkx8H2KPH+qY4ybhinwlzOgaUoqakLlPhgkKAvlak+oYqlvE+psrjybe87A
TQRmRRU6AQgAu/ramU2dmavnP2bL6drAxpjsxFmArBfpzwzAiDz9DFI7elwV
Y/yqieV0fvuYarB/f8lhcGwEQ11SLtWLpDuPiIUWOBuRPOCFjyshu2fpJPCG
8fmTycbyKvHuauyhcb2Q3vAatQ3x5uLf5o+a9J7NTBBPiRvIJ0x++lgLPLx9
iJUiqmvnaTWiR/cW+tAy4rdH7Equ+cU76eEYOyBGQn1nVBiFjgekUfLUZTvR
OAd2v3Yj3tDJ9MkFUsE8kL7tze7EFq2/ZuoeVXhpWXGoENuJirAi5keX9HwP
K32qAc63T0PofUDIVl52Zxl3pTYXL1QC4STtifmVxtd5PVys+zyRAwARAQAB
wsB2BBgBCAAqBYJmRRU6CZDgEZ+mup4LZgKbDBYhBC8cy8/ZPTJTXuuxVuAR
n6a6ngtmAACLDQf+JaZYB07DH2gKAfgzpOjhrm4BYfrMfC4A6Kc/f1MIy1jU
t23HBlcKXrHTvxiLu3MhcOtoaBE+VF+SWrz3Q6x91It5SbmMOFazJt+OD6c/
CiuUr291hJZE1kM0WCwqcKifUQwElenJPVnk5HRYv0WtMnsqCYmf2rMwEjDr
+TTHzjbu4JDoErgDDEJfeEIMD/g0zid4Q8jkU7pW8ClRNetRlQi+XwEYETR3
Ir+QTEH67dP841gPJHyS6foU80eowH9Ndl9NKIHpNu4ubc5/NIS+jank9xL5
CnWJHOOSOJ1iTODXF72eiHQuVRaH3mftjDwNMoys+snwBfhTUwQ+sMRPLA==
=LXdn
-----END PGP PUBLIC KEY BLOCK-----`

	privateKey := `-----BEGIN PGP PRIVATE KEY BLOCK-----

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
=ZU6J
-----END PGP PRIVATE KEY BLOCK-----`

	message := `
-----BEGIN PGP MESSAGE-----
Version: Keybase OpenPGP v2.0.76
Comment: https://keybase.io/crypto

wcBMA40hTk+Qn5VZAQf9EcFTPy63JE4awKD1Ho2W6uANAuFdBYecqUTDeKwsds2h
n9dHUoHw2s5WkQU10CQRl3XHyRwUR6sJi+4KL8dpuWMmhOQgScZrpjB6MKjR2BfZ
PZEiUXMZ30fVsnEmAl7nXMUwlXitDIV3Ev5qqcAXGHZd3c6eoq5QWeoSxpmahAOr
m/bRxkEoJGBIACKPOmglGkSNwBiGT/zL1sfBImlA1xokTSsRY9mL2cix3fqdjqiW
1zJwGdA7RWOAh8GCD7wCrr4ymn+wuFlsKKV9tkYpcYC4XK2epMjULERJZaNXAEto
B6Ik1JUt8epmZPNMW3UdAgBd/sMqrKel+GAXgbb/49LAsAG5/idepLYkxtR28uD1
X9cLL72RHPoP0QUDmL5xplg3vDY82qVxpURduRAOljK9wbKwPVT+wKA3QjLGgs8h
Hu7Mo3A9PuAfnA45ENlVy/id2glEu+8w1YbR1skbXU/z05xprP9tyFKDnt23zC6Q
wW7I88EVB7evpNwkqTYH30ZPerqykdBJHAM4tUah8zcv0NI/QBOFAjW7zPkSziRt
5FD86n8dU9OX3DjCyyB25USSfsyjLJSqePvEaH5ctnbTBsKE1ed+Pp5lYf4xC+ED
+Om2lQwcQhywVRiCAeDiSwg+lMB1I61hzWfWPwmfsiGzLv9MQOoRvGyISXIkBVYF
8rvREPRCzm4uOSm3uhBGkh7/+6neu9+7yyzhYcBMxpgmEratR8MvozD8mo4rRN47
SOa/iFDPaFLmxDllL+nnXnEM4ZJ67RB8u9bkHid+j+CjPmPt6CNfJaNkYVas5rFO
u+kFX2tZ28qewIgMTxdI9Nd2
=poEG
-----END PGP MESSAGE-----`

	signedEntity := &Entity{
		PublicKey: publicKey,
	}

	decrypted, err := openPGP.Decrypt(message, privateKey, passphrase, signedEntity, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("decrypted+verify:", decrypted)

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
	result, err := openPGP.DecryptFile(output, outputDecrypted, privateKey, passphrase, nil, options)
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
