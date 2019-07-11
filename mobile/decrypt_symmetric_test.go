package openpgp

import "testing"

var symmetricMessage = `-----BEGIN PGP MESSAGE-----
Provider: react-native-fast-openpgp

wy4ECQMKh9ZaS+L1qIdgUlcPFG2Fn8MojzLkB29LJhit6gvw+tZjsq0+vxasThfz
0uAB5N8A4hQS+WIkmcC80FhmWMHhG3XgL+D/4Ofgz+E9geAm5JmU5esNJpFMkJ8w
ex4dGwLgr+PbaxXCd0xq8OBU4MXgWuI7iYLg4BviHtHuHeD55GgMVGWn+237+idp
hFhABS/ig+ryWeEGIgA=
=RN2S
-----END PGP MESSAGE-----`

func TestOpenPGP_DecryptSymmetric(t *testing.T) {

	options := &KeyOptions{
		CompressionLevel: 9,
		RSABits:          4096,
		Cipher:           "aes256",
		Compression:      "zlib",
		Hash:             "sha512"}

	openPGP := NewOpenPGP()
	output, err := openPGP.DecryptSymmetric(symmetricMessage, passphrase, options)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
