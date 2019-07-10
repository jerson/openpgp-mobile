package openpgp

import (
	"bytes"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

func (o *OpenPGP) EncryptSymmetric(message, password string, options *KeyOptions) (string, error) {

	var output string
	buf := bytes.NewBuffer(nil)
	w, err := armor.Encode(buf, messageHeader, headers)
	if err != nil {
		return output, err
	}
	defer w.Close()

	config := generatePacketConfig(options)
	pt, err := openpgp.SymmetricallyEncrypt(w, []byte(password), nil, &config)
	if err != nil {
		return output, err
	}
	defer pt.Close()

	_, err = pt.Write([]byte(message))
	if err != nil {
		return output, err
	}

	return buf.String(), nil
}
