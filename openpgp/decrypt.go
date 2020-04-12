package openpgp

import (
	"bytes"
	"github.com/keybase/go-crypto/openpgp"
	"github.com/keybase/go-crypto/openpgp/armor"
	"io/ioutil"
)

func (o *FastOpenPGP) Decrypt(message, privateKey, passphrase string) (string, error) {
	return o.DecryptBytes([]byte(message), privateKey, passphrase)
}

func (o *FastOpenPGP) DecryptBytes(message []byte, privateKey, passphrase string) (string, error) {

	entityList, err := o.readPrivateKeys(privateKey, passphrase)
	if err != nil {
		return "", err
	}

	buf := bytes.NewBuffer(message)
	dec, err := armor.Decode(buf)
	if err != nil {
		return "", err
	}

	md, err := openpgp.ReadMessage(dec.Body, entityList, nil, nil)
	if err != nil {
		return "", err
	}
	output, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", err
	}
	outputString := string(output)

	return outputString, nil
}
