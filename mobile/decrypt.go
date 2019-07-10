package openpgp

import (
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"io/ioutil"
	"strings"
)

func (o *OpenPGP) Decrypt(message, privateKey, passphrase string) (string, error) {

	entityList, err := o.readPrivateKey(privateKey, passphrase)
	if err != nil {
		return "", err
	}

	dec, err := armor.Decode(strings.NewReader(message))
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

