package openpgp

import (
	"io/ioutil"
	"strings"

	"github.com/keybase/go-crypto/openpgp"
	"github.com/keybase/go-crypto/openpgp/armor"
)

func (o *FastOpenPGP) Decrypt(message, privateKey, passphrase string) (string, error) {

	entityList, err := o.readPrivateKeys(privateKey, passphrase)
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
