package openpgp

import (
	"bytes"

	"github.com/keybase/go-crypto/openpgp"
)

func (o *FastOpenPGP) Sign(message, publicKey, privateKey, passphrase string) (string, error) {

	entities, err := o.readSignKeys(publicKey, privateKey, passphrase)
	if err != nil {
		return "", err
	}

	writer := new(bytes.Buffer)
	reader := bytes.NewReader([]byte(message))
	err = openpgp.ArmoredDetachSign(writer, entities[0], reader, nil)
	if err != nil {
		return "", err
	}

	return writer.String(), nil
}
