package openpgp

import (
	"bytes"
	"errors"

	"github.com/keybase/go-crypto/openpgp"
)

func (o *FastOpenPGP) Sign(message, publicKey, privateKey, passphrase string) (string, error) {

	entityList, err := o.readSignKeys(publicKey, privateKey, passphrase)
	if err != nil {
		return "", err
	}
	if len(entityList) < 1 {
		return "", errors.New("no key found")
	}

	writer := new(bytes.Buffer)
	reader := bytes.NewReader([]byte(message))
	err = openpgp.ArmoredDetachSign(writer, entityList[0], reader, nil)
	if err != nil {
		return "", err
	}

	return writer.String(), nil
}
