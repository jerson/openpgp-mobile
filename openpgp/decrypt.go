package openpgp

import (
	"bytes"
	"github.com/keybase/go-crypto/openpgp"
	"github.com/keybase/go-crypto/openpgp/armor"
	"io"
	"io/ioutil"
)

func (o *FastOpenPGP) Decrypt(message, privateKey, passphrase string) (string, error) {
	buf := bytes.NewReader([]byte(message))
	dec, err := armor.Decode(buf)
	if err != nil {
		return "", err
	}

	output, err := o.decrypt(dec.Body, privateKey, passphrase)
	if err != nil {
		return "", err
	}
	return string(output), nil
}

func (o *FastOpenPGP) DecryptBytes(message []byte, privateKey, passphrase string) (string, error) {
	buf := bytes.NewReader(message)

	output, err := o.decrypt(buf, privateKey, passphrase)
	if err != nil {
		return "", err
	}
	return string(output), nil
}

func (o *FastOpenPGP) decrypt(reader io.Reader, privateKey, passphrase string) ([]byte, error) {
	entityList, err := o.readPrivateKeys(privateKey, passphrase)
	if err != nil {
		return nil, err
	}

	md, err := openpgp.ReadMessage(reader, entityList, nil, nil)
	if err != nil {
		return nil, err
	}
	output, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return nil, err
	}
	return output, nil
}
