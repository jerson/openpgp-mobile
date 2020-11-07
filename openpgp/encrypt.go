package openpgp

import (
	"bytes"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"io/ioutil"
)

func (o *FastOpenPGP) Encrypt(message, publicKey string) (string, error) {
	output, err := o.encrypt([]byte(message), publicKey)
	if err != nil {
		return "", err
	}

	buf := bytes.NewBuffer(nil)
	writer, err := armor.Encode(buf, messageHeader, headers)
	if err != nil {
		return "", err
	}
	_, err = writer.Write(output)
	if err != nil {
		return "", err
	}
	err = writer.Close()
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (o *FastOpenPGP) EncryptBytes(message []byte, publicKey string) ([]byte, error) {
	return o.encrypt(message, publicKey)
}

func (o *FastOpenPGP) encrypt(message []byte, publicKey string) ([]byte, error) {

	entityList, err := o.readPublicKeys(publicKey)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	w, err := openpgp.Encrypt(buf, entityList, nil, &openpgp.FileHints{
		IsBinary: true,
	}, nil)
	if err != nil {
		return nil, err
	}
	_, err = w.Write(message)
	if err != nil {
		return nil, err
	}
	err = w.Close()
	if err != nil {
		return nil, err
	}

	output, err := ioutil.ReadAll(buf)
	if err != nil {
		return nil, err
	}

	return output, nil
}
