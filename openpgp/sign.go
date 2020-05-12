package openpgp

import (
	"bytes"
	"errors"
	"io/ioutil"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

func (o *FastOpenPGP) Sign(message, publicKey, privateKey, passphrase string) (string, error) {
	return o.SignBytesToString([]byte(message), publicKey, privateKey, passphrase)
}

func (o *FastOpenPGP) SignBytesToString(message []byte, publicKey, privateKey, passphrase string) (string, error) {
	output, err := o.sign(message, publicKey, privateKey, passphrase)
	if err != nil {
		return "", err
	}

	buf := bytes.NewBuffer(nil)
	writer, err := armor.Encode(buf, signatureHeader, headers)
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

func (o *FastOpenPGP) SignBytes(message []byte, publicKey, privateKey, passphrase string) ([]byte, error) {
	return o.sign(message, publicKey, privateKey, passphrase)
}

func (o *FastOpenPGP) sign(message []byte, publicKey, privateKey, passphrase string) ([]byte, error) {

	entityList, err := o.readSignKeys(publicKey, privateKey, passphrase)
	if err != nil {
		return nil, err
	}
	if len(entityList) < 1 {
		return nil, errors.New("no key found")
	}

	writer := new(bytes.Buffer)
	reader := bytes.NewReader(message)
	err = openpgp.DetachSign(writer, entityList[0], reader, nil)
	if err != nil {
		return nil, err
	}

	output, err := ioutil.ReadAll(writer)
	if err != nil {
		return nil, err
	}

	return output, nil
}
