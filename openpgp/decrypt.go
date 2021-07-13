package openpgp

import (
	"bytes"
	"fmt"
	"golang.org/x/crypto/openpgp"
	"io"
	"io/ioutil"
)

func (o *FastOpenPGP) Decrypt(message, privateKey, passphrase string, options *KeyOptions) (string, error) {
	body, err := o.readBlock(message, messageType)
	if err != nil {
		return "", fmt.Errorf("message error: %w",err)
	}

	output, err := o.decrypt(body, privateKey, passphrase, options)
	if err != nil {
		return "", err
	}
	return string(output), nil
}

func (o *FastOpenPGP) DecryptBytes(message []byte, privateKey, passphrase string, options *KeyOptions) ([]byte, error) {
	buf := bytes.NewReader(message)
	return o.decrypt(buf, privateKey, passphrase, options)
}

func (o *FastOpenPGP) decrypt(reader io.Reader, privateKey, passphrase string, options *KeyOptions) ([]byte, error) {
	entityList, err := o.readPrivateKeys(privateKey, passphrase)
	if err != nil {
		return nil, fmt.Errorf("privateKey error: %w", err)
	}

	md, err := openpgp.ReadMessage(reader, entityList, nil, generatePacketConfig(options))
	if err != nil {
		return nil, err
	}
	output, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return nil, err
	}
	return output, nil
}
