package openpgp

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"

	"golang.org/x/crypto/openpgp"
)

func (o *FastOpenPGP) DecryptSymmetric(message, passphrase string, options *KeyOptions) (string, error) {
	body, err := o.readBlock(message, messageType)
	if err != nil {
		return "", fmt.Errorf("message error: %w",err)
	}

	output, err := o.decryptSymmetric(body, passphrase, options)
	if err != nil {
		return "", err
	}
	return string(output), nil
}

func (o *FastOpenPGP) DecryptSymmetricBytes(message []byte, passphrase string, options *KeyOptions) ([]byte, error) {
	buf := bytes.NewReader(message)
	return o.decryptSymmetric(buf, passphrase, options)
}

func (o *FastOpenPGP) decryptSymmetric(reader io.Reader, passphrase string, options *KeyOptions) ([]byte, error) {

	failed := false
	prompt := func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		if failed {
			return nil, errors.New("decryption failed")
		}
		failed = true
		return []byte(passphrase), nil
	}

	md, err := openpgp.ReadMessage(reader, nil, prompt, generatePacketConfig(options))
	if err != nil {
		return nil, fmt.Errorf("readMessage error: %w", err)
	}
	output, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return nil, err
	}
	return output, nil
}
