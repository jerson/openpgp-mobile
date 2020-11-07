package openpgp

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

func (o *FastOpenPGP) DecryptSymmetric(message, passphrase string, options *KeyOptions) (string, error) {
	buf := bytes.NewReader([]byte(message))
	dec, err := armor.Decode(buf)
	if err != nil {
		return "", err
	}

	output, err := o.decryptSymmetric(dec.Body, passphrase, options)
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
		return nil, err
	}
	output, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return nil, err
	}
	return output, nil
}
