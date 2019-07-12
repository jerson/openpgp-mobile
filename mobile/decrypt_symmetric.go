package openpgp

import (
	"bytes"
	"errors"
	"github.com/keybase/go-crypto/openpgp"
	"github.com/keybase/go-crypto/openpgp/armor"
	"io/ioutil"
)

func (o *OpenPGP) DecryptSymmetric(message, passphrase string, options *KeyOptions) (string, error) {

	var output string
	buf := bytes.NewBufferString(message)

	armorBlock, err := armor.Decode(buf)
	if err != nil {
		return output, err
	}

	failed := false
	prompt := func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		if failed {
			return nil, errors.New("decryption failed")
		}
		failed = true
		return []byte(passphrase), nil
	}

	config := generatePacketConfig(options)
	md, err := openpgp.ReadMessage(armorBlock.Body, nil, prompt, config)
	if err != nil {
		return output, err
	}

	result, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return output, err
	}

	output = string(result)
	return output, nil
}
