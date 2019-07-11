package openpgp

import (
	"bytes"
	"errors"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
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
		// If the given passphrase isn't correct, the function will be called again, forever.
		// This method will fail fast.
		// Ref: https://godoc.org/golang.org/x/crypto/openpgp#PromptFunction
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
