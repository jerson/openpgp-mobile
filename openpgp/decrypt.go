package openpgp

import (
	"bytes"
	"fmt"
	"github.com/ProtonMail/go-crypto/openpgp"
	"io"
	"io/ioutil"
	"os"
)

func (o *FastOpenPGP) Decrypt(message, privateKey, passphrase string, options *KeyOptions) (string, error) {
	body, err := o.readBlock(message, messageType)
	if err != nil {
		return "", fmt.Errorf("message error: %w", err)
	}

	output, err := o.decrypt(body, privateKey, passphrase, options)
	if err != nil {
		return "", err
	}
	return string(output), nil
}

func (o *FastOpenPGP) DecryptFile(input, output, privateKey, passphrase string, options *KeyOptions) (int, error) {
	message, err := os.Open(input)
	if err != nil {
		return 0, err
	}
	defer message.Close()
	result, err := o.decrypt(message, privateKey, passphrase, options)
	if err != nil {
		return 0, err
	}

	// TODO optimize to handle big files
	err = ioutil.WriteFile(output, result, fileDefaultPermissions)
	if err != nil {
		return 0, err
	}

	return len(result), nil
}

func (o *FastOpenPGP) DecryptBytes(message []byte, privateKey, passphrase string, options *KeyOptions) ([]byte, error) {
	return o.decrypt(bytes.NewReader(message), privateKey, passphrase, options)
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
