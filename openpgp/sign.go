package openpgp

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

func (o *FastOpenPGP) Sign(message, publicKey, privateKey, passphrase string, options *KeyOptions) (string, error) {
	return o.SignBytesToString([]byte(message), publicKey, privateKey, passphrase, options)
}

func (o *FastOpenPGP) SignBytesToString(message []byte, publicKey, privateKey, passphrase string, options *KeyOptions) (string, error) {
	output, err := o.sign(bytes.NewReader(message), publicKey, privateKey, passphrase, options)
	if err != nil {
		return "", err
	}

	buf := bytes.NewBuffer(nil)
	writer, err := armor.Encode(buf, openpgp.SignatureType, headers)
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

func (o *FastOpenPGP) SignFile(input, publicKey, privateKey, passphrase string, options *KeyOptions) (string, error) {
	message, err := os.Open(input)
	if err != nil {
		return "", err
	}
	defer message.Close()

	output, err := o.sign(message, publicKey, privateKey, passphrase, options)
	if err != nil {
		return "", err
	}

	buf := bytes.NewBuffer(nil)
	writer, err := armor.Encode(buf, openpgp.SignatureType, headers)
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

func (o *FastOpenPGP) SignBytes(message []byte, publicKey, privateKey, passphrase string, options *KeyOptions) ([]byte, error) {
	return o.sign(bytes.NewReader(message), publicKey, privateKey, passphrase, options)
}

func (o *FastOpenPGP) sign(reader io.Reader, publicKey, privateKey, passphrase string, options *KeyOptions) ([]byte, error) {

	entityList, err := o.readSignKeys(publicKey, privateKey, passphrase)
	if err != nil {
		return nil, err
	}
	if len(entityList) < 1 {
		return nil, fmt.Errorf("keys error: %w", errors.New("no key found"))
	}

	writer := new(bytes.Buffer)
	err = openpgp.DetachSign(writer, entityList[0], reader, generatePacketConfig(options))
	if err != nil {
		return nil, err
	}

	output, err := ioutil.ReadAll(writer)
	if err != nil {
		return nil, err
	}

	return output, nil
}
