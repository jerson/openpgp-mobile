package openpgp

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

func (o *FastOpenPGP) Sign(message, privateKey, passphrase string, options *KeyOptions) (string, error) {
	return o.SignBytesToString([]byte(message), privateKey, passphrase, options)
}

func (o *FastOpenPGP) SignBytesToString(message []byte, privateKey, passphrase string, options *KeyOptions) (string, error) {
	output, err := o.sign(bytes.NewReader(message), privateKey, passphrase, options)
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

func (o *FastOpenPGP) SignFile(input, privateKey, passphrase string, options *KeyOptions) (string, error) {
	message, err := os.Open(input)
	if err != nil {
		return "", err
	}
	defer message.Close()

	output, err := o.sign(message, privateKey, passphrase, options)
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

func (o *FastOpenPGP) SignBytes(message []byte, privateKey, passphrase string, options *KeyOptions) ([]byte, error) {
	return o.sign(bytes.NewReader(message), privateKey, passphrase, options)
}

func (o *FastOpenPGP) sign(reader io.Reader, privateKey, passphrase string, options *KeyOptions) ([]byte, error) {

	entityList, err := o.readPrivateKeys(privateKey, passphrase)
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

func (o *FastOpenPGP) SignData(message, privateKey, passphrase string, options *KeyOptions) (string, error) {
	return o.SignDataBytesToString([]byte(message), privateKey, passphrase, options)
}

func (o *FastOpenPGP) SignDataBytesToString(message []byte, privateKey, passphrase string, options *KeyOptions) (string, error) {
	output, err := o.signData(bytes.NewReader(message), privateKey, passphrase, options)
	if err != nil {
		return "", err
	}

	buf := bytes.NewBuffer(nil)
	writer, err := armor.Encode(buf, messageType, headers)
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

func (o *FastOpenPGP) SignDataBytes(message []byte, privateKey, passphrase string, options *KeyOptions) ([]byte, error) {
	return o.signData(bytes.NewReader(message), privateKey, passphrase, options)
}

func (o *FastOpenPGP) signData(reader io.Reader, privateKey, passphrase string, options *KeyOptions) ([]byte, error) {

	entityList, err := o.readPrivateKeys(privateKey, passphrase)
	if err != nil {
		return nil, err
	}

	if len(entityList) < 1 {
		return nil, fmt.Errorf("keys error: %w", errors.New("no key found"))
	}

	writer := new(bytes.Buffer)
	signatureWriter, err := openpgp.Sign(writer, entityList[0], &openpgp.FileHints{}, generatePacketConfig(options))
	if err != nil {
		return nil, err
	}

	_, err = io.Copy(signatureWriter, reader)
	if err != nil {
		return nil, err
	}
	signatureWriter.Close()

	// Return the signed data
	return writer.Bytes(), nil
}
