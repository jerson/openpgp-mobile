package openpgp

import (
	"bytes"
	"fmt"
	"io/ioutil"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

func (o *FastOpenPGP) EncryptSymmetric(message, passphrase string, fileHints *FileHints, options *KeyOptions) (string, error) {
	output, err := o.encryptSymmetric([]byte(message), passphrase, fileHints, options)
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

func (o *FastOpenPGP) EncryptSymmetricBytes(message []byte, passphrase string, fileHints *FileHints, options *KeyOptions) ([]byte, error) {
	return o.encryptSymmetric(message, passphrase, fileHints, options)
}

func (o *FastOpenPGP) encryptSymmetric(message []byte, passphrase string, fileHints *FileHints, options *KeyOptions) ([]byte, error) {

	buf := new(bytes.Buffer)
	w, err := openpgp.SymmetricallyEncrypt(buf, []byte(passphrase), generateFileHints(fileHints), generatePacketConfig(options))
	if err != nil {
		return nil,  fmt.Errorf("symmetricallyEncrypt error: %w", err)
	}
	defer w.Close()

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
