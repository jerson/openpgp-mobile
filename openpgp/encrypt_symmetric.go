package openpgp

import (
	"bytes"
	"fmt"
	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"io/ioutil"
)

const fileDefaultPermissions = 0755

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

func (o *FastOpenPGP) EncryptSymmetricFile(input, output string, passphrase string, fileHints *FileHints, options *KeyOptions) (int, error) {
	// TODO optimize to handle big files
	message, err := ioutil.ReadFile(input)
	if err != nil {
		return 0, err
	}
	result, err := o.encryptSymmetric(message, passphrase, fileHints, options)
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

func (o *FastOpenPGP) EncryptSymmetricBytes(message []byte, passphrase string, fileHints *FileHints, options *KeyOptions) ([]byte, error) {
	return o.encryptSymmetric(message, passphrase, fileHints, options)
}

func (o *FastOpenPGP) encryptSymmetric(message []byte, passphrase string, fileHints *FileHints, options *KeyOptions) ([]byte, error) {

	buf := new(bytes.Buffer)
	w, err := openpgp.SymmetricallyEncrypt(buf, []byte(passphrase), generateFileHints(fileHints), generatePacketConfig(options))
	if err != nil {
		return nil, fmt.Errorf("symmetricallyEncrypt error: %w", err)
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
