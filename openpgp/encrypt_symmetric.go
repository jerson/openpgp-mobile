package openpgp

import (
	"bytes"
	"io/ioutil"

	"github.com/keybase/go-crypto/openpgp"
	"github.com/keybase/go-crypto/openpgp/armor"
)

func (o *FastOpenPGP) EncryptSymmetric(message, passphrase string, options *KeyOptions) (string, error) {
	output, err := o.encryptSymmetric([]byte(message), passphrase, options)
	if err != nil {
		return "", err
	}

	buf := bytes.NewBuffer(nil)
	writer, err := armor.Encode(buf, messageHeader, headers)
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

func (o *FastOpenPGP) EncryptSymmetricBytes(message []byte, passphrase string, options *KeyOptions) ([]byte, error) {
	return o.encryptSymmetric(message, passphrase, options)
}

func (o *FastOpenPGP) encryptSymmetric(message []byte, passphrase string, options *KeyOptions) ([]byte, error) {

	config := generatePacketConfig(options)

	buf := new(bytes.Buffer)
	w, err := openpgp.SymmetricallyEncrypt(buf, []byte(passphrase), nil, config)
	if err != nil {
		return nil, err
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
