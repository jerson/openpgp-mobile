package openpgp

import (
	"bytes"
	"fmt"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"io/ioutil"
)

func (o *FastOpenPGP) Encrypt(message, publicKey string, signedEntity *Entity, fileHints *FileHints, options *KeyOptions) (string, error) {
	output, err := o.encrypt([]byte(message), publicKey, signedEntity, fileHints, options)
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

func (o *FastOpenPGP) EncryptBytes(message []byte, publicKey string, signedEntity *Entity, fileHints *FileHints, options *KeyOptions) ([]byte, error) {
	return o.encrypt(message, publicKey, signedEntity, fileHints, options)
}

func (o *FastOpenPGP) encrypt(message []byte, publicKey string, signedEntity *Entity, fileHints *FileHints, options *KeyOptions) ([]byte, error) {

	entityList, err := o.readPublicKeys(publicKey)
	if err != nil {
		return nil, fmt.Errorf("publicKey error: %w", err)
	}

	buf := new(bytes.Buffer)
	w, err := openpgp.Encrypt(buf, entityList, o.generateSignedEntity(signedEntity), generateFileHints(fileHints), generatePacketConfig(options))
	if err != nil {
		return nil, err
	}
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

func (o *FastOpenPGP) generateSignedEntity(options *Entity) *openpgp.Entity {

	if options == nil {
		return nil
	}
	entityList, err := o.readSignKeys(options.PublicKey, options.PrivateKey, options.Passphrase)
	if err != nil {
		// by now we are skipping errors, be careful
		return nil
	}
	// if for some reason dont contains any key we need to return nil
	if len(entityList) < 1 {
		return nil
	}
	// for signed entity we only use first one
	return entityList[0]
}
