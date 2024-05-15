package openpgp

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
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

func (o *FastOpenPGP) EncryptFile(input, output, publicKey string, signedEntity *Entity, fileHints *FileHints, options *KeyOptions) (int, error) {
	// TODO optimize to handle big files
	message, err := ioutil.ReadFile(input)
	if err != nil {
		return 0, err
	}
	result, err := o.encrypt(message, publicKey, signedEntity, fileHints, options)
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

func (o *FastOpenPGP) EncryptBytes(message []byte, publicKey string, signedEntity *Entity, fileHints *FileHints, options *KeyOptions) ([]byte, error) {
	return o.encrypt(message, publicKey, signedEntity, fileHints, options)
}

func (o *FastOpenPGP) encrypt(message []byte, publicKey string, signedEntity *Entity, fileHints *FileHints, options *KeyOptions) ([]byte, error) {

	entityList, err := o.readPublicKeys(publicKey)
	if err != nil {
		return nil, fmt.Errorf("publicKey error: %w", err)
	}

	var signedEntityToEncrypt *openpgp.Entity
	if signedEntity != nil {
		signedEntityToEncrypt, err = o.generateSignedEntity(signedEntity)
		if err != nil {
			return nil, fmt.Errorf("signedEntity error: %w", err)
		}
	}

	buf := new(bytes.Buffer)
	w, err := openpgp.Encrypt(buf, entityList, signedEntityToEncrypt, generateFileHints(fileHints), generatePacketConfig(options))
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

func (o *FastOpenPGP) generateSignedEntity(options *Entity) (*openpgp.Entity, error) {

	if options == nil {
		return nil, errors.New("entity not provided")
	}
	entityList, err := o.readPrivateKeys(options.PrivateKey, options.Passphrase)
	if err != nil {
		return nil, fmt.Errorf("readSignKeys: %w", err)
	}

	if len(entityList) < 1 {
		return nil, errors.New("no entities found")
	}
	// for signed entity we only use first one
	return entityList[0], nil
}
