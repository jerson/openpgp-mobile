package openpgp

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/ProtonMail/go-crypto/openpgp"
)

func (o *FastOpenPGP) Decrypt(message, privateKey, passphrase string, signedEntity *Entity, options *KeyOptions) (string, error) {
	body, err := o.readBlock(message, messageType)
	if err != nil {
		return "", fmt.Errorf("message error: %w", err)
	}

	output, err := o.decrypt(body, privateKey, passphrase, signedEntity, options)
	if err != nil {
		return "", err
	}
	return string(output), nil
}

func (o *FastOpenPGP) DecryptFile(input, output, privateKey, passphrase string, signedEntity *Entity, options *KeyOptions) (int, error) {
	message, err := os.Open(input)
	if err != nil {
		return 0, err
	}
	defer message.Close()
	result, err := o.decrypt(message, privateKey, passphrase, signedEntity, options)
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

func (o *FastOpenPGP) DecryptBytes(message []byte, privateKey, passphrase string, signedEntity *Entity, options *KeyOptions) ([]byte, error) {
	return o.decrypt(bytes.NewReader(message), privateKey, passphrase, signedEntity, options)
}

func (o *FastOpenPGP) decrypt(reader io.Reader, privateKey, passphrase string, signedEntity *Entity, options *KeyOptions) ([]byte, error) {
	entityList, err := o.readPrivateKeys(privateKey, passphrase)
	if err != nil {
		return nil, fmt.Errorf("privateKey error: %w", err)
	}

	md, err := openpgp.ReadMessage(reader, entityList, nil, generatePacketConfig(options))
	if err != nil {
		return nil, err
	}

	if signedEntity != nil {
		signedEntities, err := o.readPublicKeys(signedEntity.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("publicKey error: %w", err)
		}
		if md.SignatureError != nil {
			return nil, fmt.Errorf("signature error: %w", md.SignatureError)
		}

		if md.SignedBy == nil {
			return nil, errors.New("message is not signed")
		}

		if signedEntities.KeysById(md.SignedByKeyId) == nil {
			return nil, fmt.Errorf("signedKeyId:%d does not belong to the provided signedEntity", md.SignedByKeyId)
		}
	}

	output, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return nil, err
	}
	return output, nil
}
