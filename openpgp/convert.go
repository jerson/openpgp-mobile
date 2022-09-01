package openpgp

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

func (o *FastOpenPGP) ConvertPrivateKeyToPublicKey(key string) (string, error) {
	entityList, err := o.readArmoredKeyRing(key, openpgp.PrivateKeyType)
	if err != nil {
		return "", fmt.Errorf("privateKey error: %w", err)
	}
	if len(entityList) < 1 {
		return "", fmt.Errorf("privateKey error: %w", errors.New("no key found"))
	}

	entity := entityList[0]

	publicKeyBuf := bytes.NewBuffer(nil)
	writerPublic, err := armor.Encode(publicKeyBuf, openpgp.PublicKeyType, headers)
	if err != nil {
		return "", err
	}
	defer writerPublic.Close()

	err = entity.Serialize(writerPublic)
	if err != nil {
		return "", err
	}
	// this is required to allow close block before String
	writerPublic.Close()

	return publicKeyBuf.String(), nil
}
