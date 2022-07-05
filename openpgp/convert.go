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
		return "", fmt.Errorf("publicKey error: %w", err)
	}
	if len(entityList) < 1 {
		return "", fmt.Errorf("publicKey error: %w", errors.New("no key found"))
	}

	publicKey := entityList[0].PrimaryKey
	if publicKey == nil {
		return "", fmt.Errorf("publicKey error: %w", errors.New("no publicKey found"))
	}

	publicKeyBuf := bytes.NewBuffer(nil)
	writerPublic, err := armor.Encode(publicKeyBuf, openpgp.PublicKeyType, headers)
	if err != nil {
		return "", err
	}
	defer writerPublic.Close()

	err = publicKey.Serialize(writerPublic)
	if err != nil {
		return "", err
	}

	return publicKeyBuf.String(), nil
}
