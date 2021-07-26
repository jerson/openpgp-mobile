package openpgp

import (
	"errors"
	"fmt"
	"golang.org/x/crypto/openpgp"
	"strings"
	"time"
)

func (o *FastOpenPGP) GetPublicKeyMetadata(key string) (*PublicKeyMetadata, error) {
	entityList, err := o.readArmoredKeyRing(key, openpgp.PublicKeyType)
	if err != nil {
		return nil, fmt.Errorf("publicKey error: %w", err)
	}
	if len(entityList) < 1 {
		return nil, fmt.Errorf("publicKey error: %w", errors.New("no key found"))
	}

	publicKey := entityList[0].PrimaryKey
	if publicKey == nil {
		return nil, fmt.Errorf("publicKey error: %w", errors.New("no publicKey found"))
	}

	var byteIDs []string
	for _, byteID := range publicKey.Fingerprint {
		byteIDs = append(byteIDs, fmt.Sprint(byteID))
	}

	return &PublicKeyMetadata{
		KeyID:        publicKey.KeyIdString(),
		KeyIDShort:   publicKey.KeyIdShortString(),
		KeyIDNumeric: fmt.Sprintf("%d", publicKey.KeyId),
		CreationTime: publicKey.CreationTime.Format(time.RFC3339),
		Fingerprint:  strings.Join(byteIDs, ":"),
		IsSubKey:     publicKey.IsSubkey,
	}, nil
}

func (o *FastOpenPGP) GetPrivateKeyMetadata(key string) (*PrivateKeyMetadata, error) {
	entityList, err := o.readArmoredKeyRing(key, openpgp.PrivateKeyType)
	if err != nil {
		return nil, fmt.Errorf("privateKey error: %w", err)
	}
	if len(entityList) < 1 {
		return nil, fmt.Errorf("privateKey error: %w", errors.New("no key found"))
	}

	privateKey := entityList[0].PrivateKey
	if privateKey == nil {
		return nil, fmt.Errorf("privateKey error: %w", errors.New("no privateKey found"))
	}

	var byteIDs []string
	for _, byteID := range privateKey.Fingerprint {
		byteIDs = append(byteIDs, fmt.Sprint(byteID))
	}

	return &PrivateKeyMetadata{
		KeyID:        privateKey.KeyIdString(),
		KeyIDShort:   privateKey.KeyIdShortString(),
		KeyIDNumeric: fmt.Sprintf("%d", privateKey.KeyId),
		CreationTime: privateKey.CreationTime.Format(time.RFC3339),
		Fingerprint:  strings.Join(byteIDs, ":"),
		IsSubKey:     privateKey.IsSubkey,
		Encrypted:    privateKey.Encrypted,
	}, nil
}
