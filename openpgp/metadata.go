package openpgp

import (
	"errors"
	"fmt"
	"strings"
	"time"
)


func (o *FastOpenPGP) GetPublicKeyMetadata(key string) (*PublicKeyMetadata, error) {
	entityList, err := o.readArmoredKeyRing(key)
	if err != nil {
		return nil, err
	}
	if len(entityList) < 1 {
		return nil, errors.New("no key found")
	}

	publicKey := entityList[0].PrimaryKey
	if publicKey == nil {
		return nil, errors.New("no publicKey found")
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
	entityList, err := o.readArmoredKeyRing(key)
	if err != nil {
		return nil, err
	}
	if len(entityList) < 1 {
		return nil, errors.New("no key found")
	}

	privateKey := entityList[0].PrivateKey
	if privateKey == nil {
		return nil, errors.New("no privateKey found")
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
