package openpgp

import (
	"fmt"
	"strings"
	"time"
)

type PublicKeyMetadata struct {
	KeyID        string
	KeyIDShort   string
	CreationTime string
	Fingerprint  string
	KeyIDNumeric string
	IsSubKey     bool
}

func (o *FastOpenPGP) GetPublicKeyMetadata(key string) (*PublicKeyMetadata, error) {
	entityList, err := o.readArmoredKeyRing(key)
	if err != nil {
		return nil, err
	}

	publicKey := entityList[0].PrimaryKey
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
