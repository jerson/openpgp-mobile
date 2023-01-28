package openpgp

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
)

func getIdentities(input map[string]*openpgp.Identity) []Identity {

	var identities []Identity
	for _, identity := range input {
		if identity == nil || identity.UserId == nil {
			continue
		}
		identities = append(identities, Identity{
			ID:      identity.UserId.Id,
			Comment: identity.UserId.Comment,
			Email:   identity.UserId.Email,
			Name:    identity.UserId.Name,
		})
	}
	return identities
}

func (o *FastOpenPGP) GetPublicKeyMetadata(key string) (*PublicKeyMetadata, error) {
	entityList, err := o.readArmoredKeyRing(key, openpgp.PublicKeyType)
	if err != nil {
		return nil, fmt.Errorf("publicKey error: %w", err)
	}
	if len(entityList) < 1 {
		return nil, fmt.Errorf("publicKey error: %w", errors.New("no key found"))
	}
	entity := entityList[0]
	publicKey := entity.PrimaryKey
	if publicKey == nil {
		return nil, fmt.Errorf("publicKey error: %w", errors.New("no publicKey found"))
	}

	return &PublicKeyMetadata{
		CanSign:      publicKey.PubKeyAlgo.CanSign(),
		CanEncrypt:   publicKey.PubKeyAlgo.CanEncrypt(),
		Algorithm:    functionToAlgorithm(publicKey.PubKeyAlgo),
		KeyID:        publicKey.KeyIdString(),
		KeyIDShort:   publicKey.KeyIdShortString(),
		KeyIDNumeric: fmt.Sprintf("%d", publicKey.KeyId),
		CreationTime: publicKey.CreationTime.Format(time.RFC3339),
		Fingerprint:  o.fingerprint(publicKey.Fingerprint),
		IsSubKey:     publicKey.IsSubkey,
		Identities:   getIdentities(entity.Identities),
		SubKeys:      o.getPublicSubKeys(entity.Subkeys),
	}, nil
}

func (o *FastOpenPGP) getPublicSubKeys(keys []openpgp.Subkey) []PublicKeyMetadata {
	var subKeys []PublicKeyMetadata
	for _, subKey := range keys {
		publicKey := subKey.PublicKey
		if publicKey == nil {
			continue
		}
		subKeys = append(subKeys, PublicKeyMetadata{
			CanSign:      publicKey.PubKeyAlgo.CanSign(),
			CanEncrypt:   publicKey.PubKeyAlgo.CanEncrypt(),
			Algorithm:    functionToAlgorithm(publicKey.PubKeyAlgo),
			KeyID:        publicKey.KeyIdString(),
			KeyIDShort:   publicKey.KeyIdShortString(),
			KeyIDNumeric: fmt.Sprintf("%d", publicKey.KeyId),
			CreationTime: publicKey.CreationTime.Format(time.RFC3339),
			Fingerprint:  o.fingerprint(publicKey.Fingerprint),
			IsSubKey:     publicKey.IsSubkey,
		})
	}
	return subKeys
}

func (o *FastOpenPGP) GetPrivateKeyMetadata(key string) (*PrivateKeyMetadata, error) {
	entityList, err := o.readArmoredKeyRing(key, openpgp.PrivateKeyType)
	if err != nil {
		return nil, fmt.Errorf("privateKey error: %w", err)
	}
	if len(entityList) < 1 {
		return nil, fmt.Errorf("privateKey error: %w", errors.New("no key found"))
	}
	entity := entityList[0]
	privateKey := entity.PrivateKey
	if privateKey == nil {
		return nil, fmt.Errorf("privateKey error: %w", errors.New("no privateKey found"))
	}

	return &PrivateKeyMetadata{
		CanSign:      privateKey.CanSign(),
		KeyID:        privateKey.KeyIdString(),
		KeyIDShort:   privateKey.KeyIdShortString(),
		KeyIDNumeric: fmt.Sprintf("%d", privateKey.KeyId),
		CreationTime: privateKey.CreationTime.Format(time.RFC3339),
		Fingerprint:  o.fingerprint(privateKey.Fingerprint),
		IsSubKey:     privateKey.IsSubkey,
		Encrypted:    privateKey.Encrypted,
		Identities:   getIdentities(entity.Identities),
		SubKeys:      o.getPrivateSubKeys(entity.Subkeys),
	}, nil
}

func (o *FastOpenPGP) getPrivateSubKeys(keys []openpgp.Subkey) []PrivateKeyMetadata {
	var subKeys []PrivateKeyMetadata
	for _, subKey := range keys {
		privateKey := subKey.PrivateKey
		if privateKey == nil {
			continue
		}
		subKeys = append(subKeys, PrivateKeyMetadata{
			CanSign:      privateKey.CanSign(),
			KeyID:        privateKey.KeyIdString(),
			KeyIDShort:   privateKey.KeyIdShortString(),
			KeyIDNumeric: fmt.Sprintf("%d", privateKey.KeyId),
			CreationTime: privateKey.CreationTime.Format(time.RFC3339),
			Fingerprint:  o.fingerprint(privateKey.Fingerprint),
			IsSubKey:     privateKey.IsSubkey,
			Encrypted:    privateKey.Encrypted,
		})
	}
	return subKeys
}

func (o *FastOpenPGP) fingerprint(input []byte) string {
	var byteIDs []string
	for _, byteID := range input {
		byteIDs = append(byteIDs, fmt.Sprint(byteID))
	}
	return strings.Join(byteIDs, ":")
}
