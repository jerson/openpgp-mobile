package openpgp

import (
	"bytes"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

type KeyPair struct {
	PublicKey  string
	PrivateKey string
}

type Options struct {
	KeyOptions *KeyOptions
	Name       string
	Comment    string
	Email      string
	Passphrase string
}

func (o *OpenPGP) Generate(options *Options) (*KeyPair, error) {

	var keyPair *KeyPair
	config := generatePacketConfig(options.KeyOptions)
	entity, err := openpgp.NewEntity(options.Name, options.Comment, options.Email, config)
	if err != nil {
		return keyPair, err
	}

	for _, id := range entity.Identities {
		err := id.SelfSignature.SignUserId(id.UserId.Id, entity.PrimaryKey, entity.PrivateKey, nil)
		if err != nil {
			return keyPair, err
		}
	}

	keyPair = &KeyPair{}

	privateKeyBuf := bytes.NewBuffer(nil)
	writerPrivate, err := armor.Encode(privateKeyBuf, openpgp.PrivateKeyType, headers)
	if err != nil {
		return keyPair, err
	}
	defer writerPrivate.Close()

	err = entity.SerializePrivate(writerPrivate, nil)
	if err != nil {
		return keyPair, err
	}
	keyPair.PrivateKey = privateKeyBuf.String()

	publicKeyBuf := bytes.NewBuffer(nil)
	writerPublic, err := armor.Encode(publicKeyBuf, openpgp.PublicKeyType, headers)
	if err != nil {
		return keyPair, err
	}
	defer writerPublic.Close()

	err = entity.Serialize(writerPublic)
	if err != nil {
		return keyPair, err
	}
	keyPair.PublicKey = publicKeyBuf.String()

	return keyPair, nil
}
