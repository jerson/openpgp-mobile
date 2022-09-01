package openpgp

import (
	"bytes"
	"fmt"
	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

func (o *FastOpenPGP) Generate(options *Options) (*KeyPair, error) {
	var keyPair *KeyPair

	if options == nil {
		return keyPair, fmt.Errorf("missing parameters: Options")
	}

	if options.KeyOptions == nil {
		return keyPair, fmt.Errorf("missing parameters: KeyOptions")
	}

	config := generatePacketConfig(options.KeyOptions)
	entity, err := openpgp.NewEntity(options.Name, options.Comment, options.Email, config)
	if err != nil {
		return keyPair, fmt.Errorf("newEntity error: %w", err)
	}

	for _, id := range entity.Identities {
		err := id.SelfSignature.SignUserId(id.UserId.Id, entity.PrimaryKey, entity.PrivateKey, config)
		if err != nil {
			return keyPair, fmt.Errorf("signUserId error: %w", err)
		}
	}

	if options.Passphrase != "" {
		err = entity.PrivateKey.Encrypt([]byte(options.Passphrase))
		if err != nil {
			return keyPair, fmt.Errorf("encrypt privateKey error: %w", err)
		}
	}

	keyPair = &KeyPair{}
	privateKeyBuf := bytes.NewBuffer(nil)
	writerPrivate, err := armor.Encode(privateKeyBuf, openpgp.PrivateKeyType, headers)
	if err != nil {
		return keyPair, err
	}
	defer writerPrivate.Close()

	err = entity.SerializePrivateWithoutSigning(writerPrivate, config)
	if err != nil {
		return keyPair, err
	}
	// this is required to allow close block before String
	writerPrivate.Close()
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
	// this is required to allow close block before String
	writerPublic.Close()
	keyPair.PublicKey = publicKeyBuf.String()

	return keyPair, nil
}
