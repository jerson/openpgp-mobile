package openpgp

import (
	"bytes"
	"fmt"
	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"io"
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

	keyPair.PrivateKey, err = o.serializePrivateKey(entity, config)
	if err != nil {
		return nil, err
	}
	keyPair.PublicKey, err = o.serializePublicKey(entity)
	if err != nil {
		return nil, err
	}

	return keyPair, nil
}

func (o *FastOpenPGP) serializePrivateKey(entity *openpgp.Entity, config *packet.Config) (string, error) {
	buf := bytes.NewBuffer(nil)
	w, err := armor.Encode(buf, openpgp.PrivateKeyType, headers)
	if err != nil {
		return "", err
	}
	defer w.Close()

	err = entity.SerializePrivateWithoutSigning(w, config)
	if err != nil {
		return "", err
	}
	// this is required to allow close block before String
	w.Close()
	return buf.String(), nil
}

func (o *FastOpenPGP) serializePublicKey(entity *openpgp.Entity) (string, error) {
	buf := bytes.NewBuffer(nil)
	w, err := armor.Encode(buf, openpgp.PublicKeyType, headers)
	if err != nil {
		return "", err
	}
	defer w.Close()

	err = entity.Serialize(w)
	if err != nil {
		return "", err
	}
	// this is required to allow close block before String
	w.Close()
	return buf.String(), nil
}

type serializable interface {
	Serialize(w io.Writer) (err error)
}

func serialize(entity serializable) string {
	buf := bytes.NewBuffer(nil)
	w, err := armor.Encode(buf, openpgp.PublicKeyType, headers)
	if err != nil {
		return ""
	}
	defer w.Close()

	err = entity.Serialize(w)
	if err != nil {
		return ""
	}
	// this is required to allow close block before String
	w.Close()
	return buf.String()
}
