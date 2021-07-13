package openpgp

import (
	"bytes"
	"fmt"
	"github.com/keybase/go-crypto/openpgp/packet"
	"golang.org/x/crypto/openpgp/armor"

	keybaseOpenPGP "github.com/keybase/go-crypto/openpgp"
	"golang.org/x/crypto/openpgp"
)

func (o *FastOpenPGP) Generate(options *Options) (*KeyPair, error) {

	var keyPair *KeyPair
	config := generatePacketConfigKeybase(options.KeyOptions)
	entity, err := keybaseOpenPGP.NewEntity(options.Name, options.Comment, options.Email, config)
	if err != nil {
		return keyPair, fmt.Errorf("newEntity error: %w", err)
	}

	for _, id := range entity.Identities {
		err := id.SelfSignature.SignUserId(id.UserId.Id, entity.PrimaryKey, entity.PrivateKey, nil)
		if err != nil {
			return keyPair, fmt.Errorf("signUserId error: %w", err)
		}
	}

	if options.Passphrase != "" {
		err = entity.PrivateKey.Encrypt([]byte(options.Passphrase), nil)
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

	err = entity.SerializePrivate(writerPrivate, nil)
	if err != nil {
		return keyPair, err
	}
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
	writerPublic.Close()
	keyPair.PublicKey = publicKeyBuf.String()

	return keyPair, nil
}

func generatePacketConfigKeybase(options *KeyOptions) *packet.Config {

	if options == nil {
		return &packet.Config{}
	}

	config := &packet.Config{
		DefaultHash:            hashTo(options.Hash),
		DefaultCipher:          cipherToFunctionKeybase(options.Cipher),
		DefaultCompressionAlgo: compressionToAlgoKeybase(options.Compression),
		CompressionConfig: &packet.CompressionConfig{
			Level: options.CompressionLevel,
		},
		RSABits: options.RSABits,
	}
	return config
}

func cipherToFunctionKeybase(cipher string) packet.CipherFunction {
	switch cipher {
	case "aes256":
		return packet.CipherAES256
	case "aes192":
		return packet.CipherAES192
	case "aes128":
		fallthrough
	default:
		return packet.CipherAES128
	}
}

func compressionToAlgoKeybase(algo string) packet.CompressionAlgo {
	switch algo {
	case "zlib":
		return packet.CompressionZLIB
	case "zip":
		return packet.CompressionZIP
	case "none":
		fallthrough
	default:
		return packet.CompressionNone
	}
}
