package openpgp

import (
	"crypto"
	"errors"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"strings"
)

var headers = map[string]string{
	"Provider": "react-native-fast-openpgp",
}
var messageHeader = "PGP MESSAGE"

type KeyOptions struct {
	Hash             string
	Cipher           string
	Compression      string
	CompressionLevel int
	RSABits          int
}

func generatePacketConfig(options *KeyOptions) packet.Config {

	if options == nil {
		return packet.Config{}
	}

	return packet.Config{
		DefaultHash:            hashTo(options.Hash),
		DefaultCipher:          cipherToFunction(options.Cipher),
		DefaultCompressionAlgo: compressionToAlgo(options.Compression),
		CompressionConfig: &packet.CompressionConfig{
			Level: options.CompressionLevel,
		},
		RSABits: options.RSABits,
	}
}

func cipherToFunction(cipher string) packet.CipherFunction {
	switch cipher {
	case "aes256":
		return packet.CipherAES256
	case "aes192":
		return packet.CipherAES192
	case "aes128":
		return packet.CipherAES128
	default:
		return packet.CipherAES256
	}
}

func compressionToAlgo(algo string) packet.CompressionAlgo {
	switch algo {
	case "zlib":
		return packet.CompressionZLIB
	case "none":
		return packet.CompressionNone
	case "zip":
		return packet.CompressionZIP
	default:
		return packet.CompressionZLIB
	}
}

func hashTo(hash string) crypto.Hash {
	switch hash {
	case "sha256":
		return crypto.SHA256
	case "sha224":
		return crypto.SHA224
	case "sha384":
		return crypto.SHA384
	case "sha512":
		return crypto.SHA512
	default:
		return crypto.SHA512
	}
}

func (o *OpenPGP) readSignKey(publicKey, privateKey, passphrase string) (*openpgp.Entity, error) {

	entityListPublic, err := o.readPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	entityListPrivate, err := o.readPrivateKey(privateKey, passphrase)
	if err != nil {
		return nil, err
	}
	entityListPublic[0].PrivateKey = entityListPrivate[0].PrivateKey
	return entityListPublic[0], nil
}

func (o *OpenPGP) readPrivateKey(key, passphrase string) (openpgp.EntityList, error) {

	var entity *openpgp.Entity
	var entityList openpgp.EntityList

	entityList, err := openpgp.ReadArmoredKeyRing(strings.NewReader(key))
	if err != nil {
		return entityList, err
	}
	entity = entityList[0]

	if passphrase != "" {
		passphraseByte := []byte(passphrase)
		err = entity.PrivateKey.Decrypt(passphraseByte)
		if err != nil {
			return entityList, err
		}
		for _, subKey := range entity.Subkeys {
			err = subKey.PrivateKey.Decrypt(passphraseByte)
			if err != nil {
				return entityList, err
			}
		}
	}

	return entityList, nil
}

func (o *OpenPGP) readPublicKey(key string) (openpgp.EntityList, error) {

	entityList, err := openpgp.ReadArmoredKeyRing(strings.NewReader(key))
	if err != nil {
		return entityList, err
	}

	return entityList, nil
}
func (o *OpenPGP) readSignature(message string) (*packet.Signature, error) {

	block, err := armor.Decode(strings.NewReader(message))
	if err != nil {
		return nil, err
	}

	if block.Type != openpgp.SignatureType {
		return nil, errors.New("Invalid signature file")
	}

	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()
	if err != nil {
		return nil, err
	}

	sig, ok := pkt.(*packet.Signature)
	if !ok {
		return nil, errors.New("Invalid signature")
	}

	return sig, nil
}
