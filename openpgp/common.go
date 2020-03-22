package openpgp

import (
	"crypto"
	"errors"
	"strconv"
	"strings"

	"github.com/keybase/go-crypto/openpgp"
	"github.com/keybase/go-crypto/openpgp/armor"
	"github.com/keybase/go-crypto/openpgp/packet"
)

var headers = map[string]string{
	"Version": "fast-openpgp",
}
var messageHeader = "PGP MESSAGE"

type KeyOptions struct {
	Hash             string
	Cipher           string
	Compression      string
	CompressionLevel int
	RSABits          int
}

func (k *KeyOptions) SetCompressionLevelFromString(value string) {
	k.CompressionLevel, _ = strconv.Atoi(value)
}

func (k *KeyOptions) SetRSABitsFromString(value string) {
	k.RSABits, _ = strconv.Atoi(value)
}

func generatePacketConfig(options *KeyOptions) *packet.Config {

	if options == nil {
		return &packet.Config{}
	}

	config := &packet.Config{
		DefaultHash:            hashTo(options.Hash),
		DefaultCipher:          cipherToFunction(options.Cipher),
		DefaultCompressionAlgo: compressionToAlgo(options.Compression),
		CompressionConfig: &packet.CompressionConfig{
			Level: options.CompressionLevel,
		},
		RSABits: options.RSABits,
	}
	return config
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
		return packet.CipherAES128
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
		return packet.CompressionNone
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
		return crypto.SHA256
	}
}

func (o *FastOpenPGP) readSignKey(publicKey, privateKey, passphrase string) (*openpgp.Entity, error) {

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

func (o *FastOpenPGP) readPrivateKey(key, passphrase string) (openpgp.EntityList, error) {

	var entity *openpgp.Entity
	var entityList openpgp.EntityList

	entityList, err := openpgp.ReadArmoredKeyRing(strings.NewReader(key))
	if err != nil {
		return entityList, err
	}
	entity = entityList[0]

	if entity.PrivateKey.Encrypted {
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

func (o *FastOpenPGP) readPublicKey(key string) (openpgp.EntityList, error) {

	entityList, err := openpgp.ReadArmoredKeyRing(strings.NewReader(key))
	if err != nil {
		return entityList, err
	}

	return entityList, nil
}
func (o *FastOpenPGP) readSignature(message string) (*packet.Signature, error) {

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
