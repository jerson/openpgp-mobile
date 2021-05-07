package openpgp

import (
	"crypto"
	"errors"
	"fmt"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"strings"
	"time"
)

var headers = map[string]string{
	"Version": "fast-openpgp",
}
var messageHeader = "PGP MESSAGE"
var signatureHeader = "PGP SIGNATURE"

func generateFileHints(options *FileHints) *openpgp.FileHints {

	if options == nil {
		return &openpgp.FileHints{}
	}
	// by now we skip error, maybe later should be needed return
	var modTime time.Time
	if options.ModTime != "" {
		modTime, _ = time.Parse(time.RFC3339, options.ModTime)
	}

	return &openpgp.FileHints{
		IsBinary: options.IsBinary,
		FileName: options.FileName,
		ModTime:  modTime,
	}
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
		fallthrough
	default:
		return packet.CipherAES128
	}
}

func compressionToAlgo(algo string) packet.CompressionAlgo {
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

func hashTo(hash string) crypto.Hash {
	switch hash {
	case "sha224":
		return crypto.SHA224
	case "sha384":
		return crypto.SHA384
	case "sha512":
		return crypto.SHA512
	case "ripemd160":
		return crypto.RIPEMD160
	case "md5":
		return crypto.MD5
	case "sha1":
		return crypto.SHA1
	case "sha256":
		fallthrough
	default:
		return crypto.SHA256
	}
}

func (o *FastOpenPGP) readSignKeys(publicKey, privateKey, passphrase string) (openpgp.EntityList, error) {

	entityListPublic, err := o.readPublicKeys(publicKey)
	if err != nil {
		return nil, err
	}

	entityListPrivate, err := o.readPrivateKeys(privateKey, passphrase)
	if err != nil {
		return nil, err
	}

	for i := 0; i < len(entityListPublic); i++ {
		entityListPublic[i].PrivateKey = entityListPrivate[i].PrivateKey
	}

	return entityListPublic, nil
}

func (o *FastOpenPGP) readPrivateKeys(key, passphrase string) (openpgp.EntityList, error) {

	var entityList openpgp.EntityList

	entityList, err := o.readArmoredKeyRing(key)
	if err != nil {
		return entityList, err
	}

	for _, entity := range entityList {
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
	}

	return entityList, nil
}

// ReadPrivateKeys will only be used to check if something is wrong with the key
func (o *FastOpenPGP) ReadPrivateKeys(key, passphrase string) error {
	_, err := o.readPrivateKeys(key, passphrase)
	return err
}

func (o *FastOpenPGP) readPublicKeys(key string) (openpgp.EntityList, error) {

	entityList, err := o.readArmoredKeyRing(key)
	if err != nil {
		return entityList, err
	}

	return entityList, nil
}

func (o *FastOpenPGP) readArmoredKeyRing(keys string) (openpgp.EntityList, error) {

	flag := "-----BEGIN"
	keysSplit := strings.Split(keys, flag)
	var entityList openpgp.EntityList

	if len(keysSplit) < 1 {
		return openpgp.ReadArmoredKeyRing(strings.NewReader(keys))
	} else {
		for _, keyPart := range keysSplit {
			keyPart = strings.TrimSpace(keyPart)
			if keyPart == "" {
				continue
			}
			key := fmt.Sprintf("%s %s", flag, keyPart)

			entityListItem, err := openpgp.ReadArmoredKeyRing(strings.NewReader(key))
			if err != nil {
				return entityList, err
			}
			if len(entityListItem) > 0 {
				entityList = append(entityList, entityListItem...)
			}
		}
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
