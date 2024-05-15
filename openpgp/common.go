package openpgp

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	errorsOpenpgp "github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	_ "golang.org/x/crypto/ripemd160"
)

var headers = map[string]string{
	"Version": "openpgp-mobile",
}
var messageType = "PGP MESSAGE"

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
		Curve:                  curveToCurve(options.Curve),
		Algorithm:              algorithmToFunction(options.Algorithm),
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

func curveToCurve(curve string) packet.Curve {
	switch curve {
	case "curve448":
		return packet.Curve448
	case "p256":
		return packet.CurveNistP256
	case "p384":
		return packet.CurveNistP384
	case "p521":
		return packet.CurveNistP521
	case "secp256k1":
		return packet.CurveSecP256k1
	case "brainpoolp256":
		return packet.CurveBrainpoolP256
	case "brainpoolp384":
		return packet.CurveBrainpoolP384
	case "brainpoolp512":
		return packet.CurveBrainpoolP512
	case "curve25519":
		fallthrough
	default:
		return packet.Curve25519
	}
}

func algorithmToFunction(algorithm string) packet.PublicKeyAlgorithm {
	switch algorithm {
	case "ecdsa":
		return packet.PubKeyAlgoECDSA
	case "eddsa":
		return packet.PubKeyAlgoEdDSA
	case "echd":
		return packet.PubKeyAlgoECDH
	case "dsa":
		return packet.PubKeyAlgoDSA
	case "elgamal":
		return packet.PubKeyAlgoElGamal
	case "rsa":
		fallthrough
	default:
		return packet.PubKeyAlgoRSA
	}
}

func functionToAlgorithm(algorithm packet.PublicKeyAlgorithm) string {
	switch algorithm {
	case packet.PubKeyAlgoECDSA:
		return "ecdsa"
	case packet.PubKeyAlgoEdDSA:
		return "eddsa"
	case packet.PubKeyAlgoECDH:
		return "echd"
	case packet.PubKeyAlgoDSA:
		return "dsa"
	case packet.PubKeyAlgoElGamal:
		return "elgamal"
	case packet.PubKeyAlgoRSA:
		return "rsa"
	default:
		return ""
	}
}

func cipherToFunction(cipher string) packet.CipherFunction {
	switch cipher {
	case "3des":
		return packet.Cipher3DES
	case "cast5":
		return packet.CipherCAST5
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

func (o *FastOpenPGP) readPrivateKeys(key, passphrase string) (openpgp.EntityList, error) {

	var entityList openpgp.EntityList

	entityList, err := o.readArmoredKeyRing(key, openpgp.PrivateKeyType)
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

	entityList, err := o.readArmoredKeyRing(key, openpgp.PublicKeyType)
	if err != nil {
		return entityList, err
	}

	return entityList, nil
}

func (o *FastOpenPGP) readArmoredKeyRing(keys, blockType string) (openpgp.EntityList, error) {
	// we can use later blockType to make use that we are using right block type

	flag := "-----BEGIN"
	keysSplit := strings.Split(keys, flag)
	var entityList openpgp.EntityList

	if len(keysSplit) < 1 {
		keysReader := strings.NewReader(keys)
		ring, err := openpgp.ReadArmoredKeyRing(keysReader)
		// if no armored data is found we will try to read only
		if err == errorsOpenpgp.InvalidArgumentError("no armored data found") {
			return openpgp.ReadKeyRing(keysReader)
		}
		return ring, err
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

func (o *FastOpenPGP) readBlockWithReader(message io.Reader, blockType string) (io.Reader, error) {
	block, err := armor.Decode(message)
	if err != nil {
		return nil, err
	}
	if block.Type != blockType {
		return nil, fmt.Errorf("invalid block type, expected: %s received: %s", blockType, block.Type)
	}

	return block.Body, nil
}

func (o *FastOpenPGP) readBlock(message, blockType string) (io.Reader, error) {
	block, err := armor.Decode(strings.NewReader(message))
	if errors.Is(err, io.EOF) {
		decoded, err := base64.StdEncoding.DecodeString(message)
		if err != nil {
			return nil, err
		}
		// if we don't have a block type, we can't validate the type
		return bytes.NewReader(decoded), err
	}
	if err != nil {
		return nil, err
	}
	if block.Type != blockType {
		return nil, fmt.Errorf("invalid block type, expected: %s received: %s", blockType, block.Type)
	}

	return block.Body, err
}

func (o *FastOpenPGP) readSignature(signature string) (*packet.Signature, error) {

	body, err := o.readBlock(signature, openpgp.SignatureType)
	if err != nil {
		return nil, err
	}

	reader := packet.NewReader(body)
	pkt, err := reader.Next()
	if err != nil {
		return nil, err
	}

	sig, ok := pkt.(*packet.Signature)
	if !ok {
		return nil, errors.New("invalid signature")
	}

	return sig, nil
}
