package openpgp

import (
	"bytes"
	"errors"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"io/ioutil"
	"strings"
)

type OpenPGP struct {
}

func NewOpenPGP() *OpenPGP {
	return &OpenPGP{}
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

func (o *OpenPGP) Decrypt(message, privateKey, passphrase string) (string, error) {

	entityList, err := o.readPrivateKey(privateKey, passphrase)
	if err != nil {
		return "", err
	}

	dec, err := armor.Decode(strings.NewReader(message))
	if err != nil {
		return "", err
	}

	md, err := openpgp.ReadMessage(dec.Body, entityList, nil, nil)
	if err != nil {
		return "", err
	}
	output, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", err
	}
	outputString := string(output)

	return outputString, nil
}

func (o *OpenPGP) Encrypt(message, publicKey string) (string, error) {

	entityList, err := o.readPublicKey(publicKey)
	if err != nil {
		return "", err
	}

	buf := new(bytes.Buffer)
	w, err := openpgp.Encrypt(buf, entityList, nil, nil, nil)
	if err != nil {
		return "", err
	}
	_, err = w.Write([]byte(message))
	if err != nil {
		return "", err
	}
	err = w.Close()
	if err != nil {
		return "", err
	}

	output, err := ioutil.ReadAll(buf)
	if err != nil {
		return "", err
	}

	pubKeyBuf := bytes.NewBuffer(nil)
	pubKeyWriter, err := armor.Encode(pubKeyBuf, "PGP MESSAGE", map[string]string{
		"Provider": "react-native-fast-openpgp",
		"Version":  "0.1",
	})
	if err != nil {
		return "", err
	}
	_, err = pubKeyWriter.Write(output)
	if err != nil {
		return "", err
	}
	err = pubKeyWriter.Close()
	if err != nil {
		return "", err
	}

	outputString := pubKeyBuf.String()

	return outputString, nil
}

func (o *OpenPGP) Sign(message, publicKey, privateKey, passphrase string) (string, error) {

	entity, err := o.readSignKey(publicKey, privateKey, passphrase)
	if err != nil {
		return "", err
	}

	writer := new(bytes.Buffer)
	reader := bytes.NewReader([]byte(message))
	err = openpgp.ArmoredDetachSign(writer, entity, reader, nil)
	if err != nil {
		return "", err
	}

	return writer.String(), nil
}

func (o *OpenPGP) Verify(signature, message, publicKey string) (bool, error) {
	entityList, err := o.readPublicKey(publicKey)
	if err != nil {
		return false, err
	}

	sig, err := o.readSignature(signature)
	if err != nil {
		return false, err
	}

	hash := sig.Hash.New()
	hash.Write([]byte(message))

	entity := entityList[0]
	err = entity.PrimaryKey.VerifySignature(hash, sig)
	if err != nil {
		return false, err
	}

	return true, nil
}
