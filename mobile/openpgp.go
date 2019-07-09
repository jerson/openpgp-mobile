package openpgp

import (
	"fmt"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"io/ioutil"
	"log"
	"strings"
)

type OpenPGP struct {
}

func NewOpenPGP() *OpenPGP {
	return &OpenPGP{}
}

func (o *OpenPGP) Decode(message, privateKey, passphrase string) string {

	var entity *openpgp.Entity
	var entityList openpgp.EntityList

	keyringFileBuffer := strings.NewReader(privateKey)
	entityList, err := openpgp.ReadArmoredKeyRing(keyringFileBuffer)
	if err != nil {
		return "error reading ring"
	}
	entity = entityList[0]

	passphraseByte := []byte(passphrase)
	log.Println("Decrypting private key using passphrase")
	_ = entity.PrivateKey.Decrypt(passphraseByte)
	for _, subKey := range entity.Subkeys {
		_ = subKey.PrivateKey.Decrypt(passphraseByte)
	}
	log.Println("Finished decrypting private key using passphrase")

	dec, err  := armor.Decode(strings.NewReader(message))
	if err != nil {
		return "decode message"
	}

	md, err := openpgp.ReadMessage(dec.Body, entityList, nil, nil)
	if err != nil {
		return "error read message"
	}
	output, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "error io read"
	}
	decStr := string(output)

	return decStr
}

func (o *OpenPGP) Sample(message string) string {

	return fmt.Sprintf("%s-end",message)
}
