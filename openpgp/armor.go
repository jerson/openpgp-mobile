package openpgp

import (
	"bytes"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

func (o FastOpenPGP) ArmorEncode(packet []byte) (string, error) {
	buf := bytes.NewBuffer(nil)
	writer, err := armor.Encode(buf, messageType, headers)
	if err != nil {
		return "", err
	}
	_, err = writer.Write(packet)
	if err != nil {
		return "", err
	}
	err = writer.Close()
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}
