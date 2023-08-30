package openpgp

import (
	"bytes"
	"io/ioutil"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

func (o *FastOpenPGP) ArmorEncode(packet []byte, messageType string) (string, error) {
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

func (o *FastOpenPGP) ArmorDecode(message string) (*ArmorMetadata, error) {
	block, err := armor.Decode(strings.NewReader(message))
	if err != nil {
		return nil, err
	}

	output, err := ioutil.ReadAll(block.Body)
	if err != nil {
		return nil, err
	}

	return &ArmorMetadata{Body: output, Type: block.Type}, nil
}
