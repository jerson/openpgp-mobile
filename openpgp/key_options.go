package openpgp

import "strconv"

type KeyOptions struct {
	Algorithm        string
	Curve            string
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
