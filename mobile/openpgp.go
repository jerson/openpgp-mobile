package openpgp

import "github.com/jerson/openpgp-mobile/mobile/modules"

type OpenPGP struct {
	Key *modules.OpenPGPKey
}

func NewOpenPGP() *OpenPGP {
	return &OpenPGP{
		Key: modules.NewOpenPGPKey(),
	}
}
