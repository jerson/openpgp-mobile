package openpgp

import (
	_ "golang.org/x/crypto/ripemd160"
)

type FastOpenPGP struct {
}

func NewFastOpenPGP() *FastOpenPGP {
	return &FastOpenPGP{}
}
