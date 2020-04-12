package openpgp

import "errors"

func (o *FastOpenPGP) Verify(signature, message, publicKey string) (bool, error) {
	return o.VerifyBytes(signature, []byte(message), publicKey)
}
func (o *FastOpenPGP) VerifyBytes(signature string, message []byte, publicKey string) (bool, error) {
	entityList, err := o.readPublicKeys(publicKey)
	if err != nil {
		return false, err
	}
	if len(entityList) < 1 {
		return false, errors.New("no key found")
	}

	sig, err := o.readSignature(signature)
	if err != nil {
		return false, err
	}

	hash := sig.Hash.New()
	hash.Write(message)

	publicKeyItem := entityList[0].PrimaryKey
	if publicKeyItem == nil {
		return false, errors.New("no publicKey found")
	}
	err = publicKeyItem.VerifySignature(hash, sig)
	if err != nil {
		return false, err
	}

	return true, nil
}
