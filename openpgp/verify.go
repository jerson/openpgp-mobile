package openpgp

func (o *FastOpenPGP) Verify(signature, message, publicKey string) (bool, error) {
	entityList, err := o.readPublicKeys(publicKey)
	if err != nil {
		return false, err
	}

	sig, err := o.readSignature(signature)
	if err != nil {
		return false, err
	}

	hash := sig.Hash.New()
	hash.Write([]byte(message))

	err = entityList[0].PrimaryKey.VerifySignature(hash, sig)
	if err != nil {
		return false, err
	}

	return true, nil
}
