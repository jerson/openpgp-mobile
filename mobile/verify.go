package openpgp

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
