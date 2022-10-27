package openpgp

type KeyPair struct {
	PublicKey  string
	PrivateKey string
}

type Options struct {
	KeyOptions *KeyOptions
	Name       string
	Comment    string
	Email      string
	Passphrase string
}

type FileHints struct {
	IsBinary bool
	FileName string
	ModTime  string
}

type Entity struct {
	PublicKey  string
	PrivateKey string
	Passphrase string
}

type Identity struct {
	ID      string
	Name    string
	Comment string
	Email   string
}

type PublicKeyMetadata struct {
	Algorithm    string
	KeyID        string
	KeyIDShort   string
	CreationTime string
	Fingerprint  string
	KeyIDNumeric string
	IsSubKey     bool
	CanSign      bool
	CanEncrypt   bool
	Identities   []Identity
}

type PrivateKeyMetadata struct {
	KeyID        string
	KeyIDShort   string
	CreationTime string
	Fingerprint  string
	KeyIDNumeric string
	IsSubKey     bool
	Encrypted    bool
	CanSign      bool
	Identities   []Identity
}
