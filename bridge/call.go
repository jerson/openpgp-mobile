package openpgp_bridge

import (
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/jerson/openpgp-mobile/bridge/model"
	"github.com/jerson/openpgp-mobile/openpgp"
)

// Call ...
func Call(name string, payload []byte) ([]byte, error) {

	instance := NewInstance()
	var output proto.Message
	switch name {
	case "decrypt":
		output = instance.decrypt(payload)
	case "decryptBytes":
		output = instance.decryptBytes(payload)
	case "encrypt":
		output = instance.encrypt(payload)
	case "encryptBytes":
		output = instance.encryptBytes(payload)
	case "sign":
		output = instance.sign(payload)
	case "signBytes":
		output = instance.signBytes(payload)
	case "signBytesToString":
		output = instance.signBytesToString(payload)
	case "verify":
		output = instance.verify(payload)
	case "verifyBytes":
		output = instance.verifyBytes(payload)
	case "decryptSymmetric":
		output = instance.decryptSymmetric(payload)
	case "decryptSymmetricBytes":
		output = instance.decryptSymmetricBytes(payload)
	case "encryptSymmetric":
		output = instance.encryptSymmetric(payload)
	case "encryptSymmetricBytes":
		output = instance.encryptSymmetricBytes(payload)
	case "generate":
		output = instance.generate(payload)
	default:
		return nil, fmt.Errorf("not implemented: %s", name)
	}

	return proto.Marshal(output)
}

type instance struct {
	instance *openpgp.FastOpenPGP
}

func NewInstance() *instance {
	return &instance{instance: openpgp.NewFastOpenPGP()}
}

func (m instance) decrypt(payload []byte) proto.Message {
	response := &model.StringResponse{}
	request := &model.DecryptRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.Decrypt(request.Message, request.PrivateKey, request.Passphrase)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}

func (m instance) decryptBytes(payload []byte) proto.Message {
	response := &model.BytesResponse{}
	request := &model.DecryptBytesRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.DecryptBytes(request.Message, request.PrivateKey, request.Passphrase)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}

func (m instance) encrypt(payload []byte) proto.Message {
	response := &model.StringResponse{}
	request := &model.EncryptRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.Encrypt(request.Message, request.PublicKey)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}

func (m instance) encryptBytes(payload []byte) proto.Message {
	response := &model.BytesResponse{}
	request := &model.EncryptBytesRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.EncryptBytes(request.Message, request.PublicKey)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}

func (m instance) sign(payload []byte) proto.Message {
	response := &model.StringResponse{}
	request := &model.SignRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.Sign(request.Message, request.PublicKey, request.PrivateKey, request.Passphrase)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}
func (m instance) signBytes(payload []byte) proto.Message {
	response := &model.BytesResponse{}
	request := &model.SignBytesRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.SignBytes(request.Message, request.PublicKey, request.PrivateKey, request.Passphrase)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}
func (m instance) signBytesToString(payload []byte) proto.Message {
	response := &model.StringResponse{}
	request := &model.SignBytesRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.SignBytesToString(request.Message, request.PublicKey, request.PrivateKey, request.Passphrase)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}
func (m instance) verify(payload []byte) proto.Message {
	response := &model.BoolResponse{}
	request := &model.VerifyRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.Verify(request.Signature, request.Message, request.PublicKey)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}
func (m instance) verifyBytes(payload []byte) proto.Message {
	response := &model.BoolResponse{}
	request := &model.VerifyBytesRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.VerifyBytes(request.Signature, request.Message, request.PublicKey)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}
func (m instance) decryptSymmetric(payload []byte) proto.Message {
	response := &model.StringResponse{}
	request := &model.DecryptSymmetricRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.DecryptSymmetric(request.Message, request.Passphrase, m.parseKeyOptions(request.Options))
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}
func (m instance) decryptSymmetricBytes(payload []byte) proto.Message {
	response := &model.BytesResponse{}
	request := &model.DecryptSymmetricBytesRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.DecryptSymmetricBytes(request.Message, request.Passphrase, m.parseKeyOptions(request.Options))
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}
func (m instance) encryptSymmetric(payload []byte) proto.Message {
	response := &model.StringResponse{}
	request := &model.EncryptSymmetricRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.EncryptSymmetric(request.Message, request.Passphrase, m.parseKeyOptions(request.Options))
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}
func (m instance) encryptSymmetricBytes(payload []byte) proto.Message {
	response := &model.BytesResponse{}
	request := &model.EncryptSymmetricBytesRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.EncryptSymmetricBytes(request.Message, request.Passphrase, m.parseKeyOptions(request.Options))
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}
func (m instance) generate(payload []byte) proto.Message {
	response := &model.KeyPairResponse{}
	request := &model.GenerateRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.Generate(m.parseOptions(request.Options))
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = &model.KeyPair{
		PublicKey:  output.PrivateKey,
		PrivateKey: output.PrivateKey,
	}
	return response
}

func (m instance) parseOptions(input *model.Options) *openpgp.Options {
	if input == nil {
		return &openpgp.Options{
			KeyOptions: m.parseKeyOptions(nil),
		}
	}
	options := &openpgp.Options{
		KeyOptions: m.parseKeyOptions(input.KeyOptions),
		Name:       input.Name,
		Comment:    input.Comment,
		Email:      input.Email,
		Passphrase: input.Passphrase,
	}
	return options
}

func (m instance) parseKeyOptions(input *model.KeyOptions) *openpgp.KeyOptions {
	if input == nil {
		return &openpgp.KeyOptions{}
	}
	options := &openpgp.KeyOptions{
		Hash:             m.parseHash(input.Hash),
		Cipher:           m.parseCipher(input.Cipher),
		Compression:      m.parseCompression(input.Compression),
		CompressionLevel: int(input.CompressionLevel),
		RSABits:          int(input.RsaBits),
	}

	return options
}

func (m instance) parseHash(input model.Hash) string {
	switch input {
	case model.Hash_HASH_SHA224:
		return "sha224"
	case model.Hash_HASH_SHA384:
		return "sha384"
	case model.Hash_HASH_SHA512:
		return "sha512"
	case model.Hash_HASH_SHA256:
		fallthrough
	case model.Hash_HASH_UNSPECIFIED:
		fallthrough
	default:
		return "sha256"
	}
}

func (m instance) parseCipher(input model.Cipher) string {
	switch input {
	case model.Cipher_CIPHER_AES192:
		return "aes192"
	case model.Cipher_CIPHER_AES256:
		return "aes256"
	case model.Cipher_CIPHER_AES128:
		fallthrough
	case model.Cipher_CIPHER_UNSPECIFIED:
		fallthrough
	default:
		return "aes128"
	}
}

func (m instance) parseCompression(input model.Compression) string {
	switch input {
	case model.Compression_COMPRESSION_ZIP:
		return "zip"
	case model.Compression_COMPRESSION_ZLIB:
		return "zlib"
	case model.Compression_COMPRESSION_NONE:
		fallthrough
	case model.Compression_COMPRESSION_UNSPECIFIED:
		fallthrough
	default:
		return "none"
	}
}
