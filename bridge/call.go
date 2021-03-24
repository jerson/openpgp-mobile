package openPGPBridge

import (
	"fmt"
	flatbuffers "github.com/google/flatbuffers/go"
	"github.com/jerson/openpgp-mobile/bridge/model"
	"github.com/jerson/openpgp-mobile/openpgp"
)

// Call ...
func Call(name string, payload []byte) ([]byte, error) {

	instance := NewInstance()
	var output []byte
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

	return output, nil
}

type instance struct {
	instance *openpgp.FastOpenPGP
}

func NewInstance() *instance {
	return &instance{instance: openpgp.NewFastOpenPGP()}
}

func (m instance) decrypt(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	model.StringResponseStart(response)
	request := model.GetRootAsDecryptRequest(payload, 0)
	if request == nil {
		model.StringResponseAddError(response, response.CreateByteString([]byte("invalid payload")))
		response.Finish(model.StringResponseEnd(response))
		return response.FinishedBytes()
	}

	output, err := m.instance.Decrypt(string(request.Message()), string(request.PrivateKey()), string(request.Passphrase()), m.parseKeyOptions(request.Options(nil)))
	if err != nil {
		model.StringResponseAddError(response, response.CreateByteString([]byte(err.Error())))
		response.Finish(model.StringResponseEnd(response))
		return response.FinishedBytes()
	}
	model.StringResponseAddOutput(response, response.CreateByteString([]byte(output)))
	response.Finish(model.StringResponseEnd(response))
	return response.FinishedBytes()
}

func (m instance) decryptBytes(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	model.BytesResponseStart(response)
	request := model.GetRootAsDecryptBytesRequest(payload, 0)
	if request == nil {
		model.BytesResponseAddError(response, response.CreateByteString([]byte("invalid payload")))
		response.Finish(model.BytesResponseEnd(response))
		return response.FinishedBytes()
	}

	output, err := m.instance.DecryptBytes(request.MessageBytes(), string(request.PrivateKey()), string(request.Passphrase()), m.parseKeyOptions(request.Options(nil)))
	if err != nil {
		model.BytesResponseAddError(response, response.CreateByteString([]byte(err.Error())))
		response.Finish(model.BytesResponseEnd(response))
		return response.FinishedBytes()
	}
	model.BytesResponseAddOutput(response, response.CreateByteVector(output))
	response.Finish(model.BytesResponseEnd(response))
	return response.FinishedBytes()
}

func (m instance) encrypt(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	model.StringResponseStart(response)
	request := model.GetRootAsEncryptRequest(payload, 0)
	if request == nil {
		model.StringResponseAddError(response, response.CreateByteString([]byte("invalid payload")))
		response.Finish(model.StringResponseEnd(response))
		return response.FinishedBytes()
	}

	output, err := m.instance.Encrypt(string(request.Message()), string(request.PublicKey()), m.parseEntity(request.Signed(nil)), m.parseFileHints(request.FileHints(nil)), m.parseKeyOptions(request.Options(nil)))
	if err != nil {
		model.StringResponseAddError(response, response.CreateByteString([]byte(err.Error())))
		response.Finish(model.StringResponseEnd(response))
		return response.FinishedBytes()
	}
	model.StringResponseAddOutput(response, response.CreateByteString([]byte(output)))
	response.Finish(model.StringResponseEnd(response))
	return response.FinishedBytes()
}

func (m instance) encryptBytes(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	model.BytesResponseStart(response)
	request := model.GetRootAsEncryptBytesRequest(payload, 0)
	if request == nil {
		model.BytesResponseAddError(response, response.CreateByteString([]byte("invalid payload")))
		response.Finish(model.BytesResponseEnd(response))
		return response.FinishedBytes()
	}

	output, err := m.instance.EncryptBytes(request.MessageBytes(), string(request.PublicKey()), m.parseEntity(request.Signed(nil)), m.parseFileHints(request.FileHints(nil)), m.parseKeyOptions(request.Options(nil)))
	if err != nil {
		model.BytesResponseAddError(response, response.CreateByteString([]byte(err.Error())))
		response.Finish(model.BytesResponseEnd(response))
		return response.FinishedBytes()
	}
	model.BytesResponseAddOutput(response, response.CreateByteVector(output))
	response.Finish(model.BytesResponseEnd(response))
	return response.FinishedBytes()
}

func (m instance) sign(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	model.StringResponseStart(response)
	request := model.GetRootAsSignRequest(payload, 0)
	if request == nil {
		model.StringResponseAddError(response, response.CreateByteString([]byte("invalid payload")))
		response.Finish(model.StringResponseEnd(response))
		return response.FinishedBytes()
	}

	output, err := m.instance.Sign(string(request.Message()), string(request.PublicKey()), string(request.PrivateKey()), string(request.Passphrase()), m.parseKeyOptions(request.Options(nil)))
	if err != nil {
		model.StringResponseAddError(response, response.CreateByteString([]byte(err.Error())))
		response.Finish(model.StringResponseEnd(response))
		return response.FinishedBytes()
	}
	model.StringResponseAddOutput(response, response.CreateByteString([]byte(output)))
	response.Finish(model.StringResponseEnd(response))
	return response.FinishedBytes()
}
func (m instance) signBytes(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	model.BytesResponseStart(response)
	request := model.GetRootAsSignBytesRequest(payload, 0)
	if request == nil {
		model.BytesResponseAddError(response, response.CreateByteString([]byte("invalid payload")))
		response.Finish(model.BytesResponseEnd(response))
		return response.FinishedBytes()
	}

	output, err := m.instance.SignBytes(request.MessageBytes(), string(request.PublicKey()), string(request.PrivateKey()), string(request.Passphrase()), m.parseKeyOptions(request.Options(nil)))
	if err != nil {
		model.BytesResponseAddError(response, response.CreateByteString([]byte(err.Error())))
		response.Finish(model.BytesResponseEnd(response))
		return response.FinishedBytes()
	}
	model.BytesResponseAddOutput(response, response.CreateByteVector(output))
	response.Finish(model.BytesResponseEnd(response))
	return response.FinishedBytes()
}
func (m instance) signBytesToString(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	model.StringResponseStart(response)
	request := model.GetRootAsSignBytesRequest(payload, 0)
	if request == nil {
		model.StringResponseAddError(response, response.CreateByteString([]byte("invalid payload")))
		response.Finish(model.StringResponseEnd(response))
		return response.FinishedBytes()
	}

	output, err := m.instance.SignBytesToString(request.MessageBytes(), string(request.PublicKey()), string(request.PrivateKey()), string(request.Passphrase()), m.parseKeyOptions(request.Options(nil)))
	if err != nil {
		model.StringResponseAddError(response, response.CreateByteString([]byte(err.Error())))
		response.Finish(model.StringResponseEnd(response))
		return response.FinishedBytes()
	}
	model.StringResponseAddOutput(response, response.CreateByteString([]byte(output)))
	response.Finish(model.StringResponseEnd(response))
	return response.FinishedBytes()
}
func (m instance) verify(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	model.BoolResponseStart(response)
	request := model.GetRootAsVerifyRequest(payload, 0)
	if request == nil {
		model.BoolResponseAddError(response, response.CreateByteString([]byte("invalid payload")))
		response.Finish(model.BoolResponseEnd(response))
		return response.FinishedBytes()
	}

	output, err := m.instance.Verify(string(request.Signature()), string(request.Message()), string(request.PublicKey()))
	if err != nil {
		model.BoolResponseAddError(response, response.CreateByteString([]byte(err.Error())))
		response.Finish(model.BoolResponseEnd(response))
		return response.FinishedBytes()
	}
	model.BoolResponseAddOutput(response, output)
	response.Finish(model.BoolResponseEnd(response))
	return response.FinishedBytes()
}
func (m instance) verifyBytes(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	model.BoolResponseStart(response)
	request := model.GetRootAsVerifyBytesRequest(payload, 0)
	if request == nil {
		model.BoolResponseAddError(response, response.CreateByteString([]byte("invalid payload")))
		response.Finish(model.BoolResponseEnd(response))
		return response.FinishedBytes()
	}

	output, err := m.instance.VerifyBytes(string(request.Signature()), request.MessageBytes(), string(request.PublicKey()))
	if err != nil {
		model.BoolResponseAddError(response, response.CreateByteString([]byte(err.Error())))
		response.Finish(model.BoolResponseEnd(response))
		return response.FinishedBytes()
	}
	model.BoolResponseAddOutput(response, output)
	response.Finish(model.BoolResponseEnd(response))
	return response.FinishedBytes()
}
func (m instance) decryptSymmetric(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	model.StringResponseStart(response)
	request := model.GetRootAsDecryptSymmetricRequest(payload, 0)
	if request == nil {
		model.StringResponseAddError(response, response.CreateByteString([]byte("invalid payload")))
		response.Finish(model.StringResponseEnd(response))
		return response.FinishedBytes()
	}

	output, err := m.instance.DecryptSymmetric(string(request.Message()), string(request.Passphrase()), m.parseKeyOptions(request.Options(nil)))
	if err != nil {
		model.StringResponseAddError(response, response.CreateByteString([]byte(err.Error())))
		response.Finish(model.StringResponseEnd(response))
		return response.FinishedBytes()
	}
	model.StringResponseAddOutput(response, response.CreateByteString([]byte(output)))
	response.Finish(model.StringResponseEnd(response))
	return response.FinishedBytes()
}
func (m instance) decryptSymmetricBytes(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	model.BytesResponseStart(response)
	request := model.GetRootAsDecryptSymmetricBytesRequest(payload, 0)
	if request == nil {
		model.BytesResponseAddError(response, response.CreateByteString([]byte("invalid payload")))
		response.Finish(model.BytesResponseEnd(response))
		return response.FinishedBytes()
	}

	output, err := m.instance.DecryptSymmetricBytes(request.MessageBytes(), string(request.Passphrase()), m.parseKeyOptions(request.Options(nil)))
	if err != nil {
		model.BytesResponseAddError(response, response.CreateByteString([]byte(err.Error())))
		response.Finish(model.BytesResponseEnd(response))
		return response.FinishedBytes()
	}
	model.BytesResponseAddOutput(response, response.CreateByteVector(output))
	response.Finish(model.BytesResponseEnd(response))
	return response.FinishedBytes()
}
func (m instance) encryptSymmetric(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	model.StringResponseStart(response)
	request := model.GetRootAsEncryptSymmetricRequest(payload, 0)
	if request == nil {
		model.StringResponseAddError(response, response.CreateByteString([]byte("invalid payload")))
		response.Finish(model.StringResponseEnd(response))
		return response.FinishedBytes()
	}

	output, err := m.instance.EncryptSymmetric(string(request.Message()), string(request.Passphrase()), m.parseFileHints(request.FileHints(nil)), m.parseKeyOptions(request.Options(nil)))
	if err != nil {
		model.StringResponseAddError(response, response.CreateByteString([]byte(err.Error())))
		response.Finish(model.StringResponseEnd(response))
		return response.FinishedBytes()
	}
	model.StringResponseAddOutput(response, response.CreateByteString([]byte(output)))
	response.Finish(model.StringResponseEnd(response))
	return response.FinishedBytes()
}
func (m instance) encryptSymmetricBytes(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	model.BytesResponseStart(response)
	request := model.GetRootAsEncryptSymmetricBytesRequest(payload, 0)
	if request == nil {
		model.BytesResponseAddError(response, response.CreateByteString([]byte("invalid payload")))
		response.Finish(model.BytesResponseEnd(response))
		return response.FinishedBytes()
	}

	output, err := m.instance.EncryptSymmetricBytes(request.MessageBytes(), string(request.Passphrase()), m.parseFileHints(request.FileHints(nil)), m.parseKeyOptions(request.Options(nil)))
	if err != nil {
		model.BytesResponseAddError(response, response.CreateByteString([]byte(err.Error())))
		response.Finish(model.BytesResponseEnd(response))
		return response.FinishedBytes()
	}
	model.BytesResponseAddOutput(response, response.CreateByteVector(output))
	response.Finish(model.BytesResponseEnd(response))
	return response.FinishedBytes()
}
func (m instance) generate(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsGenerateRequest(payload, 0)
	if request == nil {
		model.KeyPairResponseStart(response)
		model.KeyPairResponseAddError(response, response.CreateByteString([]byte("invalid payload")))
		response.Finish(model.KeyPairResponseEnd(response))
		return response.FinishedBytes()
	}

	options := m.parseOptions(request.Options(nil))

	output, err := m.instance.Generate(options)
	if err != nil {
		model.KeyPairResponseStart(response)
		model.KeyPairResponseAddError(response, response.CreateByteString([]byte(err.Error())))
		response.Finish(model.KeyPairResponseEnd(response))
		return response.FinishedBytes()
	}
	publicKey :=  response.CreateByteString([]byte(output.PublicKey))
	privateKey :=  response.CreateByteString([]byte(output.PrivateKey))

	model.KeyPairStart(response)
	model.KeyPairAddPublicKey(response,publicKey)
	model.KeyPairAddPrivateKey(response,privateKey)
	keyPair := model.KeyPairEnd(response)

	model.KeyPairResponseStart(response)
	model.KeyPairResponseAddOutput(response, keyPair)
	response.Finish(model.KeyPairResponseEnd(response))
	return response.FinishedBytes()
}

func (m instance) parseOptions(input *model.Options) *openpgp.Options {
	if input == nil {
		return &openpgp.Options{
			KeyOptions: m.parseKeyOptions(nil),
		}
	}
	options := &openpgp.Options{
		KeyOptions: m.parseKeyOptions(input.KeyOptions(nil)),
		Name:       string(input.Name()),
		Comment:    string(input.Comment()),
		Email:      string(input.Email()),
		Passphrase: string(input.Passphrase()),
	}
	return options
}

func (m instance) parseKeyOptions(input *model.KeyOptions) *openpgp.KeyOptions {
	if input == nil {
		return &openpgp.KeyOptions{}
	}
	options := &openpgp.KeyOptions{
		Hash:             m.parseHash(input.Hash()),
		Cipher:           m.parseCipher(input.Cipher()),
		Compression:      m.parseCompression(input.Compression()),
		CompressionLevel: int(input.CompressionLevel()),
		RSABits:          int(input.RsaBits()),
	}

	return options
}

func (m instance) parseFileHints(input *model.FileHints) *openpgp.FileHints {
	if input == nil {
		return &openpgp.FileHints{}
	}
	options := &openpgp.FileHints{
		IsBinary: input.IsBinary(),
		FileName: string(input.FileName()),
		ModTime:  string(input.ModTime()),
	}

	return options
}

func (m instance) parseEntity(input *model.Entity) *openpgp.Entity {
	if input == nil {
		return nil
	}
	options := &openpgp.Entity{
		PublicKey:  string(input.PublicKey()),
		PrivateKey: string(input.PrivateKey()),
		Passphrase: string(input.Passphrase()),
	}

	return options
}

func (m instance) parseHash(input model.Hash) string {
	switch input {
	case model.HashHASH_SHA224:
		return "sha224"
	case model.HashHASH_SHA384:
		return "sha384"
	case model.HashHASH_SHA512:
		return "sha512"
	case model.HashHASH_SHA256:
		fallthrough
	case model.HashHASH_UNSPECIFIED:
		fallthrough
	default:
		return "sha256"
	}
}

func (m instance) parseCipher(input model.Cipher) string {
	switch input {
	case model.CipherCIPHER_AES192:
		return "aes192"
	case model.CipherCIPHER_AES256:
		return "aes256"
	case model.CipherCIPHER_AES128:
		fallthrough
	case model.CipherCIPHER_UNSPECIFIED:
		fallthrough
	default:
		return "aes128"
	}
}

func (m instance) parseCompression(input model.Compression) string {
	switch input {
	case model.CompressionCOMPRESSION_ZIP:
		return "zip"
	case model.CompressionCOMPRESSION_ZLIB:
		return "zlib"
	case model.CompressionCOMPRESSION_NONE:
		fallthrough
	case model.CompressionCOMPRESSION_UNSPECIFIED:
		fallthrough
	default:
		return "none"
	}
}
