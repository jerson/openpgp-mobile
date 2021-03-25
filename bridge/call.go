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
	request := model.GetRootAsDecryptRequest(payload, 0)

	output, err := m.instance.Decrypt(m.toString(request.Message()), m.toString(request.PrivateKey()), m.toString(request.Passphrase()), m.parseKeyOptions(request.Options(nil)))
	if err != nil {
		message := response.CreateString(err.Error())
		model.StringResponseStart(response)
		model.StringResponseAddError(response, message)
		response.Finish(model.StringResponseEnd(response))
		return response.FinishedBytes()
	}
	outputOffset := response.CreateString(output)
	model.StringResponseStart(response)
	model.StringResponseAddOutput(response, outputOffset)
	response.Finish(model.StringResponseEnd(response))
	return response.FinishedBytes()
}

func (m instance) decryptBytes(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsDecryptBytesRequest(payload, 0)

	output, err := m.instance.DecryptBytes(request.MessageBytes(), m.toString(request.PrivateKey()), m.toString(request.Passphrase()), m.parseKeyOptions(request.Options(nil)))
	if err != nil {
		message := response.CreateString(err.Error())
		model.BytesResponseStart(response)
		model.BytesResponseAddError(response, message)
		response.Finish(model.BytesResponseEnd(response))
		return response.FinishedBytes()
	}
	outputOffset := response.CreateByteVector(output)
	model.BytesResponseStart(response)
	model.BytesResponseAddOutput(response, outputOffset)
	response.Finish(model.BytesResponseEnd(response))
	return response.FinishedBytes()
}

func (m instance) encrypt(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsEncryptRequest(payload, 0)

	output, err := m.instance.Encrypt(m.toString(request.Message()), m.toString(request.PublicKey()), m.parseEntity(request.Signed(nil)), m.parseFileHints(request.FileHints(nil)), m.parseKeyOptions(request.Options(nil)))
	if err != nil {
		message := response.CreateString(err.Error())
		model.StringResponseStart(response)
		model.StringResponseAddError(response, message)
		response.Finish(model.StringResponseEnd(response))
		return response.FinishedBytes()
	}
	outputOffset := response.CreateString(output)
	model.StringResponseStart(response)
	model.StringResponseAddOutput(response, outputOffset)
	response.Finish(model.StringResponseEnd(response))
	return response.FinishedBytes()
}

func (m instance) encryptBytes(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsEncryptBytesRequest(payload, 0)

	output, err := m.instance.EncryptBytes(request.MessageBytes(), m.toString(request.PublicKey()), m.parseEntity(request.Signed(nil)), m.parseFileHints(request.FileHints(nil)), m.parseKeyOptions(request.Options(nil)))
	if err != nil {
		message := response.CreateString(err.Error())
		model.BytesResponseStart(response)
		model.BytesResponseAddError(response, message)
		response.Finish(model.BytesResponseEnd(response))
		return response.FinishedBytes()
	}
	outputOffset := response.CreateByteVector(output)
	model.BytesResponseStart(response)
	model.BytesResponseAddOutput(response, outputOffset)
	response.Finish(model.BytesResponseEnd(response))
	return response.FinishedBytes()
}

func (m instance) sign(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsSignRequest(payload, 0)

	output, err := m.instance.Sign(m.toString(request.Message()), m.toString(request.PublicKey()), m.toString(request.PrivateKey()), m.toString(request.Passphrase()), m.parseKeyOptions(request.Options(nil)))
	if err != nil {
		message := response.CreateString(err.Error())
		model.StringResponseStart(response)
		model.StringResponseAddError(response, message)
		response.Finish(model.StringResponseEnd(response))
		return response.FinishedBytes()
	}
	outputOffset := response.CreateString(output)
	model.StringResponseStart(response)
	model.StringResponseAddOutput(response, outputOffset)
	response.Finish(model.StringResponseEnd(response))
	return response.FinishedBytes()
}
func (m instance) signBytes(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsSignBytesRequest(payload, 0)

	output, err := m.instance.SignBytes(request.MessageBytes(), m.toString(request.PublicKey()), m.toString(request.PrivateKey()), m.toString(request.Passphrase()), m.parseKeyOptions(request.Options(nil)))
	if err != nil {
		message := response.CreateString(err.Error())
		model.BytesResponseStart(response)
		model.BytesResponseAddError(response, message)
		response.Finish(model.BytesResponseEnd(response))
		return response.FinishedBytes()
	}
	outputOffset := response.CreateByteVector(output)
	model.BytesResponseStart(response)
	model.BytesResponseAddOutput(response, outputOffset)
	response.Finish(model.BytesResponseEnd(response))
	return response.FinishedBytes()
}
func (m instance) signBytesToString(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsSignBytesRequest(payload, 0)

	output, err := m.instance.SignBytesToString(request.MessageBytes(), m.toString(request.PublicKey()), m.toString(request.PrivateKey()), m.toString(request.Passphrase()), m.parseKeyOptions(request.Options(nil)))
	if err != nil {
		message := response.CreateString(err.Error())
		model.StringResponseStart(response)
		model.StringResponseAddError(response, message)
		response.Finish(model.StringResponseEnd(response))
		return response.FinishedBytes()
	}
	outputOffset := response.CreateString(output)
	model.StringResponseStart(response)
	model.StringResponseAddOutput(response, outputOffset)
	response.Finish(model.StringResponseEnd(response))
	return response.FinishedBytes()
}
func (m instance) verify(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsVerifyRequest(payload, 0)

	output, err := m.instance.Verify(m.toString(request.Signature()), m.toString(request.Message()), m.toString(request.PublicKey()))
	if err != nil {
		message := response.CreateString(err.Error())
		model.BoolResponseStart(response)
		model.BoolResponseAddError(response, message)
		response.Finish(model.BoolResponseEnd(response))
		return response.FinishedBytes()
	}
	model.BoolResponseStart(response)
	model.BoolResponseAddOutput(response, output)
	response.Finish(model.BoolResponseEnd(response))
	return response.FinishedBytes()
}
func (m instance) verifyBytes(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsVerifyBytesRequest(payload, 0)

	output, err := m.instance.VerifyBytes(m.toString(request.Signature()), request.MessageBytes(), m.toString(request.PublicKey()))
	if err != nil {
		message := response.CreateString(err.Error())
		model.BoolResponseStart(response)
		model.BoolResponseAddError(response, message)
		response.Finish(model.BoolResponseEnd(response))
		return response.FinishedBytes()
	}
	model.BoolResponseStart(response)
	model.BoolResponseAddOutput(response, output)
	response.Finish(model.BoolResponseEnd(response))
	return response.FinishedBytes()
}
func (m instance) decryptSymmetric(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsDecryptSymmetricRequest(payload, 0)

	output, err := m.instance.DecryptSymmetric(m.toString(request.Message()), m.toString(request.Passphrase()), m.parseKeyOptions(request.Options(nil)))
	if err != nil {
		message := response.CreateString(err.Error())
		model.StringResponseStart(response)
		model.StringResponseAddError(response, message)
		response.Finish(model.StringResponseEnd(response))
		return response.FinishedBytes()
	}
	outputOffset := response.CreateString(output)
	model.StringResponseStart(response)
	model.StringResponseAddOutput(response, outputOffset)
	response.Finish(model.StringResponseEnd(response))
	return response.FinishedBytes()
}
func (m instance) decryptSymmetricBytes(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsDecryptSymmetricBytesRequest(payload, 0)

	output, err := m.instance.DecryptSymmetricBytes(request.MessageBytes(), m.toString(request.Passphrase()), m.parseKeyOptions(request.Options(nil)))
	if err != nil {
		message := response.CreateString(err.Error())
		model.BytesResponseStart(response)
		model.BytesResponseAddError(response, message)
		response.Finish(model.BytesResponseEnd(response))
		return response.FinishedBytes()
	}
	outputOffset := response.CreateByteVector(output)
	model.BytesResponseStart(response)
	model.BytesResponseAddOutput(response, outputOffset)
	response.Finish(model.BytesResponseEnd(response))
	return response.FinishedBytes()
}
func (m instance) encryptSymmetric(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsEncryptSymmetricRequest(payload, 0)

	output, err := m.instance.EncryptSymmetric(m.toString(request.Message()), m.toString(request.Passphrase()), m.parseFileHints(request.FileHints(nil)), m.parseKeyOptions(request.Options(nil)))
	if err != nil {
		message := response.CreateString(err.Error())
		model.StringResponseStart(response)
		model.StringResponseAddError(response, message)
		response.Finish(model.StringResponseEnd(response))
		return response.FinishedBytes()
	}
	outputOffset := response.CreateString(output)
	model.StringResponseStart(response)
	model.StringResponseAddOutput(response, outputOffset)
	response.Finish(model.StringResponseEnd(response))
	return response.FinishedBytes()
}
func (m instance) encryptSymmetricBytes(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsEncryptSymmetricBytesRequest(payload, 0)

	output, err := m.instance.EncryptSymmetricBytes(request.MessageBytes(), m.toString(request.Passphrase()), m.parseFileHints(request.FileHints(nil)), m.parseKeyOptions(request.Options(nil)))
	if err != nil {
		message := response.CreateString(err.Error())
		model.BytesResponseStart(response)
		model.BytesResponseAddError(response, message)
		response.Finish(model.BytesResponseEnd(response))
		return response.FinishedBytes()
	}
	outputOffset := response.CreateByteVector(output)
	model.BytesResponseStart(response)
	model.BytesResponseAddOutput(response, outputOffset)
	response.Finish(model.BytesResponseEnd(response))
	return response.FinishedBytes()
}
func (m instance) generate(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsGenerateRequest(payload, 0)
	options := m.parseOptions(request.Options(nil))

	output, err := m.instance.Generate(options)
	if err != nil {
		message := response.CreateString(err.Error())
		model.KeyPairResponseStart(response)
		model.KeyPairResponseAddError(response, message)
		response.Finish(model.KeyPairResponseEnd(response))
		return response.FinishedBytes()
	}
	publicKey := response.CreateByteString([]byte(output.PublicKey))
	privateKey := response.CreateByteString([]byte(output.PrivateKey))

	model.KeyPairStart(response)
	model.KeyPairAddPublicKey(response, publicKey)
	model.KeyPairAddPrivateKey(response, privateKey)
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
		Name:       m.toString(input.Name()),
		Comment:    m.toString(input.Comment()),
		Email:      m.toString(input.Email()),
		Passphrase: m.toString(input.Passphrase()),
	}
	return options
}

func (m instance) toString(input []byte) string {
	if input == nil {
		return ""
	}

	return string(input)
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
		FileName: m.toString(input.FileName()),
		ModTime:  m.toString(input.ModTime()),
	}

	return options
}

func (m instance) parseEntity(input *model.Entity) *openpgp.Entity {
	if input == nil {
		return nil
	}
	options := &openpgp.Entity{
		PublicKey:  m.toString(input.PublicKey()),
		PrivateKey: m.toString(input.PrivateKey()),
		Passphrase: m.toString(input.Passphrase()),
	}

	return options
}

func (m instance) parseHash(input model.Hash) string {
	switch input {
	case model.HashSHA224:
		return "sha224"
	case model.HashSHA384:
		return "sha384"
	case model.HashSHA512:
		return "sha512"
	case model.HashSHA256:
		fallthrough
	default:
		return "sha256"
	}
}

func (m instance) parseCipher(input model.Cipher) string {
	switch input {
	case model.CipherAES192:
		return "aes192"
	case model.CipherAES256:
		return "aes256"
	case model.CipherAES128:
		fallthrough
	default:
		return "aes128"
	}
}

func (m instance) parseCompression(input model.Compression) string {
	switch input {
	case model.CompressionZIP:
		return "zip"
	case model.CompressionZLIB:
		return "zlib"
	case model.CompressionNONE:
		fallthrough
	default:
		return "none"
	}
}
