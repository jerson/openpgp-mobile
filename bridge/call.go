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
	case "decryptFile":
		output = instance.decryptFile(payload)
	case "decryptBytes":
		output = instance.decryptBytes(payload)
	case "encrypt":
		output = instance.encrypt(payload)
	case "encryptFile":
		output = instance.encryptFile(payload)
	case "encryptBytes":
		output = instance.encryptBytes(payload)
	case "sign":
		output = instance.sign(payload)
	case "signFile":
		output = instance.signFile(payload)
	case "signBytes":
		output = instance.signBytes(payload)
	case "signBytesToString":
		output = instance.signBytesToString(payload)
	case "verify":
		output = instance.verify(payload)
	case "verifyFile":
		output = instance.verifyFile(payload)
	case "verifyBytes":
		output = instance.verifyBytes(payload)
	case "decryptSymmetric":
		output = instance.decryptSymmetric(payload)
	case "decryptSymmetricFile":
		output = instance.decryptSymmetricFile(payload)
	case "decryptSymmetricBytes":
		output = instance.decryptSymmetricBytes(payload)
	case "encryptSymmetric":
		output = instance.encryptSymmetric(payload)
	case "encryptSymmetricFile":
		output = instance.encryptSymmetricFile(payload)
	case "encryptSymmetricBytes":
		output = instance.encryptSymmetricBytes(payload)
	case "generate":
		output = instance.generate(payload)
	case "armorEncode":
		output = instance.armorEncode(payload)
	case "getPublicKeyMetadata":
		output = instance.getPublicKeyMetadata(payload)
	case "getPrivateKeyMetadata":
		output = instance.getPrivateKeyMetadata(payload)
	case "convertPrivateKeyToPublicKey":
		output = instance.convertPrivateKeyToPublicKey(payload)
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
	return m._stringResponse(response, output, err)
}

func (m instance) decryptFile(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsDecryptFileRequest(payload, 0)

	output, err := m.instance.DecryptFile(m.toString(request.Input()), m.toString(request.Output()), m.toString(request.PrivateKey()), m.toString(request.Passphrase()), m.parseKeyOptions(request.Options(nil)))
	return m._intResponse(response, int64(output), err)
}

func (m instance) decryptBytes(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsDecryptBytesRequest(payload, 0)

	output, err := m.instance.DecryptBytes(request.MessageBytes(), m.toString(request.PrivateKey()), m.toString(request.Passphrase()), m.parseKeyOptions(request.Options(nil)))
	return m._bytesResponse(response, output, err)
}

func (m instance) encrypt(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsEncryptRequest(payload, 0)

	output, err := m.instance.Encrypt(m.toString(request.Message()), m.toString(request.PublicKey()), m.parseEntity(request.Signed(nil)), m.parseFileHints(request.FileHints(nil)), m.parseKeyOptions(request.Options(nil)))
	return m._stringResponse(response, output, err)
}

func (m instance) encryptFile(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsEncryptFileRequest(payload, 0)

	output, err := m.instance.EncryptFile(m.toString(request.Input()), m.toString(request.Output()), m.toString(request.PublicKey()), m.parseEntity(request.Signed(nil)), m.parseFileHints(request.FileHints(nil)), m.parseKeyOptions(request.Options(nil)))
	return m._intResponse(response, int64(output), err)
}

func (m instance) encryptBytes(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsEncryptBytesRequest(payload, 0)

	output, err := m.instance.EncryptBytes(request.MessageBytes(), m.toString(request.PublicKey()), m.parseEntity(request.Signed(nil)), m.parseFileHints(request.FileHints(nil)), m.parseKeyOptions(request.Options(nil)))
	return m._bytesResponse(response, output, err)
}

func (m instance) sign(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsSignRequest(payload, 0)

	output, err := m.instance.Sign(m.toString(request.Message()), m.toString(request.PublicKey()), m.toString(request.PrivateKey()), m.toString(request.Passphrase()), m.parseKeyOptions(request.Options(nil)))
	return m._stringResponse(response, output, err)
}
func (m instance) signFile(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsSignFileRequest(payload, 0)

	output, err := m.instance.SignFile(m.toString(request.Input()), m.toString(request.PublicKey()), m.toString(request.PrivateKey()), m.toString(request.Passphrase()), m.parseKeyOptions(request.Options(nil)))
	return m._stringResponse(response, output, err)
}
func (m instance) signBytes(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsSignBytesRequest(payload, 0)

	output, err := m.instance.SignBytes(request.MessageBytes(), m.toString(request.PublicKey()), m.toString(request.PrivateKey()), m.toString(request.Passphrase()), m.parseKeyOptions(request.Options(nil)))
	return m._bytesResponse(response, output, err)
}
func (m instance) signBytesToString(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsSignBytesRequest(payload, 0)

	output, err := m.instance.SignBytesToString(request.MessageBytes(), m.toString(request.PublicKey()), m.toString(request.PrivateKey()), m.toString(request.Passphrase()), m.parseKeyOptions(request.Options(nil)))
	return m._stringResponse(response, output, err)
}
func (m instance) verify(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsVerifyRequest(payload, 0)

	output, err := m.instance.Verify(m.toString(request.Signature()), m.toString(request.Message()), m.toString(request.PublicKey()))
	return m._boolResponse(response, output, err)
}
func (m instance) verifyFile(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsVerifyFileRequest(payload, 0)

	output, err := m.instance.VerifyFile(m.toString(request.Signature()), m.toString(request.Input()), m.toString(request.PublicKey()))
	return m._boolResponse(response, output, err)
}
func (m instance) verifyBytes(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsVerifyBytesRequest(payload, 0)

	output, err := m.instance.VerifyBytes(m.toString(request.Signature()), request.MessageBytes(), m.toString(request.PublicKey()))
	return m._boolResponse(response, output, err)
}
func (m instance) decryptSymmetric(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsDecryptSymmetricRequest(payload, 0)

	output, err := m.instance.DecryptSymmetric(m.toString(request.Message()), m.toString(request.Passphrase()), m.parseKeyOptions(request.Options(nil)))
	return m._stringResponse(response, output, err)
}
func (m instance) decryptSymmetricFile(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsDecryptSymmetricFileRequest(payload, 0)

	output, err := m.instance.DecryptSymmetricFile(m.toString(request.Input()), m.toString(request.Output()), m.toString(request.Passphrase()), m.parseKeyOptions(request.Options(nil)))
	return m._intResponse(response, int64(output), err)
}
func (m instance) decryptSymmetricBytes(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsDecryptSymmetricBytesRequest(payload, 0)

	output, err := m.instance.DecryptSymmetricBytes(request.MessageBytes(), m.toString(request.Passphrase()), m.parseKeyOptions(request.Options(nil)))
	return m._bytesResponse(response, output, err)
}
func (m instance) encryptSymmetric(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsEncryptSymmetricRequest(payload, 0)

	output, err := m.instance.EncryptSymmetric(m.toString(request.Message()), m.toString(request.Passphrase()), m.parseFileHints(request.FileHints(nil)), m.parseKeyOptions(request.Options(nil)))
	return m._stringResponse(response, output, err)
}
func (m instance) encryptSymmetricFile(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsEncryptSymmetricFileRequest(payload, 0)

	output, err := m.instance.EncryptSymmetricFile(m.toString(request.Input()), m.toString(request.Output()), m.toString(request.Passphrase()), m.parseFileHints(request.FileHints(nil)), m.parseKeyOptions(request.Options(nil)))
	return m._intResponse(response, int64(output), err)
}
func (m instance) encryptSymmetricBytes(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsEncryptSymmetricBytesRequest(payload, 0)

	output, err := m.instance.EncryptSymmetricBytes(request.MessageBytes(), m.toString(request.Passphrase()), m.parseFileHints(request.FileHints(nil)), m.parseKeyOptions(request.Options(nil)))
	return m._bytesResponse(response, output, err)
}
func (m instance) generate(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsGenerateRequest(payload, 0)
	options := m.parseOptions(request.Options(nil))

	output, err := m.instance.Generate(options)
	return m._keyPairResponse(response, output, err)
}

func (m instance) armorEncode(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsArmorEncodeRequest(payload, 0)

	output, err := m.instance.ArmorEncode(request.PacketBytes())
	return m._stringResponse(response, output, err)
}

func (m instance) getPublicKeyMetadata(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsGetPublicKeyMetadataRequest(payload, 0)

	output, err := m.instance.GetPublicKeyMetadata(m.toString(request.PublicKey()))
	return m._publicKeyMetadataResponse(response, output, err)
}

func (m instance) getPrivateKeyMetadata(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsGetPrivateKeyMetadataRequest(payload, 0)

	output, err := m.instance.GetPrivateKeyMetadata(m.toString(request.PrivateKey()))
	return m._privateKeyMetadataResponse(response, output, err)
}

func (m instance) convertPrivateKeyToPublicKey(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsConvertPrivateKeyToPublicKeyRequest(payload, 0)

	output, err := m.instance.ConvertPrivateKeyToPublicKey(m.toString(request.PrivateKey()))
	return m._stringResponse(response, output, err)
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

func (m instance) _keyPairResponse(response *flatbuffers.Builder, output *openpgp.KeyPair, err error) []byte {
	if err != nil {
		outputOffset := response.CreateString(err.Error())
		model.KeyPairResponseStart(response)
		model.KeyPairResponseAddError(response, outputOffset)
		response.Finish(model.KeyPairResponseEnd(response))
		return response.FinishedBytes()
	}

	publicKeyOffset := response.CreateString(output.PublicKey)
	privateKeyOffset := response.CreateString(output.PrivateKey)

	model.KeyPairStart(response)
	model.KeyPairAddPublicKey(response, publicKeyOffset)
	model.KeyPairAddPrivateKey(response, privateKeyOffset)
	KeyPair := model.KeyPairEnd(response)

	model.KeyPairResponseStart(response)
	model.KeyPairResponseAddOutput(response, KeyPair)
	response.Finish(model.KeyPairResponseEnd(response))
	return response.FinishedBytes()
}

func (m instance) _publicKeyMetadataResponse(response *flatbuffers.Builder, output *openpgp.PublicKeyMetadata, err error) []byte {
	if err != nil {
		outputOffset := response.CreateString(err.Error())
		model.PublicKeyMetadataResponseStart(response)
		model.PublicKeyMetadataResponseAddError(response, outputOffset)
		response.Finish(model.PublicKeyMetadataResponseEnd(response))
		return response.FinishedBytes()
	}

	keyIDOffset := response.CreateString(output.KeyID)
	keyIDShortOffset := response.CreateString(output.KeyIDShort)
	creationTimeOffset := response.CreateString(output.CreationTime)
	fingerprintOffset := response.CreateString(output.Fingerprint)
	keyIDNumericOffset := response.CreateString(output.KeyIDNumeric)

	model.PublicKeyMetadataStart(response)
	model.PublicKeyMetadataAddKeyId(response, keyIDOffset)
	model.PublicKeyMetadataAddKeyIdShort(response, keyIDShortOffset)
	model.PublicKeyMetadataAddCreationTime(response, creationTimeOffset)
	model.PublicKeyMetadataAddFingerprint(response, fingerprintOffset)
	model.PublicKeyMetadataAddKeyIdNumeric(response, keyIDNumericOffset)
	model.PublicKeyMetadataAddIsSubKey(response, output.IsSubKey)
	KeyPair := model.PublicKeyMetadataEnd(response)

	model.PublicKeyMetadataResponseStart(response)
	model.PublicKeyMetadataResponseAddOutput(response, KeyPair)
	response.Finish(model.PublicKeyMetadataResponseEnd(response))
	return response.FinishedBytes()
}

func (m instance) _privateKeyMetadataResponse(response *flatbuffers.Builder, output *openpgp.PrivateKeyMetadata, err error) []byte {
	if err != nil {
		outputOffset := response.CreateString(err.Error())
		model.PrivateKeyMetadataResponseStart(response)
		model.PrivateKeyMetadataResponseAddError(response, outputOffset)
		response.Finish(model.PrivateKeyMetadataResponseEnd(response))
		return response.FinishedBytes()
	}

	keyIDOffset := response.CreateString(output.KeyID)
	keyIDShortOffset := response.CreateString(output.KeyIDShort)
	creationTimeOffset := response.CreateString(output.CreationTime)
	fingerprintOffset := response.CreateString(output.Fingerprint)
	keyIDNumericOffset := response.CreateString(output.KeyIDNumeric)

	model.PrivateKeyMetadataStart(response)
	model.PrivateKeyMetadataAddKeyId(response, keyIDOffset)
	model.PrivateKeyMetadataAddKeyIdShort(response, keyIDShortOffset)
	model.PrivateKeyMetadataAddCreationTime(response, creationTimeOffset)
	model.PrivateKeyMetadataAddFingerprint(response, fingerprintOffset)
	model.PrivateKeyMetadataAddKeyIdNumeric(response, keyIDNumericOffset)
	model.PrivateKeyMetadataAddIsSubKey(response, output.IsSubKey)
	model.PrivateKeyMetadataAddEncrypted(response, output.Encrypted)
	KeyPair := model.PrivateKeyMetadataEnd(response)

	model.PrivateKeyMetadataResponseStart(response)
	model.PrivateKeyMetadataResponseAddOutput(response, KeyPair)
	response.Finish(model.PrivateKeyMetadataResponseEnd(response))
	return response.FinishedBytes()
}

func (m instance) _boolResponse(response *flatbuffers.Builder, output bool, err error) []byte {
	if err != nil {
		outputOffset := response.CreateString(err.Error())
		model.BoolResponseStart(response)
		model.BoolResponseAddError(response, outputOffset)
		response.Finish(model.BoolResponseEnd(response))
		return response.FinishedBytes()
	}
	model.BoolResponseStart(response)
	model.BoolResponseAddOutput(response, output)
	response.Finish(model.BoolResponseEnd(response))
	return response.FinishedBytes()
}

func (m instance) _bytesResponse(response *flatbuffers.Builder, output []byte, err error) []byte {
	if err != nil {
		outputOffset := response.CreateString(err.Error())
		model.BytesResponseStart(response)
		model.BytesResponseAddError(response, outputOffset)
		response.Finish(model.BytesResponseEnd(response))
		return response.FinishedBytes()
	}
	outputOffset := response.CreateByteVector(output)
	model.BytesResponseStart(response)
	model.BytesResponseAddOutput(response, outputOffset)
	response.Finish(model.BytesResponseEnd(response))
	return response.FinishedBytes()
}

func (m instance) _intResponse(response *flatbuffers.Builder, output int64, err error) []byte {
	if err != nil {
		outputOffset := response.CreateString(err.Error())
		model.IntResponseStart(response)
		model.IntResponseAddError(response, outputOffset)
		response.Finish(model.IntResponseEnd(response))
		return response.FinishedBytes()
	}
	model.IntResponseStart(response)
	model.IntResponseAddOutput(response, output)
	response.Finish(model.IntResponseEnd(response))
	return response.FinishedBytes()
}

func (m instance) _stringResponse(response *flatbuffers.Builder, output string, err error) []byte {
	if err != nil {
		outputOffset := response.CreateString(err.Error())
		model.StringResponseStart(response)
		model.StringResponseAddError(response, outputOffset)
		response.Finish(model.StringResponseEnd(response))
		return response.FinishedBytes()
	}
	outputOffset := response.CreateString(output)
	model.StringResponseStart(response)
	model.StringResponseAddOutput(response, outputOffset)
	response.Finish(model.StringResponseEnd(response))
	return response.FinishedBytes()
}

func (m instance) toString(input []byte) string {
	if input == nil {
		return ""
	}

	return string(input)
}
