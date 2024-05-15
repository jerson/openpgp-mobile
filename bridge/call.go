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
	case "signData":
		output = instance.signData(payload)
	case "signFile":
		output = instance.signFile(payload)
	case "signBytes":
		output = instance.signBytes(payload)
	case "signDataBytes":
		output = instance.signDataBytes(payload)
	case "signBytesToString":
		output = instance.signBytesToString(payload)
	case "verify":
		output = instance.verify(payload)
	case "verifyData":
		output = instance.verifyData(payload)
	case "verifyFile":
		output = instance.verifyFile(payload)
	case "verifyBytes":
		output = instance.verifyBytes(payload)
	case "verifyDataBytes":
		output = instance.verifyDataBytes(payload)
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
	case "armorDecode":
		output = instance.armorDecode(payload)
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

	output, err := m.instance.Decrypt(m.toString(request.Message()), m.toString(request.PrivateKey()), m.toString(request.Passphrase()), m.parseEntity(request.Signed(nil)), m.parseKeyOptions(request.Options(nil)))
	return m._stringResponse(response, output, err)
}

func (m instance) decryptFile(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsDecryptFileRequest(payload, 0)

	output, err := m.instance.DecryptFile(m.toString(request.Input()), m.toString(request.Output()), m.toString(request.PrivateKey()), m.toString(request.Passphrase()), m.parseEntity(request.Signed(nil)), m.parseKeyOptions(request.Options(nil)))
	return m._intResponse(response, int64(output), err)
}

func (m instance) decryptBytes(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsDecryptBytesRequest(payload, 0)

	output, err := m.instance.DecryptBytes(request.MessageBytes(), m.toString(request.PrivateKey()), m.toString(request.Passphrase()), m.parseEntity(request.Signed(nil)), m.parseKeyOptions(request.Options(nil)))
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

	output, err := m.instance.Sign(m.toString(request.Message()), m.toString(request.PrivateKey()), m.toString(request.Passphrase()), m.parseKeyOptions(request.Options(nil)))
	return m._stringResponse(response, output, err)
}
func (m instance) signData(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsSignDataRequest(payload, 0)

	output, err := m.instance.SignData(m.toString(request.Message()), m.toString(request.PrivateKey()), m.toString(request.Passphrase()), m.parseKeyOptions(request.Options(nil)))
	return m._stringResponse(response, output, err)
}
func (m instance) signFile(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsSignFileRequest(payload, 0)

	output, err := m.instance.SignFile(m.toString(request.Input()), m.toString(request.PrivateKey()), m.toString(request.Passphrase()), m.parseKeyOptions(request.Options(nil)))
	return m._stringResponse(response, output, err)
}
func (m instance) signBytes(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsSignBytesRequest(payload, 0)

	output, err := m.instance.SignBytes(request.MessageBytes(), m.toString(request.PrivateKey()), m.toString(request.Passphrase()), m.parseKeyOptions(request.Options(nil)))
	return m._bytesResponse(response, output, err)
}
func (m instance) signDataBytes(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsSignDataBytesRequest(payload, 0)

	output, err := m.instance.SignDataBytes(request.MessageBytes(), m.toString(request.PrivateKey()), m.toString(request.Passphrase()), m.parseKeyOptions(request.Options(nil)))
	return m._bytesResponse(response, output, err)
}
func (m instance) signBytesToString(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsSignBytesRequest(payload, 0)

	output, err := m.instance.SignBytesToString(request.MessageBytes(), m.toString(request.PrivateKey()), m.toString(request.Passphrase()), m.parseKeyOptions(request.Options(nil)))
	return m._stringResponse(response, output, err)
}
func (m instance) verify(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsVerifyRequest(payload, 0)

	output, err := m.instance.Verify(m.toString(request.Signature()), m.toString(request.Message()), m.toString(request.PublicKey()))
	return m._boolResponse(response, output, err)
}
func (m instance) verifyData(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsVerifyDataRequest(payload, 0)

	output, err := m.instance.VerifyData(m.toString(request.Signature()), m.toString(request.PublicKey()))
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
func (m instance) verifyDataBytes(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsVerifyDataBytesRequest(payload, 0)

	output, err := m.instance.VerifyDataBytes(request.SignatureBytes(), m.toString(request.PublicKey()))
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

	output, err := m.instance.ArmorEncode(request.PacketBytes(), string(request.Type()))
	return m._stringResponse(response, output, err)
}
func (m instance) armorDecode(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsArmorDecodeRequest(payload, 0)

	output, err := m.instance.ArmorDecode(string(request.Message()))
	return m._armorDecodeResponse(response, output, err)
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
		Curve:            m.parseCurve(input.Curve()),
		Algorithm:        m.parseAlgorithm(input.Algorithm()),
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

func (m instance) parseCurve(input model.Curve) string {
	switch input {
	case model.CurveCURVE448:
		return "curve448"
	case model.CurveP256:
		return "p256"
	case model.CurveP384:
		return "p384"
	case model.CurveP521:
		return "p521"
	case model.CurveSECP256K1:
		return "secp256k1"
	case model.CurveBRAINPOOLP256:
		return "brainpoolp256"
	case model.CurveBRAINPOOLP384:
		return "brainpoolp384"
	case model.CurveBRAINPOOLP512:
		return "brainpoolp512"
	case model.CurveCURVE25519:
		fallthrough
	default:
		return "curve25519"
	}
}

func (m instance) parseAlgorithm(input model.Algorithm) string {
	switch input {
	case model.AlgorithmECDSA:
		return "ecdsa"
	case model.AlgorithmEDDSA:
		return "eddsa"
	case model.AlgorithmECHD:
		return "echd"
	case model.AlgorithmDSA:
		return "dsa"
	case model.AlgorithmELGAMAL:
		return "elgamal"
	case model.AlgorithmRSA:
		fallthrough
	default:
		return "rsa"
	}
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
	case model.CipherDES:
		return "3des"
	case model.CipherCAST5:
		return "cast5"
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

func (m instance) _armorDecodeResponse(response *flatbuffers.Builder, output *openpgp.ArmorMetadata, err error) []byte {
	if err != nil {
		outputOffset := response.CreateString(err.Error())
		model.ArmorDecodeResponseStart(response)
		model.ArmorDecodeResponseAddError(response, outputOffset)
		response.Finish(model.ArmorDecodeResponseEnd(response))
		return response.FinishedBytes()
	}

	bodyOffset := response.CreateByteVector(output.Body)
	typeOffset := response.CreateString(output.Type)

	model.ArmorMetadataStart(response)
	model.ArmorMetadataAddBody(response, bodyOffset)
	model.ArmorMetadataAddType(response, typeOffset)
	metadata := model.ArmorMetadataEnd(response)

	model.ArmorDecodeResponseStart(response)
	model.ArmorDecodeResponseAddOutput(response, metadata)
	response.Finish(model.ArmorDecodeResponseEnd(response))
	return response.FinishedBytes()
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

type publicKeyMetadataOffset struct {
	algorithm    flatbuffers.UOffsetT
	keyID        flatbuffers.UOffsetT
	keyIDShort   flatbuffers.UOffsetT
	creationTime flatbuffers.UOffsetT
	fingerprint  flatbuffers.UOffsetT
	keyIDNumeric flatbuffers.UOffsetT
	isSubKey     bool
	canSign      bool
	canEncrypt   bool
}

type privateKeyMetadataOffset struct {
	keyID        flatbuffers.UOffsetT
	keyIDShort   flatbuffers.UOffsetT
	creationTime flatbuffers.UOffsetT
	fingerprint  flatbuffers.UOffsetT
	keyIDNumeric flatbuffers.UOffsetT
	isSubKey     bool
	canSign      bool
}

type identityOffset struct {
	id      flatbuffers.UOffsetT
	name    flatbuffers.UOffsetT
	email   flatbuffers.UOffsetT
	comment flatbuffers.UOffsetT
}

func (m instance) _identitiesResponse(response *flatbuffers.Builder, output []openpgp.Identity) flatbuffers.UOffsetT {
	total := len(output)
	resultMap := map[int]identityOffset{}
	for key, identity := range output {
		resultMap[key] = identityOffset{
			id:      response.CreateString(identity.ID),
			name:    response.CreateString(identity.Name),
			email:   response.CreateString(identity.Email),
			comment: response.CreateString(identity.Comment),
		}
	}
	var offsetList []flatbuffers.UOffsetT
	for _, result := range resultMap {
		model.IdentityStart(response)
		model.IdentityAddId(response, result.id)
		model.IdentityAddName(response, result.name)
		model.IdentityAddEmail(response, result.email)
		model.IdentityAddComment(response, result.comment)
		resultOffset := model.IdentityEnd(response)
		offsetList = append(offsetList, resultOffset)
	}
	model.PublicKeyMetadataStartIdentitiesVector(response, total)
	for _, result := range offsetList {
		response.PrependUOffsetT(result)
	}
	return response.EndVector(total)
}

func (m instance) _subKeysPrivateKeyResponse(response *flatbuffers.Builder, output []openpgp.PrivateKeyMetadata) flatbuffers.UOffsetT {
	total := len(output)
	resultMap := map[int]privateKeyMetadataOffset{}
	for key, result := range output {
		resultMap[key] = privateKeyMetadataOffset{
			keyID:        response.CreateString(result.KeyID),
			keyIDShort:   response.CreateString(result.KeyIDShort),
			creationTime: response.CreateString(result.CreationTime),
			fingerprint:  response.CreateString(result.Fingerprint),
			keyIDNumeric: response.CreateString(result.KeyIDNumeric),
			isSubKey:     result.IsSubKey,
			canSign:      result.CanSign,
		}
	}
	var offsetList []flatbuffers.UOffsetT
	for _, result := range resultMap {
		model.PrivateKeyMetadataStart(response)
		model.PrivateKeyMetadataAddKeyId(response, result.keyID)
		model.PrivateKeyMetadataAddKeyIdShort(response, result.keyIDShort)
		model.PrivateKeyMetadataAddCreationTime(response, result.creationTime)
		model.PrivateKeyMetadataAddFingerprint(response, result.fingerprint)
		model.PrivateKeyMetadataAddKeyIdNumeric(response, result.keyIDNumeric)
		model.PrivateKeyMetadataAddIsSubKey(response, result.isSubKey)
		model.PrivateKeyMetadataAddCanSign(response, result.canSign)
		resultOffset := model.PrivateKeyMetadataEnd(response)
		offsetList = append(offsetList, resultOffset)
	}
	model.PrivateKeyMetadataStartSubKeysVector(response, total)
	for _, result := range offsetList {
		response.PrependUOffsetT(result)
	}
	return response.EndVector(total)
}

func (m instance) _subKeysPublicKeyResponse(response *flatbuffers.Builder, output []openpgp.PublicKeyMetadata) flatbuffers.UOffsetT {
	total := len(output)
	resultMap := map[int]publicKeyMetadataOffset{}
	for key, result := range output {
		resultMap[key] = publicKeyMetadataOffset{
			algorithm:    response.CreateString(result.Algorithm),
			keyID:        response.CreateString(result.KeyID),
			keyIDShort:   response.CreateString(result.KeyIDShort),
			creationTime: response.CreateString(result.CreationTime),
			fingerprint:  response.CreateString(result.Fingerprint),
			keyIDNumeric: response.CreateString(result.KeyIDNumeric),
			isSubKey:     result.IsSubKey,
			canSign:      result.CanSign,
			canEncrypt:   result.CanEncrypt,
		}
	}
	var offsetList []flatbuffers.UOffsetT
	for _, result := range resultMap {
		model.PublicKeyMetadataStart(response)
		model.PublicKeyMetadataAddAlgorithm(response, result.algorithm)
		model.PublicKeyMetadataAddKeyId(response, result.keyID)
		model.PublicKeyMetadataAddKeyIdShort(response, result.keyIDShort)
		model.PublicKeyMetadataAddCreationTime(response, result.creationTime)
		model.PublicKeyMetadataAddFingerprint(response, result.fingerprint)
		model.PublicKeyMetadataAddKeyIdNumeric(response, result.keyIDNumeric)
		model.PublicKeyMetadataAddIsSubKey(response, result.isSubKey)
		model.PublicKeyMetadataAddCanSign(response, result.canSign)
		model.PublicKeyMetadataAddCanEncrypt(response, result.canEncrypt)
		resultOffset := model.PublicKeyMetadataEnd(response)
		offsetList = append(offsetList, resultOffset)
	}
	model.PublicKeyMetadataStartSubKeysVector(response, total)
	for _, result := range offsetList {
		response.PrependUOffsetT(result)
	}
	return response.EndVector(total)
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
	algorithmOffset := response.CreateString(output.Algorithm)
	identitiesOffset := m._identitiesResponse(response, output.Identities)
	subKeysOffset := m._subKeysPublicKeyResponse(response, output.SubKeys)

	model.PublicKeyMetadataStart(response)
	model.PublicKeyMetadataAddAlgorithm(response, algorithmOffset)
	model.PublicKeyMetadataAddKeyId(response, keyIDOffset)
	model.PublicKeyMetadataAddKeyIdShort(response, keyIDShortOffset)
	model.PublicKeyMetadataAddCreationTime(response, creationTimeOffset)
	model.PublicKeyMetadataAddFingerprint(response, fingerprintOffset)
	model.PublicKeyMetadataAddKeyIdNumeric(response, keyIDNumericOffset)
	model.PublicKeyMetadataAddIsSubKey(response, output.IsSubKey)
	model.PublicKeyMetadataAddCanEncrypt(response, output.CanEncrypt)
	model.PublicKeyMetadataAddCanSign(response, output.CanSign)
	model.PublicKeyMetadataAddIdentities(response, identitiesOffset)
	model.PublicKeyMetadataAddSubKeys(response, subKeysOffset)
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
	identitiesOffset := m._identitiesResponse(response, output.Identities)
	subKeysOffset := m._subKeysPrivateKeyResponse(response, output.SubKeys)

	model.PrivateKeyMetadataStart(response)
	model.PrivateKeyMetadataAddKeyId(response, keyIDOffset)
	model.PrivateKeyMetadataAddKeyIdShort(response, keyIDShortOffset)
	model.PrivateKeyMetadataAddCreationTime(response, creationTimeOffset)
	model.PrivateKeyMetadataAddFingerprint(response, fingerprintOffset)
	model.PrivateKeyMetadataAddKeyIdNumeric(response, keyIDNumericOffset)
	model.PrivateKeyMetadataAddIsSubKey(response, output.IsSubKey)
	model.PrivateKeyMetadataAddEncrypted(response, output.Encrypted)
	model.PrivateKeyMetadataAddCanSign(response, output.CanSign)
	model.PrivateKeyMetadataAddIdentities(response, identitiesOffset)
	model.PrivateKeyMetadataAddSubKeys(response, subKeysOffset)
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
