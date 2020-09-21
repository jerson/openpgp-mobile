package bridge

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

	output, err := m.instance.DecryptSymmetric(request.Message, request.Passphrase, request.Options)
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

	output, err := m.instance.DecryptSymmetricBytes(request.Message, request.Passphrase, request.Options)
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

	output, err := m.instance.EncryptSymmetric(request.Message, request.Passphrase, request.Options)
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

	output, err := m.instance.EncryptSymmetricBytes(request.Message, request.Passphrase, request.Options)
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

	output, err := m.instance.Generate(request.Options)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}
