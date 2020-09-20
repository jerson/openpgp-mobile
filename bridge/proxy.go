package bridge

import (
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
	case "decrypt_bytes":
		output = instance.decryptBytes(payload)

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
