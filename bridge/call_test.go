package openPGPBridge

import (
	flatbuffers "github.com/google/flatbuffers/go"
	"github.com/jerson/openpgp-mobile/bridge/model"
	"testing"
)

func TestCall(t *testing.T) {

	b := flatbuffers.NewBuilder(0)

	comment := b.CreateString("sample")
	email := b.CreateString("sample@sample.com")
	name := b.CreateString("sample")
	passphrase := b.CreateString("sample")

	model.OptionsStart(b)
	model.OptionsAddComment(b, comment)
	model.OptionsAddEmail(b, email)
	model.OptionsAddName(b, name)
	model.OptionsAddPassphrase(b, passphrase)
	options := model.OptionsEnd(b)

	model.GenerateRequestStart(b)
	model.GenerateRequestAddOptions(b, options)
	b.Finish(model.GenerateRequestEnd(b))

	data, err := Call("generate", b.Bytes)
	if err != nil {
		t.Fatal(err)
		return
	}
	response := model.GetRootAsKeyPairResponse(data, 0)
	keyPairOutput := response.Output(nil)
	t.Log(string(keyPairOutput.PrivateKey()))
	t.Log(string(keyPairOutput.PublicKey()))
}
