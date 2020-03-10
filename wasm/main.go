// +build js,wasm

package main

import (
	"errors"
	"syscall/js"

	"github.com/jerson/openpgp-mobile/openpgp"
)

var instance = openpgp.NewFastOpenPGP()

func Promise(i []js.Value, fn func() (result interface{}, err error)) interface{} {

	if len(i) < 1 {
		println(errors.New("error: required at least one argument").Error())
		return nil
	}
	callback := i[len(i)-1:][0]
	if callback.Type() != js.TypeFunction {
		println(errors.New("error: last argument should be a callback(err,result)").Error())
		return nil
	}
	go func() {
		result, err := fn()
		if err != nil {
			callback.Invoke(err.Error(), js.Null())
			return
		}
		callback.Invoke(js.Null(), js.ValueOf(result))
	}()

	return nil
}

func Encrypt(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		return instance.Encrypt(i[0].String(), i[1].String())
	})
}

func Decrypt(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		return instance.Decrypt(i[0].String(), i[1].String(), i[2].String())
	})
}

func Sign(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		return instance.Sign(i[0].String(), i[1].String(), i[2].String(), i[3].String())
	})
}

func Verify(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		return instance.Verify(i[0].String(), i[1].String(), i[2].String())
	})
}

func EncryptSymmetric(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		return instance.EncryptSymmetric(i[0].String(), i[1].String(), getKeyOptions(i[2]))
	})
}

func DecryptSymmetric(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		return instance.DecryptSymmetric(i[0].String(), i[1].String(), getKeyOptions(i[2]))
	})
}

func Generate(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		resultKeyPair, err := instance.Generate(getOptions(i[0]))
		if err != nil {
			return nil, err
		}

		return map[string]interface{}{
			"publicKey":  resultKeyPair.PublicKey,
			"privateKey": resultKeyPair.PrivateKey,
		}, err
	})
}

func getKeyOptions(data js.Value) *openpgp.KeyOptions {

	var options *openpgp.KeyOptions
	if data.IsUndefined() || data.IsNull() {
		return options
	}

	options.Hash = data.Get("hash").String()
	options.Cipher = data.Get("cipher").String()
	options.Compression = data.Get("compression").String()
	options.CompressionLevel = data.Get("compressionLevel").Int()
	options.RSABits = data.Get("rsaBits").Int()

	return options

}

func getOptions(data js.Value) *openpgp.Options {

	var options *openpgp.Options
	if data.IsUndefined() || data.IsNull() {
		return options
	}

	options.Name = data.Get("name").String()
	options.Comment = data.Get("comment").String()
	options.Email = data.Get("email").String()
	options.Passphrase = data.Get("passphrase").String()
	options.KeyOptions = getKeyOptions(data.Get("keyOptions"))

	return options
}

func registerCallbacks() {
	js.Global().Set("OpenPGPEncrypt", js.FuncOf(Encrypt))
	js.Global().Set("OpenPGPDecrypt", js.FuncOf(Decrypt))
	js.Global().Set("OpenPGPSign", js.FuncOf(Sign))
	js.Global().Set("OpenPGPVerify", js.FuncOf(Verify))
	js.Global().Set("OpenPGPEncryptSymmetric", js.FuncOf(EncryptSymmetric))
	js.Global().Set("OpenPGPDecryptSymmetric", js.FuncOf(DecryptSymmetric))
	js.Global().Set("OpenPGPGenerate", js.FuncOf(Generate))
}

func main() {
	c := make(chan bool, 0)
	registerCallbacks()
	<-c
}
