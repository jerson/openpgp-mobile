// +build js,wasm

package main

import (
	"encoding/base64"
	"errors"
	"github.com/jerson/openpgp-mobile/bridge"
	"syscall/js"
)

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
	result, err := fn()
	if err != nil {
		callback.Invoke(err.Error(), js.Null())
		return nil
	}
	callback.Invoke(js.Null(), js.ValueOf(result))

	return nil
}

func Call(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		data, err := base64.StdEncoding.DecodeString(i[1].String())
		if err != nil {
			return nil, err
		}
		output, err := openPGPBridge.Call(i[0].String(), data)
		if err != nil {
			return nil, err
		}
		return base64.StdEncoding.EncodeToString(output), err
	})
}

func registerCallbacks() {
	js.Global().Set("OpenPGPCall", js.FuncOf(Call))
}

func main() {
	c := make(chan bool, 0)
	registerCallbacks()
	<-c
}
